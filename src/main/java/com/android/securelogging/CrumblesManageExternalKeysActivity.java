/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.securelogging;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.util.stream.Collectors.joining;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.StringRes;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;
import androidx.documentfile.provider.DocumentFile;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/** Activity for managing external keys. */
public class CrumblesManageExternalKeysActivity extends AppCompatActivity
    implements CrumblesPrivateKeyViewerDialogFragment.KeyCustodyConfirmationListener {

  private static final String TAG = "CrumblesManageExtKeysActivity";
  private static final String AUDIT_EVENT_KEY_GENERATION_FAILED = "KEY_INTERNAL_GENERATION_FAILED";
  private static final String AUDIT_EVENT_KEY_CHANGE_REQUESTED = "KEY_CHANGE_REQUESTED";
  private static final String AUDIT_EVENT_KEY_CHANGE_REFUSED = "KEY_CHANGE_REFUSED";
  private static final String AUDIT_EVENT_KEY_CHANGE_AUTH_FAILED = "KEY_CHANGE_AUTH_FAILED";
  private static final String AUDIT_EVENT_LOGS_LOST = "LOGS_LOST";
  static final String AUDIT_EVENT_RE_ENCRYPT_FAILED = "RE_ENCRYPT_FAILED";

  private record PendingUpload(ImmutableList<File> logFiles, Runnable keyChange) {}

  /**
   * Generates the keys of every key management screen, and hands over to the outgoing keys, one at
   * a time, off the main thread. Its thread ends once it has been idle for a minute.
   */
  private static final ThreadPoolExecutor defaultKeyGenerationExecutor =
      new ThreadPoolExecutor(
          /* corePoolSize= */ 0,
          /* maximumPoolSize= */ 1,
          /* keepAliveTime= */ 1,
          TimeUnit.MINUTES,
          new LinkedBlockingQueue<>());

  /**
   * Executor used by {@link #runInBackground}; defaults to {@link #defaultKeyGenerationExecutor}
   * and is replaced in tests via {@link #setKeyGenerationExecutorForTest}.
   */
  private Executor keyGenerationExecutor = defaultKeyGenerationExecutor;

  @SuppressLint("UsableSpace")
  private LongSupplier usableSpaceSupplier = () -> getFilesDir().getUsableSpace();
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private boolean isStopped;
  private int activeBackgroundTasks;
  private boolean pendingChangeDeletesInternalKey;
  private boolean reEncryptChosen;
  private ImmutableList<File> pendingLogsSnapshot = ImmutableList.of();
  @Nullable private PublicKey pendingCandidatePublicKey;
  private TextView tvCurrentExternalKeyStatus;
  @Nullable private PendingUpload pendingUpload;

  /**
   * Decrypted pending logs that the user chose to re-encrypt, held until the key change commits so
   * that they are re-encrypted to the key that became active, never to the outgoing one.
   */
  @Nullable private ImmutableList<PendingLogData> logsToReEncryptAfterKeyChange;

  @Nullable private List<PendingLogData> logsBeingDecrypted;
  @Nullable private AlertDialog reEncryptConfirmationDialog;
  @Nullable private AlertDialog exportChoiceDialog;
  @Nullable private byte[] pendingExportChoiceKeyBytes;

  private final ActivityResultLauncher<Uri> uploadFolderLauncher =
      registerForActivityResult(
          new ActivityResultContracts.OpenDocumentTree(), this::onUploadFolderChosen);

  private final ActivityResultLauncher<Intent> qrScanLauncher =
      registerForActivityResult(
          new ActivityResultContracts.StartActivityForResult(),
          result -> {
            if (result.getResultCode() != Activity.RESULT_OK) {
              Log.d(TAG, "QR Scan cancelled or failed. Result code: " + result.getResultCode());
              Toast.makeText(this, getString(R.string.toast_qr_scan_cancelled), Toast.LENGTH_LONG)
                  .show();
              return;
            }

            Intent data = result.getData();
            if (data == null) {
              Log.w(TAG, "QR Scan RESULT_OK but data intent is null.");
              Toast.makeText(
                      this, getString(R.string.toast_qr_scan_failed_no_data), Toast.LENGTH_LONG)
                  .show();
              return;
            }

            String scannedPublicKeyB64 = data.getStringExtra(CrumblesConstants.SCAN_RESULT_EXTRA);

            if (isNullOrEmpty(scannedPublicKeyB64)) {
              Log.w(TAG, "QR Scan successful but no content in SCAN_RESULT extra.");
              Toast.makeText(
                      this, getString(R.string.toast_qr_scan_failed_no_data), Toast.LENGTH_LONG)
                  .show();
              return;
            }

            try {
              processScannedPublicKeyInternal(scannedPublicKeyB64);
            } catch (CrumblesKeysException | IllegalArgumentException e) {
              // Log only the exception type: its message can echo part of the scanned payload.
              Log.w(TAG, "Scanned QR code is not a valid public key: " + e.getClass().getName());
              CrumblesAppAuditLogger.getInstance(this)
                  .logEvent(
                      "EXTERNAL_KEY_IMPORT_REJECTED", "Scanned QR code is not a valid public key.");
              showPersistentMessage(
                  R.string.dialog_title_key_not_imported, R.string.dialog_message_qr_not_a_key);
            }
          });

  /** Processes the scanned Base64 public key string. */
  protected void processScannedPublicKeyInternal(String scannedPublicKeyB64)
      throws CrumblesKeysException {
    checkArgument(
        !isNullOrEmpty(scannedPublicKeyB64),
        "Scanned public key data cannot be null or empty for processing.");
    PublicKey importedPublicKey = CrumblesScannedKeyVerifier.parseScannedKey(scannedPublicKeyB64);

    CrumblesScannedKeyVerifier.confirmFingerprint(
        this,
        importedPublicKey,
        () ->
            requestCredentialForKeyChange(
                "import a scanned public key", () -> adoptScannedKey(importedPublicKey)));
  }

  /** Hands over to the outgoing key, then stores a scanned key as the active recipient key. */
  private void adoptScannedKey(PublicKey importedPublicKey) {
    handOverAndAdoptKey(
        "an imported key",
        importedPublicKey,
        fingerprint -> saveScannedKey(importedPublicKey, fingerprint),
        this::onScannedKeyNotSaved);
  }

  /** Stores a scanned key as the active recipient key and makes it effective immediately. */
  private void saveScannedKey(PublicKey importedPublicKey, String fingerprint) {
    try {
      publicKeyManager.saveActiveExternalPublicKey(importedPublicKey);
      CrumblesDeviceAdminReceiver.cancelKeyInvalidatedNotification(this);
      CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(importedPublicKey);
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "EXTERNAL_KEY_IMPORTED",
              "External public key imported via QR scan after fingerprint confirmation."
                  + keyFingerprintSuffix(fingerprint));
      showToast(getString(R.string.toast_external_key_imported_successfully));
      reEncryptHeldLogs(importedPublicKey);
      postUi(this::finish);
    } catch (CrumblesKeysException e) {
      onScannedKeyNotSaved(e);
    }
  }

  /** Records that a scanned key could not be made the active key, and tells the user. */
  private void onScannedKeyNotSaved(CrumblesKeysException e) {
    Log.e(TAG, "Failed to save imported key.", e);
    dropHeldLogs();
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent("EXTERNAL_KEY_IMPORT_FAILED", "Scanned public key could not be saved.");
    showToast("Error importing key: " + e.getMessage());
  }

  @Override
  protected void onSaveInstanceState(@NonNull Bundle outState) {
    super.onSaveInstanceState(outState);
    if (pendingCandidatePublicKey != null) {
      outState.putByteArray("pending_candidate_public_key", pendingCandidatePublicKey.getEncoded());
    }
    outState.putBoolean("pending_change_deletes_internal_key", pendingChangeDeletesInternalKey);
    outState.putBoolean("re_encrypt_chosen", reEncryptChosen);
    outState.putStringArrayList(
        "pending_logs_snapshot",
        new ArrayList<>(pendingLogsSnapshot.stream().map(File::getPath).toList()));
  }

  @Override
  protected void onStart() {
    super.onStart();
    isStopped = false;
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    // The system can restore this activity in a process where CrumblesMain.onCreate never ran.
    // Caching the context lets key changes record their events in the activity log.
    CrumblesLogsEncryptor.setApplicationContext(this);
    setContentView(R.layout.activity_manage_external_keys);
    CrumblesWindowInsets.applySystemBarPadding(this);

    if (savedInstanceState != null
        && savedInstanceState.containsKey("pending_candidate_public_key")) {
      byte[] keyBytes = savedInstanceState.getByteArray("pending_candidate_public_key");
      if (keyBytes != null) {
        try {
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          this.pendingCandidatePublicKey =
              keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          Log.e(TAG, "Failed to restore pending candidate public key from saved instance state", e);
        }
      }
    }
    if (savedInstanceState != null) {
      pendingChangeDeletesInternalKey =
          savedInstanceState.getBoolean("pending_change_deletes_internal_key");
      reEncryptChosen = savedInstanceState.getBoolean("re_encrypt_chosen");
      List<String> saved = savedInstanceState.getStringArrayList("pending_logs_snapshot");
      if (saved != null) {
        pendingLogsSnapshot = saved.stream().map(File::new).collect(toImmutableList());
      }
    }
    if (getSupportFragmentManager().findFragmentByTag("private_key_viewer")
        instanceof CrumblesPrivateKeyViewerDialogFragment viewer) {
      viewer.setKeyCustodyConfirmationListener(this);
    }

    if (getSupportActionBar() != null) {
      getSupportActionBar().setDisplayHomeAsUpEnabled(true);
      getSupportActionBar().setTitle(getString(R.string.title_manage_external_keys));
    }

    if (publicKeyManager == null) {
      publicKeyManager = CrumblesExternalPublicKeyManager.getInstance(this);
    }
    tvCurrentExternalKeyStatus = findViewById(R.id.tv_current_external_key_status);

    Button btnGenerateKeystoreKey = findViewById(R.id.btn_generate_keystore_key);
    Button btnGenerateExportableKey = findViewById(R.id.btn_generate_exportable_key);
    Button btnImportExternalPublicKeyQr = findViewById(R.id.btn_import_external_public_key_qr);
    Button btnClearActiveExternalKey = findViewById(R.id.btn_clear_active_external_key);

    btnGenerateKeystoreKey.setOnClickListener(v -> onGenerateKeystoreKey());
    btnGenerateExportableKey.setOnClickListener(v -> onGenerateExportableKey());
    btnImportExternalPublicKeyQr.setOnClickListener(v -> startQrScan());
    btnClearActiveExternalKey.setOnClickListener(v -> clearActiveKey());

    updateStatusUi();
  }

  @Override
  protected void onResume() {
    super.onResume();
    updateStatusUi();
  }

  @Override
  protected void onStop() {
    super.onStop();
    isStopped = true;
    wipePendingExportChoiceKey();
    if (exportChoiceDialog != null && exportChoiceDialog.isShowing()) {
      pendingCandidatePublicKey = null;
      exportChoiceDialog.dismiss();
    }
    if (reEncryptConfirmationDialog != null) {
      reEncryptConfirmationDialog.dismiss();
    }
    if (activeBackgroundTasks == 0) {
      dropHeldLogs();
    }
  }

  @Override
  protected void onDestroy() {
    wipePendingExportChoiceKey();
    if (activeBackgroundTasks == 0) {
      dropHeldLogs();
    }
    super.onDestroy();
  }

  private void wipePendingExportChoiceKey() {
    if (pendingExportChoiceKeyBytes != null) {
      Arrays.fill(pendingExportChoiceKeyBytes, (byte) 0);
    }
  }

  @VisibleForTesting
  void setPublicKeyManagerForTest(CrumblesExternalPublicKeyManager manager) {
    this.publicKeyManager = manager;
  }

  @VisibleForTesting
  void setKeyGenerationExecutorForTest(Executor executor) {
    this.keyGenerationExecutor = executor;
  }

  @VisibleForTesting
  void setUsableSpaceSupplierForTest(LongSupplier supplier) {
    this.usableSpaceSupplier = supplier;
  }

  private boolean canUpdateUi() {
    return !isDestroyed() && !isStopped;
  }

  protected void updateStatusUi() {
    if (!canUpdateUi()) {
      return;
    }
    PublicKey activeKey = publicKeyManager.getActiveExternalPublicKey();
    Button btnClearActiveExternalKey = findViewById(R.id.btn_clear_active_external_key);

    if (activeKey != null) {
      String keyHash = CrumblesLogsEncryptor.getPublicKeyHash(activeKey);
      tvCurrentExternalKeyStatus.setText(
          getString(R.string.status_external_key_active_formatted, keyHash));
      btnClearActiveExternalKey.setVisibility(View.VISIBLE);
      if (!CrumblesMain.getLogsEncryptorInstance().doesPrivateKeyExist()) {
        btnClearActiveExternalKey.setText(getString(R.string.generate_keystore_key_pair_button));
      } else {
        btnClearActiveExternalKey.setText(getString(R.string.clear_active_external_key_button));
      }
    } else if (publicKeyManager.isExternalKeySelected()) {
      tvCurrentExternalKeyStatus.setText(getString(R.string.status_external_key_unreadable));
      btnClearActiveExternalKey.setVisibility(View.VISIBLE);
      if (!CrumblesMain.getLogsEncryptorInstance().doesPrivateKeyExist()) {
        btnClearActiveExternalKey.setText(getString(R.string.generate_keystore_key_pair_button));
      } else {
        btnClearActiveExternalKey.setText(getString(R.string.btn_choose_key_clear_sentinel));
      }
    } else {
      tvCurrentExternalKeyStatus.setText(getString(R.string.status_no_external_key));
      btnClearActiveExternalKey.setVisibility(View.GONE);
    }
  }

  /** Container holding a pending log file, the batch it held, its decrypted bytes and device ID. */
  private static class PendingLogData {
    final File file;
    final LogBatch batch;
    final byte[] plainBytes;
    final String deviceId;

    PendingLogData(File file, LogBatch batch, byte[] plainBytes, String deviceId) {
      this.file = file;
      this.batch = batch;
      this.plainBytes = plainBytes;
      this.deviceId = deviceId;
    }

    /** Names the batch in the activity log: by its sequence number if signed, else by its file. */
    String nameForAudit() {
      return batch.hasSignature() ? "seq " + batch.getSequenceNumber() : file.getName();
    }
  }

  /** Returns an immutable list of un-uploaded encrypted log files currently stored on device. */
  @VisibleForTesting
  public ImmutableList<File> getPendingLogFiles() {
    File directory =
        new File(getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.isDirectory()) {
      return ImmutableList.of();
    }
    File[] files =
        directory.listFiles(
            (dir, name) ->
                name.endsWith(".bin")
                    && !name.endsWith(CrumblesConstants.SENT_SUFFIX)
                    && !name.endsWith(CrumblesConstants.PROCESSING_SUFFIX));
    if (files == null) {
      return ImmutableList.of();
    }
    return ImmutableList.copyOf(files);
  }

  private static File siblingWithSuffix(File pendingFile, String suffix) {
    String name = pendingFile.getName();
    return new File(pendingFile.getParentFile(), name.substring(0, name.length() - 4) + suffix);
  }

  private ImmutableList<File> snapshotPendingAndInFlightFiles() {
    File dir = new File(getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File[] files = dir.listFiles();
    String proc = CrumblesConstants.PROCESSING_SUFFIX;
    return files == null
        ? ImmutableList.of()
        : Arrays.stream(files)
            .sorted(Comparator.comparingLong(File::lastModified))
            .map(File::getName)
            .filter(n -> n.endsWith(".bin") && !n.endsWith(CrumblesConstants.SENT_SUFFIX))
            .map(n -> n.endsWith(proc) ? n.substring(0, n.length() - proc.length()) + ".bin" : n)
            .distinct()
            .map(n -> new File(dir, n))
            .collect(toImmutableList());
  }

  private boolean hasNewInternalKeyLogsSinceSnapshot() {
    ImmutableList<File> current = snapshotPendingAndInFlightFiles();
    if (pendingChangeDeletesInternalKey && !publicKeyManager.isExternalKeySelected()) {
      return !pendingLogsSnapshot.containsAll(current);
    }
    pendingLogsSnapshot = current;
    return false;
  }

  /** Container holding decryption results for pending log files. */
  private static class DecryptionResult {
    final ImmutableList<PendingLogData> decryptedLogs;
    final ImmutableList<File> failedFiles;
    final ImmutableList<String> failureReasons;

    DecryptionResult(
        List<PendingLogData> decryptedLogs, List<File> failedFiles, List<String> failureReasons) {
      this.decryptedLogs = ImmutableList.copyOf(decryptedLogs);
      this.failedFiles = ImmutableList.copyOf(failedFiles);
      this.failureReasons = ImmutableList.copyOf(failureReasons);
    }
  }

  /**
   * Decrypts the pending files with the active key, after the prompts that their keys need, and
   * passes the result to {@code onDecrypted}. If the user does not authorize the decryption, the
   * key stays unchanged.
   */
  private void decryptPendingLogs(Runnable onEmpty, Consumer<DecryptionResult> onDecrypted) {
    List<LogBatch> logBatches = new ArrayList<>();
    IdentityHashMap<LogBatch, File> files = new IdentityHashMap<>();
    List<File> failedFiles = new ArrayList<>();
    List<String> failureReasons = new ArrayList<>();
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    runInBackground(
        R.string.dialog_message_preparing_key_change,
        () -> {
          synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
            pendingLogsSnapshot = snapshotPendingAndInFlightFiles();
            String proc = CrumblesConstants.PROCESSING_SUFFIX;
            for (File file : pendingLogsSnapshot) {
              try {
                File src = file.exists() ? file : siblingWithSuffix(file, proc);
                LogBatch logBatch = encryptor.deserializeFile(src.toPath());
                logBatches.add(logBatch);
                files.put(logBatch, file);
              } catch (RuntimeException e) {
                Log.e(TAG, "Failed to read pending log file: " + file.getName(), e);
                failedFiles.add(file);
                failureReasons.add(file.getName() + ": " + getSpecificFailureReason(e));
              }
            }
          }
          return () -> {
            if (!canUpdateUi() || getSupportFragmentManager().isStateSaved()) {
              dropHeldLogs();
            } else if (pendingLogsSnapshot.isEmpty()) {
              onEmpty.run();
            } else {
              authorizePendingLogs(logBatches, files, failedFiles, failureReasons, onDecrypted);
            }
          };
        });
  }

  private void authorizePendingLogs(
      List<LogBatch> logBatches,
      IdentityHashMap<LogBatch, File> files,
      List<File> failedFiles,
      List<String> failureReasons,
      Consumer<DecryptionResult> onDecrypted) {
    logsBeingDecrypted = new ArrayList<>();
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    new CrumblesAuthorizedLogDecryptor(this, encryptor)
        .decrypt(
            logBatches,
            new CrumblesAuthorizedLogDecryptor.Callback() {
              @Override
              public void onDecrypted(LogBatch logBatch, DecryptedLogBatch decryptedBatch) {
                if (logsBeingDecrypted != null) {
                  logsBeingDecrypted.add(
                      new PendingLogData(
                          files.get(logBatch),
                          logBatch,
                          decryptedBatch.logs(),
                          decryptedBatch.metadata().getDevice().getDeviceId()));
                } else {
                  Arrays.fill(decryptedBatch.logs(), (byte) 0);
                }
              }

              @Override
              public void onDecryptionFailed(LogBatch logBatch, Exception exception) {
                File file = files.get(logBatch);
                Log.e(TAG, "Failed to decrypt pending log file: " + file.getName(), exception);
                failedFiles.add(file);
                failureReasons.add(file.getName() + ": " + getSpecificFailureReason(exception));
              }

              @Override
              public void onNotAuthorized(int errorCode, CharSequence errorMessage) {
                if (logsBeingDecrypted != null) {
                  wipePlaintext(logsBeingDecrypted);
                  logsBeingDecrypted = null;
                }
                CrumblesAppAuditLogger.getInstance(CrumblesManageExternalKeysActivity.this)
                    .logEvent(
                        AUDIT_EVENT_KEY_CHANGE_AUTH_FAILED,
                        "Key unchanged because the pending logs were not decrypted.");
                showToast(getString(R.string.toast_key_change_auth_cancelled));
              }

              @Override
              public void onFinished() {
                List<PendingLogData> res = logsBeingDecrypted;
                logsBeingDecrypted = null;
                if (res != null) {
                  if (!canUpdateUi() || getSupportFragmentManager().isStateSaved()) {
                    wipePlaintext(res);
                    return;
                  }
                  onDecrypted.accept(
                      new DecryptionResult(res, failedFiles, failureReasons));
                }
              }
            });
  }

  private static String getSpecificFailureReason(Throwable t) {
    String msg = t.getMessage();
    Throwable cause = t.getCause();
    if (cause != null && cause.getMessage() != null && !cause.getMessage().isEmpty()) {
      msg = cause.getMessage();
    }
    if (msg != null
        && (msg.contains("unwrap")
            || msg.contains("decryption failed")
            || msg.contains("BadPadding")
            || msg.contains("AEADBadTag"))) {
      return "Keys did not match (file encrypted with a different key pair)";
    }
    if (msg != null && msg.contains("Private key not available")) {
      return "Current decryption key pair not available";
    }
    if (msg != null && !msg.isEmpty()) {
      return msg;
    }
    return "Unknown decryption or key error";
  }

  /**
   * Re-encrypts the decrypted log entries to {@code recipient}, or to the Keystore key when it is
   * null.
   */
  private int reEncryptPendingLogs(
      List<PendingLogData> decryptedLogs, @Nullable PublicKey recipient) {
    List<PendingLogData> failedBatches = new ArrayList<>();
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    for (PendingLogData item : decryptedLogs) {
      boolean reEncrypted = false;
      try {
        LogBatch reEncryptedBatch = reEncrypt(item, recipient);
        if (reEncryptedBatch != null) {
          File procFile = siblingWithSuffix(item.file, CrumblesConstants.PROCESSING_SUFFIX);
          long mtime = (item.file.exists() ? item.file : procFile).lastModified();
          File target =
              item.file.exists() ? item.file : siblingWithSuffix(item.file, "_reencrypted.bin");
          @SuppressWarnings("unused")
          Path unused =
              encryptor.serializeBytes(
                  reEncryptedBatch, item.file.getParentFile(), target.getName());
          target.setLastModified(mtime);
          procFile.delete();
          siblingWithSuffix(item.file, CrumblesConstants.SENT_SUFFIX).delete();
          reEncrypted = true;
        }
      } catch (RuntimeException e) {
        Log.e(TAG, "Failed to re-encrypt pending log file: " + item.file.getName(), e);
      }
      if (!reEncrypted) {
        failedBatches.add(item);
        if (pendingChangeDeletesInternalKey) {
          stageFailedReEncryptBatch(item);
        }
      }
    }
    logReEncryptFailed(failedBatches);
    return failedBatches.size();
  }

  /** Records in the activity log which of the pending log batches were not re-encrypted, if any. */
  private void logReEncryptFailed(List<PendingLogData> failedBatches) {
    if (!failedBatches.isEmpty()) {
      String msg =
          failedBatches.size()
              + " pending log batch(es) ("
              + failedBatches.stream().map(PendingLogData::nameForAudit).collect(joining(", "))
              + ") could not be re-encrypted after key change.";
      CrumblesAppAuditLogger.getInstance(this).logEvent(AUDIT_EVENT_RE_ENCRYPT_FAILED, msg);
    }
  }

  private void stageFailedReEncryptBatch(PendingLogData item) {
    try {
      if (new CrumblesLogStaging(this).stage(/* isNetworkBatch= */ false, item.plainBytes)) {
        siblingWithSuffix(item.file, CrumblesConstants.PROCESSING_SUFFIX).delete();
        item.file.delete();
        return;
      }
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      // RuntimeException covers ProviderException, which an ailing Keystore throws unchecked.
      Log.e(TAG, "Failed to stage log batch after re-encryption failure.", e);
    }
    String lostMsg = "1 pending log batch(es) were lost after re-encryption and staging failed.";
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST, lostMsg);
  }

  /**
   * Returns the logs of {@code item} encrypted to {@code recipient} (the Keystore key when null),
   * or null without a key. A batch signed by this installation is signed again under its sequence
   * number and this device's current ID, and seals the attestation chain of the batch-signing key,
   * so that re-encrypting leaves the recipient no gap. Any other batch keeps the device ID written
   * in it and stays unsigned, without an attestation chain and without creating a batch-signing
   * key, as does a batch that cannot be signed again, which is reported in the activity log.
   */
  @Nullable
  private LogBatch reEncrypt(PendingLogData item, @Nullable PublicKey recipient) {
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    if (!item.batch.hasSignature()) {
      return encryptor.encryptLogsAttributedTo(item.deviceId, item.plainBytes, recipient);
    }
    CrumblesBatchSigner batchSigner = new CrumblesBatchSigner(this);
    if (batchSigner.isSignedByThisInstallation(item.batch)) {
      LogBatch localBatch = encryptor.encryptLogs(this, item.plainBytes, recipient);
      if (localBatch == null) {
        return null;
      }
      try {
        return batchSigner.signAgain(item.batch, localBatch);
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to sign a re-encrypted log batch again; writing it unsigned.", e);
      }
    }
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED,
            "Re-encrypted log batch "
                + item.batch.getSequenceNumber()
                + " written without a signature: signing it again failed.");
    return encryptor.encryptLogsAttributedTo(item.deviceId, item.plainBytes, recipient);
  }

  /**
   * Asks the user to confirm their device credential before a key change, which can also discard
   * the pending logs, and refuses the change when no secure lock screen is set up. The request,
   * described by {@code change}, and its outcome are recorded in the activity log before anything
   * changes.
   */
  private void requestCredentialForKeyChange(String change, Runnable performKeyChangeAction) {
    pendingChangeDeletesInternalKey = false;
    reEncryptChosen = false;
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(this);
    auditLogger.logEvent(AUDIT_EVENT_KEY_CHANGE_REQUESTED, "User asked to " + change + ".");
    CrumblesDeviceCredentialGate.confirmScreenLock(
        this,
        getString(R.string.key_change_auth_title),
        getString(R.string.key_change_auth_subtitle),
        () -> confirmAndPerformKeyChange(performKeyChangeAction),
        () -> {
          auditLogger.logEvent(
              AUDIT_EVENT_KEY_CHANGE_AUTH_FAILED,
              "Key unchanged because no device credential was confirmed for the change.");
          showToast(getString(R.string.toast_key_change_auth_cancelled));
        },
        () -> {
          auditLogger.logEvent(
              AUDIT_EVENT_KEY_CHANGE_REFUSED,
              "Key unchanged because no secure lock screen is set up.");
          showPersistentMessage(
              R.string.dialog_title_key_not_changed,
              R.string.dialog_message_key_change_requires_screen_lock);
        });
  }

  /**
   * Prompts the user with a confirmation dialog if un-uploaded logs exist before performing a key
   * pair change, allowing them to re-encrypt existing logs or leave them as-is.
   */
  private void confirmAndPerformKeyChange(Runnable performKeyChangeAction) {
    decryptPendingLogs(
        performKeyChangeAction,
        result -> {
          ImmutableList<File> pendingLogFiles = pendingLogsSnapshot;
          if (result.failedFiles.isEmpty()) {
            showReEncryptConfirmationDialog(
                pendingLogFiles, result.decryptedLogs, performKeyChangeAction);
          } else {
            // None of the choices that the dialog offers re-encrypts the logs.
            wipePlaintext(result.decryptedLogs);
            showDecryptionErrorDialog(result, pendingLogFiles, performKeyChangeAction);
          }
        });
  }

  private void showDecryptionErrorDialog(
      DecryptionResult result, List<File> pendingLogFiles, Runnable performKeyChangeAction) {
    int failedCount = result.failedFiles.size();
    int totalCount = pendingLogFiles.size();
    StringBuilder detailsBuilder = new StringBuilder();
    for (String reason : result.failureReasons) {
      detailsBuilder.append("\n• ").append(reason);
    }
    String message =
        String.format(
            Locale.getDefault(),
            "Failed to decrypt %d out of %d pending log file(s) with your current key pair:%s\n\n"
                + "Changing your key pair now will prevent those logs from being decrypted in the"
                + " future. Would you like to upload all remaining logs as-is, discard them, or"
                + " cancel the key change?",
            failedCount,
            totalCount,
            detailsBuilder);

    new AlertDialog.Builder(this)
        .setTitle("Log Decryption Warning")
        .setMessage(message)
        .setPositiveButton(
            "Upload As-Is",
            (dialog, which) -> {
              wipePlaintext(result.decryptedLogs);
              uploadPendingLogsThenChangeKey(pendingLogFiles, performKeyChangeAction);
            })
        .setNeutralButton(
            "Discard Logs",
            (dialog, which) -> {
              wipePlaintext(result.decryptedLogs);
              discardPendingLogs(pendingLogFiles, performKeyChangeAction);
            })
        .setNegativeButton("Cancel", (dialog, which) -> wipePlaintext(result.decryptedLogs))
        .setOnCancelListener(dialog -> wipePlaintext(result.decryptedLogs))
        .show();
  }

  private void showReEncryptConfirmationDialog(
      List<File> pendingLogFiles,
      ImmutableList<PendingLogData> decryptedLogs,
      Runnable performKeyChangeAction) {
    logsToReEncryptAfterKeyChange = decryptedLogs;
    CharSequence[] options = new CharSequence[] {"Re-encrypt", "Upload As-Is", "Discard Logs"};
    reEncryptConfirmationDialog =
        new AlertDialog.Builder(this)
            .setTitle("Re-encrypt Existing Logs?")
            .setItems(
                options,
                (dialog, which) -> {
                  if (which == 0) {
                    // Re-encrypting now would target the outgoing key: the change may still wait
                    // for the user (custody of an exportable key) or fail. Each change re-encrypts
                    // these logs itself once the new key is active.
                    reEncryptChosen = true;
                    performKeyChangeAction.run();
                  } else if (which == 1) {
                    dropHeldLogs();
                    uploadPendingLogsThenChangeKey(pendingLogFiles, performKeyChangeAction);
                  } else if (which == 2) {
                    dropHeldLogs();
                    discardPendingLogs(pendingLogFiles, performKeyChangeAction);
                  }
                })
            .setNegativeButton("Cancel", (dialog, which) -> dropHeldLogs())
            .setOnCancelListener(dialog -> dropHeldLogs())
            .show();
  }

  /**
   * Re-encrypts the logs held for a key change that has just made {@code recipient} active (the
   * Keystore key when null), then wipes their plaintext.
   */
  private void reEncryptHeldLogs(@Nullable PublicKey recipient) {
    reEncryptChosen = false;
    ImmutableList<PendingLogData> heldLogs = logsToReEncryptAfterKeyChange;
    logsToReEncryptAfterKeyChange = null;
    if (heldLogs == null || heldLogs.isEmpty()) {
      return;
    }
    int failedCount = reEncryptPendingLogs(heldLogs, recipient);
    wipePlaintext(heldLogs);
    showToast(
        failedCount > 0
            ? getResources()
                .getQuantityString(
                    R.plurals.toast_logs_re_encrypted_with_failures, failedCount, failedCount)
            : getString(R.string.toast_logs_re_encrypted));
  }

  /** Wipes the logs held for a key change that did not happen; their files stay as they were. */
  private void dropHeldLogs() {
    if (logsToReEncryptAfterKeyChange != null) {
      wipePlaintext(logsToReEncryptAfterKeyChange);
      logsToReEncryptAfterKeyChange = null;
    }
    if (logsBeingDecrypted != null) {
      wipePlaintext(logsBeingDecrypted);
      logsBeingDecrypted = null;
    }
  }

  private static void wipePlaintext(List<PendingLogData> logs) {
    for (PendingLogData item : logs) {
      Arrays.fill(item.plainBytes, (byte) 0);
    }
  }

  /** Deletes the specified pending log files from the device, then runs {@code afterDiscard}. */
  private void discardPendingLogs(List<File> pendingLogFiles, Runnable afterDiscard) {
    runInBackground(
        R.string.dialog_message_preparing_key_change,
        () -> {
          int deleteCount = 0;
          synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
            if (hasNewInternalKeyLogsSinceSnapshot()) {
              return abortBecausePendingLogsChanged();
            }
            for (File file : pendingLogFiles) {
              // Deletes both files, even when the first deletion succeeds.
              boolean deletedProcessingFile =
                  siblingWithSuffix(file, CrumblesConstants.PROCESSING_SUFFIX).delete();
              boolean deletedPendingFile = file.delete();
              if (deletedProcessingFile || deletedPendingFile) {
                deleteCount++;
              }
            }
          }
          if (deleteCount > 0) {
            CrumblesAppAuditLogger.getInstance(this)
                .logEvent(
                    "LOGS_DISCARDED",
                    deleteCount + " pending log file(s) discarded prior to key rotation.");
            showToast(deleteCount + " pending log file(s) discarded.");
          }
          return () -> {
            if (canUpdateUi() && !getSupportFragmentManager().isStateSaved()) {
              afterDiscard.run();
            }
          };
        });
  }

  /**
   * Asks the user for a folder, copies the pending log files into it and then changes the key.
   *
   * <p>Unlike sharing the files with another app, copying them through the Storage Access Framework
   * tells Crumbles whether each file was written, so the key is only changed once every file is
   * safe, or once the user agrees to leave the others behind.
   */
  private void uploadPendingLogsThenChangeKey(
      List<File> pendingLogFiles, Runnable performKeyChangeAction) {
    try {
      uploadFolderLauncher.launch(/* input= */ null);
      pendingUpload =
          new PendingUpload(ImmutableList.copyOf(pendingLogFiles), performKeyChangeAction);
    } catch (ActivityNotFoundException e) {
      Log.e(TAG, "No app available to choose an upload folder.", e);
      reportLogsNotCopied(pendingLogFiles.size(), pendingLogFiles.size(), performKeyChangeAction);
    }
  }

  private void onUploadFolderChosen(@Nullable Uri folderUri) {
    if (pendingUpload == null) {
      // The activity was recreated while the picker was open, so the key change is gone.
      return;
    }
    if (folderUri == null) {
      showToast(getString(R.string.toast_upload_folder_not_chosen));
      return;
    }
    PendingUpload upload = pendingUpload;
    pendingUpload = null;
    runInBackground(
        R.string.dialog_message_preparing_key_change,
        () -> {
          int failedCount = upload.logFiles().size() - copyToFolder(upload.logFiles(), folderUri);
          return () -> finishUploadBeforeKeyChange(upload, failedCount);
        });
  }

  private void finishUploadBeforeKeyChange(PendingUpload pendingUpload, int failedCount) {
    if (!canUpdateUi() || getSupportFragmentManager().isStateSaved()) {
      dropHeldLogs();
      return;
    }
    if (failedCount > 0) {
      reportLogsNotCopied(failedCount, pendingUpload.logFiles().size(), pendingUpload.keyChange());
      return;
    }
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            "LOGS_COPIED_BEFORE_KEY_CHANGE",
            pendingUpload.logFiles().size()
                + " pending log file(s) copied to a chosen folder before key rotation.");
    showToast(getString(R.string.toast_logs_copied_before_key_change));
    pendingUpload.keyChange().run();
  }

  /**
   * Copies {@code logFiles} into the folder at {@code folderUri} and marks each copied file as
   * sent, so that the upload worker neither uploads it again nor keeps it.
   *
   * @return the number of files copied
   */
  private int copyToFolder(List<File> logFiles, Uri folderUri) {
    DocumentFile folder = null;
    try {
      folder = DocumentFile.fromTreeUri(this, folderUri);
    } catch (IllegalArgumentException e) {
      Log.e(TAG, "The chosen upload location is not a folder.", e);
    }
    if (folder == null) {
      return 0;
    }
    RemoteStorageUploader uploader = new GoogleDriveStorageUploader(folder);
    int copiedCount = 0;
    for (File file : logFiles) {
      if (CrumblesSendAndMarkProcessingWorker.uploadSingleFile(
          this, uploader, file, file.getParentFile())) {
        copiedCount++;
      }
    }
    return copiedCount;
  }

  /** Records that some pending log files were not copied and asks whether to change the key. */
  private void reportLogsNotCopied(int failedCount, int totalCount, Runnable keyChange) {
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            "LOGS_COPY_BEFORE_KEY_CHANGE_FAILED",
            failedCount
                + " of "
                + totalCount
                + " pending log file(s) could not be copied before key rotation; kept on device.");
    new AlertDialog.Builder(this)
        .setTitle(R.string.dialog_logs_not_copied_title)
        .setMessage(R.string.dialog_logs_not_copied_message)
        .setPositiveButton(
            R.string.dialog_logs_not_copied_confirm, (dialog, which) -> keyChange.run())
        .setNegativeButton(android.R.string.cancel, /* listener= */ null)
        .show();
  }

  private void onGenerateKeystoreKey() {
    KeyguardManager keyguardManager = getSystemService(KeyguardManager.class);
    if (keyguardManager == null || !keyguardManager.isDeviceSecure()) {
      reportNoScreenLock();
      return;
    }
    requestCredentialForKeyChange("generate a new Keystore key pair", this::switchToNewKeystoreKey);
    pendingChangeDeletesInternalKey = true;
  }

  /** Generates a Keystore key pair before dropping the external key, so failures keep that key. */
  private void switchToNewKeystoreKey() {
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    runInBackground(R.string.dialog_message_generating_key, () -> generateKeystoreKey(encryptor));
  }

  private void postUi(Runnable action) {
    runOnUiThread(
        () -> {
          if (canUpdateUi()) {
            action.run();
          }
        });
  }

  /**
   * Runs {@code task} off the main thread behind a progress dialog showing {@code
   * progressMessageId}, then runs the continuation it returns on the main thread even if the screen
   * closed meanwhile.
   *
   * <p>Generating an RSA key takes up to several seconds, in StrongBox or for 3072-bit keys, and a
   * handover waits for its upload. The orientation is locked meanwhile, so that rotating the phone
   * does not recreate the screen and drop the logs held for the key change.
   */
  private void runInBackground(@StringRes int progressMessageId, Supplier<Runnable> task) {
    activeBackgroundTasks++;
    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LOCKED);
    AlertDialog progressDialog =
        new AlertDialog.Builder(this).setMessage(progressMessageId).setCancelable(false).show();
    keyGenerationExecutor.execute(
        () -> {
          Runnable continuation = this::dropHeldLogs;
          try {
            continuation = task.get();
          } finally {
            Runnable finalContinuation = continuation;
            runOnUiThread(
                () -> {
                  if (isDestroyed()) {
                    Log.w(TAG, "Key management screen closed before its background task ended.");
                  } else {
                    progressDialog.dismiss();
                    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED);
                  }
                  try {
                    finalContinuation.run();
                  } finally {
                    activeBackgroundTasks--;
                  }
                });
          }
        });
  }

  /**
   * Generates the Keystore key pair, hands over to the outgoing key and returns how to finish the
   * change.
   */
  private Runnable generateKeystoreKey(CrumblesLogsEncryptor encryptor) {
    return handOverToOutgoingKey(
        "Changing to a new on-device key",
        () -> {
          try {
            PublicKey newPublicKey = encryptor.generateKeyPair().getPublic();
            finishSwitchToNewKeystoreKey(
                encryptor, newPublicKey, fingerprintForAudit(newPublicKey));
          } catch (CrumblesKeysException e) {
            onKeystoreKeySwitchFailed(e);
          }
        });
  }

  /** Makes the generated Keystore key pair active, dropping the external key. */
  private void finishSwitchToNewKeystoreKey(
      CrumblesLogsEncryptor encryptor, PublicKey newPublicKey, String newKeyFingerprint) {
    try {
      publicKeyManager.saveActiveExternalPublicKey(null);
    } catch (CrumblesKeysException e) {
      if (publicKeyManager.isExternalKeySelected()) {
        onKeystoreKeySwitchFailed(e);
        return;
      }
      // No external key is selected, so the new Keystore key encrypts the logs from now on.
      Log.e(TAG, "Failed to clear the external key record; the new Keystore key is active.", e);
    }
    CrumblesDeviceAdminReceiver.recordActivatedInternalKey(this, newPublicKey);
    encryptor.setExternalEncryptionPublicKey(null);
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            "KEY_INTERNAL_GENERATED",
            "New internal Keystore key pair generated." + keyFingerprintSuffix(newKeyFingerprint));
    showToast("New internal Keystore key generated successfully.");
    reEncryptHeldLogs(/* recipient= */ null);
    postUi(this::finish);
  }

  private void onKeystoreKeySwitchFailed(CrumblesKeysException e) {
    Log.e(TAG, "Failed to switch to a new internal key pair.", e);
    // generateKeyPair() deletes the previous Keystore key first, so the held logs can no longer
    // be decrypted where they are: keep them readable with the external key that stays active.
    PublicKey activeExternalKey = publicKeyManager.getActiveExternalPublicKey();
    ImmutableList<PendingLogData> held = logsToReEncryptAfterKeyChange;
    CrumblesDeviceAdminReceiver.clearActivatedInternalKey(this);
    if (activeExternalKey != null) {
      reEncryptHeldLogs(activeExternalKey);
    } else if (held != null) {
      logsToReEncryptAfterKeyChange = null;
      // Stage them before any activity log write: their plaintext is the only readable copy left.
      List<String> heldBatches = new ArrayList<>();
      int lost = 0;
      for (PendingLogData item : held) {
        heldBatches.add(
            item.batch.hasSignature()
                ? "seq " + item.batch.getSequenceNumber()
                : item.file.getName());
        boolean staged = false;
        try {
          staged =
              new CrumblesLogStaging(this).stage(/* isNetworkBatch= */ false, item.plainBytes);
        } catch (GeneralSecurityException | IOException | RuntimeException ex) {
          Log.e(TAG, "Failed to stage log batch after re-encryption failure.", ex);
        }
        if (staged) {
          siblingWithSuffix(item.file, CrumblesConstants.PROCESSING_SUFFIX).delete();
          item.file.delete();
        } else {
          lost++;
        }
      }
      wipePlaintext(held);
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              AUDIT_EVENT_RE_ENCRYPT_FAILED,
              held.size()
                  + " pending log batch(es) ("
                  + String.join(", ", heldBatches)
                  + ") could not be re-encrypted after key change.");
      if (lost > 0) {
        CrumblesAppAuditLogger.getInstance(this)
            .logEvent(
                AUDIT_EVENT_LOGS_LOST,
                lost
                    + " pending log batch(es) were lost after re-encryption and staging"
                    + " failed.");
      }
    }
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            AUDIT_EVENT_KEY_GENERATION_FAILED,
            "Switching to a new internal Keystore key pair failed.");
    int failureMsg = R.string.dialog_message_key_generation_failed;
    postUi(() -> showPersistentMessage(R.string.title_keystore_key_not_created, failureMsg));
  }

  /**
   * Records and explains that the authentication-bound Keystore key needs a screen lock, leaving
   * the existing keys untouched.
   */
  private void reportNoScreenLock() {
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            AUDIT_EVENT_KEY_GENERATION_FAILED,
            "Internal Keystore key pair not generated: no screen lock is set on this device.");
    if (!postNoScreenLockNotification()) {
      showPersistentMessage(
          R.string.title_keystore_key_not_created, R.string.notification_text_no_screen_lock);
    }
  }

  /**
   * Posts a notification that opens screen lock setup and stays until the user taps or dismisses
   * it.
   *
   * @return whether the notification could be posted, which also takes a system activity that sets
   *     a screen lock
   */
  // Suppress "MissingPermission" and "PendingIntentMutability" because a missing notification
  // permission is handled here and PendingIntent.FLAG_IMMUTABLE is explicitly supplied.
  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private boolean postNoScreenLockNotification() {
    NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);
    Optional<Intent> screenLockSettings = CrumblesScreenLockSettings.intent(getPackageManager());
    if (!notificationManager.areNotificationsEnabled() || screenLockSettings.isEmpty()) {
      return false;
    }
    NotificationChannel channel =
        new NotificationChannel(
            CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID,
            getString(R.string.notification_channel_name_action_needed),
            NotificationManager.IMPORTANCE_HIGH);
    channel.setDescription(getString(R.string.notification_channel_description_action_needed));
    // Keep the content off the lock screen: revealing that the device collects security logs
    // endangers at-risk users.
    channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
    notificationManager.createNotificationChannel(channel);

    PendingIntent setScreenLockIntent =
        PendingIntent.getActivity(
            this, /* requestCode= */ 0, screenLockSettings.get(), PendingIntent.FLAG_IMMUTABLE);
    String text = getString(R.string.notification_text_no_screen_lock);
    Notification notification =
        new NotificationCompat.Builder(
                this, CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(getString(R.string.title_keystore_key_not_created))
            .setContentText(text)
            .setStyle(new NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(setScreenLockIntent)
            .setAutoCancel(true)
            .build();
    try {
      notificationManager.notify(CrumblesConstants.NO_SCREEN_LOCK_NOTIFICATION_ID, notification);
      return true;
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted; explaining in a dialog instead.", e);
      return false;
    }
  }

  /** Shows a message that stays on screen until the user dismisses it, unlike a toast. */
  private void showPersistentMessage(int titleId, int messageId) {
    if (!canUpdateUi()) {
      return;
    }
    new AlertDialog.Builder(this)
        .setTitle(titleId)
        .setMessage(messageId)
        .setPositiveButton(android.R.string.ok, /* listener= */ null)
        .show();
  }

  private void onGenerateExportableKey() {
    requestCredentialForKeyChange(
        "generate a new exportable key pair",
        () -> runInBackground(R.string.dialog_message_generating_key, this::generateExportableKey));
  }

  /** Generates a candidate exportable key pair and returns how to hand over its private key. */
  private Runnable generateExportableKey() {
    try {
      KeyPair candidatePair =
          CrumblesMain.getLogsEncryptorInstance().generateCandidateExternalKeyPair();
      byte[] privateKeyBytes = candidatePair.getPrivate().getEncoded();
      return () -> {
        if (!canUpdateUi()) {
          Arrays.fill(privateKeyBytes, (byte) 0);
          dropHeldLogs();
          return;
        }
        this.pendingCandidatePublicKey = candidatePair.getPublic();
        showPrivateKeyExportChoiceDialog(privateKeyBytes);
      };
    } catch (CrumblesKeysException e) {
      return () -> {
        Log.e(TAG, "Failed to generate exportable key pair", e);
        dropHeldLogs();
        showToast(
            getString(R.string.toast_generate_external_key_error_with_message, e.getMessage()));
      };
    }
  }

  private void showPrivateKeyExportChoiceDialog(final byte[] privateKeyBytes) {
    pendingExportChoiceKeyBytes = privateKeyBytes;
    final boolean[] handedToViewer = {false};
    exportChoiceDialog =
        new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_choose_key_format)
            .setMessage(R.string.dialog_message_choose_key_format)
            .setPositiveButton(
                R.string.dialog_button_view_as_text,
                (dialog, which) -> {
                  handedToViewer[0] = true;
                  pendingExportChoiceKeyBytes = null;
                  showPrivateKeyViewer(privateKeyBytes, /* showQrInitially= */ false);
                })
            .setNegativeButton(
                R.string.dialog_button_view_as_qr,
                (dialog, which) -> {
                  handedToViewer[0] = true;
                  pendingExportChoiceKeyBytes = null;
                  showPrivateKeyViewer(privateKeyBytes, /* showQrInitially= */ true);
                })
            .setOnDismissListener(
                dialog -> {
                  if (!handedToViewer[0]) {
                    wipePendingExportChoiceKey();
                    pendingCandidatePublicKey = null;
                    dropHeldLogs();
                    Log.d(
                        TAG,
                        "Defensive copy cleared after user dismissed export choice; active key"
                            + " preserved.");
                    showToast(getString(R.string.toast_key_export_cancelled_active_key_preserved));
                    updateStatusUi();
                  }
                })
            .create();
    exportChoiceDialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    exportChoiceDialog.show();
  }

  @VisibleForTesting
  public void showPrivateKeyViewer(byte[] privateKeyBytes, boolean showQrInitially) {
    CrumblesPrivateKeyViewerDialogFragment fragment =
        CrumblesPrivateKeyViewerDialogFragment.newInstance(privateKeyBytes, showQrInitially);
    fragment.setKeyCustodyConfirmationListener(this);
    fragment.show(getSupportFragmentManager(), "private_key_viewer");
  }

  @Override
  public void onKeyCustodyConfirmed() {
    PublicKey candidatePublicKey = pendingCandidatePublicKey;
    pendingCandidatePublicKey = null;
    if (candidatePublicKey == null) {
      Log.w(TAG, "Custody confirmed but pendingCandidatePublicKey is null.");
      dropHeldLogs();
      return;
    }
    handOverAndAdoptKey(
        "a new exportable key",
        candidatePublicKey,
        fingerprint -> commitCandidateKey(candidatePublicKey, fingerprint),
        this::onCandidateKeyNotCommitted);
  }

  /** Makes the candidate key, whose private key the user took custody of, the active key. */
  private void commitCandidateKey(PublicKey candidatePublicKey, String fingerprint) {
    try {
      publicKeyManager.saveActiveExternalPublicKey(candidatePublicKey);
      CrumblesDeviceAdminReceiver.cancelKeyInvalidatedNotification(this);
      CrumblesMain.getLogsEncryptorInstance().commitExternalPublicKey(candidatePublicKey);
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "KEY_EXPORTABLE_GENERATED",
              "New exportable key pair generated and custody confirmed."
                  + keyFingerprintSuffix(fingerprint));
      showToast(getString(R.string.toast_new_external_key_generated_successfully));
      reEncryptHeldLogs(candidatePublicKey);
      postUi(this::updateStatusUi);
    } catch (CrumblesKeysException e) {
      onCandidateKeyNotCommitted(e);
    }
  }

  /** Keeps the active key and tells the user that the candidate key could not be activated. */
  private void onCandidateKeyNotCommitted(CrumblesKeysException e) {
    Log.e(TAG, "Failed to commit candidate public key", e);
    dropHeldLogs();
    showToast("Error activating external key: " + e.getMessage());
  }

  @Override
  public void onKeyCustodyCancelled() {
    pendingCandidatePublicKey = null;
    reEncryptChosen = false;
    dropHeldLogs();
    Log.d(TAG, "Key custody cancelled or dismissed; active key preserved.");
    showToast(getString(R.string.toast_key_export_cancelled_active_key_preserved));
    updateStatusUi();
  }

  private void startQrScan() {
    if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
        != PackageManager.PERMISSION_GRANTED) {
      requestPermissions(
          new String[] {Manifest.permission.CAMERA},
          CrumblesConstants.CAMERA_PERMISSION_REQUEST_CODE);
      return;
    }
    Intent intent = new Intent(this, CrumblesQrScannerActivity.class);
    qrScanLauncher.launch(intent);
  }

  private void clearActiveKey() {
    if (!CrumblesMain.getLogsEncryptorInstance().doesPrivateKeyExist()) {
      onGenerateKeystoreKey();
      return;
    }
    requestCredentialForKeyChange(
        "clear the active external key",
        () ->
            handOverToOutgoingKeyInBackground(
                "Clearing the external key", this::commitClearActiveKey));
  }

  /** Clears the active external key after the outgoing key has been handed over to. */
  private void commitClearActiveKey() {
    try {
      PublicKey clearedKey = publicKeyManager.getActiveExternalPublicKey();
      // A key that can no longer be read must still be clearable.
      String clearedKeyFingerprint =
          clearedKey == null ? "unreadable" : fingerprintForAudit(clearedKey);
      publicKeyManager.saveActiveExternalPublicKey(null);
      CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "EXTERNAL_KEY_CLEARED",
              "Active external key was cleared." + keyFingerprintSuffix(clearedKeyFingerprint));
      showToast(getString(R.string.toast_external_key_cleared_successfully));
      reEncryptHeldLogs(/* recipient= */ null);
      postUi(this::updateStatusUi);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to clear active key.", e);
      dropHeldLogs();
      showToast("Error clearing active key: " + e.getMessage());
    }
  }

  /**
   * Hands over to the outgoing key off the main thread, naming {@code newKey} as {@code
   * newKeyKind}, then runs {@code commitKey} on the main thread with the key's fingerprint.
   */
  private void handOverAndAdoptKey(
      String newKeyKind,
      PublicKey newKey,
      Consumer<String> commitKey,
      Consumer<CrumblesKeysException> onFailure) {
    String fingerprint;
    try {
      fingerprint = fingerprintForAudit(newKey);
    } catch (CrumblesKeysException e) {
      onFailure.accept(e);
      return;
    }
    handOverToOutgoingKeyInBackground(
        describeChangeTo(newKeyKind, fingerprint), () -> commitKey.accept(fingerprint));
  }

  /**
   * Hands over to the outgoing key off the main thread, behind a progress dialog, then runs {@code
   * keyChange} on the main thread.
   */
  private void handOverToOutgoingKeyInBackground(String changeDescription, Runnable keyChange) {
    runInBackground(
        R.string.dialog_message_handing_over_key,
        () -> handOverToOutgoingKey(changeDescription, keyChange));
  }

  private Runnable abortBecausePendingLogsChanged() {
    dropHeldLogs();
    String msg = "Key unchanged: new logs arrived during the key change.";
    CrumblesAppAuditLogger.getInstance(this).logEvent(AUDIT_EVENT_KEY_CHANGE_REFUSED, msg);
    return () -> showToast(getString(R.string.toast_pending_logs_changed_retry));
  }

  @Nullable
  private Runnable checkReadyForHandoverLocked() {
    if (hasNewInternalKeyLogsSinceSnapshot()) {
      return abortBecausePendingLogsChanged();
    }
    ImmutableList<PendingLogData> held = logsToReEncryptAfterKeyChange;
    boolean empty = held == null || held.isEmpty();
    boolean cleared = reEncryptChosen && empty;
    long req =
        empty ? 0 : 131072L * held.size() + held.stream().mapToLong(i -> i.plainBytes.length).sum();
    if (!cleared && (req == 0 || usableSpaceSupplier.getAsLong() >= req)) {
      return null;
    }
    reEncryptChosen = false;
    dropHeldLogs();
    String msg =
        cleared
            ? "Key unchanged: decrypted logs were cleared before key change completed."
            : "Key unchanged: insufficient storage space to re-encrypt pending logs.";
    CrumblesAppAuditLogger.getInstance(this).logEvent(AUDIT_EVENT_KEY_CHANGE_REFUSED, msg);
    return () ->
        showToast(
            cleared
                ? getString(R.string.toast_pending_logs_changed_retry)
                : "Not enough storage space to re-encrypt pending logs.");
  }

  /**
   * Hands over to the outgoing key, then commits {@code keyChange} under {@code UPLOAD_LOCK} if no
   * new internal-key logs arrived.
   *
   * <p>Never call this on the main thread: the handover can upload to a WebDAV server.
   */
  private Runnable handOverToOutgoingKey(String changeDescription, Runnable keyChange) {
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      Runnable abort = checkReadyForHandoverLocked();
      if (abort != null) {
        return abort;
      }
    }
    CrumblesKeyHandover.Outcome outcome = CrumblesKeyHandover.handOver(this, changeDescription);
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      Runnable abort = checkReadyForHandoverLocked();
      if (abort != null) {
        return abort;
      }
      if (outcome.equals(CrumblesKeyHandover.Outcome.NOT_SEALED)) {
        showToast(getString(R.string.toast_key_handover_not_sealed));
      } else if (outcome.equals(CrumblesKeyHandover.Outcome.UPLOAD_FAILED)) {
        showToast(getString(R.string.toast_key_handover_upload_failed));
      }
      keyChange.run();
    }
    return () -> {};
  }

  private static String describeChangeTo(String newKeyKind, String newKeyFingerprint) {
    return "Changing to " + newKeyKind + " with fingerprint " + newKeyFingerprint;
  }

  /** Returns the key's SHA-256 fingerprint on one line, as the activity log records it. */
  private static String fingerprintForAudit(PublicKey key) throws CrumblesKeysException {
    return CrumblesLogsEncryptor.getPublicKeyFingerprint(key).replace('\n', ':');
  }

  /** Returns the sentence that names the key in a key change's activity log event. */
  private static String keyFingerprintSuffix(String fingerprint) {
    return " Key fingerprint: " + fingerprint + ".";
  }

  protected void showToast(String message) {
    postUi(() -> Toast.makeText(this, message, Toast.LENGTH_LONG).show());
  }

  @Override
  public void onRequestPermissionsResult(
      int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    if (requestCode == CrumblesConstants.CAMERA_PERMISSION_REQUEST_CODE) {
      if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
        startQrScan();
      } else {
        showToast(getString(R.string.toast_camera_permission_denied_qr));
      }
    }
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      finish();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }
}
