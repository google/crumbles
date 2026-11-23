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
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.annotation.VisibleForTesting;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;
import androidx.documentfile.provider.DocumentFile;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.KeyEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogKey;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;

/** Activity for managing external keys. */
public class CrumblesManageExternalKeysActivity extends AppCompatActivity
    implements CrumblesPrivateKeyViewerDialogFragment.KeyCustodyConfirmationListener {

  private static final String TAG = "CrumblesManageExtKeysActivity";
  private static final String AUDIT_EVENT_KEY_GENERATION_FAILED = "KEY_INTERNAL_GENERATION_FAILED";
  private static final String AUDIT_EVENT_KEY_CHANGE_REQUESTED = "KEY_CHANGE_REQUESTED";
  private static final String AUDIT_EVENT_KEY_CHANGE_REFUSED = "KEY_CHANGE_REFUSED";
  private static final String AUDIT_EVENT_KEY_CHANGE_AUTH_FAILED = "KEY_CHANGE_AUTH_FAILED";
  private static final String AUDIT_EVENT_KEY_CHANGE_ABANDONED = "KEY_CHANGE_ABANDONED";
  private static final String AUDIT_EVENT_LOGS_LOST = "LOGS_LOST";
  static final String AUDIT_EVENT_LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE =
      "LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE";
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

  /**
   * The pending files, as last read for a key change, that are of no use to the holder of an
   * external key: batches encrypted to a built-in key, which never leaves this device, and files
   * that hold no batch. The key change tries the built-in key on no other batch, as one that may be
   * encrypted to an external key would only bring a prompt that cannot decrypt it.
   */
  private ImmutableSet<File> builtInKeyOrUnreadableFiles = ImmutableSet.of();

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
  @Nullable private AlertDialog decryptionErrorDialog;
  @Nullable private AlertDialog logsNotCopiedDialog;
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
    CrumblesLauncherEntry.applyToTask(this);
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
    abandonKeyChangeChoice();
    if (activeBackgroundTasks == 0) {
      dropHeldLogs();
    }
  }

  /**
   * Closes the dialogs that continue a key change after the device credential was confirmed, so
   * that whoever unlocks the phone next cannot discard the pending logs or change the key, and
   * records that the change was abandoned.
   */
  private void abandonKeyChangeChoice() {
    if (isShowing(reEncryptConfirmationDialog)
        || isShowing(decryptionErrorDialog)
        || isShowing(logsNotCopiedDialog)) {
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              AUDIT_EVENT_KEY_CHANGE_ABANDONED,
              "Key unchanged because the screen was left before the change was confirmed.");
    }
    dismiss(reEncryptConfirmationDialog);
    dismiss(decryptionErrorDialog);
    dismiss(logsNotCopiedDialog);
  }

  private static boolean isShowing(@Nullable AlertDialog dialog) {
    return dialog != null && dialog.isShowing();
  }

  private static void dismiss(@Nullable AlertDialog dialog) {
    if (dialog != null) {
      dialog.dismiss();
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

  /**
   * Container holding a pending log file, the batch it held, its decrypted bytes and the decrypted
   * metadata, with the device ID and the time that the batch recorded.
   */
  private static class PendingLogData {
    final File file;
    final LogBatch batch;
    final byte[] plainBytes;
    final LogMetadata metadata;

    PendingLogData(File file, LogBatch batch, byte[] plainBytes, LogMetadata metadata) {
      this.file = file;
      this.batch = batch;
      this.plainBytes = plainBytes;
      this.metadata = metadata;
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
        directory.listFiles((dir, name) ->
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

  /** Returns whether pending batches may be encrypted to an external key, as one is or was set. */
  private boolean mayHaveExternalKeyBatches() {
    return publicKeyManager.isExternalKeySelected()
        || !CrumblesSendAndMarkProcessingWorker.readUserPreferences(this)
            .getExternalPublicKeysMap()
            .isEmpty();
  }

  /**
   * Returns which pending batches are encrypted to a built-in key: every batch that carries a
   * batch-wrap key id, which this version gives each batch for a built-in key and none for an
   * external key. A batch that an earlier version wrote without one is also for a built-in key if
   * no external key is or was set, if its key is wrapped with PKCS#1 v1.5 padding, which only a
   * built-in key uses, or if its wrapped key does not have the size of any saved external key's
   * modulus.
   */
  private Predicate<LogBatch> builtInKeyBatches() {
    if (!mayHaveExternalKeyBatches()) {
      return logBatch -> true;
    }
    Optional<ImmutableSet<Integer>> externalKeySizes = savedExternalKeySizes();
    return logBatch -> {
      LogKey key = logBatch.getKey();
      return key.hasBatchWrapKeyId()
          || key.getKeyEncryptionType().equals(KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC)
          || externalKeySizes
              .map(sizes -> !sizes.contains(key.getEncryptedSymmetricKey().size()))
              .orElse(false);
    };
  }

  /**
   * Returns the sizes in bytes of the moduli of the saved external keys, which are also those of
   * the keys that they wrap, or empty if there are none or they cannot all be read.
   */
  private Optional<ImmutableSet<Integer>> savedExternalKeySizes() {
    ImmutableList<PublicKey> externalKeys;
    try {
      externalKeys = publicKeyManager.getSavedExternalPublicKeys();
    } catch (CrumblesKeysException e) {
      Log.w(TAG, "Failed to read the saved external keys.", e);
      return Optional.empty();
    }
    ImmutableSet.Builder<Integer> sizes = ImmutableSet.builder();
    for (PublicKey externalKey : externalKeys) {
      if (!(externalKey instanceof RSAPublicKey rsaKey)) {
        return Optional.empty();
      }
      sizes.add((rsaKey.getModulus().bitLength() + Byte.SIZE - 1) / Byte.SIZE);
    }
    return externalKeys.isEmpty() ? Optional.empty() : Optional.of(sizes.build());
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
    Set<File> builtInKeyOrUnreadable = new HashSet<>();
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    runInBackground(
        R.string.dialog_message_preparing_key_change,
        () -> {
          // Batches collected before the unlock that still wait change key with the others.
          CrumblesDeviceAdminReceiver.saveLogsCollectedBeforeUnlock(this);
          synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
            pendingLogsSnapshot = snapshotPendingAndInFlightFiles();
            String proc = CrumblesConstants.PROCESSING_SUFFIX;
            Predicate<LogBatch> isForBuiltInKey = builtInKeyBatches();
            for (File file : pendingLogsSnapshot) {
              try {
                File src = file.exists() ? file : siblingWithSuffix(file, proc);
                LogBatch logBatch = encryptor.deserializeFile(src.toPath());
                logBatches.add(logBatch);
                files.put(logBatch, file);
                if (isForBuiltInKey.test(logBatch)) {
                  builtInKeyOrUnreadable.add(file);
                }
              } catch (RuntimeException e) {
                Log.e(TAG, "Failed to read pending log file: " + file.getName(), e);
                builtInKeyOrUnreadable.add(file);
                failedFiles.add(file);
                failureReasons.add(file.getName() + ": " + getSpecificFailureReason(e));
              }
            }
            // Batches collected before the unlock that still wait, as for a full quota, cannot
            // change key here, but the user can discard them with the others.
            for (File waiting : new CrumblesDirectBootStore(this).batches()) {
              try {
                if (isForBuiltInKey.test(encryptor.deserializeFile(waiting.toPath()))) {
                  builtInKeyOrUnreadable.add(waiting);
                }
              } catch (RuntimeException e) {
                // Match pending-file handling above: corrupt or unreadable waiting batches cannot
                // be decrypted by an external key holder either.
                Log.w(TAG, "Failed to read waiting Direct Boot log file: " + waiting.getName(), e);
                builtInKeyOrUnreadable.add(waiting);
              }
              failedFiles.add(waiting);
              failureReasons.add(waiting.getName() + ": collected before the first unlock");
            }
          }
          return () -> {
            builtInKeyOrUnreadableFiles = ImmutableSet.copyOf(builtInKeyOrUnreadable);
            if (!canUpdateUi() || getSupportFragmentManager().isStateSaved()) {
              dropHeldLogs();
            } else if (pendingLogsSnapshot.isEmpty() && failedFiles.isEmpty()) {
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
    // The key change has just asked for the device credential. A batch that may be encrypted to an
    // external key fails without a prompt of its own, as the built-in key would most likely not
    // decrypt it.
    CrumblesAuthorizedLogDecryptor.forKeyChange(
            this,
            encryptor,
            /* mayBeForAnExternalKey= */ logBatch ->
                !builtInKeyOrUnreadableFiles.contains(files.get(logBatch)))
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
                          decryptedBatch.metadata()));
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
                  onDecrypted.accept(new DecryptionResult(res, failedFiles, failureReasons));
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
   * or null without a key. The new batch keeps the time recorded in {@code item}. A batch signed by
   * this installation is signed again under its sequence number and this device's current ID, and
   * seals the attestation chain of the batch-signing key, so that re-encrypting leaves the
   * recipient no gap. Any other batch keeps the device ID written in it and stays unsigned, without
   * an attestation chain and without creating a batch-signing key, as does a batch that cannot be
   * signed again, which is reported in the activity log.
   */
  @Nullable
  private LogBatch reEncrypt(PendingLogData item, @Nullable PublicKey recipient) {
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    if (!item.batch.hasSignature()) {
      return encryptor.encryptLogsAttributedTo(item.metadata, item.plainBytes, recipient);
    }
    CrumblesBatchSigner batchSigner = new CrumblesBatchSigner(this);
    if (batchSigner.isSignedByThisInstallation(item.batch)) {
      ImmutableList<ByteString> attestationChain = batchSigner.attestationChainToSeal();
      LogBatch localBatch =
          encryptor.encryptLogsForSigningAgain(
              this, item.metadata, item.plainBytes, recipient, attestationChain);
      if (localBatch == null) {
        return null;
      }
      try {
        return batchSigner.signAgain(item.batch, localBatch, attestationChain);
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
    return encryptor.encryptLogsAttributedTo(item.metadata, item.plainBytes, recipient);
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
            decryptionErrorDialog =
                showDecryptionErrorDialog(result, pendingLogFiles, performKeyChangeAction);
          }
        });
  }

  private AlertDialog showDecryptionErrorDialog(
      DecryptionResult result, List<File> pendingLogFiles, Runnable performKeyChangeAction) {
    int failedCount = result.failedFiles.size();
    int totalCount =
        pendingLogFiles.size()
            + (int) result.failedFiles.stream().filter(f -> !pendingLogFiles.contains(f)).count();
    StringBuilder detailsBuilder = new StringBuilder();
    for (String reason : result.failureReasons) {
      detailsBuilder.append("\n• ").append(reason);
    }
    // Deleting the built-in key only leaves the files that it alone could decrypt unreadable for
    // good. The others may be encrypted to an external key, whose holder can still read them.
    ImmutableList<File> unreadableFiles =
        result.failedFiles.stream()
            .filter(builtInKeyOrUnreadableFiles::contains)
            .collect(toImmutableList());
    int keptCount = failedCount - unreadableFiles.size();
    String message =
        pendingChangeDeletesInternalKey
            ? String.format(
                Locale.getDefault(),
                "Failed to decrypt %d out of %d pending log file(s) with your current key"
                    + " pair:%s\n\n%s",
                failedCount,
                totalCount,
                detailsBuilder,
                questionBeforeBuiltInKeyDeletion(unreadableFiles.size(), keptCount))
            : getResources()
                .getQuantityString(
                    R.plurals.dialog_message_logs_not_decrypted,
                    failedCount,
                    failedCount,
                    totalCount,
                    detailsBuilder);

    AlertDialog.Builder warning =
        new AlertDialog.Builder(this).setTitle("Log Decryption Warning").setMessage(message);
    if (pendingChangeDeletesInternalKey) {
      // The change deletes the built-in key that the decrypted logs are encrypted to: hold them to
      // re-encrypt them to the new key, and refuse the change if they are dropped before then.
      logsToReEncryptAfterKeyChange = result.decryptedLogs;
      warning.setPositiveButton(
          unreadableFiles.isEmpty()
              ? R.string.dialog_button_keep_queued_for_upload
              : R.string.dialog_button_discard_unreadable_logs,
          (dialog, which) -> {
            reEncryptChosen = !result.decryptedLogs.isEmpty();
            discardUnreadableThenChangeKey(
                unreadableFiles, keptCount, totalCount, performKeyChangeAction);
          });
    } else {
      // None of the choices that the dialog offers re-encrypts the logs.
      wipePlaintext(result.decryptedLogs);
      warning.setPositiveButton(
          R.string.dialog_button_keep_queued_for_upload,
          (dialog, which) -> {
            // The files stay as they are, so the upload worker sends them to the destination.
            CrumblesAppAuditLogger.getInstance(this)
                .logEvent(
                    AUDIT_EVENT_LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE,
                    failedCount
                        + " of "
                        + totalCount
                        + " pending log file(s) could not be decrypted on this device; all were"
                        + " kept queued for upload before key rotation.");
            performKeyChangeAction.run();
          });
    }
    return warning
        .setNeutralButton(
            "Discard Logs",
            (dialog, which) -> {
              dropHeldLogs();
              // With the batches collected before the unlock that the warning lists.
              discardPendingLogs(
                  ImmutableSet.<File>builder()
                      .addAll(pendingLogFiles)
                      .addAll(result.failedFiles)
                      .build()
                      .asList(),
                  performKeyChangeAction);
            })
        .setNegativeButton("Cancel", (dialog, which) -> dropHeldLogs())
        .setOnCancelListener(dialog -> dropHeldLogs())
        .show();
  }

  /**
   * Returns the question that ends the decryption warning before a change that deletes the built-in
   * key, when {@code unreadableCount} of the files that failed to decrypt are no use to anyone and
   * the other {@code keptCount} stay queued.
   */
  private String questionBeforeBuiltInKeyDeletion(int unreadableCount, int keptCount) {
    if (keptCount == 0) {
      return getString(R.string.dialog_message_unreadable_logs_before_keystore_key_change);
    }
    if (unreadableCount == 0) {
      return getString(R.string.dialog_message_logs_kept_before_keystore_key_change);
    }
    return getResources()
        .getQuantityString(
            R.plurals.dialog_message_some_logs_kept_before_keystore_key_change,
            keptCount,
            keptCount);
  }

  /**
   * Discards {@code unreadableFiles}, if any, then changes the key, recording that the other {@code
   * keptCount} of the {@code totalCount} pending files that failed to decrypt stay queued.
   */
  private void discardUnreadableThenChangeKey(
      ImmutableList<File> unreadableFiles,
      int keptCount,
      int totalCount,
      Runnable performKeyChangeAction) {
    Runnable keepOthersQueuedThenChangeKey =
        () -> {
          if (keptCount > 0) {
            CrumblesAppAuditLogger.getInstance(this)
                .logEvent(
                    AUDIT_EVENT_LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE,
                    keptCount
                        + " of "
                        + totalCount
                        + " pending log file(s) could not be decrypted on this device and may be"
                        + " encrypted to an external key or, if an older version of the app wrote"
                        + " them, to the replaced built-in key; they were kept queued for upload"
                        + " before key rotation.");
          }
          performKeyChangeAction.run();
        };
    if (unreadableFiles.isEmpty()) {
      keepOthersQueuedThenChangeKey.run();
    } else {
      discardPendingLogs(unreadableFiles, keepOthersQueuedThenChangeKey);
    }
  }

  private void showReEncryptConfirmationDialog(
      List<File> pendingLogFiles,
      ImmutableList<PendingLogData> decryptedLogs,
      Runnable performKeyChangeAction) {
    logsToReEncryptAfterKeyChange = decryptedLogs;
    ImmutableList.Builder<CharSequence> options = ImmutableList.builder();
    ImmutableList.Builder<Runnable> choices = ImmutableList.builder();
    options.add("Re-encrypt");
    choices.add(() -> {
      // Re-encrypting now would target the outgoing key: the change may still wait for the
      // user (custody of an exportable key) or fail. Each change re-encrypts these logs itself
      // once the new key is active.
      reEncryptChosen = true;
      performKeyChangeAction.run();
    });
    // Every log here was decrypted with the built-in key, even while an external key is selected,
    // so copies left encrypted to it could never be decrypted once the change deletes it.
    if (!pendingChangeDeletesInternalKey) {
      options.add("Upload As-Is");
      choices.add(() -> {
        dropHeldLogs();
        uploadPendingLogsThenChangeKey(pendingLogFiles, performKeyChangeAction);
      });
    }
    options.add("Discard Logs");
    choices.add(() -> {
      dropHeldLogs();
      discardPendingLogs(pendingLogFiles, performKeyChangeAction);
    });
    ImmutableList<Runnable> actions = choices.build();
    reEncryptConfirmationDialog =
        new AlertDialog.Builder(this)
            .setTitle("Re-encrypt Existing Logs?")
            .setItems(
                options.build().toArray(new CharSequence[0]),
                (dialog, which) -> actions.get(which).run())
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

  /**
   * Deletes the specified pending log files from the device, then runs {@code afterDiscard}.
   * Batches collected before the unlock that still wait are deleted only if they are specified.
   */
  private void discardPendingLogs(List<File> pendingLogFiles, Runnable afterDiscard) {
    runInBackground(
        R.string.dialog_message_preparing_key_change,
        () -> {
          int deleteCount = 0;
          synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
            if (hasNewInternalKeyLogsSinceSnapshot()) {
              return abortBecausePendingLogsChanged();
            }
            // Each with the attestation chain that it sealed.
            deleteCount += new CrumblesDirectBootStore(this).deleteBatches(pendingLogFiles);
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
            } else {
              // No key change follows to re-encrypt the logs held for it.
              dropHeldLogs();
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
    runUploadInBackground(
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
   * Copies {@code logFiles} into the folder at {@code folderUri}. Unless that folder is the upload
   * folder, they stay pending, so that the upload worker still sends them to the configured
   * destination. It stops at the first failure in transit: the folder's provider would hold the
   * next files for the same deadline.
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
    // Copied to the upload folder, a file is uploaded: marked as sent, it is not uploaded twice.
    boolean isUploadFolder = folderUri.toString().equals(configuredUploadFolder());
    int copiedCount = 0;
    for (File file : logFiles) {
      boolean copied;
      if (isUploadFolder) {
        copied =
            CrumblesSendAndMarkProcessingWorker.uploadSingleFile(
                this, uploader, file, file.getParentFile());
      } else {
        // An upload run that has started on the file holds it under its processing name.
        File source =
            file.exists() ? file : siblingWithSuffix(file, CrumblesConstants.PROCESSING_SUFFIX);
        copied = uploader.uploadFile(this, source, file.getName());
      }
      if (copied) {
        copiedCount++;
      } else if (uploader.transportFailed()) {
        break;
      }
    }
    return copiedCount;
  }

  /** Returns the URI of the folder that the upload worker uploads to, or "" if it uses none. */
  private String configuredUploadFolder() {
    RemoteStorageConfig config =
        CrumblesSendAndMarkProcessingWorker.readUserPreferences(this).getRemoteStorageConfig();
    if (config.getStorageType().equals(StorageType.STORAGE_TYPE_WEBDAV)) {
      return "";
    }
    return config.getUploadDestinationUri().isEmpty()
        ? getSharedPreferences(CrumblesConstants.PREFS_NAME, MODE_PRIVATE)
            .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, /* defValue= */ "")
        : config.getUploadDestinationUri();
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
    logsNotCopiedDialog =
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
    // Generating a key pair deletes the built-in key, if there is one: clearing an external key on
    // an install that never had a built-in key deletes nothing.
    pendingChangeDeletesInternalKey = CrumblesMain.getLogsEncryptorInstance().doesPrivateKeyExist();
  }

  /** Generates a Keystore key pair before dropping the external key, so failures keep that key. */
  private void switchToNewKeystoreKey() {
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    // Generating the key starts with a handover, which uploads.
    runUploadInBackground(
        R.string.dialog_message_generating_key, () -> generateKeystoreKey(encryptor));
  }

  private void postUi(Runnable action) {
    runOnUiThread(() -> {
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
   * <p>Generating an RSA key takes up to several seconds, in StrongBox or for 3072-bit keys. The
   * orientation is locked meanwhile, so that rotating the phone does not recreate the screen and
   * drop the logs held for the key change.
   */
  private void runInBackground(@StringRes int progressMessageId, Supplier<Runnable> task) {
    runBehind(newProgressDialog(progressMessageId).show(), task);
  }

  /**
   * Runs {@code task}, which uploads, as {@link #runInBackground} does, but its progress dialog
   * lets the user stop waiting for the upload. Stopping ends the task's calls into documents
   * providers and its transfers as their deadlines would: the task then finishes at once, as after
   * a failed upload. The dialog stays until it has, so that nothing else starts meanwhile.
   */
  private void runUploadInBackground(@StringRes int progressMessageId, Supplier<Runnable> task) {
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.untilStopped();
    AlertDialog progressDialog =
        newProgressDialog(progressMessageId)
            .setNegativeButton(R.string.dialog_button_stop_waiting, /* listener= */ null)
            .show();
    // Set on the button rather than on the dialog, which would close with the first click.
    Button stopWaiting = progressDialog.getButton(DialogInterface.BUTTON_NEGATIVE);
    stopWaiting.setOnClickListener(v -> {
      stopWaiting.setEnabled(false);
      budget.stop();
    });
    runBehind(progressDialog, () -> CrumblesTransferDeadline.within(budget, task));
  }

  private AlertDialog.Builder newProgressDialog(@StringRes int progressMessageId) {
    return new AlertDialog.Builder(this).setMessage(progressMessageId).setCancelable(false);
  }

  private void runBehind(AlertDialog progressDialog, Supplier<Runnable> task) {
    activeBackgroundTasks++;
    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LOCKED);
    keyGenerationExecutor.execute(() -> {
      Runnable continuation = this::dropHeldLogs;
      try {
        continuation = task.get();
      } finally {
        Runnable finalContinuation = continuation;
        runOnUiThread(() -> {
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
            recordLogsCollectedBeforeUnlockLeftWaiting();
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

  /**
   * Records that batches collected before the first unlock that are unreadable or may be encrypted
   * to the replaced on-device key still wait, as for a full quota, before the key is deleted.
   */
  private void recordLogsCollectedBeforeUnlockLeftWaiting() {
    if (!pendingChangeDeletesInternalKey) {
      return;
    }
    long waiting =
        new CrumblesDirectBootStore(this)
            .batches().stream().filter(builtInKeyOrUnreadableFiles::contains).count();
    if (waiting > 0) {
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              AUDIT_EVENT_LOGS_LOST,
              waiting
                  + " security log batch(es) collected before the first unlock may be unreadable:"
                  + " they still wait on this device, and may be encrypted to the on-device key"
                  + " that the key change deletes.");
    }
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
          staged = new CrumblesLogStaging(this).stage(/* isNetworkBatch= */ false, item.plainBytes);
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
            .setOnDismissListener(dialog -> {
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
    runUploadInBackground(
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
