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

import static com.google.common.base.Strings.isNullOrEmpty;

import android.Manifest;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.content.ContextCompat;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Activity for managing external keys. */
public class CrumblesManageExternalKeysActivity extends AppCompatActivity {

  private static final String TAG = "CrumblesManageExtKeysActivity";
  private static final int REQUEST_CODE_CONFIRM_CREDENTIALS = 1001;

  private CrumblesExternalPublicKeyManager publicKeyManager;
  private TextView tvCurrentExternalKeyStatus;
  @Nullable private Runnable pendingKeyChangeAction;
  private CrumblesUriGenerator uriGenerator = new CrumblesUriGenerator();

  @VisibleForTesting
  void setUriGeneratorForTest(CrumblesUriGenerator uriGenerator) {
    this.uriGenerator = uriGenerator;
  }

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
              Log.e(TAG, "Error processing scanned public key.", e);
              Toast.makeText(
                      this,
                      getString(
                          R.string.toast_import_public_key_error_with_message, e.getMessage()),
                      Toast.LENGTH_LONG)
                  .show();
            }
          });

  /** Processes the scanned Base64 public key string. */
  protected void processScannedPublicKeyInternal(String scannedPublicKeyB64)
      throws CrumblesKeysException {
    if (isNullOrEmpty(scannedPublicKeyB64)) {
      throw new IllegalArgumentException(
          "Scanned public key data cannot be null or empty for processing.");
    }
    PublicKey importedPublicKey = CrumblesLogsEncryptor.publicKeyFromBase64(scannedPublicKeyB64);

    if (importedPublicKey == null) {
      throw new CrumblesKeysException(
          "Failed to decode public key from QR data; result was unexpectedly null.", null);
    }

    confirmAndPerformKeyChange(
        () -> {
          try {
            publicKeyManager.saveActiveExternalPublicKey(importedPublicKey);
            CrumblesMain.getLogsEncryptorInstance()
                .setExternalEncryptionPublicKey(importedPublicKey);
            CrumblesAppAuditLogger.getInstance(this)
                .logEvent("EXTERNAL_KEY_IMPORTED", "External public key imported via QR scan.");
            Toast.makeText(
                    this,
                    getString(R.string.toast_external_key_imported_successfully),
                    Toast.LENGTH_LONG)
                .show();
            finish();
          } catch (CrumblesKeysException e) {
            Log.e(TAG, "Failed to save imported key.", e);
            showToast("Error importing key: " + e.getMessage());
          }
        });
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_manage_external_keys);

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
    btnClearActiveExternalKey.setOnClickListener(
        v -> {
          try {
            clearActiveKey();
          } catch (CrumblesKeysException e) {
            Log.e(TAG, "Failed to clear active key.", e);
            showToast("Error clearing active key: " + e.getMessage());
          }
        });

    updateStatusUi();
  }

  @Override
  protected void onResume() {
    super.onResume();
    updateStatusUi();
  }

  @VisibleForTesting
  void setPublicKeyManagerForTest(CrumblesExternalPublicKeyManager manager) {
    this.publicKeyManager = manager;
  }

  protected void updateStatusUi() {
    PublicKey activeKey = publicKeyManager.getActiveExternalPublicKey();
    Button btnClearActiveExternalKey = findViewById(R.id.btn_clear_active_external_key);

    if (activeKey != null) {
      String keyHash = CrumblesLogsEncryptor.getPublicKeyHash(activeKey);
      tvCurrentExternalKeyStatus.setText(
          getString(R.string.status_external_key_active_formatted, keyHash));
      btnClearActiveExternalKey.setVisibility(View.VISIBLE);
    } else {
      tvCurrentExternalKeyStatus.setText(getString(R.string.status_no_external_key));
      btnClearActiveExternalKey.setVisibility(View.GONE);
    }
  }

  /** Container holding a pending log file reference and its decrypted bytes. */
  private static class PendingLogData {
    final File file;
    final byte[] plainBytes;

    PendingLogData(File file, byte[] plainBytes) {
      this.file = file;
      this.plainBytes = plainBytes;
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
            (dir, name) -> name.endsWith(".bin") && !name.endsWith(CrumblesConstants.SENT_SUFFIX));
    if (files == null) {
      return ImmutableList.of();
    }
    return ImmutableList.copyOf(files);
  }

  /** Container holding decryption results for pending log files. */
  private static class DecryptionResult {
    final ImmutableList<PendingLogData> decryptedLogs;
    final ImmutableList<File> failedFiles;
    final ImmutableList<String> failureReasons;
    final boolean requiresAuthentication;

    DecryptionResult(
        List<PendingLogData> decryptedLogs,
        List<File> failedFiles,
        List<String> failureReasons,
        boolean requiresAuthentication) {
      this.decryptedLogs = ImmutableList.copyOf(decryptedLogs);
      this.failedFiles = ImmutableList.copyOf(failedFiles);
      this.failureReasons = ImmutableList.copyOf(failureReasons);
      this.requiresAuthentication = requiresAuthentication;
    }
  }

  /** Decrypts the given list of pending log files using the active decryption key. */
  private DecryptionResult decryptPendingLogs(List<File> pendingFiles) {
    List<PendingLogData> decryptedLogs = new ArrayList<>();
    List<File> failedFiles = new ArrayList<>();
    List<String> failureReasons = new ArrayList<>();
    boolean requiresAuthentication = false;
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    for (File file : pendingFiles) {
      try {
        LogBatch logBatch = encryptor.deserializeFile(file.toPath());
        byte[] plainBytes = encryptor.decryptLogs(logBatch);
        decryptedLogs.add(new PendingLogData(file, plainBytes));
      } catch (UserNotAuthenticatedException e) {
        Log.e(TAG, "Failed to decrypt pending log file: " + file.getName(), e);
        failedFiles.add(file);
        failureReasons.add(file.getName() + ": User authentication required");
        requiresAuthentication = true;
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to decrypt pending log file: " + file.getName(), e);
        failedFiles.add(file);
        if (e.getCause() instanceof UserNotAuthenticatedException) {
          failureReasons.add(file.getName() + ": User authentication required");
          requiresAuthentication = true;
        } else {
          failureReasons.add(file.getName() + ": " + getSpecificFailureReason(e));
        }
      } catch (RuntimeException e) {
        Log.e(TAG, "Failed to decrypt pending log file: " + file.getName(), e);
        failedFiles.add(file);
        failureReasons.add(file.getName() + ": " + getSpecificFailureReason(e));
      }
    }
    return new DecryptionResult(decryptedLogs, failedFiles, failureReasons, requiresAuthentication);
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

  /** Re-encrypts the decrypted log entries with the newly configured public key. */
  private int reEncryptPendingLogs(List<PendingLogData> decryptedLogs) {
    int failedCount = 0;
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    PublicKey newPublicKey = publicKeyManager.getActiveExternalPublicKey();
    for (PendingLogData item : decryptedLogs) {
      try {
        LogBatch reEncryptedBatch = encryptor.encryptLogs(item.plainBytes, newPublicKey);
        if (reEncryptedBatch != null) {
          @SuppressWarnings("unused")
          Path unused =
              encryptor.serializeBytes(
                  reEncryptedBatch, item.file.getParentFile(), item.file.getName());
        } else {
          failedCount++;
        }
      } catch (RuntimeException e) {
        Log.e(TAG, "Failed to re-encrypt pending log file: " + item.file.getName(), e);
        failedCount++;
      }
    }
    return failedCount;
  }

  /**
   * Prompts the user with a confirmation dialog if un-uploaded logs exist before performing a key
   * pair change, allowing them to re-encrypt existing logs or leave them as-is.
   */
  private void confirmAndPerformKeyChange(Runnable performKeyChangeAction) {
    ImmutableList<File> pendingLogFiles = getPendingLogFiles();
    if (pendingLogFiles.isEmpty()) {
      performKeyChangeAction.run();
      return;
    }

    DecryptionResult result = decryptPendingLogs(pendingLogFiles);
    if (result.requiresAuthentication) {
      KeyguardManager keyguardManager =
          (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
      if (keyguardManager != null) {
        Intent intent =
            keyguardManager.createConfirmDeviceCredentialIntent(
                "Authentication Required",
                "Please authenticate to decrypt your pending log files before key rotation.");
        if (intent != null) {
          this.pendingKeyChangeAction = performKeyChangeAction;
          startActivityForResult(intent, REQUEST_CODE_CONFIRM_CREDENTIALS);
          return;
        }
      }
    }

    if (!result.failedFiles.isEmpty()) {
      showDecryptionErrorDialog(result, pendingLogFiles, performKeyChangeAction);
      return;
    }

    showReEncryptConfirmationDialog(pendingLogFiles, result.decryptedLogs, performKeyChangeAction);
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == REQUEST_CODE_CONFIRM_CREDENTIALS) {
      Runnable action = pendingKeyChangeAction;
      pendingKeyChangeAction = null;
      if (resultCode == RESULT_OK && action != null) {
        confirmAndPerformKeyChange(action);
      } else {
        showToast("Authentication cancelled. Key rotation aborted.");
      }
    }
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
                + "Changing your key pair now will prevent those logs from being decrypted in the future. "
                + "Would you like to upload all remaining logs as-is, discard them, or cancel the key change?",
            failedCount,
            totalCount,
            detailsBuilder.toString());

    new AlertDialog.Builder(this)
        .setTitle("Log Decryption Warning")
        .setMessage(message)
        .setPositiveButton(
            "Upload As-Is",
            (dialog, which) -> {
              uploadPendingLogs(pendingLogFiles);
              performKeyChangeAction.run();
            })
        .setNeutralButton(
            "Discard Logs",
            (dialog, which) -> {
              discardPendingLogs(pendingLogFiles);
              performKeyChangeAction.run();
            })
        .setNegativeButton("Cancel", null)
        .show();
  }

  private void showReEncryptConfirmationDialog(
      List<File> pendingLogFiles,
      ImmutableList<PendingLogData> decryptedLogs,
      Runnable performKeyChangeAction) {
    CharSequence[] options = new CharSequence[] {"Re-encrypt", "Upload As-Is", "Discard Logs"};
    new AlertDialog.Builder(this)
        .setTitle("Re-encrypt Existing Logs?")
        .setItems(
            options,
            (dialog, which) -> {
              if (which == 0) {
                performKeyChangeAction.run();
                if (!decryptedLogs.isEmpty()) {
                  int failedCount = reEncryptPendingLogs(decryptedLogs);
                  if (failedCount > 0) {
                    showToast(
                        "Logs re-encrypted with new key pair ("
                            + failedCount
                            + " file(s) failed to re-encrypt).");
                  } else {
                    showToast("Logs re-encrypted with new key pair.");
                  }
                }
              } else if (which == 1) {
                uploadPendingLogs(pendingLogFiles);
                performKeyChangeAction.run();
              } else if (which == 2) {
                discardPendingLogs(pendingLogFiles);
                performKeyChangeAction.run();
              }
            })
        .setNegativeButton("Cancel", null)
        .show();
  }

  /** Deletes the specified pending log files from the device. */
  private void discardPendingLogs(List<File> pendingLogFiles) {
    if (pendingLogFiles == null || pendingLogFiles.isEmpty()) {
      return;
    }
    int deleteCount = 0;
    for (File file : pendingLogFiles) {
      if (file.exists() && file.delete()) {
        deleteCount++;
      }
    }
    if (deleteCount > 0) {
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "LOGS_DISCARDED",
              deleteCount + " pending log file(s) discarded prior to key rotation.");
      showToast(deleteCount + " pending log file(s) discarded.");
    }
  }

  /** Triggers the upload flow for pending logs by launching the system chooser intent. */
  private void uploadPendingLogs(List<File> pendingLogFiles) {
    if (pendingLogFiles == null || pendingLogFiles.isEmpty()) {
      return;
    }
    ArrayList<Uri> filesToSendUris = new ArrayList<>();
    for (File file : pendingLogFiles) {
      Uri uri = uriGenerator.getUriForFile(this, file);
      if (uri != null) {
        filesToSendUris.add(uri);
      }
    }
    if (filesToSendUris.isEmpty()) {
      Log.w(TAG, "No valid URIs generated for pending log files.");
      return;
    }

    showToast("Prompting for upload destination...");

    Intent uploadIntent = new Intent(Intent.ACTION_SEND_MULTIPLE);
    uploadIntent.setType("application/octet-stream");
    uploadIntent.putParcelableArrayListExtra(Intent.EXTRA_STREAM, filesToSendUris);
    uploadIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

    try {
      startActivity(Intent.createChooser(uploadIntent, "Upload Filtered Log Files..."));
    } catch (ActivityNotFoundException e) {
      Log.e(TAG, "No app available to handle log upload chooser", e);
      showToast("No suitable app found to upload logs.");
    }
  }

  private void onGenerateKeystoreKey() {
    confirmAndPerformKeyChange(
        () -> {
          try {
            publicKeyManager.saveActiveExternalPublicKey(null);
            CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
            CrumblesMain.getLogsEncryptorInstance().generateKeyPair();
            CrumblesAppAuditLogger.getInstance(this)
                .logEvent("KEY_INTERNAL_GENERATED", "New internal Keystore key pair generated.");
            Toast.makeText(
                    this,
                    "New internal Keystore key generated successfully.",
                    Toast.LENGTH_LONG)
                .show();
            finish();
          } catch (CrumblesKeysException e) {
            Log.e(TAG, "Failed to generate internal key pair.", e);
            showToast("Error generating internal key: " + e.getMessage());
          }
        });
  }

  private void onGenerateExportableKey() {
    confirmAndPerformKeyChange(
        () -> {
          try {
            CrumblesMain.getLogsEncryptorInstance()
                .generateAndSetExternalKeyPair(
                    privateKeyBytes -> {
                      PublicKey newPublicKey =
                          CrumblesMain.getLogsEncryptorInstance()
                              .getExternalEncryptionPublicKey();
                      if (newPublicKey == null) {
                        throw new CrumblesKeysException(
                            "Generated public key was null after generation.", null);
                      }

                      publicKeyManager.saveActiveExternalPublicKey(newPublicKey);
                      CrumblesAppAuditLogger.getInstance(this)
                          .logEvent(
                              "KEY_EXPORTABLE_GENERATED", "New exportable key pair generated.");
                      showToast(
                          getString(
                              R.string.toast_new_external_key_generated_successfully));

                      showPrivateKeyExportChoiceDialog(privateKeyBytes);
                    });
          } catch (CrumblesKeysException e) {
            Log.e(TAG, "Failed to generate or process exportable key pair", e);
            showToast(
                getString(
                    R.string.toast_generate_external_key_error_with_message, e.getMessage()));
          }
        });
  }

  private void showPrivateKeyExportChoiceDialog(final byte[] privateKeyBytes) {
    new AlertDialog.Builder(this)
        .setTitle(R.string.dialog_title_choose_key_format)
        .setMessage(R.string.dialog_message_choose_key_format)
        .setPositiveButton(
            R.string.dialog_button_view_as_text,
            (dialog, which) ->
                // Pass the key to the viewer. The viewer is now responsible for cleanup.
                showPrivateKeyViewer(privateKeyBytes, false))
        // The Arrays.fill() call is REMOVED from here.
        .setNegativeButton(
            R.string.dialog_button_view_as_qr,
            (dialog, which) ->
                // Pass the key to the viewer. The viewer is now responsible for cleanup.
                showPrivateKeyViewer(privateKeyBytes, true))
        // The Arrays.fill() call is REMOVED from here.
        .setOnCancelListener(
            (dialog) -> {
              // The cleanup when the user cancels the choice is still correct.
              Arrays.fill(privateKeyBytes, (byte) 0);
              Log.d(TAG, "Defensive copy cleared after user cancelled export choice.");
            })
        .show();
  }

  @VisibleForTesting
  public void showPrivateKeyViewer(byte[] privateKeyBytes, boolean showQrInitially) {
    CrumblesPrivateKeyViewerDialogFragment.newInstance(privateKeyBytes, showQrInitially)
        .show(getSupportFragmentManager(), "private_key_viewer");
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

  private void clearActiveKey() throws CrumblesKeysException {
    confirmAndPerformKeyChange(
        () -> {
          try {
            publicKeyManager.saveActiveExternalPublicKey(null);
            CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
            CrumblesAppAuditLogger.getInstance(this)
                .logEvent("EXTERNAL_KEY_CLEARED", "Active external key was cleared.");
            showToast(getString(R.string.toast_external_key_cleared_successfully));
            updateStatusUi();
          } catch (CrumblesKeysException e) {
            Log.e(TAG, "Failed to clear active key.", e);
            showToast("Error clearing active key: " + e.getMessage());
          }
        });
  }

  protected void showToast(String message) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
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
