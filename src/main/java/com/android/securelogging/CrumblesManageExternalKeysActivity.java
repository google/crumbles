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
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
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
import java.security.PublicKey;
import java.util.Arrays;

/** Activity for managing external keys. */
public class CrumblesManageExternalKeysActivity extends AppCompatActivity {

  private static final String TAG = "CrumblesManageExtKeysActivity";

  private CrumblesExternalPublicKeyManager publicKeyManager;
  private TextView tvCurrentExternalKeyStatus;

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

    publicKeyManager.saveActiveExternalPublicKey(importedPublicKey);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(importedPublicKey);
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent("EXTERNAL_KEY_IMPORTED", "External public key imported via QR scan.");
    Toast.makeText(
            this, getString(R.string.toast_external_key_imported_successfully), Toast.LENGTH_LONG)
        .show();
    // Finish activity after successful import to show updated main screen.
    finish();
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

  private void onGenerateKeystoreKey() {
    try {
      publicKeyManager.saveActiveExternalPublicKey(null);
      CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
      CrumblesMain.getLogsEncryptorInstance().generateKeyPair();
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent("KEY_INTERNAL_GENERATED", "New internal Keystore key pair generated.");
      Toast.makeText(this, "New internal Keystore key generated successfully.", Toast.LENGTH_LONG)
          .show();
      finish();
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to generate internal key pair.", e);
      showToast("Error generating internal key: " + e.getMessage());
    }
  }

  private void onGenerateExportableKey() {
    try {
      CrumblesMain.getLogsEncryptorInstance()
          .generateAndSetExternalKeyPair(
              privateKeyBytes -> {
                PublicKey newPublicKey =
                    CrumblesMain.getLogsEncryptorInstance().getExternalEncryptionPublicKey();
                if (newPublicKey == null) {
                  throw new CrumblesKeysException(
                      "Generated public key was null after generation.", null);
                }

                publicKeyManager.saveActiveExternalPublicKey(newPublicKey);
                CrumblesAppAuditLogger.getInstance(this)
                    .logEvent("KEY_EXPORTABLE_GENERATED", "New exportable key pair generated.");
                showToast(getString(R.string.toast_new_external_key_generated_successfully));

                // Pass the original byte array directly to the choice dialog.
                showPrivateKeyExportChoiceDialog(privateKeyBytes);
              });
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to generate or process exportable key pair", e);
      showToast(getString(R.string.toast_generate_external_key_error_with_message, e.getMessage()));
    }
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
    publicKeyManager.saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent("EXTERNAL_KEY_CLEARED", "Active external key was cleared.");
    showToast(getString(R.string.toast_external_key_cleared_successfully));
    updateStatusUi();
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
