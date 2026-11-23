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

import android.Manifest;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.format.DateUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager.Authenticators;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.core.content.ContextCompat;
import androidx.lifecycle.Lifecycle;
import com.android.securelogging.CrumblesExternalPublicKeyManager.SavedReEncryptKey;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/** An activity to select, import, or remove an external public key for re-encryption. */
public class CrumblesReEncryptKeysActivity extends AppCompatActivity {

  private static final String TAG = "CrumblesReEncryptKeys";
  public static final String EXTRA_SELECTED_KEY_ALIAS = "selected_key_alias";
  public static final String EXTRA_SELECTED_KEY_IS_INTERNAL = "is_internal_key";

  private CrumblesExternalPublicKeyManager publicKeyManager;
  private List<KeyInfo> availableKeys;
  private ArrayAdapter<KeyInfo> adapter;
  private boolean awaitingQrScan;

  @SuppressWarnings("NonFinalStaticField")
  @VisibleForTesting
  static CrumblesExternalPublicKeyManager publicKeyManagerForTest = null;

  private PublicKey pendingImportKey;
  @Nullable private KeyInfo pendingRemovalKey;
  private BiometricPrompt credentialPrompt;
  private boolean awaitingCredential;

  private BiometricPrompt createCredentialPrompt() {
    return new BiometricPrompt(
        this,
        new BiometricPrompt.AuthenticationCallback() {
          @Override
          public void onAuthenticationSucceeded(
              @NonNull BiometricPrompt.AuthenticationResult result) {
            onCredentialConfirmed();
          }

          @Override
          public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
            onCredentialCancelled();
          }
        });
  }

  private void onCredentialConfirmed() {
    awaitingCredential = false;
    PublicKey key = pendingImportKey;
    pendingImportKey = null;
    KeyInfo keyToRemove = pendingRemovalKey;
    pendingRemovalKey = null;
    if (key != null) {
      saveReEncryptKey(key);
    } else if (keyToRemove != null) {
      removeReEncryptKey(keyToRemove);
    }
    closeIfStopped();
  }

  private void onCredentialCancelled() {
    awaitingCredential = false;
    if (pendingRemovalKey != null) {
      recordCancelledRemoval(pendingRemovalKey);
      pendingRemovalKey = null;
    } else if (pendingImportKey != null) {
      pendingImportKey = null;
      recordCancelledCredential();
    }
    closeIfStopped();
  }

  /**
   * Ends the decrypted-logs session and closes the key picker if the prompt answered after the user
   * left the app, since {@link #onStop()} kept both only while the prompt was pending.
   */
  private void closeIfStopped() {
    if (!getLifecycle().getCurrentState().isAtLeast(Lifecycle.State.STARTED)) {
      CrumblesDecryptedLogsSession.destroyActiveSession();
      finish();
    }
  }

  private void recordCancelledRemoval(KeyInfo keyInfo) {
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            "RE_ENCRYPT_KEY_REMOVE_AUTH_FAILED",
            "Kept the re-encryption key with fingerprint "
                + keyInfo.alias()
                + " because no device credential was confirmed for removing it.");
    Toast.makeText(this, R.string.toast_remove_re_encrypt_key_auth_cancelled, Toast.LENGTH_SHORT)
        .show();
  }

  private void recordCancelledCredential() {
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent("EXTERNAL_KEY_IMPORT_CANCELLED", "Device credential prompt was cancelled.");
    Toast.makeText(
            this, getString(R.string.toast_reencrypt_key_auth_cancelled), Toast.LENGTH_SHORT)
        .show();
  }

  private void requireDeviceCredentialAndSave(PublicKey importedKey) {
    KeyguardManager keyguardManager = getSystemService(KeyguardManager.class);
    if (keyguardManager == null || !keyguardManager.isDeviceSecure()) {
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "EXTERNAL_KEY_IMPORT_REFUSED",
              "Key not saved because no secure lock screen is set up.");
      Toast.makeText(
              this, getString(R.string.toast_reencrypt_key_requires_screen_lock), Toast.LENGTH_SHORT)
          .show();
      return;
    }
    if (getSupportFragmentManager().isStateSaved()) {
      recordCancelledCredential();
      return;
    }
    pendingRemovalKey = null;
    pendingImportKey = importedKey;
    awaitingCredential = true;
    credentialPrompt.authenticate(
        new PromptInfo.Builder()
            .setTitle(getString(R.string.reencrypt_key_auth_title))
            .setSubtitle(getString(R.string.reencrypt_key_auth_subtitle))
            .setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL)
            .build());
  }

  private void requestKeyRemoval(KeyInfo keyInfo) {
    KeyguardManager km = getSystemService(KeyguardManager.class);
    if (km == null || !km.isDeviceSecure()) {
      CrumblesAppAuditLogger.getInstance(this).logEvent("RE_ENCRYPT_KEY_REMOVE_REFUSED",
          "Re-encryption key removal refused because no secure lock screen is set up.");
      Toast.makeText(this, R.string.toast_remove_re_encrypt_key_requires_screen_lock, Toast.LENGTH_SHORT).show();
      return;
    }
    if (getSupportFragmentManager().isStateSaved()) {
      recordCancelledRemoval(keyInfo);
      return;
    }
    pendingImportKey = null;
    pendingRemovalKey = keyInfo;
    awaitingCredential = true;
    credentialPrompt.authenticate(
        new PromptInfo.Builder()
            .setTitle(getString(R.string.remove_re_encrypt_key_auth_title))
            .setSubtitle(getString(R.string.remove_re_encrypt_key_auth_subtitle))
            .setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL)
            .build());
  }

  private void removeReEncryptKey(KeyInfo keyToRemove) {
    try {
      publicKeyManager.removeExternalPublicKey(keyToRemove.keyId());
      CrumblesAppAuditLogger.getInstance(this).logEvent("RE_ENCRYPT_KEY_REMOVED",
          "Removed the re-encryption key with fingerprint " + keyToRemove.alias() + ".");
      Toast.makeText(this, R.string.toast_re_encrypt_key_removed, Toast.LENGTH_SHORT).show();
      loadAvailableKeys();
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to remove re-encryption key", e);
      Toast.makeText(this, R.string.toast_re_encrypt_key_remove_failed, Toast.LENGTH_SHORT).show();
    }
  }

  private final ActivityResultLauncher<Intent> qrScanLauncher =
      registerForActivityResult(
          new ActivityResultContracts.StartActivityForResult(),
          result -> {
            awaitingQrScan = false;
            long sessionId = getIntent().getLongExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, -1);
            if (sessionId != -1 && CrumblesDecryptedLogsSession.getSession(sessionId).isEmpty()) {
              setResult(Activity.RESULT_CANCELED);
              finish();
              return;
            }
            if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
              Intent data = result.getData();
              String scannedPublicKeyB64 = data.getStringExtra(CrumblesConstants.SCAN_RESULT_EXTRA);
              if (scannedPublicKeyB64 != null && !scannedPublicKeyB64.isEmpty()) {
                try {
                  PublicKey importedKey =
                      CrumblesLogsEncryptor.publicKeyFromBase64(scannedPublicKeyB64);
                  if (importedKey != null) {
                    CrumblesScannedKeyVerifier.confirmFingerprint(
                        this, importedKey, () -> requireDeviceCredentialAndSave(importedKey));
                  }
                } catch (CrumblesKeysException e) {
                  Toast.makeText(this, "Failed to import key.", Toast.LENGTH_SHORT).show();
                  // Not the message, which can echo part of what was scanned.
                  Log.e(TAG, "Failed to process imported key: " + e.getClass().getName());
                  CrumblesAppAuditLogger.getInstance(this)
                      .logEvent(
                          "EXTERNAL_KEY_IMPORT_FAILED",
                          "Scanned re-encryption key could not be read.");
                }
              }
            } else {
              Toast.makeText(this, "QR Scan cancelled or failed.", Toast.LENGTH_SHORT).show();
            }
          });

  /** Stores a scanned re-encryption key whose fingerprint the user has confirmed. */
  private void saveReEncryptKey(PublicKey importedKey) {
    try {
      String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(importedKey);
      publicKeyManager.saveReEncryptPublicKey(importedKey);
      // Logs re-encrypted to this key can leave the phone, so the activity log must show who
      // can read them.
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "RE_ENCRYPT_KEY_IMPORTED",
              "Imported the re-encryption key with fingerprint " + fingerprint + ".");
    } catch (CrumblesKeysException e) {
      Toast.makeText(this, "Failed to import key.", Toast.LENGTH_SHORT).show();
      Log.e(TAG, "Failed to save imported key", e);
      return;
    }
    Toast.makeText(this, "New external re-encryption key imported.", Toast.LENGTH_SHORT).show();
    loadAvailableKeys(); // Refresh list.
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    CrumblesLauncherEntry.applyToTask(this);
    setContentView(R.layout.activity_re_encrypt_keys);
    CrumblesWindowInsets.applySystemBarPadding(this);
    credentialPrompt = createCredentialPrompt();
    if (savedInstanceState != null) {
      awaitingQrScan = savedInstanceState.getBoolean("awaiting_qr_scan");
      awaitingCredential = savedInstanceState.getBoolean("awaiting_credential");
      try {
        pendingImportKey =
            CrumblesLogsEncryptor.publicKeyFromBase64(
                savedInstanceState.getString("pending_import_key"));
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to restore pending import key", e);
      }
      String removalId = savedInstanceState.getString("pending_removal_key_id");
      if (removalId != null) {
        pendingRemovalKey =
            new KeyInfo(removalId, savedInstanceState.getString("pending_removal_alias", ""), "");
      }
    }
    if (getSupportActionBar() != null) {
      getSupportActionBar().setDisplayHomeAsUpEnabled(true);
      getSupportActionBar().setTitle("Select Re-encryption Key");
    }

    // Use the test manager if it's been injected.
    if (publicKeyManagerForTest != null) {
      publicKeyManager = publicKeyManagerForTest;
    } else {
      publicKeyManager = CrumblesExternalPublicKeyManager.getInstance(this);
    }

    availableKeys = new ArrayList<>();

    ListView listView = findViewById(R.id.re_encrypt_key_list);
    adapter = new KeyInfoAdapter(this, availableKeys, this::requestKeyRemoval);
    listView.setAdapter(adapter);

    listView.setOnItemClickListener(
        (parent, view, position, id) -> {
          KeyInfo selectedKey = availableKeys.get(position);
          Intent resultIntent = new Intent();
          resultIntent.putExtra(EXTRA_SELECTED_KEY_ALIAS, selectedKey.alias());
          resultIntent.putExtra(EXTRA_SELECTED_KEY_IS_INTERNAL, false);
          setResult(Activity.RESULT_OK, resultIntent);
          finish();
        });

    Button importExternalKey = findViewById(R.id.btn_import_external_re_encrypt_key);
    importExternalKey.setOnClickListener(v -> startQrScan());
  }

  @Override
  protected void onSaveInstanceState(@NonNull Bundle outState) {
    super.onSaveInstanceState(outState);
    outState.putString(
        "pending_import_key", CrumblesLogsEncryptor.publicKeyToBase64(pendingImportKey));
    if (pendingRemovalKey != null) {
      outState.putString("pending_removal_key_id", pendingRemovalKey.keyId());
      outState.putString("pending_removal_alias", pendingRemovalKey.alias());
    }
    outState.putBoolean("awaiting_qr_scan", awaitingQrScan);
    outState.putBoolean("awaiting_credential", awaitingCredential);
  }

  @Override
  protected void onResume() {
    super.onResume();
    loadAvailableKeys();
  }

  /**
   * Ends the decrypted-logs session and closes the key picker if the user leaves it without opening
   * the QR scanner or device-credential prompt (for example, by locking the screen or switching
   * apps).
   */
  @Override
  protected void onStop() {
    super.onStop();
    if (!isChangingConfigurations() && !isFinishing() && !awaitingQrScan && !awaitingCredential) {
      CrumblesDecryptedLogsSession.destroyActiveSession();
      finish();
    }
  }

  private void loadAvailableKeys() {
    availableKeys.clear();

    for (SavedReEncryptKey savedKey : publicKeyManager.getSavedReEncryptPublicKeys()) {
      try {
        String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(savedKey.publicKey());
        availableKeys.add(
            new KeyInfo(
                savedKey.keyId(), fingerprint, formatImportedSubtitle(savedKey.importedAt())));
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to get fingerprint for key", e);
      }
    }

    adapter.notifyDataSetChanged();
  }

  private String formatImportedSubtitle(Optional<Instant> importedAt) {
    if (importedAt.isEmpty()) {
      return getString(R.string.re_encrypt_key_imported_time_unknown);
    }
    String formatted =
        DateUtils.formatDateTime(
            this,
            importedAt.get().toEpochMilli(),
            DateUtils.FORMAT_SHOW_DATE
                | DateUtils.FORMAT_SHOW_YEAR
                | DateUtils.FORMAT_SHOW_TIME
                | DateUtils.FORMAT_ABBREV_MONTH);
    return getString(R.string.re_encrypt_key_imported_at, formatted);
  }

  private void startQrScan() {
    if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
        != PackageManager.PERMISSION_GRANTED) {
      requestPermissions(
          new String[] {Manifest.permission.CAMERA},
          CrumblesConstants.CAMERA_PERMISSION_REQUEST_CODE);
      return;
    }
    Intent intent =
        new Intent(this, CrumblesQrScannerActivity.class)
            .putExtra(CrumblesQrScannerActivity.EXTRA_END_DECRYPTED_SESSION_ON_STOP, true);
    awaitingQrScan = true;
    try {
      qrScanLauncher.launch(intent);
    } catch (ActivityNotFoundException | SecurityException e) {
      // Devices or restricted profiles without a resolvable scanner activity throw on launch.
      awaitingQrScan = false;
      Log.e(TAG, "Failed to launch QR scanner", e);
      Toast.makeText(this, "QR Scan cancelled or failed.", Toast.LENGTH_SHORT).show();
    }
  }

  @Override
  public void onRequestPermissionsResult(
      int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    if (requestCode == CrumblesConstants.CAMERA_PERMISSION_REQUEST_CODE) {
      if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
        startQrScan();
      } else {
        Toast.makeText(this, "Camera permission denied.", Toast.LENGTH_SHORT).show();
      }
    }
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      setResult(Activity.RESULT_CANCELED);
      finish();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }

  // Simple data class to hold key info for the adapter.
  static class KeyInfo {
    private final String keyId;
    private final String alias;
    private final String subtitle;

    KeyInfo(String keyId, String alias, String subtitle) {
      this.keyId = keyId;
      this.alias = alias;
      this.subtitle = subtitle;
    }

    String keyId() {
      return keyId;
    }

    String alias() {
      return alias;
    }

    String subtitle() {
      return subtitle;
    }
  }

  // Custom adapter to display the key info and per-row remove action.
  private static class KeyInfoAdapter extends ArrayAdapter<KeyInfo> {
    private final Consumer<KeyInfo> onRemoveClicked;

    KeyInfoAdapter(Context context, List<KeyInfo> keys, Consumer<KeyInfo> onRemoveClicked) {
      super(context, R.layout.list_item_re_encrypt_key, R.id.tv_re_encrypt_key_fingerprint, keys);
      this.onRemoveClicked = onRemoveClicked;
    }

    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
      View view = LayoutInflater.from(getContext()).inflate(R.layout.list_item_re_encrypt_key, parent, false);
      KeyInfo keyInfo = getItem(position);
      ((TextView) view.findViewById(R.id.tv_re_encrypt_key_fingerprint)).setText(keyInfo.alias());
      ((TextView) view.findViewById(R.id.tv_re_encrypt_key_imported_at)).setText(keyInfo.subtitle());
      view.findViewById(R.id.btn_remove_re_encrypt_key).setOnClickListener(v -> onRemoveClicked.accept(keyInfo));
      return view;
    }
  }
}
