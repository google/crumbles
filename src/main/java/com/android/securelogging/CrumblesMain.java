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

import static java.nio.charset.StandardCharsets.UTF_8;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.UriPermission;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.icu.text.MessageFormat;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.support.v4.app.FragmentActivity;
import android.support.v7.app.AlertDialog;
import android.text.InputType;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.annotation.VisibleForTesting;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.documentfile.provider.DocumentFile;
import androidx.work.WorkManager;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditLogViewerActivity;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.android.libraries.security.content.SafeContentResolver;
import com.google.android.libraries.security.content.SafeContentResolver.SourcePolicy;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.common.base.Ascii;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteStreams;
import com.google.common.util.concurrent.Futures;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import javax.net.ssl.SSLSocketFactory;

/** Main activity for the Crumbles app. */
public class CrumblesMain extends FragmentActivity {
  private static final String TAG = "[Crumbles]";
  private DevicePolicyManager dpm;

  private final ExecutorService webDavProbeExecutor = Executors.newSingleThreadExecutor();
  private final ExecutorService keyProbeExecutor = Executors.newSingleThreadExecutor();
  @Nullable @VisibleForTesting AlertDialog webDavDialog;
  @Nullable private AlertDialog serverKeyPinDialog;
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private TextView encryptionKeyStatusTextView;
  private TextView uploadDestinationStatusTextView;
  @Nullable private SelectedLogsCallback selectedLogsCallback;
  @Nullable private ConfirmedServerKey lastConfirmedPin;

  private static final class ConfirmedServerKey {
    final String serverUrl;
    final WebDavServerKeyPin pin;

    ConfirmedServerKey(String serverUrl, WebDavServerKeyPin pin) {
      this.serverUrl = serverUrl;
      this.pin = pin;
    }
  }

  // Suppress "StaticFieldLeak" because CrumblesLogsEncryptor only holds the application context
  // or a null context, so retaining it in a static field does not cause an Activity leak.
  @SuppressLint("StaticFieldLeak")
  private static final CrumblesLogsEncryptor prodLogsEncryptorInstance =
      new CrumblesLogsEncryptor();

  // Suppress "StaticFieldLeak" because CrumblesLogsEncryptor only holds the application context
  // or a null context, so retaining it in a static field does not cause an Activity leak.
  @SuppressLint("StaticFieldLeak")
  @SuppressWarnings("NonFinalStaticField")
  protected static CrumblesLogsEncryptor testLogsEncryptorInstance = null;

  public static CrumblesLogsEncryptor getLogsEncryptorInstance() {
    if (testLogsEncryptorInstance != null) {
      return testLogsEncryptorInstance;
    }
    return prodLogsEncryptorInstance;
  }

  static void setLogsEncryptorInstanceForTest(CrumblesLogsEncryptor testInstance) {
    testLogsEncryptorInstance = testInstance;
  }

  @VisibleForTesting
  void setPublicKeyManagerForTest(CrumblesExternalPublicKeyManager manager) {
    this.publicKeyManager = manager;
  }

  /** Lazily initializes and returns the public key manager. */
  private CrumblesExternalPublicKeyManager getPublicKeyManager() {
    // Lazy initialization. If a test has injected a mock, this will return the mock.
    // Otherwise, it creates a real one the first time it's needed.
    if (publicKeyManager == null) {
      publicKeyManager = CrumblesExternalPublicKeyManager.getInstance(this);
    }
    return publicKeyManager;
  }

  @Override
  public void onStart() {
    super.onStart();
    Log.d(TAG, "started");
  }

  @Override
  public void onStop() {
    super.onStop();
    if (selectedLogsCallback != null) {
      selectedLogsCallback.wipe();
      selectedLogsCallback = null;
    }
    dismissDialog(webDavDialog);
    Log.d(TAG, "stopped");
  }

  @Override
  protected void onDestroy() {
    webDavProbeExecutor.shutdownNow();
    keyProbeExecutor.shutdown();
    dismissDialog(webDavDialog);
    super.onDestroy();
  }

  private static void dismissDialog(@Nullable AlertDialog dialog) {
    if (dialog != null) {
      dialog.dismiss();
    }
  }

  @Override
  public void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    if (!CrumblesSetupActivity.isAcknowledged(this)) {
      // Nothing on the main screen runs until the user has read what Crumbles collects.
      startActivity(new Intent(this, CrumblesSetupActivity.class));
      finish();
      return;
    }
    setContentView(R.layout.crumbles_main);
    CrumblesWindowInsets.applySystemBarPadding(this);
    // Lets encryptors created without a context record key events in the activity log.
    CrumblesLogsEncryptor.setApplicationContext(this);
    initDpm();
    // Drop re-encrypted logs that a previous run of the app left staged for sharing.
    CrumblesReEncryptedCache.sweep(this);

    // Field initialization is now handled by the lazy getter.
    encryptionKeyStatusTextView = findViewById(R.id.encryption_key_status_textview);
    uploadDestinationStatusTextView = findViewById(R.id.upload_destination_status_textview);

    // Single key management button.
    Button manageKeyButton = findViewById(R.id.btn_manage_encryption_key);
    if (manageKeyButton != null) {
      manageKeyButton.setOnClickListener(
          v -> {
            Intent intent = new Intent(CrumblesMain.this, CrumblesManageExternalKeysActivity.class);
            startActivity(intent);
          });
    }

    if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
        != PackageManager.PERMISSION_GRANTED) {
      ActivityCompat.requestPermissions(
          CrumblesMain.this, new String[] {Manifest.permission.POST_NOTIFICATIONS}, 101);
    }

    // Setup listeners that only need to be configured once.
    Button viewAuditLogButton = findViewById(R.id.btn_view_audit_log);
    if (viewAuditLogButton != null) {
      viewAuditLogButton.setOnClickListener(
          v -> {
            Intent intent = new Intent(CrumblesMain.this, CrumblesAuditLogViewerActivity.class);
            startActivity(intent);
          });
    }

    Button selectUploadDestButton = findViewById(R.id.btn_select_upload_dest);
    if (selectUploadDestButton != null) {
      selectUploadDestButton.setOnClickListener(v -> onSelectUploadDestinationClicked());
    }
    setUpUploadAndWipe();

    Button setScreenLockButton = findViewById(R.id.btn_set_screen_lock);
    setScreenLockButton.setOnClickListener(v -> openScreenLockSettings());
    findViewById(R.id.btn_activate_device_admin)
        .setOnClickListener(v -> requestDeviceAdminActivation());

    showAppSigningFingerprint();

    // Schedule work manager tasks once. Scheduling again keeps the pending upload where it is, so
    // opening the app neither re-runs it nor postpones it.
    CrumblesWorkScheduler.scheduleAllPeriodicWork(this, WorkManager.getInstance(this));
  }

  @Override
  protected void onResume() {
    super.onResume();
    // Refresh the key status, upload destination status, and UI every time the activity becomes
    // visible.
    loadAndApplyExternalPublicKey();
    setLoggingToggle();
    setNetworkCollectionToggle();
    setNeutralLauncherToggle();
    setDecryptLogsButton();
    updateUiBasedOnKeyState();
    updateUploadDestinationStatusUi();
    updateUploadIssueUi();
    updateWipeAnywayButton();
    updateScreenLockWarning();
    updateDeviceAdminOffer();
  }

  /**
   * Shows the screen lock warning while the device has no screen lock. Without one, the device
   * credential checks that guard sensitive changes are skipped.
   */
  private void updateScreenLockWarning() {
    boolean hasNoScreenLock =
        dpm != null && dpm.getPasswordComplexity() == DevicePolicyManager.PASSWORD_COMPLEXITY_NONE;
    findViewById(R.id.screen_lock_warning)
        .setVisibility(hasNoScreenLock ? View.VISIBLE : View.GONE);
  }

  /**
   * Offers to activate Crumbles as a device admin while it collects logs as a delegate of another
   * app, the device owner. Unlike a device owner, a delegate is not an active admin, so Android
   * lets anyone holding the unlocked device clear its storage, force stop it or uninstall it.
   */
  private void updateDeviceAdminOffer() {
    boolean isLoggingDelegate =
        CrumblesLoggingAccess.forSecurityLogging(this)
                .mode()
                .equals(CrumblesLoggingAccess.Mode.DELEGATE)
            || CrumblesLoggingAccess.forNetworkLogging(this)
                .mode()
                .equals(CrumblesLoggingAccess.Mode.DELEGATE);
    boolean offer =
        isLoggingDelegate && dpm != null && !dpm.isAdminActive(getDeviceAdminComponent());
    findViewById(R.id.device_admin_offer).setVisibility(offer ? View.VISIBLE : View.GONE);
  }

  /** Opens the system screen that asks the user to activate Crumbles as a device admin. */
  private void requestDeviceAdminActivation() {
    Intent intent =
        new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, getDeviceAdminComponent())
            .putExtra(
                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                getString(R.string.device_admin_explanation));
    try {
      startActivity(intent);
    } catch (ActivityNotFoundException e) {
      // Modified ROMs can ship without a system activity for ACTION_ADD_DEVICE_ADMIN.
      Log.e(TAG, "Failed to open the device admin activation screen", e);
      showToast(getString(R.string.toast_device_admin_activation_unavailable));
    }
  }

  private ComponentName getDeviceAdminComponent() {
    return new ComponentName(this, CrumblesDeviceAdminReceiver.class);
  }

  /** Opens the system screen where the user sets a screen lock. */
  private void openScreenLockSettings() {
    try {
      startActivity(
          CrumblesScreenLockSettings.intent(getPackageManager())
              .orElseThrow(ActivityNotFoundException::new));
    } catch (ActivityNotFoundException e) {
      // Modified ROMs can ship without a system activity for ACTION_SET_NEW_PASSWORD.
      Log.e(TAG, "Failed to open the screen lock settings", e);
      showToast(getString(R.string.toast_screen_lock_settings_unavailable));
    }
  }

  /**
   * Displays the SHA-256 fingerprint of the certificate that signed the installed app, so that the
   * user can compare it against the value published on the official release page.
   */
  private void showAppSigningFingerprint() {
    TextView fingerprintTextView = findViewById(R.id.app_signing_fingerprint_textview);
    if (fingerprintTextView == null) {
      return;
    }
    // The layout already carries the "unavailable" text, so only the success case needs a write.
    CrumblesSigningCertificate.getInstalledAppFingerprint(this)
        .ifPresent(
            fingerprint ->
                fingerprintTextView.setText(
                    getString(R.string.app_signing_fingerprint, fingerprint)));
  }

  /**
   * Loads the active external public key from the ExternalPublicKeyManager and applies it to the
   * CrumblesLogsEncryptor instance.
   */
  private void loadAndApplyExternalPublicKey() {
    PublicKey externalKey = getPublicKeyManager().getActiveExternalPublicKey();
    getLogsEncryptorInstance().setExternalEncryptionPublicKey(externalKey);
    Log.d(TAG, "External public key loaded and applied is null? " + (externalKey == null));
    var unused =
        keyProbeExecutor.submit(
            () -> {
              if (!getPublicKeyManager().isExternalKeySelected()
                  && CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(this)) {
                runOnUiThread(this::updateUiBasedOnKeyState);
              }
            });
  }

  /* Control UI elements based on the current key state. */
  private void updateUiBasedOnKeyState() {
    Button manageKeyButton = findViewById(R.id.btn_manage_encryption_key);
    Button decryptButton = findViewById(R.id.decrypt_logs_button);

    PublicKey externalKey = getPublicKeyManager().getActiveExternalPublicKey();
    boolean externalKeySelected =
        externalKey != null || getPublicKeyManager().isExternalKeySelected();
    boolean isInternalKey = getLogsEncryptorInstance().doesPrivateKeyExist();

    if (!externalKeySelected && !isInternalKey) {
      manageKeyButton.setText(getString(R.string.no_key_ready_generate_button));
    } else {
      manageKeyButton.setText(getString(R.string.change_encryption_key_button));
    }

    // Enable/disable decrypt button.
    // Decryption is only possible if we have the internal private key AND no external key is
    // active.
    if (externalKeySelected) {
      // If an external key is active, we assume logs are encrypted with it, so we can't decrypt
      // with the internal key.
      decryptButton.setEnabled(false);
      decryptButton.setAlpha(0.5f);
    } else {
      // If no external key is active, enable decryption ONLY if an internal key exists.
      decryptButton.setEnabled(isInternalKey);
      decryptButton.setAlpha(isInternalKey ? 1.0f : 0.5f);
    }
    updateEncryptionKeyStatusUi();
  }

  /**
   * Updates the UI element in CrumblesMain to reflect the current encryption key being used
   * (Keystore or External).
   */
  private void updateEncryptionKeyStatusUi() {
    if (encryptionKeyStatusTextView == null) {
      // Attempt to find it again if it was null, or log an error.
      // This might happen if called before UI is fully inflated or if ID is wrong.
      encryptionKeyStatusTextView = findViewById(R.id.encryption_key_status_textview);
      if (encryptionKeyStatusTextView == null) {
        Log.e(TAG, "encryptionKeyStatusTextView is null, cannot update UI.");
        return;
      }
    }

    PublicKey activeExternalKey = getLogsEncryptorInstance().getExternalEncryptionPublicKey();
    if (activeExternalKey != null) {
      String keyHash = CrumblesLogsEncryptor.getPublicKeyHash(activeExternalKey);
      encryptionKeyStatusTextView.setText(
          getString(R.string.encryption_key_status_external, keyHash));
      return;
    }
    if (getPublicKeyManager().isExternalKeySelected()) {
      encryptionKeyStatusTextView.setText(getString(R.string.status_external_key_unreadable));
      return;
    }
    if (getLogsEncryptorInstance().doesPrivateKeyExist()) {
      encryptionKeyStatusTextView.setText(getString(R.string.encryption_key_status_keystore));
      return;
    }
    encryptionKeyStatusTextView.setText(getString(R.string.encryption_key_status_none));
  }

  private void showToast(String message) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
  }

  private void initDpm() {
    this.dpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
    if (this.dpm == null) {
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "DEVICE_POLICY_MANAGER_NOT_AVAILABLE",
              "DevicePolicyManager not available. Logging might not work.");
      Log.e(TAG, "Unable to get DevicePolicyManager. Device owner features will be unavailable.");
      showToast("DevicePolicyManager not available. Logging control might not work.");
    }
  }

  private void setLoggingToggle() {
    final SwitchMaterial enableLoggingSwitch = findViewById(R.id.material_switch);
    // Detach the listener so that syncing the switch below does not trigger it.
    enableLoggingSwitch.setOnCheckedChangeListener(null);
    boolean isLoggingEnabled = dpm != null && isLoggingOn();
    enableLoggingSwitch.setChecked(isLoggingEnabled);
    enableLoggingSwitch.setText(
        isLoggingEnabled ? R.string.enable_logging_switch_msg : R.string.material_switch_msg);

    enableLoggingSwitch.setOnCheckedChangeListener(
        (buttonView, isChecked) -> {
          if (dpm == null) {
            showToast("DevicePolicyManager not available. Cannot change logging state.");
            enableLoggingSwitch.setChecked(!isChecked);
            return;
          }
          boolean canControlLogging = canControlLogging();
          if (isChecked) {
            enableLoggingSwitch.setText(R.string.enable_logging_switch_msg);
            if (canControlLogging) {
              if (!CrumblesLoggingAccess.forSecurityLogging(this).isAvailable()) {
                CrumblesCollectionScope.setNetworkCollectionEnabled(this, /* enabled= */ true);
                setNetworkCollectionToggle();
              }
              setSecurityLoggingEnabledIfAvailable(/* enabled= */ true);
              boolean enableNetwork = CrumblesCollectionScope.isNetworkCollectionEnabled(this);
              setNetworkLoggingEnabledIfAvailable(enableNetwork);
              SharedPreferences.Editor observedLogging =
                  getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
                      .edit()
                      .putBoolean(
                          CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED,
                          enableNetwork);
              // A network logging delegate leaves security logging as the watchdog last saw it, so
              // that the watchdog still reports losing access to it.
              if (CrumblesLoggingAccess.forSecurityLogging(this).isAvailable()) {
                observedLogging.putBoolean(
                    CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED, true);
              }
              observedLogging.apply();
              CrumblesDeviceAdminReceiver.bumpLoggingEnableEpoch(this);
              CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(this, /* enabled= */ true);
              showToast("Logging enabled");
            } else {
              showToast("Not device owner, cannot enable logging.");
              setLoggingToggle();
            }
          } else if (canControlLogging) {
            // Logging stays on until the user confirms their device credential. setChecked does
            // not notify this listener again while it runs.
            enableLoggingSwitch.setChecked(true);
            requestCredentialToDisableLogging();
          } else {
            showToast("Not device owner, cannot disable logging.");
            setLoggingToggle();
          }
        });
  }

  /**
   * Returns whether logging is on: security logging, or network logging for an app that the device
   * owner delegated only network logging to.
   */
  private boolean isLoggingOn() {
    CrumblesLoggingAccess securityAccess = CrumblesLoggingAccess.forSecurityLogging(this);
    if (securityAccess.isAvailable()) {
      return dpm.isSecurityLoggingEnabled(securityAccess.admin());
    }
    CrumblesLoggingAccess networkAccess = CrumblesLoggingAccess.forNetworkLogging(this);
    return networkAccess.isAvailable() && dpm.isNetworkLoggingEnabled(networkAccess.admin());
  }

  /** Returns whether Crumbles may control security logging, network logging or both. */
  private boolean canControlLogging() {
    return CrumblesLoggingAccess.forSecurityLogging(this).isAvailable()
        || CrumblesLoggingAccess.forNetworkLogging(this).isAvailable();
  }

  /**
   * Turns security logging on or off if Crumbles is the device owner or the security logging
   * delegate.
   */
  private void setSecurityLoggingEnabledIfAvailable(boolean enabled) {
    CrumblesLoggingAccess securityAccess = CrumblesLoggingAccess.forSecurityLogging(this);
    if (securityAccess.isAvailable()) {
      dpm.setSecurityLoggingEnabled(securityAccess.admin(), enabled);
    }
  }

  /**
   * Turns network logging on or off if Crumbles is the device owner or the network logging
   * delegate.
   */
  private void setNetworkLoggingEnabledIfAvailable(boolean enabled) {
    CrumblesLoggingAccess networkAccess = CrumblesLoggingAccess.forNetworkLogging(this);
    if (networkAccess.isAvailable()) {
      dpm.setNetworkLoggingEnabled(networkAccess.admin(), enabled);
    }
  }

  /**
   * Asks the user to confirm their device credential before turning logging off. Without a secure
   * lock screen, the request is refused and logging stays on.
   */
  private void requestCredentialToDisableLogging() {
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(this);
    auditLogger.logEvent(
        "LOGGING_DISABLE_REQUESTED", "User asked to turn off security and network logging.");
    CrumblesDeviceCredentialGate.confirmScreenLock(
        this,
        getString(R.string.disable_logging_auth_title),
        getString(R.string.disable_logging_auth_subtitle),
        () -> handleKeyguardDisableLoggingResult(Activity.RESULT_OK),
        () -> handleKeyguardDisableLoggingResult(Activity.RESULT_CANCELED),
        () -> {
          showToast(getString(R.string.toast_disable_logging_requires_screen_lock));
          auditLogger.logEvent(
              "LOGGING_DISABLE_REFUSED",
              "Logging stays on because no secure lock screen is set up.");
        });
  }

  private void setNetworkCollectionToggle() {
    SwitchMaterial networkCollectionSwitch = findViewById(R.id.network_collection_switch);
    boolean isNetworkCollectionEnabled = CrumblesCollectionScope.isNetworkCollectionEnabled(this);
    networkCollectionSwitch.setOnCheckedChangeListener(null);
    networkCollectionSwitch.setChecked(isNetworkCollectionEnabled);
    networkCollectionSwitch.setText(getNetworkCollectionLabel(isNetworkCollectionEnabled));
    networkCollectionSwitch.setOnCheckedChangeListener(
        (buttonView, isChecked) -> onNetworkCollectionToggled(networkCollectionSwitch, isChecked));
  }

  private void onNetworkCollectionToggled(
      SwitchMaterial networkCollectionSwitch, boolean isChecked) {
    if (!isChecked) {
      // Network collection stays on until the user confirms their device credential. setChecked
      // does not notify this listener again while it runs.
      networkCollectionSwitch.setChecked(true);
      requestCredentialToDisableNetworkCollection();
      return;
    }
    applyNetworkCollectionScope(/* enabled= */ true);
  }

  /** Stores and applies the network collection choice, and syncs the switch with it. */
  private void applyNetworkCollectionScope(boolean enabled) {
    CrumblesCollectionScope.setNetworkCollectionEnabled(this, enabled);
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            "NETWORK_COLLECTION_SCOPE_CHANGED",
            enabled
                ? "Network collection turned on: DNS and connection events are captured"
                    + " device-wide."
                : "Network collection turned off: DNS and connection events are no longer"
                    + " captured.");
    CrumblesLoggingAccess securityAccess = CrumblesLoggingAccess.forSecurityLogging(this);
    // While security logging is off, turning network collection on only stores the choice, which
    // applies when logging is turned on. Turning it off applies at once, and so does every choice
    // of a delegate of network logging only, whose logging is network logging alone.
    boolean waitsForLogging =
        enabled
            && dpm != null
            && securityAccess.isAvailable()
            && !dpm.isSecurityLoggingEnabled(securityAccess.admin());
    if (!waitsForLogging) {
      if (!enabled && !securityAccess.isAvailable()) {
        CrumblesDeviceAdminReceiver.sealFinalBatch(this);
      }
      setNetworkLoggingEnabledIfAvailable(enabled);
      CrumblesDeviceAdminReceiver.bumpNetworkLoggingEnableEpoch(this);
    }
    showToast(
        getString(
            enabled
                ? R.string.toast_network_collection_enabled
                : R.string.toast_network_collection_disabled));
    setNetworkCollectionToggle();
    if (!securityAccess.isAvailable()) {
      setLoggingToggle();
    }
  }

  /**
   * Asks the user to confirm their device credential before turning network collection off. Without
   * a secure lock screen, the request is refused and network collection stays on.
   */
  private void requestCredentialToDisableNetworkCollection() {
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(this);
    auditLogger.logEvent(
        "NETWORK_COLLECTION_DISABLE_REQUESTED", "User asked to turn off network collection.");
    CrumblesDeviceCredentialGate.confirmScreenLock(
        this,
        getString(R.string.disable_network_collection_auth_title),
        getString(R.string.disable_network_collection_auth_subtitle),
        () -> handleKeyguardDisableNetworkCollectionResult(Activity.RESULT_OK),
        () -> handleKeyguardDisableNetworkCollectionResult(Activity.RESULT_CANCELED),
        () -> {
          showToast(getString(R.string.toast_disable_network_collection_requires_screen_lock));
          auditLogger.logEvent(
              "NETWORK_COLLECTION_DISABLE_REFUSED",
              "Network collection stays on because no secure lock screen is set up.");
        });
  }

  private static int getNetworkCollectionLabel(boolean isEnabled) {
    return isEnabled
        ? R.string.network_collection_switch_on_msg
        : R.string.network_collection_switch_off_msg;
  }

  private void setNeutralLauncherToggle() {
    SwitchMaterial neutralLauncherSwitch = findViewById(R.id.neutral_launcher_switch);
    String neutralName = getString(R.string.neutral_launcher_label);
    neutralLauncherSwitch.setText(getString(R.string.neutral_launcher_switch_msg, neutralName));
    neutralLauncherSwitch.setOnCheckedChangeListener(null);
    neutralLauncherSwitch.setChecked(CrumblesLauncherEntry.isNeutral(this));
    neutralLauncherSwitch.setOnCheckedChangeListener(
        (buttonView, isChecked) -> onNeutralLauncherToggled(isChecked, neutralName));
  }

  private void onNeutralLauncherToggled(boolean isChecked, String neutralName) {
    if (isChecked) {
      CrumblesLauncherEntry.showNeutral(this);
      showToast(getString(R.string.toast_neutral_launcher_on, neutralName));
    } else {
      CrumblesLauncherEntry.showDefault(this);
      showToast(getString(R.string.toast_neutral_launcher_off));
    }
  }

  private void setDecryptLogsButton() {
    final Button decryptButton = findViewById(R.id.decrypt_logs_button);
    decryptButton.setOnClickListener(
        v -> {
          Log.d(TAG, "Decrypt logs button clicked.");
          if (!getLogsEncryptorInstance().doesPrivateKeyExist()) {
            showToast(
                "No private key available for decryption. Please generate or load a key pair"
                    + " first.");
            return;
          }
          openFilePicker();
        });
  }

  /**
   * Wires "Upload now and wipe", and "Wipe anyway", which shows while the last upload and wipe has
   * left batches on this device.
   */
  private void setUpUploadAndWipe() {
    findViewById(R.id.btn_upload_and_wipe)
        .setOnClickListener(
            v -> {
              CrumblesUploadAndWipeWorker.start(this);
              // Only the copies that a WebDAV server confirmed are deleted.
              boolean deletesCopies =
                  readRemoteStorageConfig()
                      .getStorageType()
                      .equals(StorageType.STORAGE_TYPE_WEBDAV);
              showToast(
                  getString(
                      deletesCopies
                          ? R.string.toast_upload_and_wipe_started
                          : R.string.toast_upload_and_wipe_started_folder));
            });
    findViewById(R.id.btn_wipe_anyway).setOnClickListener(v -> onWipeAnywayClicked());
    WorkManager.getInstance(this)
        .getWorkInfosForUniqueWorkLiveData(CrumblesUploadAndWipeWorker.UNIQUE_WORK_NAME)
        .observe(this, workInfos -> updateWipeAnywayButton());
  }

  private void updateWipeAnywayButton() {
    Button wipeAnywayButton = findViewById(R.id.btn_wipe_anyway);
    int notUploadedCount = CrumblesUploadAndWipeWorker.getBatchesLeft(this);
    int keptSentCount = CrumblesUploadAndWipeWorker.countKeptSafBatches(this);

    if (notUploadedCount > 0) {
      wipeAnywayButton.setVisibility(View.VISIBLE);
      wipeAnywayButton.setText(
          getResources()
              .getQuantityString(
                  R.plurals.btn_wipe_anyway_label, notUploadedCount, notUploadedCount));
    } else if (keptSentCount > 0) {
      wipeAnywayButton.setVisibility(View.VISIBLE);
      // The wipe also deletes the batches not uploaded yet, so the label counts them too.
      int pendingCount = CrumblesUploadAndWipeWorker.countPendingBatches(this);
      wipeAnywayButton.setText(
          pendingCount == 0
              ? getResources()
                  .getQuantityString(
                      R.plurals.btn_wipe_kept_copies_label, keptSentCount, keptSentCount)
              : MessageFormat.format(
                  getString(R.string.btn_wipe_kept_copies_and_pending_label),
                  ImmutableMap.of("kept", keptSentCount, "pending", pendingCount)));
    } else {
      wipeAnywayButton.setVisibility(View.GONE);
    }

    TextView textKeptCopies = findViewById(R.id.text_saf_kept_copies);
    if (keptSentCount > 0) {
      textKeptCopies.setVisibility(View.VISIBLE);
      textKeptCopies.setText(
          getResources()
              .getQuantityString(R.plurals.label_saf_kept_copies, keptSentCount, keptSentCount));
    } else {
      textKeptCopies.setVisibility(View.GONE);
    }
  }

  private void onWipeAnywayClicked() {
    // Without pending batches, the wipe deletes only copies of batches that were uploaded.
    boolean keptCopiesOnly = CrumblesUploadAndWipeWorker.countPendingBatches(this) == 0;
    CrumblesDeviceCredentialGate.confirmScreenLock(
        this,
        getString(
            keptCopiesOnly
                ? R.string.wipe_kept_copies_auth_title
                : R.string.wipe_anyway_auth_title),
        getString(
            keptCopiesOnly
                ? R.string.wipe_kept_copies_auth_subtitle
                : R.string.wipe_anyway_auth_subtitle),
        () -> handleWipeAnywayAuthResult(Activity.RESULT_OK),
        () -> handleWipeAnywayAuthResult(Activity.RESULT_CANCELED),
        () -> {
          CrumblesAppAuditLogger.getInstance(this)
              .logEvent(
                  "UPLOAD_AND_WIPE_FORCED_REFUSED",
                  "Wipe anyway refused because the device has no screen lock.");
          showToast(getString(R.string.toast_wipe_anyway_needs_screen_lock));
        });
  }

  private void handleWipeAnywayAuthResult(int resultCode) {
    if (resultCode != Activity.RESULT_OK) {
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "UPLOAD_AND_WIPE_FORCED_AUTH_FAILED",
              "Wipe anyway cancelled because the device credential was not confirmed.");
      showToast(getString(R.string.toast_wipe_anyway_auth_cancelled));
      return;
    }
    int wipedCount = CrumblesUploadAndWipeWorker.wipeAllBatches(this);
    showToast(
        getResources().getQuantityString(R.plurals.toast_wipe_anyway_done, wipedCount, wipedCount));
    updateWipeAnywayButton();
  }

  private void openFilePicker() {
    Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
    intent.addCategory(Intent.CATEGORY_OPENABLE);
    intent.setType("*/*");
    intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);

    try {
      startActivityForResult(intent, CrumblesConstants.FILE_PICKER_REQUEST_CODE);
    } catch (RuntimeException e) {
      Log.e(TAG, "Error launching file picker", e);
      showToast("Could not open file picker. Ensure a file manager app is installed.");
    }
  }

  /** Persists read and write permissions for the selected tree URI. */
  // Suppress WrongConstant because Intent#getFlags() returns a general int bitmask
  // that is masked with Intent#FLAG_GRANT_READ_URI_PERMISSION and
  // Intent#FLAG_GRANT_WRITE_URI_PERMISSION as required by
  // ContentResolver#takePersistableUriPermission(Uri, int).
  @SuppressWarnings("WrongConstant")
  private void takePersistableUriPermission(Uri uri, Intent data) {
    int takeFlags =
        data.getFlags()
            & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    getContentResolver().takePersistableUriPermission(uri, takeFlags);
  }

  /* onActivityResult triggers the biometric prompt instead of directly processing files. */
  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);

    switch (requestCode) {
      case CrumblesConstants.FILE_PICKER_REQUEST_CODE -> handleFilePickerResult(resultCode, data);
      case CrumblesConstants.FILE_TREE_REQUEST_CODE -> handleFileTreeResult(resultCode, data);
      default -> {}
    }
  }

  private void handleFilePickerResult(int resultCode, Intent data) {
    if (resultCode == Activity.RESULT_OK && data != null) {
      List<Uri> fileUris = new ArrayList<>();
      if (data.getClipData() != null) {
        for (int i = 0; i < data.getClipData().getItemCount(); i++) {
          fileUris.add(data.getClipData().getItemAt(i).getUri());
        }
      } else if (data.getData() != null) {
        fileUris.add(data.getData());
      }

      if (!fileUris.isEmpty()) {
        processSelectedFilesForDecryption(fileUris);
      } else {
        showToast("No files selected.");
      }
    } else {
      showToast("File selection cancelled.");
    }
  }

  private void handleKeyguardDestinationResult(int resultCode) {
    if (resultCode == Activity.RESULT_OK) {
      showStorageTypeSelectionDialog();
    } else {
      showToast(getString(R.string.toast_upload_dest_auth_cancelled));
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "UPLOAD_DESTINATION_AUTH_FAILED",
              "User authentication cancelled when attempting to change upload destination.");
    }
  }

  /**
   * Turns logging off if the user confirmed their device credential. Otherwise logging stays on.
   */
  private void handleKeyguardDisableLoggingResult(int resultCode) {
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(this);
    if (resultCode != Activity.RESULT_OK) {
      showToast(getString(R.string.toast_disable_logging_auth_cancelled));
      auditLogger.logEvent(
          "LOGGING_DISABLE_AUTH_FAILED",
          "User authentication cancelled when attempting to turn off logging.");
      return;
    }
    if (dpm == null || !canControlLogging()) {
      auditLogger.logEvent(
          "LOGGING_DISABLE_FAILED",
          "Logging stays on because the app is no longer device owner or logging delegate.");
      showToast(getString(R.string.dpm_not_device_owner_disable_log_failed_toast_msg));
      return;
    }
    // Recorded before anything changes, so the event survives even if the app is killed midway.
    auditLogger.logEvent(
        "LOGGING_DISABLED", "User confirmed their device credential and turned off logging.");
    // Logging goes off even if sealing fails; the failure is in the activity log.
    if (isLoggingOn()) {
      CrumblesDeviceAdminReceiver.sealFinalBatch(this);
    }
    if (!CrumblesLoggingAccess.forSecurityLogging(this).isAvailable()) {
      CrumblesCollectionScope.setNetworkCollectionEnabled(this, /* enabled= */ false);
      setNetworkCollectionToggle();
    }
    setSecurityLoggingEnabledIfAvailable(/* enabled= */ false);
    setNetworkLoggingEnabledIfAvailable(/* enabled= */ false);
    getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED, false)
        .putBoolean(CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED, false)
        .apply();
    CrumblesDeviceAdminReceiver.bumpLoggingEnableEpoch(this);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(this, /* enabled= */ false);
    CrumblesDeviceAdminReceiver.reconcileSecondaryUserPause(this);
    showToast(getString(R.string.dpm_logging_disabled_toast_msg));
    setLoggingToggle();
  }

  /**
   * Turns network collection off if the user confirmed their device credential. Otherwise network
   * collection stays on.
   */
  private void handleKeyguardDisableNetworkCollectionResult(int resultCode) {
    if (resultCode != Activity.RESULT_OK) {
      showToast(getString(R.string.toast_disable_network_collection_auth_cancelled));
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "NETWORK_COLLECTION_DISABLE_AUTH_FAILED",
              "User authentication cancelled when attempting to turn off network collection.");
      return;
    }
    applyNetworkCollectionScope(/* enabled= */ false);
  }

  private void handleFileTreeResult(int resultCode, Intent data) {
    if (resultCode == Activity.RESULT_OK && data != null && data.getData() != null) {
      Uri treeUri = data.getData();
      if (!Objects.equals(treeUri.getScheme(), ContentResolver.SCHEME_CONTENT)) {
        showToast(getString(R.string.toast_upload_dest_invalid_uri));
        return;
      }
      try {
        takePersistableUriPermission(treeUri, data);
      } catch (SecurityException e) {
        Log.e(TAG, "Failed to take persistable URI permission for: " + treeUri, e);
        showToast(getString(R.string.toast_upload_dest_invalid_uri));
        return;
      }

      // Double check that persistable write permission was confirmed by the Android OS.
      boolean verifiedWrite = false;
      for (UriPermission perm : getContentResolver().getPersistedUriPermissions()) {
        if (perm.getUri().equals(treeUri) && perm.isWritePermission()) {
          verifiedWrite = true;
          break;
        }
      }

      if (!verifiedWrite) {
        Log.w(TAG, "Persisted permission write check failed for: " + treeUri);
        showToast(getString(R.string.toast_upload_dest_invalid_uri));
        return;
      }

      try {
        // Replacing the whole config also deletes any sealed WebDAV credentials.
        saveRemoteStorageConfig(
            RemoteStorageConfig.newBuilder()
                .setStorageType(StorageType.STORAGE_TYPE_GOOGLE_DRIVE)
                .setUploadDestinationUri(treeUri.toString())
                .build());
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to save the upload folder", e);
        showToast(getString(R.string.toast_upload_dest_save_failed));
        return;
      }
      getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
          .edit()
          .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, treeUri.toString())
          .apply();

      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "UPLOAD_DESTINATION_CONFIGURED",
              // The authority names the storage provider, not the account or the folder.
              "Configured upload destination URI with verified persistable write permissions."
                  + " Storage provider: "
                  + treeUri.getAuthority()
                  + ".");
      showToast(getString(R.string.toast_upload_dest_set_success));
      updateUploadDestinationStatusUi();
    } else {
      showToast(getString(R.string.toast_upload_dest_set_cancelled));
    }
  }

  /**
   * Asks the user to confirm their device credential before choosing an upload folder. Without a
   * secure lock screen, the request is refused, because anyone holding the phone could otherwise
   * send the logs somewhere else.
   */
  private void onSelectUploadDestinationClicked() {
    CrumblesDeviceCredentialGate.confirmScreenLock(
        this,
        getString(R.string.upload_dest_auth_title),
        getString(R.string.upload_dest_auth_subtitle),
        () -> handleKeyguardDestinationResult(Activity.RESULT_OK),
        () -> handleKeyguardDestinationResult(Activity.RESULT_CANCELED),
        () -> {
          showToast(getString(R.string.toast_upload_dest_requires_screen_lock));
          CrumblesAppAuditLogger.getInstance(this)
              .logEvent(
                  "UPLOAD_DESTINATION_REFUSED",
                  "Upload destination unchanged because no secure lock screen is set up.");
        });
  }

  private void showStorageTypeSelectionDialog() {
    CharSequence[] options =
        new CharSequence[] {
          getString(R.string.storage_type_folder), getString(R.string.storage_type_webdav),
        };
    showSecureDialog(
        new AlertDialog.Builder(this)
            .setTitle(R.string.storage_type_dialog_title)
            .setItems(
                options,
                (dialog, which) -> {
                  if (which == 0) {
                    launchDocumentTreePicker();
                  } else if (which == 1) {
                    showWebDavConfigDialog();
                  }
                })
            .setNegativeButton(android.R.string.cancel, null)
            .create());
  }

  /** Shows the WebDAV settings dialog, which starts empty because saved values are sealed. */
  private void showWebDavConfigDialog() {
    dismissDialog(webDavDialog);
    LinearLayout layout = new LinearLayout(this);
    layout.setOrientation(LinearLayout.VERTICAL);
    layout.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
    int padding = (int) (16 * getResources().getDisplayMetrics().density);
    layout.setPadding(padding, padding, padding, padding);

    EditText urlField = new EditText(this);
    urlField.setId(R.id.webdav_server_url_input);
    urlField.setHint(R.string.webdav_server_url_hint);
    configureSensitiveInput(urlField);
    layout.addView(urlField);

    EditText usernameField = new EditText(this);
    usernameField.setId(R.id.webdav_username_input);
    usernameField.setHint(R.string.webdav_username_hint);
    configureSensitiveInput(usernameField);
    layout.addView(usernameField);

    EditText passwordField = new EditText(this);
    passwordField.setId(R.id.webdav_password_input);
    passwordField.setHint(R.string.webdav_password_hint);
    passwordField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
    configureSensitiveInput(passwordField);
    layout.addView(passwordField);

    TextView statusText = new TextView(this);
    statusText.setId(R.id.webdav_status_text);
    statusText.setPadding(0, padding / 2, 0, padding / 2);
    layout.addView(statusText);

    Button testButton = new Button(this);
    testButton.setId(R.id.webdav_test_connection_button);
    testButton.setText(R.string.webdav_test_connection_button);
    testButton.setOnClickListener(
        v -> testWebDavConnection(urlField, usernameField, passwordField, statusText, testButton));
    layout.addView(testButton);

    AlertDialog dialog =
        new AlertDialog.Builder(this)
            .setTitle(R.string.webdav_config_dialog_title)
            .setView(layout)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create();
    webDavDialog = dialog;
    dialog.setOnDismissListener(
        d -> {
          dismissDialog(serverKeyPinDialog);
          urlField.getText().clear();
          usernameField.getText().clear();
          passwordField.getText().clear();
          lastConfirmedPin = null;
          if (Objects.equals(webDavDialog, d)) {
            webDavDialog = null;
          }
        });
    showSecureDialog(dialog);
    dialog
        .getButton(DialogInterface.BUTTON_POSITIVE)
        .setOnClickListener(
            v -> saveWebDavConfig(dialog, urlField, usernameField, passwordField));
  }

  private static void configureSensitiveInput(EditText field) {
    field.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
    field.setSaveEnabled(false);
    field.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
  }

  private static void showSecureDialog(AlertDialog dialog) {
    Window window = dialog.getWindow();
    if (window != null) {
      // A dialog window does not inherit FLAG_SECURE or overlay hiding from the activity window.
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
      window.setHideOverlayWindows(true);
    }
    dialog.show();
  }

  /**
   * Seals the settings entered in the WebDAV dialog and makes them the upload destination. For an
   * HTTPS server, that happens only once the user has confirmed the server's public key, which is
   * then pinned with the settings.
   */
  private void saveWebDavConfig(
      AlertDialog dialog, EditText urlField, EditText usernameField, EditText passwordField) {
    String serverUrl = urlField.getText().toString().trim();
    if (usernameField.length() == 0
        || passwordField.length() == 0
        || !WebDavStorageUploader.isAcceptableServerUrl(serverUrl)) {
      showToast(getString(R.string.toast_webdav_invalid_fields));
      return;
    }
    byte[] username = toUtf8Bytes(usernameField.getText());
    byte[] password = toUtf8Bytes(passwordField.getText());
    RemoteStorageConfig config;
    try {
      config = sealWebDavConfig(serverUrl, username, password);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to save the WebDAV upload destination", e);
      showToast(getString(R.string.toast_upload_dest_save_failed));
      return;
    } finally {
      Arrays.fill(username, (byte) 0);
      Arrays.fill(password, (byte) 0);
    }
    if (!Ascii.equalsIgnoreCase("https", Strings.nullToEmpty(Uri.parse(serverUrl).getScheme()))) {
      // Plaintext HTTP, which only a loopback server may use, has no server key to pin.
      commitWebDavConfig(dialog, config, /* serverKeyPin= */ null);
      return;
    }
    if (lastConfirmedPin != null && lastConfirmedPin.serverUrl.equals(serverUrl)) {
      commitWebDavConfig(dialog, config, lastConfirmedPin.pin);
      return;
    }
    confirmServerKeyPin(
        serverUrl, () -> {}, pin -> commitWebDavConfig(dialog, config, pin));
  }

  /**
   * Opens the server identity dialog for {@code serverUrl}, reads the server's public key in the
   * background without sending credentials, and runs {@code onConfirmed} once the user confirms it.
   */
  private void confirmServerKeyPin(
      String serverUrl, Runnable onDismiss, Consumer<WebDavServerKeyPin> onConfirmed) {
    WebDavServerKeyPin knownKey = knownServerKey(serverUrl);
    lastConfirmedPin = null;
    dismissDialog(serverKeyPinDialog);
    serverKeyPinDialog =
        new AlertDialog.Builder(this)
            .setTitle(R.string.webdav_server_key_dialog_title)
            .setMessage(R.string.webdav_reading_server_key)
            .setPositiveButton(R.string.webdav_server_key_confirm_button, null)
            .setNegativeButton(android.R.string.cancel, null)
            .setOnDismissListener(d -> onDismiss.run())
            .create();
    showSecureDialog(serverKeyPinDialog);
    serverKeyPinDialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
    AlertDialog dialog = serverKeyPinDialog;
    webDavProbeExecutor.execute(
        () -> {
          Optional<WebDavServerKeyPin> pin = readServerKeyPin(serverUrl);
          runOnUiThread(() -> offerServerKeyPin(dialog, serverUrl, knownKey, pin, onConfirmed));
        });
  }

  /**
   * Returns the key already confirmed for {@code serverUrl} in this dialog or in stored settings,
   * or {@code null} if none matches {@code serverUrl}.
   */
  @Nullable
  private WebDavServerKeyPin knownServerKey(String serverUrl) {
    if (lastConfirmedPin != null && lastConfirmedPin.serverUrl.equals(serverUrl)) {
      return lastConfirmedPin.pin;
    }
    RemoteStorageConfig config = readRemoteStorageConfig();
    if (config.getWebdavServerKeySha256().getCiphertext().isEmpty()) {
      return null;
    }
    try {
      CrumblesLogsEncryptor encryptor = getLogsEncryptorInstance();
      String storedUrl =
          new String(
              encryptor.decryptDataStoreEntry(
                  config.getWebdavServerUrl(), CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID),
              UTF_8);
      return storedUrl.equals(serverUrl)
          ? WebDavServerKeyPin.ofSha256(
              encryptor.decryptDataStoreEntry(
                  config.getWebdavServerKeySha256(),
                  CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID))
          : null;
    } catch (CrumblesKeysException | IllegalArgumentException e) {
      Log.w(TAG, "Failed to read the pinned WebDAV server key", e);
      return null;
    }
  }

  /** Returns the pin of the public key that {@code serverUrl} presents, or empty if it fails. */
  private static Optional<WebDavServerKeyPin> readServerKeyPin(String serverUrl) {
    try {
      return Optional.of(
          WebDavStorageUploader.fetchServerKeyPin(
              serverUrl, WebDavServerKeyPin.platformTrustManager()));
    } catch (IOException | GeneralSecurityException e) {
      // Leaves the exception out, because its message can echo the server's host name.
      Log.e(TAG, "Failed to read the WebDAV server's public key: " + e.getClass().getName());
      return Optional.empty();
    }
  }

  private void offerServerKeyPin(
      AlertDialog dialog,
      String serverUrl,
      @Nullable WebDavServerKeyPin knownKey,
      Optional<WebDavServerKeyPin> serverKeyPin,
      Consumer<WebDavServerKeyPin> onConfirmed) {
    if (!dialog.isShowing()) {
      return;
    }
    if (serverKeyPin.isEmpty()) {
      dialog.setMessage(getString(R.string.webdav_server_key_unreadable));
      return;
    }
    if (knownKey != null) {
      if (knownKey.equals(serverKeyPin.get())) {
        dialog.setOnDismissListener(null);
        dialog.dismiss();
        lastConfirmedPin = new ConfirmedServerKey(serverUrl, serverKeyPin.get());
        onConfirmed.accept(serverKeyPin.get());
        return;
      }
      dialog.setMessage(
          getString(R.string.webdav_server_key_changed)
              + getString(
                  R.string.webdav_server_key_dialog_message,
                  serverKeyPin.get().fingerprint()));
    } else {
      dialog.setMessage(
          getString(
              R.string.webdav_server_key_dialog_message,
              serverKeyPin.get().fingerprint()));
    }
    Button confirmButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
    confirmButton.setOnClickListener(
        v -> {
          dialog.setOnDismissListener(null);
          dialog.dismiss();
          lastConfirmedPin = new ConfirmedServerKey(serverUrl, serverKeyPin.get());
          onConfirmed.accept(serverKeyPin.get());
        });
    confirmButton.setEnabled(true);
  }

  /**
   * Seals {@code serverKeyPin} (if any) into {@code config}, saves the upload destination, and
   * closes {@code dialog}.
   */
  private void commitWebDavConfig(
      AlertDialog dialog, RemoteStorageConfig config, @Nullable WebDavServerKeyPin serverKeyPin) {
    try {
      if (serverKeyPin != null) {
        config =
            config.toBuilder()
                .setWebdavServerKeySha256(
                    getLogsEncryptorInstance()
                        .encryptDataStoreEntry(
                            serverKeyPin.toSha256(),
                            CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID))
                .build();
      }
      saveRemoteStorageConfig(config);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to save the WebDAV upload destination", e);
      showToast(getString(R.string.toast_upload_dest_save_failed));
      return;
    }
    dialog.dismiss();
    // The server URL stays out of the audit trail because it can name the account.
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent("UPLOAD_DESTINATION_CONFIGURED", "Configured a WebDAV upload destination.");
    showToast(getString(R.string.toast_webdav_config_success));
    updateUploadDestinationStatusUi();
    updateWipeAnywayButton();
  }

  /**
   * Runs a WebDAV connection check in the background and shows the result in the dialog. For an
   * HTTPS server, the user confirms the server's public key first and the probe is pinned to it.
   */
  private void testWebDavConnection(
      EditText urlField,
      EditText usernameField,
      EditText passwordField,
      TextView statusText,
      Button testButton) {
    String serverUrl = urlField.getText().toString().trim();
    if (usernameField.length() == 0
        || passwordField.length() == 0
        || !WebDavStorageUploader.isAcceptableServerUrl(serverUrl)) {
      statusText.setText(R.string.toast_webdav_invalid_fields);
      return;
    }
    testButton.setEnabled(false);
    if (Ascii.equalsIgnoreCase("https", Strings.nullToEmpty(Uri.parse(serverUrl).getScheme()))) {
      confirmServerKeyPin(
          serverUrl,
          () -> testButton.setEnabled(true),
          pin ->
              startWebDavProbe(
                  serverUrl, usernameField, passwordField, pin, statusText, testButton));
      return;
    }
    startWebDavProbe(
        serverUrl, usernameField, passwordField, /* serverKeyPin= */ null, statusText, testButton);
  }

  private void startWebDavProbe(
      String serverUrl,
      EditText usernameField,
      EditText passwordField,
      @Nullable WebDavServerKeyPin serverKeyPin,
      TextView statusText,
      Button testButton) {
    byte[] username = toUtf8Bytes(usernameField.getText());
    byte[] password = toUtf8Bytes(passwordField.getText());
    statusText.setText(R.string.webdav_testing_connection);
    testButton.setEnabled(false);
    webDavProbeExecutor.execute(
        () -> {
          @StringRes int messageId = probeWebDavServer(serverUrl, username, password, serverKeyPin);
          runOnUiThread(
              () -> {
                statusText.setText(
                    messageId == R.string.webdav_result_server_not_found
                        ? getString(messageId, 404)
                        : getString(messageId));
                testButton.setEnabled(true);
              });
        });
  }

  /** Probes {@code serverUrl}, wipes both credential arrays and returns the status string ID. */
  @StringRes
  private static int probeWebDavServer(
      String serverUrl, byte[] username, byte[] password, @Nullable WebDavServerKeyPin pin) {
    try {
      SSLSocketFactory tlsSocketFactory =
          pin == null ? null : pin.newSocketFactory(WebDavServerKeyPin.platformTrustManager());
      return switch (WebDavStorageUploader.testConnection(
          serverUrl, username, password, tlsSocketFactory)) {
        case SUCCESS -> R.string.webdav_result_success;
        case AUTH_FAILED -> R.string.webdav_result_auth_failed;
        case SERVER_NOT_FOUND -> R.string.webdav_result_server_not_found;
        case REDIRECTED -> R.string.webdav_result_redirected;
        case INVALID_URL -> R.string.toast_webdav_invalid_fields;
        case NETWORK_ERROR -> R.string.webdav_result_network_error;
      };
    } catch (GeneralSecurityException e) {
      return R.string.webdav_result_network_error;
    } finally {
      Arrays.fill(username, (byte) 0);
      Arrays.fill(password, (byte) 0);
    }
  }

  /** Returns WebDAV settings in which each value is sealed to its own DataStore entry. */
  private static RemoteStorageConfig sealWebDavConfig(
      String serverUrl, byte[] username, byte[] password) throws CrumblesKeysException {
    CrumblesLogsEncryptor encryptor = getLogsEncryptorInstance();
    return RemoteStorageConfig.newBuilder()
        .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
        .setWebdavServerUrl(
            encryptor.encryptDataStoreEntry(
                serverUrl.getBytes(UTF_8), CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID))
        .setWebdavCredentials(
            WebDavCredentials.newBuilder()
                .setUsername(
                    encryptor.encryptDataStoreEntry(
                        username, CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
                .setPassword(
                    encryptor.encryptDataStoreEntry(
                        password, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
                .build())
        .build();
  }

  /** Makes {@code config} the upload destination, replacing the previous config as a whole. */
  private void saveRemoteStorageConfig(RemoteStorageConfig config) throws CrumblesKeysException {
    Futures.getChecked(
        CrumblesDataStoreHolder.getInstance(this)
            .updateDataAsync(
                preferences -> preferences.toBuilder().setRemoteStorageConfig(config).build()),
        CrumblesKeysException.class);
  }

  /** Returns the saved upload destination, or the default instance if it cannot be read. */
  private RemoteStorageConfig readRemoteStorageConfig() {
    try {
      return Futures.getChecked(
              CrumblesDataStoreHolder.getInstance(this).getDataAsync(), CrumblesKeysException.class)
          .getRemoteStorageConfig();
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to read the upload destination", e);
      return RemoteStorageConfig.getDefaultInstance();
    }
  }

  /** Encodes {@code text} as UTF-8 without making a {@code String}, which could not be wiped. */
  private static byte[] toUtf8Bytes(CharSequence text) {
    ByteBuffer encoded = UTF_8.encode(CharBuffer.wrap(text));
    byte[] bytes = new byte[encoded.remaining()];
    encoded.get(bytes);
    Arrays.fill(encoded.array(), encoded.arrayOffset(), encoded.limit(), (byte) 0);
    return bytes;
  }

  @VisibleForTesting
  void launchDocumentTreePicker() {
    Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
    intent.addFlags(
        Intent.FLAG_GRANT_READ_URI_PERMISSION
            | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
    try {
      startActivityForResult(intent, CrumblesConstants.FILE_TREE_REQUEST_CODE);
    } catch (ActivityNotFoundException | SecurityException e) {
      // Devices without a documents provider or customized ROMs throw when resolving
      // ACTION_OPEN_DOCUMENT_TREE.
      Log.e(TAG, "Failed to launch document tree picker", e);
      showToast("Could not open directory picker.");
    }
  }

  @VisibleForTesting
  void updateUploadDestinationStatusUi() {
    if (uploadDestinationStatusTextView == null) {
      Log.e(TAG, "uploadDestinationStatusTextView is null, cannot update upload destination UI.");
      return;
    }
    if (readRemoteStorageConfig().getStorageType() == StorageType.STORAGE_TYPE_WEBDAV) {
      // Only the type is shown, because the server URL can name the account.
      uploadDestinationStatusTextView.setText(
          getString(
              R.string.upload_dest_status_configured, getString(R.string.storage_type_webdav)));
      return;
    }
    String uriString =
        getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, null);

    boolean hasValidGrant = false;
    if (uriString != null) {
      for (UriPermission permission : getContentResolver().getPersistedUriPermissions()) {
        if (permission.getUri().toString().equals(uriString) && permission.isWritePermission()) {
          hasValidGrant = true;
          break;
        }
      }
    }

    uploadDestinationStatusTextView.setText(
        hasValidGrant
            ? describeConfiguredUploadDestination(Uri.parse(uriString))
            : getString(R.string.upload_dest_status_not_set));
  }

  /**
   * Shows the problem that keeps uploads from going through, if one was reported and still lasts,
   * with the number of batches that wait on this phone meanwhile.
   */
  private void updateUploadIssueUi() {
    TextView uploadIssueTextView = findViewById(R.id.upload_issue_textview);
    Optional<String> issue = CrumblesSendAndMarkProcessingWorker.describeReportedUploadIssue(this);
    uploadIssueTextView.setVisibility(issue.isPresent() ? View.VISIBLE : View.GONE);
    if (issue.isPresent()) {
      int pendingCount = CrumblesUploadAndWipeWorker.countPendingBatches(this);
      uploadIssueTextView.setText(
          getResources()
              .getQuantityString(
                  R.plurals.upload_issue_status, pendingCount, pendingCount, issue.get()));
    }
  }

  /**
   * Returns the status text for a configured upload folder. It names the folder when its storage
   * provider reports a display name, and the app that holds the folder when that app is installed,
   * so the user can see which app receives the logs.
   */
  private String describeConfiguredUploadDestination(Uri treeUri) {
    String folderName = readUploadFolderName(treeUri);
    PackageManager packageManager = getPackageManager();
    ProviderInfo storageProvider =
        packageManager.resolveContentProvider(treeUri.getAuthority(), /* flags= */ 0);
    if (storageProvider == null) {
      return TextUtils.isEmpty(folderName)
          ? getString(R.string.upload_dest_status_configured_unnamed)
          : getString(R.string.upload_dest_status_configured, folderName);
    }
    // The package name identifies the app even when its label imitates another app's. The label is
    // escaped and capped in length, the folder name is escaped, and the folder comes last, so that
    // neither can disguise or push out of view the package name.
    String storageApp =
        getString(
            R.string.upload_dest_storage_app,
            CrumblesDeviceAdminReceiver.escapeLabel(
                storageProvider.applicationInfo.loadLabel(packageManager)),
            storageProvider.packageName);
    return TextUtils.isEmpty(folderName)
        ? getString(R.string.upload_dest_status_unnamed_in_app, storageApp)
        : getString(R.string.upload_dest_status_configured_in_app, folderName, storageApp);
  }

  /**
   * Returns the display name that the storage provider reports for the upload folder, if any,
   * {@link CrumblesDeviceAdminReceiver#escapeLabel escaped and capped} since the provider chooses it.
   */
  @Nullable
  private String readUploadFolderName(Uri treeUri) {
    try {
      DocumentFile folder = DocumentFile.fromTreeUri(this, treeUri);
      String folderName = folder == null ? null : folder.getName();
      return folderName == null ? null : CrumblesDeviceAdminReceiver.escapeLabel(folderName);
    } catch (IllegalArgumentException e) {
      // A stored URI that is not a document tree URI must not crash the main screen.
      Log.w(TAG, "Upload destination is not a document tree URI: " + treeUri, e);
      return null;
    }
  }

  private String getAllowedAdHocFolderCanonicalPath() throws IOException {
    File documentsDir =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS);
    File adHocFolder = new File(documentsDir, CrumblesConstants.TEMP_RE_ENCRYPTED_DIR);

    if (!adHocFolder.exists()) {
      if (!adHocFolder.mkdirs()) {
        Log.e(TAG, "Failed to create allowed ad-hoc folder: " + adHocFolder.getAbsolutePath());
        throw new IOException("Ad-hoc folder setup failed: " + adHocFolder.getAbsolutePath());
      }
    }
    return adHocFolder.getCanonicalPath();
  }

  /**
   * Returns the canonical form of {@code pathFromUri} if it is a regular file inside the allowed
   * ad-hoc folder.
   *
   * <p>Canonicalization resolves {@code ..} segments and symbolic links before the containment
   * check, so neither can be used to escape the folder. {@link Path#startsWith(Path)} compares
   * whole name elements, so a sibling folder that merely shares the name prefix does not match.
   *
   * @throws SecurityException if the canonical path is outside the allowed ad-hoc folder
   * @throws FileNotFoundException if the canonical path is not a regular file
   */
  private File resolveFileInAllowedAdHocFolder(String pathFromUri, Uri uri) throws IOException {
    File canonicalInputFile = new File(pathFromUri).getCanonicalFile();
    Path canonicalInputPath = canonicalInputFile.toPath();
    Path allowedFolderPath = Path.of(getAllowedAdHocFolderCanonicalPath());
    Log.d(TAG, "File URI canonical path: " + canonicalInputPath);
    Log.d(TAG, "Allowed ad-hoc folder canonical path: " + allowedFolderPath);
    if (!canonicalInputPath.startsWith(allowedFolderPath)) {
      Log.e(
          TAG,
          "File path is not within the allowed ad-hoc folder. Input: "
              + canonicalInputPath
              + ", Allowed Base: "
              + allowedFolderPath);
      throw new SecurityException(
          "Access Denied: File is not within the designated secure folder for URI: " + uri);
    }
    if (!canonicalInputFile.isFile()) {
      Log.e(TAG, "Selected path is not a file: " + canonicalInputPath);
      throw new FileNotFoundException("Selected path is not a file: " + uri);
    }
    return canonicalInputFile;
  }

  protected byte[] readBytesFromUri(Uri uri) throws IOException {
    if (uri == null) {
      throw new IOException("URI cannot be null.");
    }

    String scheme = uri.getScheme();
    Log.d(TAG, "Reading URI: " + uri + " with scheme: " + scheme);

    InputStream inputStream = null;
    try {
      if (Objects.equals(scheme, ContentResolver.SCHEME_FILE)) {
        String pathFromUri = uri.getPath();
        if (pathFromUri == null) {
          throw new FileNotFoundException("File URI has null path: " + uri);
        }

        File inputFile = resolveFileInAllowedAdHocFolder(pathFromUri, uri);
        // If the file URI has passed the ad-hoc folder check, it's considered trusted by app logic.
        // Therefore we do not need to use SafeContentResolver.
        Log.d(TAG, "Opening vetted file URI directly: " + uri);
        inputStream = new FileInputStream(inputFile);

      } else if (Objects.equals(scheme, ContentResolver.SCHEME_CONTENT)) {
        rejectIfDeclaredSizeExceedsLimit(uri);
        // For content:// URIs, use SafeContentResolver as intended for external content.
        Log.d(TAG, "Opening content URI via SafeContentResolver: " + uri);
        inputStream = SafeContentResolver.openInputStream(this, uri, SourcePolicy.EXTERNAL_ONLY);
        if (inputStream == null) {
          throw new FileNotFoundException(
              "SafeContentResolver.openInputStream returned null for content URI: " + uri);
        }
      } else {
        Log.w(TAG, "Unsupported URI scheme for reading: " + scheme + " for URI: " + uri);
        throw new IOException("Unsupported URI scheme: " + scheme);
      }

      // Read one byte past the limit so that a provider streaming more than it declared, or a
      // file:// file that grew after it was selected, is detected without buffering it whole.
      byte[] fileBytes =
          ByteStreams.toByteArray(
              ByteStreams.limit(
                  inputStream, CrumblesConstants.MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES + 1));
      if (fileBytes.length > CrumblesConstants.MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES) {
        throw newFileTooLargeException();
      }
      return fileBytes;
    } finally {
      if (inputStream != null) {
        try {
          inputStream.close();
        } catch (IOException e) {
          Log.w(TAG, "Error closing InputStream for URI: " + uri, e);
        }
      }
    }
  }

  /**
   * Rejects {@code uri} without opening it if its provider declares a size above {@link
   * CrumblesConstants#MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES}, which spares reading up to the limit
   * into memory only to discard the file.
   *
   * <p>A provider can declare any size, or none, so {@link #readBytesFromUri} also bounds the read.
   */
  private void rejectIfDeclaredSizeExceedsLimit(Uri uri) throws IOException {
    try (Cursor cursor =
        getContentResolver()
            .query(
                uri,
                new String[] {OpenableColumns.SIZE},
                /* selection= */ null,
                /* selectionArgs= */ null,
                /* sortOrder= */ null)) {
      if (cursor != null && cursor.moveToFirst()) {
        int sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE);
        if (sizeIndex != -1
            && !cursor.isNull(sizeIndex)
            && cursor.getLong(sizeIndex) > CrumblesConstants.MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES) {
          throw newFileTooLargeException();
        }
      }
    }
  }

  private static IOException newFileTooLargeException() {
    return new IOException(
        "File exceeds the maximum size of "
            + CrumblesConstants.MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES
            + " bytes.");
  }

  /**
   * Reads the selected log files, then decrypts them together after the prompts that their keys
   * need, and shows the decrypted logs.
   */
  protected void processSelectedFilesForDecryption(List<Uri> uris) {
    if (!getLogsEncryptorInstance().doesPrivateKeyExist()) {
      showToast("Decryption aborted: Private key is not available.");
      Log.w(TAG, "Attempted decryption without a private key.");
      return;
    }

    List<LogBatch> logBatches = new ArrayList<>();
    IdentityHashMap<LogBatch, String> fileNames = new IdentityHashMap<>();
    boolean allRead = true;
    for (Uri uri : uris) {
      String fileName = getFileNameFromUri(uri);
      byte[] fileBytes = null;
      try {
        fileBytes = readBytesFromUri(uri);
        Log.d(TAG, "Read " + fileBytes.length + " bytes from " + fileName);
      } catch (IOException | RuntimeException e) {
        Log.e(TAG, "Unexpected error processing file: " + fileName, e);
        // A content provider can throw an exception with any message it chooses, so the toast
        // names only the file.
        showToast("Could not read " + fileName + ".");
        allRead = false;
        continue;
      }

      LogBatch logBatch;
      try {
        logBatch = LogBatch.parseFrom(fileBytes, ExtensionRegistryLite.getGeneratedRegistry());
        Log.d(TAG, "Successfully deserialized LogBatch from " + fileName);
      } catch (InvalidProtocolBufferException e) {
        Log.e(TAG, "Failed to parse LogBatch from file: " + fileName, e);
        showToast("Error: " + fileName + " is not a valid LogBatch format.");
        allRead = false;
        continue;
      }
      logBatches.add(logBatch);
      fileNames.put(logBatch, fileName);
    }
    selectedLogsCallback =
        new SelectedLogsCallback(uris.isEmpty(), allRead, logBatches, fileNames);
    selectedLogsCallback.decryptor.decrypt(logBatches, selectedLogsCallback);
  }

  /** Collects the logs decrypted from a selection, and shows them once the decryptor is done. */
  private final class SelectedLogsCallback implements CrumblesAuthorizedLogDecryptor.Callback {
    private final CrumblesAuthorizedLogDecryptor decryptor =
        new CrumblesAuthorizedLogDecryptor(CrumblesMain.this, getLogsEncryptorInstance());
    private final boolean noFileSelected;
    private final List<LogBatch> logBatches;
    private final IdentityHashMap<LogBatch, String> fileNames;
    private final IdentityHashMap<LogBatch, CrumblesDecryptedLogEntry> decryptedEntries =
        new IdentityHashMap<>();
    private boolean allDecrypted;

    SelectedLogsCallback(
        boolean noFileSelected,
        boolean allRead,
        List<LogBatch> logBatches,
        IdentityHashMap<LogBatch, String> fileNames) {
      this.noFileSelected = noFileSelected;
      this.allDecrypted = allRead;
      this.logBatches = logBatches;
      this.fileNames = fileNames;
    }

    @Override
    public void onDecrypted(LogBatch logBatch, DecryptedLogBatch decryptedBatch) {
      String fileName = fileNames.get(logBatch);
      decryptedEntries.put(
          logBatch,
          new CrumblesDecryptedLogEntry(
              fileName,
              decryptedBatch.logs(),
              decryptedBatch.metadata().getDevice().getDeviceId(),
              logBatch));
      Log.i(TAG, "Successfully decrypted: " + fileName);
      CrumblesAppAuditLogger.getInstance(CrumblesMain.this)
          .logEvent("DECRYPTION_SUCCESS", "Successfully decrypted file: " + fileName);
    }

    @Override
    public void onDecryptionFailed(LogBatch logBatch, Exception exception) {
      String fileName = fileNames.get(logBatch);
      Log.e(TAG, "Unexpected error processing file: " + fileName, exception);
      showToast("Failed to decrypt " + fileName + ".");
      CrumblesAppAuditLogger.getInstance(CrumblesMain.this)
          .logEvent(
              "DECRYPTION_FAILURE",
              "Failed to decrypt '" + fileName + "'. Reason: Decryption failed.");
      allDecrypted = false;
    }

    void wipe() {
      decryptor.cancel();
      for (CrumblesDecryptedLogEntry entry : decryptedEntries.values()) {
        entry.wipe();
      }
      decryptedEntries.clear();
    }

    @Override
    public void onNotAuthorized(int errorCode, CharSequence errorMessage) {
      Log.w(TAG, "Decryption not authorized, error " + errorCode + ": " + errorMessage);
      showToast(errorMessage.toString());
      wipe();
    }

    @Override
    public void onFinished() {
      selectedLogsCallback = null;
      showDecryptedLogs();
    }

    /** Shows the logs decrypted so far, in the order of the selection. */
    private void showDecryptedLogs() {
      ArrayList<CrumblesDecryptedLogEntry> entries = new ArrayList<>();
      for (LogBatch logBatch : logBatches) {
        if (decryptedEntries.containsKey(logBatch)) {
          entries.add(decryptedEntries.get(logBatch));
        }
      }
      if (!entries.isEmpty()) {
        long sessionId = CrumblesDecryptedLogsSession.startSession(entries);
        Intent intent = new Intent(CrumblesMain.this, CrumblesDecryptedLogsActivity.class);
        intent.putExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, sessionId);
        startActivity(intent);
        if (allDecrypted) {
          showToast("All selected logs decrypted and displayed.");
        } else {
          showToast("Some logs could not be decrypted. See details above or check logs.");
        }
      } else if (noFileSelected) {
        showToast("No files were processed for decryption.");
      } else if (allDecrypted) {
        showToast("No content to display. Files might be empty or not contain valid data.");
      }
    }
  }

  /**
   * Returns the display name of {@code uri}, {@link CrumblesDeviceAdminReceiver#escapeLabel escaped
   * and capped in length} because whoever runs the provider or names the file chooses it, and the
   * name is shown in toasts and with the decrypted logs and recorded in the activity log.
   */
  protected String getFileNameFromUri(Uri uri) {
    String fileName = "Unknown_File";
    if (uri == null) {
      Log.w(TAG, "getFileNameFromUri called with null URI.");
      return fileName;
    }

    String scheme = uri.getScheme();
    Log.d(TAG, "Getting file name for URI: " + uri + " with scheme: " + scheme);

    if (Objects.equals(scheme, ContentResolver.SCHEME_CONTENT)) {
      // SafeContentResolver does not have a public query method.
      // Use standard ContentResolver for querying display name.
      // Security here relies on the ContentProvider's implementation and URI permissions.
      Cursor cursor = null;
      try {
        cursor =
            getContentResolver()
                .query(
                    uri,
                    new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME},
                    null,
                    null,
                    null);

        if (cursor != null && cursor.moveToFirst()) {
          int nameIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME);
          if (nameIndex != -1 && cursor.getString(nameIndex) != null) {
            fileName = cursor.getString(nameIndex);
          }
        }
      } catch (RuntimeException e) {
        Log.e(TAG, "Exception querying display name for content URI: " + uri, e);
      } finally {
        if (cursor != null) {
          cursor.close();
        }
      }
    } else if (Objects.equals(scheme, ContentResolver.SCHEME_FILE)) {
      String path = uri.getPath();
      if (path != null) {
        fileName = new File(path).getName();
      } else {
        Log.w(TAG, "File URI has null path: " + uri + ". Using default name.");
      }
    } else {
      Log.w(
          TAG,
          "Unsupported URI scheme for getFileNameFromUri: "
              + scheme
              + " for URI: "
              + uri
              + ". Using default name.");
    }
    return CrumblesDeviceAdminReceiver.escapeFileName(fileName);
  }
}
