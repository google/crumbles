package com.android.securelogging;

import static java.nio.charset.StandardCharsets.UTF_8;

import android.Manifest;
import android.app.Activity;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v4.app.FragmentActivity;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.VisibleForTesting;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.work.WorkManager;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditLogViewerActivity;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.android.libraries.security.content.SafeContentResolver;
import com.google.android.libraries.security.content.SafeContentResolver.SourcePolicy;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.common.io.ByteStreams;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Main activity for the Crumbles app. */
public class CrumblesMain extends FragmentActivity {
  private static final String TAG = "[Crumbles]";
  private ComponentName adminComponentName;
  private DevicePolicyManager dpm;

  private CrumblesExternalPublicKeyManager publicKeyManager;
  private TextView encryptionKeyStatusTextView;

  private List<Uri> pendingFileUrisForDecryption;

  private static final CrumblesLogsEncryptor prodLogsEncryptorInstance =
      new CrumblesLogsEncryptor();

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
    Log.d(TAG, "stopped");
  }

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.crumbles_main);
    initDpm();

    // Field initialization is now handled by the lazy getter.
    encryptionKeyStatusTextView = findViewById(R.id.encryption_key_status_textview);

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

    // Schedule work manager tasks once.
    Log.d(TAG, "Cancelling any previously scheduled WorkManager tasks...");
    WorkManager.getInstance(this).cancelUniqueWork(CrumblesConstants.SEND_WORK_TAG);
    Log.d(TAG, "Scheduling new WorkManager tasks...");
    CrumblesWorkScheduler.scheduleAllPeriodicWork(this, WorkManager.getInstance(this));
  }

  @Override
  protected void onResume() {
    super.onResume();
    // Refresh the key status and UI every time the activity becomes visible.
    loadAndApplyExternalPublicKey();
    setLoggingToggle();
    setDecryptLogsButton();
    updateUiBasedOnKeyState();
  }

  /**
   * Loads the active external public key from the ExternalPublicKeyManager and applies it to the
   * CrumblesLogsEncryptor instance.
   */
  private void loadAndApplyExternalPublicKey() {
    PublicKey externalKey = getPublicKeyManager().getActiveExternalPublicKey();
    getLogsEncryptorInstance().setExternalEncryptionPublicKey(externalKey);
    Log.d(TAG, "External public key loaded and applied is null? " + (externalKey == null));
  }

  /* Control UI elements based on the current key state. */
  private void updateUiBasedOnKeyState() {
    Button manageKeyButton = findViewById(R.id.btn_manage_encryption_key);
    Button decryptButton = findViewById(R.id.decrypt_logs_button);

    PublicKey externalKey = getPublicKeyManager().getActiveExternalPublicKey();
    boolean isInternalKey = getLogsEncryptorInstance().doesPrivateKeyExist();

    if (externalKey == null && !isInternalKey) {
      manageKeyButton.setText(getString(R.string.no_key_ready_generate_button));
    } else {
      manageKeyButton.setText(getString(R.string.change_encryption_key_button));
    }

    // Enable/disable decrypt button.
    // Decryption is only possible if we have the internal private key AND no external key is
    // active.
    if (externalKey != null) {
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
    this.adminComponentName =
        new ComponentName(
            CrumblesMain.this.getApplicationContext(), CrumblesDeviceAdminReceiver.class);
  }

  private void setLoggingToggle() {
    final SwitchMaterial enableLoggingSwitch = findViewById(R.id.material_switch);
    if (dpm != null && dpm.isDeviceOwnerApp(getPackageName())) {
      boolean isLoggingEnabled = dpm.isSecurityLoggingEnabled(adminComponentName);
      enableLoggingSwitch.setChecked(isLoggingEnabled);
      enableLoggingSwitch.setText(
          isLoggingEnabled ? R.string.enable_logging_switch_msg : R.string.material_switch_msg);
    } else {
      enableLoggingSwitch.setChecked(false);
      enableLoggingSwitch.setText(R.string.material_switch_msg);
    }

    enableLoggingSwitch.setOnCheckedChangeListener(
        (buttonView, isChecked) -> {
          if (dpm == null) {
            showToast("DevicePolicyManager not available. Cannot change logging state.");
            enableLoggingSwitch.setChecked(!isChecked);
            return;
          }
          if (isChecked) {
            enableLoggingSwitch.setText(R.string.enable_logging_switch_msg);
            if (dpm.isDeviceOwnerApp(getPackageName())) {
              dpm.setSecurityLoggingEnabled(adminComponentName, true);
              dpm.setNetworkLoggingEnabled(adminComponentName, true);
              showToast("Logging enabled");
            } else {
              showToast("Not device owner, cannot enable logging.");
              enableLoggingSwitch.setChecked(false);
            }
          } else {
            if (dpm.isDeviceOwnerApp(getPackageName())) {
              dpm.setSecurityLoggingEnabled(adminComponentName, false);
              dpm.setNetworkLoggingEnabled(adminComponentName, false);
              showToast("Logging disabled");
            } else {
              showToast("Not device owner, cannot disable logging.");
              enableLoggingSwitch.setChecked(true);
            }
            enableLoggingSwitch.setText(R.string.material_switch_msg);
          }
        });
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

  /* onActivityResult triggers the biometric prompt instead of directly processing files. */
  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);

    switch (requestCode) {
      case CrumblesConstants.FILE_PICKER_REQUEST_CODE:
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
            // Store the URIs and make the FIRST attempt.
            this.pendingFileUrisForDecryption = fileUris;
            attemptDecryption();
          } else {
            showToast("No files selected.");
          }
        } else {
          showToast("File selection cancelled.");
        }
        break;
      case CrumblesConstants.KEYGUARD_REQUEST_CODE:
        if (resultCode == Activity.RESULT_OK) {
          // User authenticated successfully. Retry the decryption.
          attemptDecryption();
        } else {
          showToast("Authentication cancelled.");
          this.pendingFileUrisForDecryption = null; // Clear pending files.
        }
        break;
      default:
        break;
    }
  }

  private void attemptDecryption() {
    if (this.pendingFileUrisForDecryption == null || this.pendingFileUrisForDecryption.isEmpty()) {
      Log.w(TAG, "attemptDecryption called with no pending files.");
      return;
    }

    try {
      processSelectedFilesForDecryption(this.pendingFileUrisForDecryption);
      // If we get here, it worked. Clear the pending files.
      this.pendingFileUrisForDecryption = null;
    } catch (UserNotAuthenticatedException e) {
      // We caught the exception, now we manually ask for auth.
      Log.w(TAG, "Authentication required. Launching Keyguard.", e);
      showAuthenticationScreen();
    }
  }

  private void showAuthenticationScreen() {
    KeyguardManager keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
    if (keyguardManager == null) {
      showToast("Device does not support Keyguard.");
      return;
    }

    // This intent will show the PIN, pattern, or password screen.
    Intent intent =
        keyguardManager.createConfirmDeviceCredentialIntent(
            "Authentication required", "Please unlock to decrypt logs");
    if (intent != null) {
      startActivityForResult(intent, CrumblesConstants.KEYGUARD_REQUEST_CODE);
    } else {
      // This happens if the user has no screen lock set up.
      showToast("Please set up a screen lock in your device settings.");
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

        File inputFile = new File(pathFromUri);
        String canonicalInputPath = inputFile.getCanonicalPath();
        String allowedFolderPath = getAllowedAdHocFolderCanonicalPath();

        Log.d(TAG, "File URI canonical path: " + canonicalInputPath);
        Log.d(TAG, "Allowed ad-hoc folder canonical path: " + allowedFolderPath);
        Path inputNioPath = inputFile.toPath().toAbsolutePath().normalize();
        Path allowedNioPathBase =
            Path.of(getAllowedAdHocFolderCanonicalPath()).toAbsolutePath().normalize();
        Log.d(TAG, "Normalized Input Path: " + inputNioPath);
        Log.d(TAG, "Normalized Allowed Ad-Hoc Base Path: " + allowedNioPathBase);
        if (!inputNioPath.startsWith(allowedNioPathBase)
            || inputNioPath.equals(allowedNioPathBase)) {
          // Check if the parent of the input file is the allowed directory.
          if (inputNioPath.getParent() == null
              || !inputNioPath.getParent().equals(allowedNioPathBase)) {
            Log.e(
                TAG,
                "File path is not directly within the allowed ad-hoc folder. Input: "
                    + inputNioPath
                    + ", Allowed Base: "
                    + allowedNioPathBase);
            throw new SecurityException(
                "Access Denied: File is not within the designated secure folder for URI: " + uri);
          }
        }
        if (!inputFile.isFile()) {
          Log.e(TAG, "Selected path is not a file: " + canonicalInputPath);
          throw new FileNotFoundException("Selected path is not a file: " + uri);
        }
        // If the file URI has passed the ad-hoc folder check, it's considered trusted by app logic.
        // Therefore we do not need to use SafeContentResolver.
        Log.d(TAG, "Opening vetted file URI directly: " + uri);
        inputStream = new FileInputStream(inputFile);

      } else if (Objects.equals(scheme, ContentResolver.SCHEME_CONTENT)) {
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

      ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();
      ByteStreams.copy(inputStream, byteBuffer);
      return byteBuffer.toByteArray();
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

  protected void processSelectedFilesForDecryption(List<Uri> uris)
      throws UserNotAuthenticatedException {
    if (!getLogsEncryptorInstance().doesPrivateKeyExist()) {
      showToast("Decryption aborted: Private key is not available.");
      Log.w(TAG, "Attempted decryption without a private key.");
      return;
    }

    ArrayList<CrumblesDecryptedLogEntry> decryptedEntries = new ArrayList<>();
    boolean allSuccessful = true;
    for (Uri uri : uris) {
      String fileName = getFileNameFromUri(uri);
      byte[] fileBytes = null;
      try {
        fileBytes = readBytesFromUri(uri);
        Log.d(TAG, "Read " + fileBytes.length + " bytes from " + fileName);
      } catch (IOException | RuntimeException e) {
        Log.e(TAG, "Unexpected error processing file: " + fileName, e);
        showToast("Unexpected error with " + fileName + ": " + e.getMessage());
        allSuccessful = false;
        continue;
      }

      LogBatch logBatch;
      try {
        logBatch = LogBatch.parseFrom(fileBytes, ExtensionRegistryLite.getGeneratedRegistry());
        Log.d(TAG, "Successfully deserialized LogBatch from " + fileName);
      } catch (InvalidProtocolBufferException e) {
        Log.e(TAG, "Failed to parse LogBatch from file: " + fileName, e);
        showToast("Error: " + fileName + " is not a valid LogBatch format.");
        allSuccessful = false;
        continue;
      }

      try {
        // This call will trigger the system authentication prompt if required.
        // If auth fails or is cancelled, it will throw UserNotAuthenticatedException.
        byte[] decryptedBytes = getLogsEncryptorInstance().decryptLogs(logBatch);
        String decryptedContent = new String(decryptedBytes, UTF_8);
        decryptedEntries.add(
            new CrumblesDecryptedLogEntry(fileName, decryptedContent, decryptedBytes));
        Log.i(TAG, "Successfully decrypted: " + fileName);
        CrumblesAppAuditLogger.getInstance(this)
            .logEvent("DECRYPTION_SUCCESS", "Successfully decrypted file: " + fileName);
      } catch (RuntimeException | CrumblesKeysException e) {
        Log.e(TAG, "Unexpected error processing file: " + fileName, e);
        showToast("Unexpected error with " + fileName + ": " + e.getMessage());
        CrumblesAppAuditLogger.getInstance(this)
            .logEvent(
                "DECRYPTION_FAILURE",
                "Failed to decrypt '" + fileName + "'. Reason: " + e.getMessage());
        allSuccessful = false;
      }
    }
    if (!decryptedEntries.isEmpty()) {
      Intent intent = new Intent(this, CrumblesDecryptedLogsActivity.class);
      intent.putExtra(CrumblesConstants.EXTRA_DECRYPTED_LOGS, decryptedEntries);
      startActivity(intent);
      if (allSuccessful) {
        showToast("All selected logs decrypted and displayed.");
      } else {
        showToast("Some logs could not be decrypted. See details above or check logs.");
      }
    } else {
      if (!uris.isEmpty() && allSuccessful) {
        showToast("No content to display. Files might be empty or not contain valid data.");
      } else if (uris.isEmpty()) {
        showToast("No files were processed for decryption.");
      }
    }
  }

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
    return fileName;
  }
}
