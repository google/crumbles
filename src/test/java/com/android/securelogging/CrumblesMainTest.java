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

import static com.android.securelogging.CrumblesConstants.FILE_PICKER_REQUEST_CODE;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Environment;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import androidx.core.content.IntentCompat;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowApplication;
import org.robolectric.shadows.ShadowDevicePolicyManager;
import org.robolectric.shadows.ShadowEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowToast;

/** Tests the main activity of the Crumbles app. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesMainTest {

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private Context context;
  private File rootOfTestCleanup;
  private File mockAdHocDir;
  private KeyPair testExternalKeyPair;

  private static KeyPair generateTestRsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return kpg.generateKeyPair();
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    ShadowLog.stream = System.out;

    context = ApplicationProvider.getApplicationContext();
    context.setTheme(R.style.Theme_Crumbles);

    testExternalKeyPair = generateTestRsaKeyPair();
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);

    Configuration config = new Configuration.Builder().setMinimumLoggingLevel(Log.DEBUG).build();
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config);

    // Base path that ShadowEnvironment.setExternalStoragePublicDirectory() will use.
    File mockPublicStorageBase = new File(context.getCacheDir(), "TestPublicStorageBase");
    mockPublicStorageBase.mkdirs();
    ShadowEnvironment.setExternalStoragePublicDirectory(mockPublicStorageBase.toPath());

    File shadowedDocumentsDir =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS);
    shadowedDocumentsDir.mkdirs();

    this.mockAdHocDir = new File(shadowedDocumentsDir, CrumblesConstants.TEMP_RE_ENCRYPTED_DIR);
    this.mockAdHocDir.mkdirs();
    this.rootOfTestCleanup = mockPublicStorageBase;
  }

  @After
  public void tearDown() {
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    if (rootOfTestCleanup != null) {
      deleteRecursive(rootOfTestCleanup);
    }
  }

  private void deleteRecursive(File fileOrDirectory) {
    if (fileOrDirectory.isDirectory()) {
      File[] children = fileOrDirectory.listFiles();
      if (children != null) {
        for (File child : children) {
          deleteRecursive(child);
        }
      }
    }
    fileOrDirectory.delete();
  }

  private ActivityScenario<CrumblesMain> launchActivityWithNotificationPermission(
      boolean notificationsGranted) {
    Application application = ApplicationProvider.getApplicationContext();
    ShadowApplication shadowApplication = shadowOf(application);

    if (notificationsGranted) {
      shadowApplication.grantPermissions(Manifest.permission.POST_NOTIFICATIONS);
    } else {
      shadowApplication.denyPermissions(Manifest.permission.POST_NOTIFICATIONS);
    }

    // Launch the activity, but don't move it to RESUMED state immediately.
    ActivityScenario<CrumblesMain> currentScenario = ActivityScenario.launch(CrumblesMain.class);
    // Inject the mock manager *before* onResume is called.
    currentScenario.onActivity(
        activity -> activity.setPublicKeyManagerForTest(mockPublicKeyManager));
    // Now move the activity to RESUMED, which will trigger the UI updates.
    currentScenario.moveToState(Lifecycle.State.RESUMED);
    shadowOf(Looper.getMainLooper()).idle();
    return currentScenario;
  }

  @Test
  public void getLogsEncryptorInstance_whenTestInstanceIsSet_returnsTestInstance() {
    // Given: The test instance is set in @Before.
    // When: getLogsEncryptorInstance is called.
    CrumblesLogsEncryptor instance = CrumblesMain.getLogsEncryptorInstance();
    // Then: The returned instance is the mocked test instance.
    assertThat(instance).isSameInstanceAs(mockLogsEncryptor);
  }

  @Test
  public void onCreate_initializesUIElements() {
    // When: The activity is launched.
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      // Then: Verify essential UI elements are present.
      scenario.onActivity(
          activity -> {
            // A NullPointerException would occur if a view is not found, failing the test.
            assertThat((Object) activity.findViewById(R.id.material_switch)).isNotNull();
            assertThat((Object) activity.findViewById(R.id.encryption_key_status_textview))
                .isNotNull();
            assertThat((Object) activity.findViewById(R.id.btn_manage_encryption_key)).isNotNull();
            assertThat((Object) activity.findViewById(R.id.decrypt_logs_button)).isNotNull();
            assertThat((Object) activity.findViewById(R.id.btn_view_audit_log)).isNotNull();
          });
    }
  }

  // --- UI State Tests ---

  @Test
  public void uiState_whenNoKeys_showsGenerateButtonAndDisablesDecrypt() {
    // Given: The mock manager returns null for the external key.
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);
    // And: No internal Keystore key exists.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);

    // When: Activity is launched.
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      // Then: The UI reflects the "no keys" state.
      scenario.onActivity(
          activity -> {
            Button manageKeyButton = activity.findViewById(R.id.btn_manage_encryption_key);
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            TextView statusTextView = activity.findViewById(R.id.encryption_key_status_textview);

            assertThat(manageKeyButton.getText().toString())
                .isEqualTo(activity.getString(R.string.no_key_ready_generate_button));
            assertThat(decryptButton.isEnabled()).isFalse();
            assertThat(decryptButton.getAlpha()).isEqualTo(0.5f); // Verify disabled alpha
            assertThat(statusTextView.getText().toString())
                .isEqualTo(activity.getString(R.string.encryption_key_status_none));
          });
    }
  }

  @Test
  public void uiState_whenInternalKeyExists_showsChangeButtonAndEnablesDecrypt() {
    // Given: An internal Keystore key exists.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    // And: The mock manager returns null for the external key.
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);

    // When: Activity is launched.
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      // Then: The UI reflects the "Keystore active" state.
      scenario.onActivity(
          activity -> {
            Button manageKeyButton = activity.findViewById(R.id.btn_manage_encryption_key);
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            TextView statusTextView = activity.findViewById(R.id.encryption_key_status_textview);

            assertThat(manageKeyButton.getText().toString())
                .isEqualTo(activity.getString(R.string.change_encryption_key_button));
            assertThat(decryptButton.isEnabled()).isTrue();
            assertThat(decryptButton.getAlpha()).isEqualTo(1.0f); // Verify enabled alpha
            assertThat(statusTextView.getText().toString())
                .isEqualTo(activity.getString(R.string.encryption_key_status_keystore));
          });
    }
  }

  @Test
  public void uiState_whenExternalKeyExists_showsChangeButtonAndDisablesDecrypt() throws Exception {
    // Given: The mock manager will return an external key.
    when(mockPublicKeyManager.getActiveExternalPublicKey())
        .thenReturn(testExternalKeyPair.getPublic());
    // And: No internal Keystore key exists.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);

    // When: Activity is launched.
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      // Then: The UI reflects the "external key active" state.
      scenario.onActivity(
          activity -> {
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            assertThat(decryptButton.isEnabled()).isFalse();
            assertThat(decryptButton.getAlpha()).isEqualTo(0.5f); // Verify disabled alpha
          });
    }
  }

  @Test
  public void getLogsEncryptorInstance_whenTestInstanceIsNull_returnsProdInstance() {
    // Given: The test instance is explicitly set to null.
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    // When: getLogsEncryptorInstance is called.
    CrumblesLogsEncryptor instance = CrumblesMain.getLogsEncryptorInstance();
    // Then: The returned instance is a non-null production instance.
    assertThat(instance).isNotNull();
    assertThat(instance).isNotSameInstanceAs(mockLogsEncryptor);
  }

  @Test
  public void setLoggingToggle_asDeviceOwner_enablesAndDisablesLogging() {
    // Given: DPM setup (as before).
    Application application = ApplicationProvider.getApplicationContext();
    DevicePolicyManager dpmService =
        (DevicePolicyManager) application.getSystemService(Context.DEVICE_POLICY_SERVICE);
    ShadowDevicePolicyManager shadowDpm = shadowOf(dpmService);
    ComponentName adminReceiverComponent =
        new ComponentName(application, CrumblesDeviceAdminReceiver.class);
    shadowDpm.setDeviceOwner(adminReceiverComponent);
    shadowDpm.setActiveAdmin(adminReceiverComponent);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          SwitchMaterial toggle = activity.findViewById(R.id.material_switch);
          // When: The toggle is clicked to enable logging.
          toggle.performClick();
          shadowOf(activity.getMainLooper()).idle();
          // Then: Logging is enabled and toast is shown.
          assertThat(toggle.isChecked()).isTrue();
          assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging enabled");

          // When: The toggle is clicked again to disable logging.
          toggle.performClick();
          shadowOf(activity.getMainLooper()).idle();
          // Then: Logging is disabled and toast is shown.
          assertThat(toggle.isChecked()).isFalse();
          assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging disabled");
        });
  }

  @Test
  public void manageEncryptionKeyButton_onClick_launchesManageExternalKeysActivity() {
    // Given: Activity is launched.
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final Intent[] startedIntent = new Intent[1];

    // When: The "Manage Encryption Key" button is clicked.
    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_manage_encryption_key).performClick();
          shadowOf(activity.getMainLooper()).idle();
          startedIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    // Then: CrumblesManageExternalKeysActivity is launched.
    assertThat(startedIntent[0]).isNotNull();
    assertThat(startedIntent[0].getComponent().getClassName())
        .isEqualTo(CrumblesManageExternalKeysActivity.class.getName());
  }

  @Test
  public void uiState_whenNoKeys_showsGenerateButtonAndEnablesDecrypt() {
    // Given: No external key and no internal private key.
    // SharedPreferences cleared in @Before. CrumblesExternalPublicKeyManager will return null.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false); // No internal key.
    when(mockLogsEncryptor.getExternalEncryptionPublicKey()).thenReturn(null);

    // When: Activity is launched.
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    // Then: Button text is "No Encryption Key Ready - Generate", Decrypt is disabled.
    scenario.onActivity(
        activity -> {
          Button manageKeyButton = activity.findViewById(R.id.btn_manage_encryption_key);
          Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
          TextView statusTextView = activity.findViewById(R.id.encryption_key_status_textview);

          assertThat(manageKeyButton.getText().toString())
              .isEqualTo(activity.getString(R.string.no_key_ready_generate_button));
          assertThat(decryptButton.isEnabled()).isFalse();
          assertThat(statusTextView.getText().toString())
              .isEqualTo(activity.getString(R.string.encryption_key_status_none));
        });
  }

  @Test
  public void decryptLogsButton_whenPrivateKeyAvailable_opensFilePicker() {
    // Given: Encryptor has a private key and no external key is active.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.getExternalEncryptionPublicKey()).thenReturn(null);

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final Intent[] startedIntent = new Intent[1];

    // When: Decrypt button is clicked.
    scenario.onActivity(
        activity -> {
          Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
          assertThat(decryptButton.isEnabled()).isTrue();
          decryptButton.performClick();
          ShadowActivity shadowActivity = shadowOf(activity);
          ShadowActivity.IntentForResult intentForResult =
              shadowActivity.getNextStartedActivityForResult();
          assertThat(intentForResult).isNotNull();
          startedIntent[0] = intentForResult.intent;
        });

    // Then: File picker intent is launched.
    assertThat(startedIntent[0]).isNotNull();
    assertThat(startedIntent[0].getAction()).isEqualTo(Intent.ACTION_OPEN_DOCUMENT);
  }

  @Test
  public void onActivityResult_withValidFileAndSuccessfulAuth_startsDecryptedLogsActivity()
      throws IOException, CrumblesKeysException, UserNotAuthenticatedException {
    // Arrange
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);

    byte[] fakeEncryptedBytes =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("encrypted")))
            .build()
            .toByteArray();
    File testFile = new File(mockAdHocDir, "good_log.bin");
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write(fakeEncryptedBytes);
    }
    Intent resultDataIntent = new Intent().setData(Uri.fromFile(testFile));

    byte[] decryptedBytes = "decrypted_content".getBytes(UTF_8);
    when(mockLogsEncryptor.decryptLogs(any(LogBatch.class))).thenReturn(decryptedBytes);

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final Intent[] nextActivityIntent = new Intent[1];

    // Act
    scenario.onActivity(
        activity -> {
          activity.onActivityResult(FILE_PICKER_REQUEST_CODE, Activity.RESULT_OK, resultDataIntent);
          shadowOf(activity.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    // Assert
    assertThat(nextActivityIntent[0]).isNotNull();
    assertThat(nextActivityIntent[0].getComponent().getClassName())
        .isEqualTo(CrumblesDecryptedLogsActivity.class.getName());

    ArrayList<CrumblesDecryptedLogEntry> logs =
        IntentCompat.getParcelableArrayListExtra(
            nextActivityIntent[0],
            CrumblesConstants.EXTRA_DECRYPTED_LOGS,
            CrumblesDecryptedLogEntry.class);

    assertThat(logs).isNotNull();
    assertThat(logs).hasSize(1);
    assertThat(logs.get(0).getFileName()).isEqualTo("good_log.bin");
    assertThat(logs.get(0).getContent()).isEqualTo("decrypted_content");
    assertThat(ShadowToast.getTextOfLatestToast()).contains("All selected logs decrypted");
  }

  @Test
  public void onActivityResult_whenAuthFails_showsToastAndDoesNotContinue() throws Exception {
    // Arrange: Simulate the user failing/cancelling the system's authentication prompt
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptLogs(any(LogBatch.class)))
        .thenThrow(new UserNotAuthenticatedException("User cancelled prompt"));

    File testFile = new File(mockAdHocDir, "auth_fail_test.bin");
    testFile.createNewFile();
    Intent resultDataIntent = new Intent().setData(Uri.fromFile(testFile));

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    // Act
    scenario.onActivity(
        activity -> {
          activity.onActivityResult(FILE_PICKER_REQUEST_CODE, Activity.RESULT_OK, resultDataIntent);
          shadowOf(Looper.getMainLooper()).idle();
        });

    // Assert
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Please set up a screen lock in your device settings.");
    scenario.onActivity(
        activity -> {
          Intent nextStartedActivity = shadowOf(activity).getNextStartedActivity();
          assertThat(nextStartedActivity).isNull();
        });
  }

  @Test
  public void getFileNameFromUri_forFileScheme_returnsCorrectName() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Uri fileUri = Uri.parse("file:///storage/emulated/0/MyDocs/report.pdf");
    final String[] fileName = new String[1];
    scenario.onActivity(activity -> fileName[0] = activity.getFileNameFromUri(fileUri));
    assertThat(fileName[0]).isEqualTo("report.pdf");
  }

  @Test
  public void getFileNameFromUri_forContentSchemeWithDisplayName_returnsCorrectName() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Uri contentUri = Uri.parse("content://com.some.provider/docs/42");
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"document_from_provider.txt"});
    final String[] fileName = new String[1];
    scenario.onActivity(
        activity -> {
          Robolectric.buildContentProvider(FakeContentProvider.class)
              .create(contentUri.getAuthority())
              .get();
          FakeContentProvider.setNextCursor(cursor);
          fileName[0] = activity.getFileNameFromUri(contentUri);
        });
    assertThat(fileName[0]).isEqualTo("document_from_provider.txt");
  }

  @Test
  public void readBytesFromUri_forFileNotInAllowedAdHocFolder_throwsSecurityException()
      throws IOException {
    // Given: A file path that will be outside the redirected (internal) ad-hoc folder.
    File appFilesDir = context.getFilesDir();
    File otherInternalDir = new File(appFilesDir, "unrestricted_internal_zone");
    assertWithMessage("Failed to create otherInternalDir for test.")
        .that(otherInternalDir.mkdirs() || otherInternalDir.exists())
        .isTrue();
    File testFile = new File(otherInternalDir, "external_ish_file.dat");
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write("some data".getBytes(UTF_8));
    }
    Uri externalFileUri = Uri.fromFile(testFile);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final SecurityException[] caughtException = new SecurityException[1];

    // When: readBytesFromUri is called.
    scenario.onActivity(
        activity -> {
          try {
            byte[] unused = activity.readBytesFromUri(externalFileUri);
          } catch (SecurityException se) {
            caughtException[0] = se;
          } catch (IOException e) {
            // Do nothing.
          }
        });

    // Then: A SecurityException should be thrown.
    assertThat(caughtException[0]).isNotNull();
    assertThat(caughtException[0])
        .hasMessageThat()
        .contains("Access Denied: File is not within the designated secure folder");

    // Cleanup.
    assertThat(testFile.delete()).isTrue();
    assertThat(otherInternalDir.delete()).isTrue();
  }

  @Test
  public void readBytesFromUri_forFileInAllowedAdHocFolder_readsBytes() throws IOException {
    // Given: A file inside the (now internal, redirected) mockAdHocDir.
    File testFile = new File(mockAdHocDir, "internal_file.dat");
    byte[] expectedBytes = "secure data from adhoc".getBytes(UTF_8);
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write(expectedBytes);
    }
    Uri internalFileUri = Uri.fromFile(testFile);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final byte[][] readBytes = new byte[1][];
    final Exception[] caughtException = new Exception[1];

    // When: readBytesFromUri is called.
    scenario.onActivity(
        activity -> {
          try {
            readBytes[0] = activity.readBytesFromUri(internalFileUri);
          } catch (IOException e) {
            caughtException[0] = e;
          }
        });

    // Then: No exception should be thrown, and bytes should match.
    assertWithMessage("IOException should not be thrown for allowed redirected internal path.")
        .that(caughtException[0])
        .isNull();
    assertWithMessage("Read bytes should match expected bytes from internal ad-hoc folder.")
        .that(readBytes[0])
        .isEqualTo(expectedBytes);
  }

  @Test
  public void processSelectedFilesForDecryption_whenPrivateKeyIsNull_showsToastAndAborts() {
    // Given: No private key.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    List<Uri> urisToProcess = Collections.singletonList(Uri.parse("file:///dummy.enc"));

    // When: Processing is attempted.
    scenario.onActivity(
        activity -> {
          try {
            shadowOf(activity).clearNextStartedActivities();
            activity.processSelectedFilesForDecryption(urisToProcess);
            shadowOf(Looper.getMainLooper()).idle();
          } catch (UserNotAuthenticatedException e) {
            throw new AssertionError(
                "Test setup failed, UserNotAuthenticatedException thrown unexpectedly.", e);
          }
        });

    // Then: Toast shows decryption aborted.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Decryption aborted: Private key is not available.");
    // And: No new activity started.
    scenario.onActivity(
        activity -> assertThat(shadowOf(activity).getNextStartedActivity()).isNull());
  }

  @Test
  public void processSelectedFilesForDecryption_whenLogBatchParsingFails_showsToastAndContinues()
      throws Exception {
    // Given: Private key available.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File invalidFile = new File(mockAdHocDir, "invalid_batch.bin");
    try (FileOutputStream fos = new FileOutputStream(invalidFile)) {
      fos.write("not a protobuf".getBytes(UTF_8));
    }
    Uri invalidFileUri = Uri.fromFile(invalidFile);
    List<Uri> urisToProcess = Collections.singletonList(invalidFileUri);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    // When: Processing is attempted.
    scenario.onActivity(
        activity -> {
          try {
            shadowOf(activity).clearNextStartedActivities();
            activity.processSelectedFilesForDecryption(urisToProcess);
            shadowOf(Looper.getMainLooper()).idle();
          } catch (UserNotAuthenticatedException e) {
            throw new AssertionError(
                "Test setup failed, UserNotAuthenticatedException thrown unexpectedly.", e);
          }
        });

    // Then: Toast shows parsing error.
    String latestToast = ShadowToast.getTextOfLatestToast();
    assertThat(latestToast).isNotNull();
    assertThat(latestToast).contains("invalid_batch.bin");
    assertThat(latestToast).contains("not a valid LogBatch format");
    // And: No new activity started.
    scenario.onActivity(
        activity -> assertThat(shadowOf(activity).getNextStartedActivity()).isNull());
  }

  @Test
  public void processSelectedFilesForDecryption_whenDecryptionFails_showsToastAndContinues()
      throws Exception {
    // Given: Private key available.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File undecryptableFile = new File(mockAdHocDir, "undecryptable.bin");
    byte[] validLogBatchBytes =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("encrypted_data")))
            .build()
            .toByteArray();
    try (FileOutputStream fos = new FileOutputStream(undecryptableFile)) {
      fos.write(validLogBatchBytes);
    }
    Uri undecryptableFileUri = Uri.fromFile(undecryptableFile);
    List<Uri> urisToProcess = Collections.singletonList(undecryptableFileUri);
    String decryptionErrorMessage = "Simulated decryption failure.";
    when(mockLogsEncryptor.decryptLogs(any(LogBatch.class)))
        .thenThrow(new CrumblesKeysException(decryptionErrorMessage, null));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    // When: Processing is attempted.
    scenario.onActivity(
        activity -> {
          try {
            shadowOf(activity).clearNextStartedActivities();
            activity.processSelectedFilesForDecryption(urisToProcess);
            shadowOf(Looper.getMainLooper()).idle();
          } catch (UserNotAuthenticatedException e) {
            throw new AssertionError(
                "Test setup failed, UserNotAuthenticatedException thrown unexpectedly.", e);
          }
        });

    // Then: Toast shows decryption error.
    String latestToast = ShadowToast.getTextOfLatestToast();
    assertThat(latestToast).isNotNull();
    assertThat(latestToast)
        .contains("Unexpected error with undecryptable.bin: " + decryptionErrorMessage);
    // And: No new activity started.
    scenario.onActivity(
        activity -> assertThat(shadowOf(activity).getNextStartedActivity()).isNull());
  }

  @Test
  public void onCreate_initializesUiAndPublicKeyManagerAndKeyStatusTextView() {
    // Given: SharedPreferences are cleared (done in @Before) so no external key is active.
    // And: mockLogsEncryptor will return null for getExternalEncryptionPublicKey.
    when(mockLogsEncryptor.getExternalEncryptionPublicKey()).thenReturn(null);
    // And: mockLogsEncryptor will return null for getPrivateKey (no internal key).
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);

    ShadowLog.clear();

    // When: The activity is driven through its onCreate() method ONLY using ActivityController.
    ActivityController<CrumblesMain> controller = Robolectric.buildActivity(CrumblesMain.class);
    CrumblesMain activity = controller.create().get();
    shadowOf(Looper.getMainLooper()).idle();

    // Then: Verify UI elements initialized by onCreate.
    TextView statusTextView = activity.findViewById(R.id.encryption_key_status_textview);
    assertWithMessage("encryptionKeyStatusTextView should be found and initialized by onCreate.")
        .that(statusTextView)
        .isNotNull();

    ImmutableList<ShadowLog.LogItem> logs = ShadowLog.getLogsForTag("[Crumbles]");
    boolean textViewMissingErrorLogged = false;
    if (logs != null) {
      for (ShadowLog.LogItem logItem : logs) {
        if (logItem.type == Log.ERROR
            && logItem.msg.contains("encryptionKeyStatusTextView is null, cannot update UI.")) {
          textViewMissingErrorLogged = true;
          break;
        }
      }
    }
    assertWithMessage(
            "Error log for missing encryptionKeyStatusTextView should not appear if layout is"
                + " correct.")
        .that(textViewMissingErrorLogged)
        .isFalse();

    verify(mockLogsEncryptor).doesPrivateKeyExist();

    controller.destroy();
  }

  /** Fake implementation of ContentProvider for testing purposes. */
  public static class FakeContentProvider extends ContentProvider {
    @SuppressWarnings("NonFinalStaticField")
    private static Cursor nextCursor;

    public static void setNextCursor(Cursor cursor) {
      nextCursor = cursor;
    }

    @Override
    public boolean onCreate() {
      return true;
    }

    @Override
    public Cursor query(Uri u, String[] p, String s, String[] sa, String so) {
      Cursor t = nextCursor;
      nextCursor = null;
      return t;
    }

    @Override
    public String getType(Uri u) {
      return null;
    }

    @Override
    public Uri insert(Uri u, ContentValues v) {
      return null;
    }

    @Override
    public int delete(Uri u, String s, String[] sa) {
      return 0;
    }

    @Override
    public int update(Uri u, ContentValues v, String s, String[] sa) {
      return 0;
    }
  }
}
