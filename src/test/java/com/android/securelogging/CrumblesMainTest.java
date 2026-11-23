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
import static com.android.securelogging.CrumblesLogsEncryptor.KEY_ALIAS;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.Assert.assertThrows;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.app.Dialog;
import android.app.KeyguardManager;
import android.app.NotificationManager;
import android.app.admin.ConnectEvent;
import android.app.admin.DevicePolicyManager;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.UriPermission;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.hardware.biometrics.BiometricPrompt;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Environment;
import android.os.Looper;
import android.os.UserManager;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.security.keystore.UserNotAuthenticatedException;
import android.text.InputType;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.ExistingWorkPolicy;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.testing.TestListenableWorkerBuilder;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.CrumblesLogsEncryptor.BulkDecryptPartition;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.CrumblesSendAndMarkProcessingWorkerTest.FakeGoogleDriveContentProvider;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.audit.CrumblesAuditLogViewerActivity;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.truth.Expect;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Constructor;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowApplication;
import org.robolectric.shadows.ShadowBiometricPrompt;
import org.robolectric.shadows.ShadowDevicePolicyManager;
import org.robolectric.shadows.ShadowDialog;
import org.robolectric.shadows.ShadowEnvironment;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowNetworkCapabilities;
import org.robolectric.shadows.ShadowPausedLooper;
import org.robolectric.shadows.ShadowResolveInfo;
import org.robolectric.shadows.ShadowToast;
import org.robolectric.util.ReflectionHelpers;

/** Tests the main activity of the Crumbles app. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesMainTest {

  // A loopback server reached over plaintext HTTP has no key to pin, so it is saved unconfirmed.
  private static final String WEBDAV_SERVER_URL = "http://127.0.0.1/remote.php/dav/files/alice/";

  private static final Uri TEAM_LOGS_TREE_URI =
      Uri.parse("content://com.example.storage.documents/tree/team_logs");

  /** The folder that {@link FakeGoogleDriveContentProvider} serves. */
  private static final Uri DRIVE_TREE_URI =
      Uri.parse("content://com.google.android.apps.docs.storage/tree/valid_drive");

  private static final HeldCertificate testRootCertificate =
      new HeldCertificate.Builder().certificateAuthority(/* maxIntermediateCas= */ 0).build();
  private static final HeldCertificate serverCertificate =
      new HeldCertificate.Builder()
          .addSubjectAlternativeName("localhost")
          .signedBy(testRootCertificate)
          .build();
  private static final HeldCertificate rotatedServerCertificate =
      new HeldCertificate.Builder()
          .addSubjectAlternativeName("localhost")
          .signedBy(testRootCertificate)
          .build();

  @Rule public final Expect expect = Expect.create();

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private Context context;
  private File rootOfTestCleanup;
  private File mockAdHocDir;
  private KeyPair testExternalKeyPair;
  private HttpServer webDavServer;

  /** The storage app of {@link #DRIVE_TREE_URI}, once a test sets it up. */
  private FakeGoogleDriveContentProvider driveProvider;

  /** Opens to let the storage app go on after {@link #stallDriveProvider}. */
  private final CountDownLatch driveProviderStall = new CountDownLatch(1);

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
    // Declared in the manifest, so granted at install.
    shadowOf((Application) ApplicationProvider.getApplicationContext())
        .grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);
    // The main screen only opens once the user has acknowledged what Crumbles collects.
    CrumblesSetupActivity.markAcknowledged(context);

    testExternalKeyPair = generateTestRsaKeyPair();
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    // Every selected batch goes to the RSA key, as for batches written without batch-unwrap keys.
    when(mockLogsEncryptor.partitionForBulkDecrypt(any()))
        .thenAnswer(
            invocation ->
                new BulkDecryptPartition(
                    ImmutableList.of(),
                    ImmutableList.copyOf(invocation.<List<LogBatch>>getArgument(0)),
                    ImmutableList.of()));
    CrumblesAppAuditLogger.setInstanceForTest(null);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    // The DataStore is a process-wide singleton, so empty it to isolate the tests.
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(preferences -> UserKeyPreferences.getDefaultInstance())
        .get();

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

  @Test
  public void onCreate_sweepsStaleReEncryptedCacheDirectory() throws Exception {
    File staleFile = new File(CrumblesReEncryptedCache.getDirectory(context), "leftover.bin");
    assertThat(staleFile.getParentFile().mkdirs()).isTrue();
    assertThat(staleFile.createNewFile()).isTrue();
    try (ActivityScenario<CrumblesMain> unused = ActivityScenario.launch(CrumblesMain.class)) {
      assertThat(staleFile.exists()).isFalse();
    }
  }

  @After
  public void tearDown() {
    // A test that failed while the storage app held a document lets it go on.
    driveProviderStall.countDown();
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesDecryptedLogsSession.destroyActiveSession();
    Security.removeProvider(TestRootTrustProvider.NAME);
    if (rootOfTestCleanup != null) {
      deleteRecursive(rootOfTestCleanup);
    }
    if (webDavServer != null) {
      webDavServer.stop(/* delay= */ 0);
    }
    // Drops any key manager made with the real encryptor for the other tests.
    ReflectionHelpers.setStaticField(CrumblesExternalPublicKeyManager.class, "instance", null);
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
      // Then: Verify essential UI elements are present, indicating successful initialization.
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

  @Test
  public void onCreate_hidesOverlayWindows() {
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(activity -> assertThat(hidesOverlayWindows(activity)).isTrue());
    }
  }

  @Test
  public void onCreate_setsFlagSecure() {
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity ->
              assertThat(
                      activity.getWindow().getAttributes().flags
                          & WindowManager.LayoutParams.FLAG_SECURE)
                  .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE));
    }
  }

  @Test
  public void onCreate_cachesApplicationContextForLogsEncryptor() throws Exception {
    CrumblesLogsEncryptor.setApplicationContext(null);
    shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesAppAuditLogger mockAuditLogger = mock(CrumblesAppAuditLogger.class);
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.isSecretKeyImportRefused = true;
    try (ActivityScenario<CrumblesMain> unused = ActivityScenario.launch(CrumblesMain.class)) {
      KeyPair unusedKeyPair = new CrumblesLogsEncryptor().generateKeyPair();

      verify(mockAuditLogger).logEvent(eq("BATCH_WRAP_FAILED"), anyString());
    } finally {
      CrumblesLogsEncryptor.setApplicationContext(null);
      FakeAndroidKeyStoreSpi.isSecretKeyImportRefused = false;
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
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
            activity.onResume();
            Button manageKeyButton = activity.findViewById(R.id.btn_manage_encryption_key);
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            assertThat(manageKeyButton.getText().toString())
                .isEqualTo(activity.getString(R.string.change_encryption_key_button));
            assertThat(decryptButton.isEnabled()).isFalse();
            assertThat(decryptButton.getAlpha()).isEqualTo(0.5f); // Verify disabled alpha
          });
    }
  }

  @Test
  public void uiState_whenSelectedExternalKeyIsUnreadable_showsUnreadableStatusNotKeystore() {
    // Given: An external key is selected, but it could not be read, so the encryptor has none.
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    when(mockLogsEncryptor.getExternalEncryptionPublicKey()).thenReturn(null);
    // And: An internal Keystore key exists.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ActivityController<CrumblesMain> controller = Robolectric.buildActivity(CrumblesMain.class);
    // Inject the mock manager before onResume first reads the key state.
    controller.get().setPublicKeyManagerForTest(mockPublicKeyManager);

    // When: Activity is launched.
    CrumblesMain activity = controller.setup().get();

    // Then: The status reports the unreadable external key, not the Keystore key.
    TextView statusTextView = activity.findViewById(R.id.encryption_key_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo(activity.getString(R.string.status_external_key_unreadable));
  }

  @Test
  public void uiState_whenExternalKeySelectedButUnreadable_showsUnreadableAndDisablesDecrypt() {
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            activity.onResume();
            Button manageKeyButton = activity.findViewById(R.id.btn_manage_encryption_key);
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            TextView statusTextView = activity.findViewById(R.id.encryption_key_status_textview);

            expect
                .that(manageKeyButton.getText().toString())
                .isEqualTo(activity.getString(R.string.change_encryption_key_button));
            expect.that(decryptButton.isEnabled()).isFalse();
            expect.that(decryptButton.getAlpha()).isEqualTo(0.5f);
            expect
                .that(statusTextView.getText().toString())
                .isEqualTo(activity.getString(R.string.status_external_key_unreadable));

            when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
            activity.onResume();
            expect
                .that(manageKeyButton.getText().toString())
                .isEqualTo(activity.getString(R.string.change_encryption_key_button));
            expect
                .that(statusTextView.getText().toString())
                .isEqualTo(activity.getString(R.string.status_external_key_unreadable));
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
  public void setLoggingToggle_asDeviceOwner_enablesLogging() {
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
          UserManager um = application.getSystemService(UserManager.class);
          assertThat(um.hasUserRestriction(UserManager.DISALLOW_ADD_USER)).isTrue();
          assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging enabled");
        });
  }

  @Test
  public void networkCollectionToggle_byDefault_isCheckedAndEnablesNetworkLogging() {
    setUpDeviceOwner();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);
          SwitchMaterial loggingToggle = activity.findViewById(R.id.material_switch);

          loggingToggle.performClick();
          shadowOf(activity.getMainLooper()).idle();

          assertThat(networkToggle.isChecked()).isTrue();
          assertThat(CrumblesCollectionScope.isNetworkCollectionEnabled(activity)).isTrue();
          assertThat(loggingToggle.isChecked()).isTrue();
          assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging enabled");
        });
  }

  @Test
  public void networkCollectionToggle_whenTurnedOffWithScreenLock_asksForCredential() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    shadowOf((KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(true);
    SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);

    networkToggle.performClick();

    expect.that(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
    expect.that(networkToggle.isChecked()).isTrue();
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    expect.that(hasAuditEvent("NETWORK_COLLECTION_DISABLE_REQUESTED")).isTrue();
    verify(activity.mockDpm, never())
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
  }

  @Test
  public void networkCollectionToggle_whenTurnedOffWithoutScreenLock_refusesAndKeepsItOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);

    networkToggle.performClick();

    expect.that(shadowOf(activity).getNextStartedActivityForResult()).isNull();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            activity.getString(R.string.toast_disable_network_collection_requires_screen_lock));
    expect.that(networkToggle.isChecked()).isTrue();
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    expect.that(hasAuditEvent("NETWORK_COLLECTION_DISABLE_REFUSED")).isTrue();
    verify(activity.mockDpm, never())
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
  }

  @Test
  public void networkCollectionToggle_whenKeyguardServiceUnavailable_refusesAndKeepsItOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    activity.keyguardUnavailable = true;
    SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);

    networkToggle.performClick();

    expect.that(networkToggle.isChecked()).isTrue();
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    expect.that(hasAuditEvent("NETWORK_COLLECTION_DISABLE_REFUSED")).isTrue();
  }

  @Test
  public void onActivityResult_disableNetworkCollectionConfirmed_stopsNetworkLoggingOnly() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();

    clickAndConfirmPrompt(activity, R.id.network_collection_switch);

    SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);
    expect.that(networkToggle.isChecked()).isFalse();
    expect
        .that(networkToggle.getText().toString())
        .isEqualTo(activity.getString(R.string.network_collection_switch_off_msg));
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isFalse();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_network_collection_disabled));
    expect.that(hasAuditEvent("NETWORK_COLLECTION_SCOPE_CHANGED")).isTrue();
    verify(activity.mockDpm)
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    verify(activity.mockDpm, never())
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
  }

  @Test
  public void onActivityResult_disableNetworkCollectionCancelled_keepsItOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();

    clickAndCancelPrompt(activity, R.id.network_collection_switch);

    SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);
    expect.that(networkToggle.isChecked()).isTrue();
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_disable_network_collection_auth_cancelled));
    expect.that(hasAuditEvent("NETWORK_COLLECTION_DISABLE_AUTH_FAILED")).isTrue();
    verify(activity.mockDpm, never())
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
  }

  @Test
  public void networkCollectionToggle_whenTurnedOn_appliesWithoutCredential() {
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);

    networkToggle.performClick();

    expect.that(shadowOf(activity).getNextStartedActivityForResult()).isNull();
    expect.that(networkToggle.isChecked()).isTrue();
    expect
        .that(networkToggle.getText().toString())
        .isEqualTo(activity.getString(R.string.network_collection_switch_on_msg));
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_network_collection_enabled));
    expect.that(hasAuditEvent("NETWORK_COLLECTION_SCOPE_CHANGED")).isTrue();
    verify(activity.mockDpm).setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ true);
  }

  @Test
  public void networkCollectionToggle_whenTurnedOnWhileSecurityLoggingOff_waitsForLogging() {
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    when(activity.mockDpm.isSecurityLoggingEnabled(getAdminComponentName())).thenReturn(false);

    activity.findViewById(R.id.network_collection_switch).performClick();

    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    verify(activity.mockDpm, never())
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ true);
  }

  @Test
  public void
      onActivityResult_disableNetworkCollectionConfirmedWhileSecurityLoggingOff_stopsNetworkLogging() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    when(activity.mockDpm.isSecurityLoggingEnabled(getAdminComponentName())).thenReturn(false);

    clickAndConfirmPrompt(activity, R.id.network_collection_switch);

    verify(activity.mockDpm)
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
  }

  @Test
  public void setLoggingToggle_whenNetworkCollectionOff_enablesSecurityLoggingOnly() {
    setUpDeviceOwner();
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          SwitchMaterial networkToggle = activity.findViewById(R.id.network_collection_switch);
          SwitchMaterial loggingToggle = activity.findViewById(R.id.material_switch);

          loggingToggle.performClick();
          shadowOf(activity.getMainLooper()).idle();

          assertThat(networkToggle.isChecked()).isFalse();
          assertThat(loggingToggle.isChecked()).isTrue();
          assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging enabled");
          assertThat(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isFalse();
        });
  }

  @Test
  public void neutralLauncherSwitch_whenTurnedOn_showsTheNeutralLauncherEntry() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    String[] switchText = new String[1];

    scenario.onActivity(
        activity -> {
          SwitchMaterial neutralLauncherSwitch =
              activity.findViewById(R.id.neutral_launcher_switch);
          switchText[0] = neutralLauncherSwitch.getText().toString();
          neutralLauncherSwitch.performClick();
        });

    expect.that(switchText[0]).isEqualTo("Show in the app list as \"Device sync\"");
    expect.that(CrumblesLauncherEntry.isNeutral(context)).isTrue();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            "The app list now shows Crumbles as \"Device sync\". Crumbles may close while the"
                + " launcher updates.");

    scenario.moveToState(Lifecycle.State.STARTED);
    CrumblesLauncherEntry.showDefault(context);
    ShadowToast.reset();
    scenario.moveToState(Lifecycle.State.RESUMED);

    expect.that(ShadowToast.getTextOfLatestToast()).isNull();
  }

  @Test
  public void neutralLauncherSwitch_whenTurnedOff_restoresTheCrumblesLauncherEntry() {
    CrumblesLauncherEntry.showNeutral(context);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> activity.findViewById(R.id.neutral_launcher_switch).performClick());

    expect.that(CrumblesLauncherEntry.isNeutral(context)).isFalse();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            "The app list now shows Crumbles under its own name. Crumbles may close while the"
                + " launcher updates.");
  }

  @Test
  public void onCreate_whenNeutralEntryIsEnabled_namesTheTaskDeviceSync() {
    CrumblesLauncherEntry.showNeutral(context);

    // An alert opens CrumblesMain itself, so the neutral entry does not name the task it starts.
    for (Class<? extends Activity> screen :
        ImmutableList.of(
            CrumblesMain.class,
            CrumblesDecryptedLogsActivity.class,
            CrumblesManageExternalKeysActivity.class,
            CrumblesQrScannerActivity.class,
            CrumblesReEncryptKeysActivity.class,
            CrumblesSetupActivity.class,
            CrumblesAuditLogViewerActivity.class)) {
      Activity activity = Robolectric.buildActivity(screen).create().get();
      expect
          .withMessage(screen.getSimpleName())
          .that(taskDescriptionOf(activity).getLabel())
          .isEqualTo("Device sync");
    }
  }

  @Test
  public void onCreate_whenDefaultEntryIsEnabled_leavesTheTaskUnnamed() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    assertThat(taskDescriptionOf(activity).getLabel()).isNull();
  }

  @Test
  public void neutralLauncherSwitch_whenTurnedOn_namesTheTaskDeviceSync() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    activity.findViewById(R.id.neutral_launcher_switch).performClick();

    assertThat(taskDescriptionOf(activity).getLabel()).isEqualTo("Device sync");
  }

  @Test
  public void neutralLauncherSwitch_whenTurnedOff_leavesTheTaskUnnamed() {
    CrumblesLauncherEntry.showNeutral(context);
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    activity.findViewById(R.id.neutral_launcher_switch).performClick();

    assertThat(taskDescriptionOf(activity).getLabel()).isNull();
  }

  /** Returns the description that {@code activity} gave its task, which Recents shows. */
  private static ActivityManager.TaskDescription taskDescriptionOf(Activity activity) {
    return ReflectionHelpers.getField(activity, "mTaskDescription");
  }

  @Test
  public void setLoggingToggle_asLoggingDelegate_enablesLogging() {
    setUpLoggingDelegate();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          SwitchMaterial loggingToggle = activity.findViewById(R.id.material_switch);

          loggingToggle.performClick();
          shadowOf(activity.getMainLooper()).idle();

          assertThat(loggingToggle.isChecked()).isTrue();
          assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging enabled");
        });
  }

  @Test
  public void setLoggingToggle_whenNeitherDeviceOwnerNorDelegate_staysOff() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          SwitchMaterial loggingToggle = activity.findViewById(R.id.material_switch);

          loggingToggle.performClick();
          shadowOf(activity.getMainLooper()).idle();

          assertThat(loggingToggle.isChecked()).isFalse();
          assertThat(ShadowToast.getTextOfLatestToast())
              .isEqualTo("Not device owner, cannot enable logging.");
        });
  }

  private static ComponentName getAdminComponentName() {
    return new ComponentName(
        ApplicationProvider.getApplicationContext(), CrumblesDeviceAdminReceiver.class);
  }

  private static void setUpDeviceOwner() {
    Application application = ApplicationProvider.getApplicationContext();
    DevicePolicyManager dpm =
        (DevicePolicyManager) application.getSystemService(Context.DEVICE_POLICY_SERVICE);
    ShadowDevicePolicyManager shadowDpm = shadowOf(dpm);
    shadowDpm.setDeviceOwner(getAdminComponentName());
    shadowDpm.setActiveAdmin(getAdminComponentName());
  }

  /** Makes another app the device owner, which delegates both logging scopes to Crumbles. */
  private static void setUpLoggingDelegate() {
    setUpDelegate(
        DevicePolicyManager.DELEGATION_SECURITY_LOGGING,
        DevicePolicyManager.DELEGATION_NETWORK_LOGGING);
  }

  /** Makes another app the device owner, which delegates {@code scopes} to Crumbles. */
  private static void setUpDelegate(String... scopes) {
    Application application = ApplicationProvider.getApplicationContext();
    DevicePolicyManager dpm =
        (DevicePolicyManager) application.getSystemService(Context.DEVICE_POLICY_SERVICE);
    ComponentName otherDeviceOwner = new ComponentName("org.example.dpc", "org.example.dpc.Admin");
    shadowOf(dpm).setDeviceOwner(otherDeviceOwner);
    dpm.setDelegatedScopes(
        otherDeviceOwner, application.getPackageName(), ImmutableList.copyOf(scopes));
  }

  /** Uses a mock device policy manager, since the Robolectric shadow does not track logging. */
  private static class CrumblesMainWithMockDpm extends CrumblesMain {
    private final DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    private boolean keyguardUnavailable;

    @Override
    public Object getSystemService(String name) {
      if (keyguardUnavailable && name.equals(Context.KEYGUARD_SERVICE)) {
        return null;
      }
      return name.equals(Context.DEVICE_POLICY_SERVICE) ? mockDpm : super.getSystemService(name);
    }
  }

  private CrumblesMainWithMockDpm launchAsDeviceOwnerWithLoggingOn() {
    ActivityController<CrumblesMainWithMockDpm> controller =
        Robolectric.buildActivity(CrumblesMainWithMockDpm.class);
    DevicePolicyManager mockDpm = controller.get().mockDpm;
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(getAdminComponentName())).thenReturn(true);
    doAnswer(
            invocation -> {
              when(mockDpm.isSecurityLoggingEnabled(getAdminComponentName())).thenReturn(false);
              return null;
            })
        .when(mockDpm)
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    CrumblesMainWithMockDpm activity = controller.setup().get();
    shadowOf(activity).clearNextStartedActivities();
    return activity;
  }

  private CrumblesMainWithMockDpm launchAsLoggingDelegateWithLoggingOn() {
    ActivityController<CrumblesMainWithMockDpm> controller =
        Robolectric.buildActivity(CrumblesMainWithMockDpm.class);
    DevicePolicyManager mockDpm = controller.get().mockDpm;
    when(mockDpm.getDelegatedScopes(/* admin= */ null, context.getPackageName()))
        .thenReturn(
            ImmutableList.of(
                DevicePolicyManager.DELEGATION_SECURITY_LOGGING,
                DevicePolicyManager.DELEGATION_NETWORK_LOGGING));
    when(mockDpm.isSecurityLoggingEnabled(/* admin= */ null)).thenReturn(true);
    CrumblesMainWithMockDpm activity = controller.setup().get();
    shadowOf(activity).clearNextStartedActivities();
    return activity;
  }

  /**
   * Launches Crumbles as an app that the device owner delegated only network logging to. As on a
   * device, its device policy manager then refuses every security logging call.
   */
  private CrumblesMainWithMockDpm launchAsNetworkLoggingDelegate(boolean isNetworkLoggingEnabled) {
    ActivityController<CrumblesMainWithMockDpm> controller =
        Robolectric.buildActivity(CrumblesMainWithMockDpm.class);
    DevicePolicyManager mockDpm = controller.get().mockDpm;
    when(mockDpm.getDelegatedScopes(/* admin= */ null, context.getPackageName()))
        .thenReturn(ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING));
    when(mockDpm.isNetworkLoggingEnabled(/* admin= */ null)).thenReturn(isNetworkLoggingEnabled);
    doAnswer(
            invocation -> {
              boolean enabled = invocation.getArgument(1);
              when(mockDpm.isNetworkLoggingEnabled(/* admin= */ null)).thenReturn(enabled);
              return null;
            })
        .when(mockDpm)
        .setNetworkLoggingEnabled(/* admin= */ eq(null), anyBoolean());
    when(mockDpm.isSecurityLoggingEnabled(any())).thenThrow(SecurityException.class);
    doThrow(SecurityException.class).when(mockDpm).setSecurityLoggingEnabled(any(), anyBoolean());
    CrumblesMainWithMockDpm activity = controller.setup().get();
    shadowOf(activity).clearNextStartedActivities();
    return activity;
  }

  private boolean hasAuditEvent(String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .anyMatch(event -> event.getEventType().equals(eventType));
  }

  @Test
  public void loggingToggle_whenTurnedOffWithScreenLock_asksForCredentialAndKeepsLoggingOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    shadowOf((KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(true);
    SwitchMaterial toggle = activity.findViewById(R.id.material_switch);

    toggle.performClick();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
    assertThat(toggle.isChecked()).isTrue();
    verify(activity.mockDpm, never())
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    assertThat(hasAuditEvent("LOGGING_DISABLE_REQUESTED")).isTrue();
  }

  @Test
  public void loggingToggle_whenTurnedOffWithoutScreenLock_refusesAndKeepsLoggingOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    SwitchMaterial toggle = activity.findViewById(R.id.material_switch);

    toggle.performClick();

    assertThat(shadowOf(activity).getNextStartedActivityForResult()).isNull();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_disable_logging_requires_screen_lock));
    assertThat(toggle.isChecked()).isTrue();
    verify(activity.mockDpm, never())
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    assertThat(hasAuditEvent("LOGGING_DISABLE_REFUSED")).isTrue();
  }

  @Test
  public void loggingToggle_whenKeyguardServiceUnavailable_refusesAndKeepsLoggingOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    activity.keyguardUnavailable = true;
    SwitchMaterial toggle = activity.findViewById(R.id.material_switch);

    toggle.performClick();

    assertThat(toggle.isChecked()).isTrue();
    assertThat(hasAuditEvent("LOGGING_DISABLE_REFUSED")).isTrue();
  }

  @Test
  public void onActivityResult_disableLoggingConfirmed_turnsSecurityAndNetworkLoggingOff() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();

    clickAndConfirmPrompt(activity, R.id.material_switch);

    verify(activity.mockDpm)
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    verify(activity.mockDpm)
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    SharedPreferences prefs =
        activity.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    assertThat(prefs.getBoolean(CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED, true))
        .isFalse();
    assertThat(prefs.getBoolean(CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED, true))
        .isFalse();
    SwitchMaterial toggle = activity.findViewById(R.id.material_switch);
    assertThat(toggle.isChecked()).isFalse();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.dpm_logging_disabled_toast_msg));
    assertThat(hasAuditEvent("LOGGING_DISABLED")).isTrue();
  }

  @Test
  public void onActivityResult_disableLoggingConfirmed_sealsFinalBatch() {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.getPublicKey()).thenReturn(testExternalKeyPair.getPublic());
    when(mockLogsEncryptor.encryptLogs(
            any(Context.class), any(byte[].class), any(PublicKey.class), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
    when(mockLogsEncryptor.serializeBytes(any(LogBatch.class), any(File.class), anyString()))
        .thenCallRealMethod();
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();

    clickAndConfirmPrompt(activity, R.id.material_switch);

    File logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsDirectory.list()).hasLength(1);
  }

  @Test
  public void onActivityResult_disableLoggingConfirmedButNoLongerDeviceOwner_recordsFailure() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    clickToOpenPrompt(activity, R.id.material_switch);
    when(activity.mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);

    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();

    verify(activity.mockDpm, never())
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.dpm_not_device_owner_disable_log_failed_toast_msg));
    assertThat(hasAuditEvent("LOGGING_DISABLE_FAILED")).isTrue();
  }

  @Test
  public void onActivityResult_disableLoggingCancelled_keepsLoggingOn() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();

    clickAndCancelPrompt(activity, R.id.material_switch);

    verify(activity.mockDpm, never())
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    verify(activity.mockDpm, never())
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ false);
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_disable_logging_auth_cancelled));
    assertThat(hasAuditEvent("LOGGING_DISABLE_AUTH_FAILED")).isTrue();
  }

  @Test
  public void loggingToggle_whenTurnedOffAsDelegate_asksForCredentialAndKeepsLoggingOn() {
    CrumblesMainWithMockDpm activity = launchAsLoggingDelegateWithLoggingOn();
    shadowOf((KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(true);
    SwitchMaterial toggle = activity.findViewById(R.id.material_switch);

    toggle.performClick();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
    assertThat(toggle.isChecked()).isTrue();
    verify(activity.mockDpm, never())
        .setSecurityLoggingEnabled(/* admin= */ null, /* enabled= */ false);
  }

  @Test
  public void onActivityResult_disableLoggingConfirmedAsDelegate_turnsLoggingOff() {
    CrumblesMainWithMockDpm activity = launchAsLoggingDelegateWithLoggingOn();

    clickAndConfirmPrompt(activity, R.id.material_switch);

    verify(activity.mockDpm).setSecurityLoggingEnabled(/* admin= */ null, /* enabled= */ false);
    verify(activity.mockDpm).setNetworkLoggingEnabled(/* admin= */ null, /* enabled= */ false);
    assertThat(hasAuditEvent("LOGGING_DISABLED")).isTrue();
  }

  @Test
  public void disableLogging_clearsManagedRestrictionAndPauseAlert() {
    CrumblesMainWithMockDpm activity = launchAsDeviceOwnerWithLoggingOn();
    CrumblesDeviceAdminReceiver.prefs(context)
        .edit()
        .putBoolean(CrumblesDeviceAdminReceiver.PREF_MANAGED_DISALLOW_ADD_USER, true)
        .putBoolean(CrumblesDeviceAdminReceiver.PREF_PAUSED_BY_SECONDARY_USER, true)
        .commit();
    CrumblesDeviceAdminReceiver.notifyCollectionPaused(context);

    clickAndConfirmPrompt(activity, R.id.material_switch);

    verify(activity.mockDpm)
        .clearUserRestriction(getAdminComponentName(), UserManager.DISALLOW_ADD_USER);
    expect
        .that(context.getSystemService(NotificationManager.class).getActiveNotifications())
        .isEmpty();
    expect
        .that(hasAuditEvent(CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_RESUMED))
        .isFalse();
  }

  @Test
  public void loggingToggle_whenTurnedOnAsNetworkLoggingDelegate_startsNetworkLogging() {
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    CrumblesMainWithMockDpm activity =
        launchAsNetworkLoggingDelegate(/* isNetworkLoggingEnabled= */ false);

    activity.findViewById(R.id.material_switch).performClick();

    verify(activity.mockDpm).setNetworkLoggingEnabled(/* admin= */ null, /* enabled= */ true);
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
    SwitchMaterial networkSwitch = activity.findViewById(R.id.network_collection_switch);
    expect.that(networkSwitch.isChecked()).isTrue();
    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Logging enabled");
    // Only network logging was turned on, so the logging watchdog must not see security logging as
    // on, which would make it report losing access to security logging.
    SharedPreferences prefs =
        activity.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    expect
        .that(prefs.getBoolean(CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED, false))
        .isFalse();
    expect
        .that(prefs.getBoolean(CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED, false))
        .isTrue();
  }

  @Test
  public void loggingToggle_whenTurnedOnAsDeviceOwner_recordsEachTypeOfLoggingTurnedOnOnce() {
    ActivityController<CrumblesMainWithMockDpm> controller =
        Robolectric.buildActivity(CrumblesMainWithMockDpm.class);
    DevicePolicyManager mockDpm = controller.get().mockDpm;
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    doAnswer(
            invocation -> {
              when(mockDpm.isSecurityLoggingEnabled(getAdminComponentName())).thenReturn(true);
              return null;
            })
        .when(mockDpm)
        .setSecurityLoggingEnabled(getAdminComponentName(), /* enabled= */ true);
    doAnswer(
            invocation -> {
              when(mockDpm.isNetworkLoggingEnabled(getAdminComponentName())).thenReturn(true);
              return null;
            })
        .when(mockDpm)
        .setNetworkLoggingEnabled(getAdminComponentName(), /* enabled= */ true);
    CrumblesMainWithMockDpm activity = controller.setup().get();

    activity.findViewById(R.id.material_switch).performClick();

    ImmutableList<String> eventTypes = auditEventTypes();
    expect
        .that(
            Collections.frequency(
                eventTypes, CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_ENABLED))
        .isEqualTo(1);
    expect
        .that(
            Collections.frequency(
                eventTypes, CrumblesLoggingWatchdogWorker.AUDIT_EVENT_NETWORK_LOGGING_ENABLED))
        .isEqualTo(1);
  }

  @Test
  public void loggingToggle_whenTurnedOffAsNetworkLoggingDelegate_asksForCredential() {
    CrumblesMainWithMockDpm activity =
        launchAsNetworkLoggingDelegate(/* isNetworkLoggingEnabled= */ true);
    shadowOf((KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(true);
    SwitchMaterial toggle = activity.findViewById(R.id.material_switch);

    toggle.performClick();

    expect.that(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
    expect.that(toggle.isChecked()).isTrue();
    expect
        .that(toggle.getText().toString())
        .isEqualTo(activity.getString(R.string.enable_logging_switch_msg));
  }

  @Test
  public void
      onActivityResult_disableLoggingConfirmedAsNetworkLoggingDelegate_turnsNetworkLoggingOff() {
    CrumblesMainWithMockDpm activity =
        launchAsNetworkLoggingDelegate(/* isNetworkLoggingEnabled= */ true);

    clickAndConfirmPrompt(activity, R.id.material_switch);

    verify(activity.mockDpm).setNetworkLoggingEnabled(/* admin= */ null, /* enabled= */ false);
    expect.that(hasAuditEvent("LOGGING_DISABLED")).isTrue();
  }

  @Test
  public void
      onActivityResult_disableNetworkCollectionConfirmedAsNetworkLoggingDelegate_stopsNetworkLogging() {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.getPublicKey()).thenReturn(testExternalKeyPair.getPublic());
    when(mockLogsEncryptor.encryptLogs(
            any(Context.class), any(byte[].class), any(PublicKey.class), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
    when(mockLogsEncryptor.serializeBytes(any(LogBatch.class), any(File.class), anyString()))
        .thenCallRealMethod();
    CrumblesMainWithMockDpm activity =
        launchAsNetworkLoggingDelegate(/* isNetworkLoggingEnabled= */ true);

    clickAndConfirmPrompt(activity, R.id.network_collection_switch);

    verify(activity.mockDpm).setNetworkLoggingEnabled(/* admin= */ null, /* enabled= */ false);
    expect.that(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isFalse();
    File logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    expect.that(logsDirectory.list()).hasLength(1);
    SwitchMaterial loggingToggle = activity.findViewById(R.id.material_switch);
    expect.that(loggingToggle.isChecked()).isFalse();
  }

  @Test
  public void networkCollectionToggle_whenTurnedOnAsNetworkLoggingDelegate_startsNetworkLogging() {
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    CrumblesMainWithMockDpm activity =
        launchAsNetworkLoggingDelegate(/* isNetworkLoggingEnabled= */ false);

    activity.findViewById(R.id.network_collection_switch).performClick();

    verify(activity.mockDpm).setNetworkLoggingEnabled(/* admin= */ null, /* enabled= */ true);
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

    LogBatch originalBatch =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("encrypted")))
            .setMetadata(
                LogMetadata.newBuilder()
                    .setEncryptionType(
                        LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA))
            .build();
    byte[] fakeEncryptedBytes = originalBatch.toByteArray();
    File testFile = new File(mockAdHocDir, "good_log.bin");
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write(fakeEncryptedBytes);
    }
    Intent resultDataIntent = new Intent().setData(Uri.fromFile(testFile));

    LogMetadata sealedMetadata =
        LogMetadata.newBuilder()
            .setDevice(DeviceId.newBuilder().setDeviceId("original-device"))
            .build();
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(
            new DecryptedLogBatch(sealedMetadata, "decrypted_content".getBytes(UTF_8)));

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final Intent[] nextActivityIntent = new Intent[1];

    // Act
    scenario.onActivity(
        activity -> {
          activity.onActivityResult(FILE_PICKER_REQUEST_CODE, Activity.RESULT_OK, resultDataIntent);
          awaitSelectionRead(activity);
          shadowOf(activity.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(activity.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    // Assert
    assertThat(nextActivityIntent[0]).isNotNull();
    assertThat(nextActivityIntent[0].getComponent().getClassName())
        .isEqualTo(CrumblesDecryptedLogsActivity.class.getName());

    long sessionId =
        nextActivityIntent[0].getLongExtra(
            CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, /* defaultValue= */ -1);
    List<CrumblesDecryptedLogEntry> logs =
        CrumblesDecryptedLogsSession.getSession(sessionId).orElseThrow().getEntries();
    assertThat(logs).isNotNull();
    assertThat(logs).hasSize(1);
    assertThat(logs.get(0).getFileName()).isEqualTo("good_log.bin");
    assertThat(logs.get(0).getContent()).isEqualTo("decrypted_content");
    assertThat(logs.get(0).getDeviceId()).isEqualTo("original-device");
    assertThat(logs.get(0).getOriginalBatch()).isEqualTo(originalBatch);
    assertThat(ShadowToast.getTextOfLatestToast()).contains("All selected logs decrypted");
  }

  @Test
  public void onActivityResult_whenTheDecryptionPromptIsCancelled_showsToastAndDoesNotContinue()
      throws Exception {
    // Arrange: The time window of the key is closed, so decryption needs a prompt.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenThrow(new UserNotAuthenticatedException("Key window closed"));

    File testFile = new File(mockAdHocDir, "auth_fail_test.bin");
    testFile.createNewFile();
    Intent resultDataIntent = new Intent().setData(Uri.fromFile(testFile));

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    // Act
    scenario.onActivity(
        activity -> {
          activity.onActivityResult(FILE_PICKER_REQUEST_CODE, Activity.RESULT_OK, resultDataIntent);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionWithError(
              BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Authentication canceled");
          shadowOf(Looper.getMainLooper()).idle();
        });

    // Assert
    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Authentication canceled");
    scenario.onActivity(
        activity -> {
          Intent nextStartedActivity = shadowOf(activity).getNextStartedActivity();
          assertThat(nextStartedActivity).isNull();
        });
  }

  @Test
  public void processSelectedFilesForDecryption_showsDecryptedLogsInTheOrderOfTheSelection()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ImmutableList<Uri> selection = writeLogFiles("first", "second");
    // The batch-unwrap key covers the second batch only, so it is decrypted before the first.
    doAnswer(
            invocation -> {
              List<LogBatch> logBatches = invocation.getArgument(0);
              return new BulkDecryptPartition(
                  ImmutableList.of(logBatches.get(1)),
                  ImmutableList.of(logBatches.get(0)),
                  ImmutableList.of());
            })
        .when(mockLogsEncryptor)
        .partitionForBulkDecrypt(any());
    Cipher unwrapCipher = Cipher.getInstance("AES/CBC/NoPadding");
    SecretKey secondKey = new SecretKeySpec(new byte[] {2}, "AES");
    when(mockLogsEncryptor.createBatchUnwrapCipher()).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.unwrapBatchKeys(same(unwrapCipher), any()))
        .thenReturn(ImmutableList.of(secondKey));
    byte[] firstLogs = "first logs".getBytes(UTF_8);
    when(mockLogsEncryptor.decryptLogsWithSymmetricKey(any(), same(secondKey)))
        .thenReturn(decrypted("second logs".getBytes(UTF_8)));
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class))).thenReturn(decrypted(firstLogs));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] nextActivityIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });
    scenario.moveToState(Lifecycle.State.CREATED);

    assertThat(decryptedFileNames(nextActivityIntent[0]))
        .containsExactly("first.bin", "second.bin")
        .inOrder();
    assertThat(firstLogs).isEqualTo("first logs".getBytes(UTF_8));
  }

  @Test
  public void processSelectedFilesForDecryption_whenAPromptIsCancelled_wipesTheLogsDecryptedSoFar()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ImmutableList<Uri> selection = writeLogFiles("first", "second");
    byte[] firstLogs = "first logs".getBytes(UTF_8);
    // The time window of the key closes after the first batch, so the second needs a prompt.
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(decrypted(firstLogs))
        .thenThrow(new UserNotAuthenticatedException("Key window closed"));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] nextActivityIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionWithError(
              BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Authentication canceled");
          shadowOf(Looper.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    assertThat(nextActivityIntent[0]).isNull();
    assertThat(firstLogs).isEqualTo(new byte[firstLogs.length]);
  }

  @Test
  public void
      processSelectedFilesForDecryption_whenActivityStopsDuringPrompt_wipesTheLogsDecryptedSoFar()
          throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ImmutableList<Uri> selection = writeLogFiles("first", "second");
    byte[] firstLogs = "first logs".getBytes(UTF_8);
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(decrypted(firstLogs))
        .thenThrow(new UserNotAuthenticatedException("Key window closed"))
        .thenThrow(new CrumblesKeysException("No key"));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] nextActivityIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
        });
    scenario.moveToState(Lifecycle.State.CREATED);

    assertThat(firstLogs).isEqualTo(new byte[firstLogs.length]);

    scenario.moveToState(Lifecycle.State.RESUMED);
    scenario.onActivity(
        activity -> {
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });
    assertThat(nextActivityIntent[0]).isNull();
  }

  @Test
  public void processSelectedFilesForDecryption_whenActivityStopsDuringPrompt_decryptsNothingMore()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ImmutableList<Uri> selection = writeLogFiles("first", "second");
    // The second batch waits for a prompt, after which it would decrypt.
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(decrypted("first logs".getBytes(UTF_8)))
        .thenThrow(new UserNotAuthenticatedException("Key window closed"))
        .thenReturn(decrypted("second logs".getBytes(UTF_8)));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] nextActivityIntent = new Intent[1];
    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
        });
    scenario.moveToState(Lifecycle.State.CREATED);
    scenario.moveToState(Lifecycle.State.RESUMED);

    scenario.onActivity(
        activity -> {
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    assertThat(nextActivityIntent[0]).isNull();
    verify(mockLogsEncryptor, times(2)).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void
      processSelectedFilesForDecryption_whenActivityStopsDuringPrompt_releasesTheSelection()
          throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ImmutableList<Uri> selection = writeLogFiles("first");
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenThrow(new UserNotAuthenticatedException("Key window closed"));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          assertThat((Object) ReflectionHelpers.getField(activity, "selectedLogsCallback"))
              .isNotNull();
        });

    scenario.moveToState(Lifecycle.State.CREATED);

    scenario.onActivity(
        activity ->
            assertThat((Object) ReflectionHelpers.getField(activity, "selectedLogsCallback"))
                .isNull());
  }

  @Test
  public void processSelectedFilesForDecryption_whenMoreFilesThanTheLimit_readsNone()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    List<Uri> selection =
        Collections.nCopies(
            CrumblesConstants.MAX_DECRYPTION_FILES_PER_SESSION + 1, writeLogFiles("first").get(0));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
        });

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_decryption_too_many_files));
    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void processSelectedFilesForDecryption_withAsManyFilesAsTheLimit_decryptsThemAll()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(decrypted("logs".getBytes(UTF_8)));
    List<Uri> selection =
        Collections.nCopies(
            CrumblesConstants.MAX_DECRYPTION_FILES_PER_SESSION, writeLogFiles("first").get(0));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
        });

    verify(mockLogsEncryptor, times(CrumblesConstants.MAX_DECRYPTION_FILES_PER_SESSION))
        .decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void processSelectedFilesForDecryption_whenTheFilesExceedTheTotalLimit_skipsTheRest()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    // The first two files reach the limit exactly, and the third exceeds it.
    ImmutableList.Builder<Uri> selection = ImmutableList.builder();
    for (String name : ImmutableList.of("a", "b", "c")) {
      File largeFile = new File(mockAdHocDir, name + ".bin");
      try (RandomAccessFile sparseFile = new RandomAccessFile(largeFile, "rw")) {
        sparseFile.setLength(CrumblesConstants.MAX_DECRYPTION_SESSION_BYTES / 2);
      }
      selection.add(Uri.fromFile(largeFile));
    }
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(selection.build());
          awaitSelectionRead(activity);
        });

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_decryption_selection_too_large, "c.bin"));
  }

  @Test
  public void
      processSelectedFilesForDecryption_whenANewerSelectionIsMadeWhileReading_dropsTheOlder()
          throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(decrypted("logs".getBytes(UTF_8)));
    ImmutableList<Uri> olderSelection = writeLogFiles("older");
    ImmutableList<Uri> newerSelection = writeLogFiles("newer");
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] nextActivityIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.processSelectedFilesForDecryption(olderSelection);
          activity.processSelectedFilesForDecryption(newerSelection);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    assertThat(decryptedFileNames(nextActivityIntent[0])).containsExactly("newer.bin");
  }

  @Test
  public void processSelectedFilesForDecryption_whenTheActivityStopsWhileReading_decryptsNothing()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ImmutableList<Uri> selection = writeLogFiles("first");
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    ExecutorService executor =
        ReflectionHelpers.getField(controller.get(), "decryptionInputExecutor");
    controller.get().processSelectedFilesForDecryption(selection);
    Futures.getUnchecked(executor.submit(() -> {}));

    controller.pause().stop();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void
      processSelectedFilesForDecryption_whenTheActivityStopsWhileReadingUndecryptableBatch_reportsNothing()
          throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    doAnswer(
            invocation ->
                new BulkDecryptPartition(
                    ImmutableList.of(),
                    ImmutableList.of(),
                    ImmutableList.copyOf(invocation.<List<LogBatch>>getArgument(0))))
        .when(mockLogsEncryptor)
        .partitionForBulkDecrypt(any());
    ImmutableList<Uri> selection = writeLogFiles("first");
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    ExecutorService executor =
        ReflectionHelpers.getField(controller.get(), "decryptionInputExecutor");
    controller.get().processSelectedFilesForDecryption(selection);
    Futures.getUnchecked(executor.submit(() -> {}));

    controller.pause().stop();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(hasAuditEvent("DECRYPTION_FAILURE")).isFalse();
    expect.that(ShadowToast.getTextOfLatestToast()).isNotEqualTo("Failed to decrypt first.bin.");
  }

  /** Writes a log file per name into the ad hoc folder, and returns their URIs in that order. */
  private ImmutableList<Uri> writeLogFiles(String... names) throws IOException {
    ImmutableList.Builder<Uri> uris = ImmutableList.builder();
    for (String name : names) {
      File logFile = new File(mockAdHocDir, name + ".bin");
      Files.write(
          logFile.toPath(),
          LogBatch.newBuilder()
              .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8(name)))
              .build()
              .toByteArray());
      uris.add(Uri.fromFile(logFile));
    }
    return uris.build();
  }

  /** Waits for {@code activity} to read the selected log files and start decrypting them. */
  private static void awaitSelectionRead(CrumblesMain activity) {
    ExecutorService executor = ReflectionHelpers.getField(activity, "decryptionInputExecutor");
    Futures.getUnchecked(executor.submit(() -> {}));
    shadowOf(Looper.getMainLooper()).idle();
  }

  /** Returns the names of the files whose logs {@code decryptedLogsIntent} shows, in order. */
  private static ImmutableList<String> decryptedFileNames(Intent decryptedLogsIntent) {
    long sessionId =
        decryptedLogsIntent.getLongExtra(
            CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, /* defaultValue= */ -1);
    return CrumblesDecryptedLogsSession.getSession(sessionId).orElseThrow().getEntries().stream()
        .map(CrumblesDecryptedLogEntry::getFileName)
        .collect(toImmutableList());
  }

  /** Returns {@code logs} as decrypted from a batch without metadata. */
  private static DecryptedLogBatch decrypted(byte[] logs) {
    return new DecryptedLogBatch(LogMetadata.getDefaultInstance(), logs);
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
  public void getFileNameFromUri_whenDisplayNameHasLineBreakOrBidiControl_escapesThem() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Uri contentUri = Uri.parse("content://com.some.provider/docs/43");
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"a.bin ---\n--- Log: forged.bin\u202e"});
    final String[] fileName = new String[1];
    scenario.onActivity(
        activity -> {
          Robolectric.buildContentProvider(FakeContentProvider.class)
              .create(contentUri.getAuthority())
              .get();
          FakeContentProvider.setNextCursor(cursor);
          fileName[0] = activity.getFileNameFromUri(contentUri);
        });
    assertThat(fileName[0]).isEqualTo("a.bin ---\\u000a--- Log: forged.bin\\u202e");
  }

  @Test
  public void getFileNameFromUri_whenDisplayNameIsLong_capsLength() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Uri contentUri = Uri.parse("content://com.some.provider/docs/44");
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"a".repeat(300) + ".bin"});
    final String[] fileName = new String[1];
    scenario.onActivity(
        activity -> {
          Robolectric.buildContentProvider(FakeContentProvider.class)
              .create(contentUri.getAuthority())
              .get();
          FakeContentProvider.setNextCursor(cursor);
          fileName[0] = activity.getFileNameFromUri(contentUri);
        });
    assertThat(fileName[0]).isEqualTo("a".repeat(255) + "…");
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
            @SuppressWarnings("unused")
            var unusedBytes = activity.readBytesFromUri(externalFileUri);
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
  public void readBytesFromUri_withDotDotEscapingAdHocFolder_throwsSecurityException()
      throws IOException {
    Files.write(new File(rootOfTestCleanup, "outside.dat").toPath(), "secret".getBytes(UTF_8));
    Uri traversalUri = Uri.fromFile(new File(mockAdHocDir, "../../outside.dat"));

    SecurityException thrown = readBytesFromUriExpectingSecurityException(traversalUri);

    assertThat(thrown)
        .hasMessageThat()
        .contains("Access Denied: File is not within the designated secure folder");
  }

  @Test
  public void readBytesFromUri_forSymlinkToOutsideFile_throwsSecurityException()
      throws IOException {
    File outsideFile = new File(rootOfTestCleanup, "outside.dat");
    Files.write(outsideFile.toPath(), "secret".getBytes(UTF_8));
    File symlink = new File(mockAdHocDir, "link.dat");
    Files.createSymbolicLink(symlink.toPath(), outsideFile.toPath());

    SecurityException thrown = readBytesFromUriExpectingSecurityException(Uri.fromFile(symlink));

    assertThat(thrown)
        .hasMessageThat()
        .contains("Access Denied: File is not within the designated secure folder");
  }

  @Test
  public void readBytesFromUri_forSiblingFolderSharingNamePrefix_throwsSecurityException()
      throws IOException {
    File siblingDir =
        new File(mockAdHocDir.getParentFile(), CrumblesConstants.TEMP_RE_ENCRYPTED_DIR + "_evil");
    assertThat(siblingDir.mkdirs()).isTrue();
    File siblingFile = new File(siblingDir, "sibling.dat");
    Files.write(siblingFile.toPath(), "secret".getBytes(UTF_8));

    SecurityException thrown =
        readBytesFromUriExpectingSecurityException(Uri.fromFile(siblingFile));

    assertThat(thrown)
        .hasMessageThat()
        .contains("Access Denied: File is not within the designated secure folder");
  }

  private SecurityException readBytesFromUriExpectingSecurityException(Uri uri) {
    SecurityException[] thrown = new SecurityException[1];
    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity ->
              thrown[0] =
                  assertThrows(SecurityException.class, () -> activity.readBytesFromUri(uri)));
    }
    return thrown[0];
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
          shadowOf(activity).clearNextStartedActivities();
          activity.processSelectedFilesForDecryption(urisToProcess);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
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
          shadowOf(activity).clearNextStartedActivities();
          activity.processSelectedFilesForDecryption(urisToProcess);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
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
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenThrow(new CrumblesKeysException(decryptionErrorMessage, null));
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    // When: Processing is attempted.
    scenario.onActivity(
        activity -> {
          shadowOf(activity).clearNextStartedActivities();
          activity.processSelectedFilesForDecryption(urisToProcess);
          awaitSelectionRead(activity);
          shadowOf(Looper.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(Looper.getMainLooper()).idle();
        });

    // Then: Toast shows decryption error.
    String latestToast = ShadowToast.getTextOfLatestToast();
    assertThat(latestToast).isNotNull();
    assertThat(latestToast).isEqualTo("Failed to decrypt undecryptable.bin.");
    // And: The failure is audited.
    assertThat(hasAuditEvent("DECRYPTION_FAILURE")).isTrue();
    // And: No new activity started.
    scenario.onActivity(
        activity -> assertThat(shadowOf(activity).getNextStartedActivity()).isNull());
  }

  @Test
  public void processSelectedFilesForDecryption_whenFileExceedsMaxSize_showsToastAndSkips()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File oversizeFile = new File(mockAdHocDir, "oversize.bin");
    try (RandomAccessFile sparseFile = new RandomAccessFile(oversizeFile, "rw")) {
      sparseFile.setLength(CrumblesConstants.MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES + 1);
    }
    List<Uri> urisToProcess = Collections.singletonList(Uri.fromFile(oversizeFile));

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            activity.processSelectedFilesForDecryption(urisToProcess);
            awaitSelectionRead(activity);
          });
      shadowOf(Looper.getMainLooper()).idle();
    }

    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Could not read oversize.bin.");
    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void readBytesFromUri_whenProviderDeclaresOversizeFile_throwsIoException() {
    Uri contentUri = Uri.parse("content://com.some.provider/docs/oversize");
    MatrixCursor cursor = new MatrixCursor(new String[] {OpenableColumns.SIZE});
    cursor.addRow(new Object[] {CrumblesConstants.MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES + 1});
    IOException[] thrown = new IOException[1];

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            Robolectric.buildContentProvider(FakeContentProvider.class)
                .create(contentUri.getAuthority())
                .get();
            FakeContentProvider.setNextCursor(cursor);
            thrown[0] =
                assertThrows(IOException.class, () -> activity.readBytesFromUri(contentUri));
          });
    }

    assertThat(thrown[0]).hasMessageThat().contains("File exceeds the maximum size");
  }

  @Test
  public void readBytesFromUri_whenProviderDeclaresSizeWithinLimit_readsBytes() {
    Uri contentUri = Uri.parse("content://com.some.provider/docs/sized");
    byte[] expectedBytes = "bytes from provider".getBytes(UTF_8);
    MatrixCursor cursor = new MatrixCursor(new String[] {OpenableColumns.SIZE});
    cursor.addRow(new Object[] {expectedBytes.length});
    shadowOf(context.getContentResolver())
        .registerInputStream(contentUri, new ByteArrayInputStream(expectedBytes));
    byte[][] readBytes = new byte[1][];

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            Robolectric.buildContentProvider(FakeContentProvider.class)
                .create(contentUri.getAuthority())
                .get();
            FakeContentProvider.setNextCursor(cursor);
            try {
              readBytes[0] = activity.readBytesFromUri(contentUri);
            } catch (IOException e) {
              throw new AssertionError("IOException thrown unexpectedly.", e);
            }
          });
    }

    assertThat(readBytes[0]).isEqualTo(expectedBytes);
  }

  @Test
  public void readBytesFromUri_whenProviderReturnsNoCursor_readsBytes() {
    Uri contentUri = Uri.parse("content://com.some.provider/docs/unsized");
    byte[] expectedBytes = "bytes from provider".getBytes(UTF_8);
    shadowOf(context.getContentResolver())
        .registerInputStream(contentUri, new ByteArrayInputStream(expectedBytes));
    byte[][] readBytes = new byte[1][];

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            Robolectric.buildContentProvider(FakeContentProvider.class)
                .create(contentUri.getAuthority())
                .get();
            FakeContentProvider.setNextCursor(null);
            try {
              readBytes[0] = activity.readBytesFromUri(contentUri);
            } catch (IOException e) {
              throw new AssertionError("IOException thrown unexpectedly.", e);
            }
          });
    }

    assertThat(readBytes[0]).isEqualTo(expectedBytes);
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
  }

  @Test
  public void testSelectUploadDestination_whenDeviceSecure_launchesKeyguardIntent() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    shadowOf((KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(true);

    Button selectDestButton = activity.findViewById(R.id.btn_select_upload_dest);
    assertThat(selectDestButton).isNotNull();
    assertThat(selectDestButton.isEnabled()).isTrue();
    assertThat(selectDestButton.hasOnClickListeners()).isTrue();

    shadowOf(activity).clearNextStartedActivities();
    selectDestButton.performClick();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
  }

  private static AlertDialog getLatestAppCompatAlertDialog() {
    Dialog lastDialog = ShadowDialog.getLatestDialog();
    if (lastDialog instanceof AlertDialog alertDialog) {
      return alertDialog;
    }
    return null;
  }

  @Test
  public void testUploadDestination_authSucceeded_launchesDocumentTreePicker() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    clickAndConfirmPrompt(activity, R.id.btn_select_upload_dest);

    AlertDialog dialog = getLatestAppCompatAlertDialog();
    assertThat(dialog).isNotNull();
    dialog.getListView().performItemClick(null, 0, 0);
    shadowOf(Looper.getMainLooper()).idle();

    Intent nextIntent = shadowOf(activity).getNextStartedActivity();
    assertThat(nextIntent).isNotNull();
    assertThat(nextIntent.getAction()).isEqualTo(Intent.ACTION_OPEN_DOCUMENT_TREE);
  }

  @Test
  public void testUploadDestination_authCancelled_showsToastAndLogs() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    clickAndCancelPrompt(activity, R.id.btn_select_upload_dest);

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Authentication cancelled. Destination unchanged.");
  }

  @Test
  public void testUploadDestination_fileTreeCancelled_showsToast() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    activity.onActivityResult(
        CrumblesConstants.FILE_TREE_REQUEST_CODE, Activity.RESULT_CANCELED, null);

    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Destination selection cancelled.");
  }

  @Test
  public void testUploadDestination_invalidNonContentUri_showsToast() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    Intent data = new Intent();
    data.setData(Uri.parse("file:///sdcard/Download"));

    activity.onActivityResult(CrumblesConstants.FILE_TREE_REQUEST_CODE, Activity.RESULT_OK, data);

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Invalid destination: write permission could not be verified.");
  }

  @Test
  public void testUpdateUploadDestinationStatusUi_whenValidGrant_showsConfigured() {
    Uri treeUri = Uri.parse("content://com.android.externalstorage.documents/tree/my_drive");
    ApplicationProvider.getApplicationContext()
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, treeUri.toString())
        .commit();

    ApplicationProvider.getApplicationContext()
        .getContentResolver()
        .takePersistableUriPermission(
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView).isNotNull();
    assertThat(statusTextView.getText().toString())
        .isEqualTo(activity.getString(R.string.upload_dest_status_configured_unnamed));
  }

  @Test
  public void testUpdateUploadDestinationStatusUi_whenProviderReportsFolderName_showsFolderName() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    Robolectric.setupContentProvider(FakeContentProvider.class, treeUri.getAuthority());
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"Team Logs"});
    FakeContentProvider.setNextCursor(cursor);
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, treeUri.toString())
        .commit();
    context
        .getContentResolver()
        .takePersistableUriPermission(
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    awaitUploadFolderName(activity);

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString()).isEqualTo("Upload Destination: Team Logs");
  }

  @Test
  public void updateUploadDestinationStatusUi_whenStorageAppIsInstalled_namesFolderAndApp() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    installStorageApp(treeUri.getAuthority());
    Robolectric.setupContentProvider(FakeContentProvider.class, treeUri.getAuthority());
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"Team Logs"});
    FakeContentProvider.setNextCursor(cursor);
    saveUploadDestinationWithGrant(treeUri);

    SpyPackageManagerActivity activity =
        Robolectric.buildActivity(SpyPackageManagerActivity.class).setup().get();
    awaitUploadFolderName(activity);

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo(
            "Upload Destination: Example Storage (com.example.storage), folder \"Team Logs\"");
    verify(activity.getPackageManager(), atLeastOnce())
        .resolveContentProvider(treeUri.getAuthority(), /* flags= */ 0);
  }

  @Test
  public void updateUploadDestinationStatusUi_whenNamesImitateAnotherApp_showsRealAppFirst() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    installStorageApp(treeUri.getAuthority(), "Drive\n\u202e");
    Robolectric.setupContentProvider(FakeContentProvider.class, treeUri.getAuthority());
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"Logs\", in Drive (com.google.android.apps.docs)"});
    FakeContentProvider.setNextCursor(cursor);
    saveUploadDestinationWithGrant(treeUri);

    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    awaitUploadFolderName(activity);

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo(
            "Upload Destination: Drive\\u000a\\u202e (com.example.storage), folder"
                + " \"Logs\\\", in Drive (com.google.android.app…\"");
  }

  @Test
  public void escapeFileName_capsPostEscapeLengthWithoutSplittingEscapeTokens() {
    assertThat(CrumblesDeviceAdminReceiver.escapeFileName("\u200b".repeat(255)))
        .isEqualTo("\\u200b".repeat(42) + "…");
    assertThat(CrumblesDeviceAdminReceiver.escapeFileName("a".repeat(253) + "\""))
        .isEqualTo("a".repeat(253) + "\\\"");
    assertThat(CrumblesDeviceAdminReceiver.escapeFileName("a".repeat(254) + "\""))
        .isEqualTo("a".repeat(254) + "…");
  }

  @Test
  public void updateUploadDestinationStatusUi_whenLabelIsPadded_capsLabelBeforePackageName() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    installStorageApp(
        treeUri.getAuthority(), "Drive (com.google.android.apps.docs)" + "\u2800".repeat(300));
    Robolectric.setupContentProvider(FakeContentProvider.class, treeUri.getAuthority());
    MatrixCursor cursor =
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
    cursor.addRow(new Object[] {"Team Logs"});
    FakeContentProvider.setNextCursor(cursor);
    saveUploadDestinationWithGrant(treeUri);

    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    awaitUploadFolderName(activity);

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo(
            "Upload Destination: Drive (com.google.android.apps.docs)"
                + "\u2800".repeat(4)
                + "… (com.example.storage), folder \"Team Logs\"");
  }

  @Test
  public void updateUploadDestinationStatusUi_whenFolderNameIsUnreadable_stillNamesStorageApp() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    installStorageApp(treeUri.getAuthority());
    Robolectric.setupContentProvider(FakeContentProvider.class, treeUri.getAuthority());
    FakeContentProvider.setNextCursor(
        new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME}));
    saveUploadDestinationWithGrant(treeUri);

    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    awaitUploadFolderName(activity);

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo("Upload Destination: Configured, in Example Storage (com.example.storage)");
  }

  @Test
  public void onResume_whenStorageProviderDoesNotAnswer_showsTheDestinationWithoutWaiting() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    installStorageApp(treeUri.getAuthority());
    StalledFolderProvider provider =
        Robolectric.setupContentProvider(StalledFolderProvider.class, treeUri.getAuthority());
    saveUploadDestinationWithGrant(treeUri);

    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo("Upload Destination: Configured, in Example Storage (com.example.storage)");
    // A second refresh while the first read is still waiting does not start a second read.
    activity.updateUploadDestinationStatusUi();
    // Lets the read that still waits for the provider end within this test.
    provider.answer.countDown();
    awaitUploadFolderName(activity);
    expect.that(provider.queries.get()).isEqualTo(1);
    // Once that read ends, clearing the cached name lets the next refresh read it again.
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .remove(CrumblesConstants.PREF_UPLOAD_FOLDER_NAME)
        .commit();
    activity.updateUploadDestinationStatusUi();
    awaitUploadFolderName(activity);
    expect.that(provider.queries.get()).isEqualTo(2);
  }

  @Test
  public void onDestroy_shutsDownFolderNameExecutor() {
    ActivityController<CrumblesMain> controller = Robolectric.buildActivity(CrumblesMain.class);
    CrumblesMain activity = controller.setup().get();
    ExecutorService executor = ReflectionHelpers.getField(activity, "folderNameExecutor");

    controller.destroy();

    assertThat(executor.isShutdown()).isTrue();
  }

  /** Waits until {@code activity} has read the name of its upload folder, and shows it. */
  private static void awaitUploadFolderName(CrumblesMain activity) {
    ExecutorService executor = ReflectionHelpers.getField(activity, "folderNameExecutor");
    Futures.getUnchecked(executor.submit(() -> {}));
    shadowOf(Looper.getMainLooper()).idle();
  }

  /** Installs a storage app labelled "Example Storage" whose provider serves {@code authority}. */
  private void installStorageApp(String authority) {
    installStorageApp(authority, "Example Storage");
  }

  /** Installs a storage app labelled {@code label} whose provider serves {@code authority}. */
  private void installStorageApp(String authority, String label) {
    ApplicationInfo storageApp = new ApplicationInfo();
    storageApp.packageName = "com.example.storage";
    storageApp.nonLocalizedLabel = label;
    ProviderInfo provider = new ProviderInfo();
    provider.packageName = storageApp.packageName;
    provider.name = "com.example.storage.FolderProvider";
    provider.authority = authority;
    // A provider label of its own must not replace the label of the app that holds the folder.
    provider.nonLocalizedLabel = "Folders";
    provider.applicationInfo = storageApp;
    shadowOf(context.getPackageManager()).addOrUpdateProvider(provider);
  }

  /** Saves {@code treeUri} as the upload destination and grants persistable write access to it. */
  private void saveUploadDestinationWithGrant(Uri treeUri) {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, treeUri.toString())
        .commit();
    context
        .getContentResolver()
        .takePersistableUriPermission(
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
  }

  @Test
  public void testUpdateUploadDestinationStatusUi_whenUriIsNotTreeUri_showsConfigured() {
    Uri documentUri =
        Uri.parse("content://com.android.externalstorage.documents/document/primary%3ALogs");
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, documentUri.toString())
        .commit();
    context
        .getContentResolver()
        .takePersistableUriPermission(
            documentUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo(activity.getString(R.string.upload_dest_status_configured_unnamed));
  }

  @Test
  public void onCreate_showsDestinationNeutralUploadFolderButtonAndPickerHint() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    Button selectFolderButton = activity.findViewById(R.id.btn_select_upload_dest);
    TextView hintTextView = activity.findViewById(R.id.upload_destination_hint_textview);
    expect.that(selectFolderButton.getText().toString()).isEqualTo("Select Upload Folder");
    expect
        .that(hintTextView.getText().toString())
        .isEqualTo("You can pick Google Drive or another storage app from the picker menu.");
  }

  @Test
  public void testUpdateUploadDestinationStatusUi_whenNotConfigured_showsNotSet() {
    ApplicationProvider.getApplicationContext()
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .remove(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI)
        .commit();

    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView).isNotNull();
    assertThat(statusTextView.getText().toString())
        .isEqualTo(activity.getString(R.string.upload_dest_status_not_set));
  }

  @Test
  public void testUpdateUploadDestinationStatusUi_whenUriConfiguredButGrantMissing_showsNotSet() {
    Uri treeUri = Uri.parse("content://com.android.externalstorage.documents/tree/revoked_drive");
    ApplicationProvider.getApplicationContext()
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, treeUri.toString())
        .commit();

    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView).isNotNull();
    assertThat(statusTextView.getText().toString())
        .isEqualTo(activity.getString(R.string.upload_dest_status_not_set));
  }

  @Test
  public void changeUploadDestinationButton_withoutScreenLock_refusesWithoutOpeningPicker() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    shadowOf(activity).clearNextStartedActivities();

    activity.findViewById(R.id.btn_select_upload_dest).performClick();

    expect.that(shadowOf(activity).getNextStartedActivityForResult()).isNull();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_upload_dest_requires_screen_lock));
    expect.that(hasAuditEvent("UPLOAD_DESTINATION_REFUSED")).isTrue();
  }

  @Test
  public void testUploadDestination_keyguardSuccess_launchesOpenDocumentTree() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    clickAndConfirmPrompt(activity, R.id.btn_select_upload_dest);

    AlertDialog dialog = getLatestAppCompatAlertDialog();
    assertThat(dialog).isNotNull();
    dialog.getListView().performItemClick(null, 0, 0);
    shadowOf(Looper.getMainLooper()).idle();

    Intent startedIntent = shadowOf(activity).getNextStartedActivityForResult().intent;
    assertThat(startedIntent).isNotNull();
    assertThat(startedIntent.getAction()).isEqualTo(Intent.ACTION_OPEN_DOCUMENT_TREE);
    assertThat(startedIntent.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION).isNotEqualTo(0);
    assertThat(startedIntent.getFlags() & Intent.FLAG_GRANT_WRITE_URI_PERMISSION).isNotEqualTo(0);
    assertThat(startedIntent.getFlags() & Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        .isNotEqualTo(0);
  }

  @Test
  public void testUploadDestination_validTreeUri_persistsPermissionAndUpdatesUi() {
    Uri treeUri = Uri.parse("content://com.android.externalstorage.documents/tree/valid_folder");
    ApplicationProvider.getApplicationContext()
        .getContentResolver()
        .takePersistableUriPermission(
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    CrumblesMain activity = controller.get();

    Intent data = new Intent();
    data.setData(treeUri);
    data.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

    activity.onActivityResult(CrumblesConstants.FILE_TREE_REQUEST_CODE, Activity.RESULT_OK, data);

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_upload_dest_set_success));

    String savedUri =
        ApplicationProvider.getApplicationContext()
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, null);
    assertThat(savedUri).isEqualTo(treeUri.toString());

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    assertThat(statusTextView.getText().toString())
        .isEqualTo(activity.getString(R.string.upload_dest_status_configured_unnamed));
  }

  @Test
  public void onActivityResult_validTreeUri_recordsStorageProviderInActivityLog() {
    Uri treeUri = Uri.parse("content://com.example.storage.documents/tree/team_logs");
    context
        .getContentResolver()
        .takePersistableUriPermission(
            treeUri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    Intent data =
        new Intent()
            .setData(treeUri)
            .addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

    activity.onActivityResult(CrumblesConstants.FILE_TREE_REQUEST_CODE, Activity.RESULT_OK, data);

    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .filter(event -> event.getEventType().equals("UPLOAD_DESTINATION_CONFIGURED"))
                .map(CrumblesAuditEvent::getMessage)
                .toList())
        .containsExactly(
            "Configured upload destination URI with verified persistable write permissions."
                + " Storage provider: com.example.storage.documents.");
  }

  @Test
  public void onActivityResult_folderReplacingWebDav_firstSendsNoticeToWebDav() throws Exception {
    AtomicInteger webDavUploads = new AtomicInteger();

    switchFromWebDavToFolderWithExternalKey(HttpURLConnection.HTTP_CREATED, webDavUploads);

    expect.that(webDavUploads.get()).isEqualTo(1);
    expect.that(auditEventTypes()).contains("DESTINATION_HANDOVER_UPLOADED");
    expect
        .that(readSavedRemoteStorageConfig().getUploadDestinationUri())
        .isEqualTo(TEAM_LOGS_TREE_URI.toString());
  }

  @Test
  public void onActivityResult_folderReplacingWebDav_whenNoticeFails_asksBeforeSwitching()
      throws Exception {
    switchFromWebDavToFolderWithExternalKey(
        HttpURLConnection.HTTP_INTERNAL_ERROR, new AtomicInteger());

    AlertDialog dialog = getLatestAppCompatAlertDialog();
    expect
        .that(messageOf(dialog))
        .isEqualTo(context.getString(R.string.dialog_destination_not_handed_over_message));
    expect.that(dialog.isShowing()).isTrue();
    expect.that(hidesOverlayWindows(dialog.getWindow())).isTrue();
    expect.that(auditEventTypes()).contains("DESTINATION_HANDOVER_UPLOAD_FAILED");
    expect
        .that(readSavedRemoteStorageConfig().getStorageType())
        .isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
  }

  @Test
  public void onActivityResult_folderReplacingWebDav_whenNoticeFailsAndUserCancels_keepsWebDav()
      throws Exception {
    switchFromWebDavToFolderWithExternalKey(
        HttpURLConnection.HTTP_INTERNAL_ERROR, new AtomicInteger());

    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(auditEventTypes()).contains("UPLOAD_DESTINATION_ABANDONED");
    expect
        .that(readSavedRemoteStorageConfig().getStorageType())
        .isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
  }

  @Test
  public void onActivityResult_folderReplacingWebDav_whenNoticeFailsAndUserConfirms_switches()
      throws Exception {
    AtomicInteger webDavUploads = new AtomicInteger();
    ActivityController<CrumblesMain> controller =
        switchFromWebDavToFolderWithExternalKey(
            HttpURLConnection.HTTP_INTERNAL_ERROR, webDavUploads);
    AlertDialog dialog = getLatestAppCompatAlertDialog();

    dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    awaitDestinationHandover(controller.get());

    expect.that(dialog.isShowing()).isFalse();
    expect
        .that(auditEventMessages("DESTINATION_CHANGED_WITHOUT_HANDOVER"))
        .containsExactly(
            "The user chose to change the upload destination although the outgoing destination"
                + " did not confirm the handover notice (UPLOAD_FAILED).");
    expect.that(auditEventTypes()).doesNotContain("UPLOAD_DESTINATION_ABANDONED");
    // A second notice, which carries that record, went to the WebDAV server before the change.
    expect.that(webDavUploads.get()).isEqualTo(2);
    expect
        .that(readSavedRemoteStorageConfig().getUploadDestinationUri())
        .isEqualTo(TEAM_LOGS_TREE_URI.toString());
  }

  @Test
  public void onActivityResult_folderReplacingFolder_whenOffline_asksBeforeSwitching()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();

    chooseTeamLogsFolder(activity);
    awaitDestinationHandover(activity);

    AlertDialog dialog = getLatestAppCompatAlertDialog();
    expect
        .that(messageOf(dialog))
        .isEqualTo(context.getString(R.string.dialog_destination_handover_offline_message));
    expect.that(dialog.isShowing()).isTrue();
    expect.that(auditEventTypes()).contains("DESTINATION_HANDOVER_UPLOADED_OFFLINE");
    expect.that(savedUploadFolderUri()).isEqualTo(DRIVE_TREE_URI.toString());
  }

  @Test
  public void onActivityResult_folderReplacingFolder_whenOfflineAndUserConfirms_switches()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    chooseTeamLogsFolder(activity);
    awaitDestinationHandover(activity);

    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    awaitDestinationHandover(activity);

    expect
        .that(auditEventMessages("DESTINATION_CHANGED_WITHOUT_HANDOVER"))
        .containsExactly(
            "The user chose to change the upload destination although the outgoing destination"
                + " did not confirm the handover notice (UPLOADED_OFFLINE).");
    expect.that(savedUploadFolderUri()).isEqualTo(TEAM_LOGS_TREE_URI.toString());
  }

  @Test
  public void onActivityResult_folderReplacingFolder_whenOnline_stillAsksBeforeSwitching()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    validateActiveNetwork();

    chooseTeamLogsFolder(activity);
    awaitDestinationHandover(activity);

    AlertDialog dialog = getLatestAppCompatAlertDialog();
    expect
        .that(messageOf(dialog))
        .isEqualTo(context.getString(R.string.dialog_destination_handover_unconfirmed_message));
    expect.that(dialog.isShowing()).isTrue();
    expect.that(auditEventTypes()).contains("DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED");
    expect.that(auditEventTypes()).doesNotContain("UPLOAD_DESTINATION_CONFIGURED");
    expect.that(savedUploadFolderUri()).isEqualTo(DRIVE_TREE_URI.toString());
  }

  @Test
  public void onActivityResult_folderReplacingFolder_whenUserConfirms_recordsItInTheOldFolder()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    validateActiveNetwork();
    chooseTeamLogsFolder(activity);
    awaitDestinationHandover(activity);

    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    awaitDestinationHandover(activity);

    expect.that(readNoticesInDriveFolder()).hasSize(2);
    expect
        .that(readNoticeInDriveFolderThatRecords("DESTINATION_CHANGED_WITHOUT_HANDOVER"))
        .startsWith(
            "Crumbles upload destination change\nChange: Changing the upload destination to a"
                + " folder of storage provider com.example.storage.documents anyway, although the"
                + " outgoing destination did not confirm the first notice"
                + " (UPLOADED_UNCONFIRMED)\n");
    expect
        .that(auditEventTypes().reverse())
        .containsAtLeast(
            "DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED",
            "DESTINATION_CHANGED_WITHOUT_HANDOVER",
            "DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED",
            "UPLOAD_DESTINATION_CONFIGURED")
        .inOrder();
    expect.that(savedUploadFolderUri()).isEqualTo(TEAM_LOGS_TREE_URI.toString());
  }

  @Test
  public void onActivityResult_whileTheOldFolderStalls_cancellingTheWaitAsksBeforeSwitching()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    CountDownLatch stalled = stallDriveProvider();
    chooseTeamLogsFolder(activity);
    assertThat(stalled.await(5, TimeUnit.SECONDS)).isTrue();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();

    progressDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();
    AlertDialog dialogDuringStall = getLatestAppCompatAlertDialog();
    // The storage app answers only now, which must not change what the user is asked.
    driveProviderStall.countDown();
    awaitDestinationHandover(activity);

    expect.that(progressDialog.isShowing()).isFalse();
    expect
        .that(messageOf(dialogDuringStall))
        .isEqualTo(context.getString(R.string.dialog_destination_not_handed_over_message));
    expect.that(getLatestAppCompatAlertDialog()).isSameInstanceAs(dialogDuringStall);
    expect.that(dialogDuringStall.isShowing()).isTrue();
    expect.that(auditEventTypes()).contains("DESTINATION_HANDOVER_UPLOADED_OFFLINE");
    expect.that(auditEventTypes()).doesNotContain("UPLOAD_DESTINATION_CONFIGURED");
    expect.that(savedUploadFolderUri()).isEqualTo(DRIVE_TREE_URI.toString());
  }

  @Test
  public void changeAnywayButton_whileTheOldFolderStalls_changeNowSwitches() throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    chooseTeamLogsFolder(activity);
    awaitDestinationHandover(activity);
    CountDownLatch stalled = stallDriveProvider();
    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    assertThat(stalled.await(5, TimeUnit.SECONDS)).isTrue();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();

    progressDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();
    String folderDuringStall = savedUploadFolderUri();
    // The storage app answers only now, which must not change the destination again.
    driveProviderStall.countDown();
    awaitDestinationHandover(activity);

    expect
        .that(progressDialog.getButton(AlertDialog.BUTTON_NEGATIVE).getText().toString())
        .isEqualTo(context.getString(R.string.dialog_destination_change_now));
    expect.that(progressDialog.isShowing()).isFalse();
    expect.that(folderDuringStall).isEqualTo(TEAM_LOGS_TREE_URI.toString());
    expect.that(auditEventTypes()).contains("DESTINATION_CHANGED_WITHOUT_HANDOVER");
    expect
        .that(Collections.frequency(auditEventTypes(), "UPLOAD_DESTINATION_CONFIGURED"))
        .isEqualTo(1);
    expect.that(savedUploadFolderUri()).isEqualTo(TEAM_LOGS_TREE_URI.toString());
  }

  @Test
  public void changeNowButton_whileTheOldFolderStalls_keepsItsGrantUntilTheNoticeEnds()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    chooseTeamLogsFolder(activity);
    awaitDestinationHandover(activity);
    CountDownLatch stalled = stallDriveProvider();
    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    assertThat(stalled.await(5, TimeUnit.SECONDS)).isTrue();

    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();
    ImmutableList<Uri> grantsDuringStall = persistedGrants();
    // The storage app answers only now, and gets the second notice under the old folder's grant.
    driveProviderStall.countDown();
    awaitDestinationHandover(activity);

    expect.that(grantsDuringStall).contains(DRIVE_TREE_URI);
    expect.that(readNoticesInDriveFolder()).hasSize(2);
    expect.that(persistedGrants()).containsExactly(TEAM_LOGS_TREE_URI);
  }

  @Test
  public void changeNowButton_whileTheFirstNoticeIsSealed_sendsNoNoticeToTheNewServer()
      throws Exception {
    CrumblesMain activity = setUpFolderDestinationWithExternalKey().get();
    AtomicInteger newServerRequests = new AtomicInteger();
    String newServerUrl = startWebDavServer(HttpURLConnection.HTTP_CREATED, newServerRequests);
    AlertDialog webDavDialog = openWebDavDialog(activity);
    ImmutableList<Uri> grantsBeforeTheNoticesEnd;

    // Sealing a notice needs this lock, so the first notice is sealed only after the change.
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      saveWebDavSettings(webDavDialog, newServerUrl, "bob", "battery staple");
      clickOnLatestDialog(AlertDialog.BUTTON_NEGATIVE);
      clickOnLatestDialog(AlertDialog.BUTTON_POSITIVE);
      clickOnLatestDialog(AlertDialog.BUTTON_NEGATIVE);
      grantsBeforeTheNoticesEnd = persistedGrants();
    }
    awaitDestinationHandover(activity);

    expect
        .that(readSavedRemoteStorageConfig().getStorageType())
        .isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
    expect.that(newServerRequests.get()).isEqualTo(0);
    expect.that(auditEventTypes()).doesNotContain("DESTINATION_HANDOVER_UPLOADED");
    expect
        .that(Collections.frequency(auditEventTypes(), "DESTINATION_HANDOVER_UPLOAD_FAILED"))
        .isEqualTo(2);
    ImmutableList<String> pendingNotices = readPendingNotices();
    expect.that(pendingNotices).hasSize(2);
    expect
        .that(
            Iterables.filter(
                pendingNotices,
                notice -> notice.contains(recordOf("DESTINATION_CHANGED_WITHOUT_HANDOVER"))))
        .hasSize(1);
    expect.that(readNoticesInDriveFolder()).isEmpty();
    expect.that(grantsBeforeTheNoticesEnd).contains(DRIVE_TREE_URI);
    expect.that(persistedGrants()).doesNotContain(DRIVE_TREE_URI);
  }

  @Test
  public void onStop_whileTheNoticeIsSent_abandonsTheChange() throws Exception {
    ActivityController<CrumblesMain> controller = setUpFolderDestinationWithExternalKey();
    CountDownLatch stalled = stallDriveProvider();
    chooseTeamLogsFolder(controller.get());
    assertThat(stalled.await(5, TimeUnit.SECONDS)).isTrue();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();

    controller.pause().stop();
    boolean progressShownAfterStop = progressDialog.isShowing();
    // The storage app answers only now, which must neither ask about nor make the change.
    driveProviderStall.countDown();
    awaitDestinationHandover(controller.get());

    expect.that(progressShownAfterStop).isFalse();
    expect.that(getLatestAppCompatAlertDialog()).isSameInstanceAs(progressDialog);
    expect
        .that(auditEventMessages("UPLOAD_DESTINATION_ABANDONED"))
        .containsExactly(
            "Upload destination unchanged because the app left the screen while the change was"
                + " handed over.");
    expect.that(auditEventTypes()).doesNotContain("DESTINATION_CHANGED_WITHOUT_HANDOVER");
    expect.that(auditEventTypes()).doesNotContain("UPLOAD_DESTINATION_CONFIGURED");
    expect.that(savedUploadFolderUri()).isEqualTo(DRIVE_TREE_URI.toString());
  }

  @Test
  public void onStop_whileAskingToSwitchWithoutHandover_abandonsTheChange() throws Exception {
    ActivityController<CrumblesMain> controller =
        switchFromWebDavToFolderWithExternalKey(
            HttpURLConnection.HTTP_INTERNAL_ERROR, new AtomicInteger());
    AlertDialog dialog = getLatestAppCompatAlertDialog();

    controller.pause().stop();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(dialog.isShowing()).isFalse();
    expect.that(auditEventTypes()).contains("UPLOAD_DESTINATION_ABANDONED");
  }

  @Test
  public void onActivityResult_folderReplacingWebDav_whenScreenClosesMeanwhile_keepsWebDav()
      throws Exception {
    ActivityController<CrumblesMain> controller =
        setUpWebDavDestinationWithExternalKey(HttpURLConnection.HTTP_CREATED, new AtomicInteger());
    chooseTeamLogsFolder(controller.get());

    controller.get().finish();
    awaitDestinationHandover(controller.get());

    expect.that(auditEventTypes()).contains("UPLOAD_DESTINATION_ABANDONED");
    expect
        .that(readSavedRemoteStorageConfig().getStorageType())
        .isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
  }

  @Test
  public void onDestroy_duringHandover_finishesItButKeepsDestination() throws Exception {
    ActivityController<CrumblesMain> controller =
        setUpWebDavDestinationWithExternalKey(HttpURLConnection.HTTP_CREATED, new AtomicInteger());
    chooseTeamLogsFolder(controller.get());
    ExecutorService handover =
        ReflectionHelpers.getField(controller.get(), "destinationHandoverExecutor");

    controller.pause().stop().destroy();
    boolean handoverFinished = handover.awaitTermination(5, TimeUnit.SECONDS);
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(handoverFinished).isTrue();
    // Leaving the screen abandons the change at once, which the activity log may record before or
    // after the upload of the notice.
    expect
        .that(auditEventTypes())
        .containsAtLeast("DESTINATION_HANDOVER_UPLOADED", "UPLOAD_DESTINATION_ABANDONED");
    expect
        .that(readSavedRemoteStorageConfig().getStorageType())
        .isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
  }

  @Test
  public void webDavDialog_replacingDestination_savesOnceHandedOverBehindProgressDialog()
      throws Exception {
    AtomicInteger webDavUploads = new AtomicInteger();
    ActivityController<CrumblesMain> controller =
        setUpWebDavDestinationWithExternalKey(HttpURLConnection.HTTP_CREATED, webDavUploads);
    String teamServerUrl = "http://localhost:" + webDavServer.getAddress().getPort() + "/dav/team/";

    saveWebDavSettings(openWebDavDialog(controller.get()), teamServerUrl, "bob", "battery staple");
    awaitDestinationHandover(controller.get());

    AlertDialog progressDialog = getLatestAppCompatAlertDialog();
    expect
        .that(messageOf(progressDialog))
        .isEqualTo(context.getString(R.string.dialog_message_handing_over_destination));
    expect
        .that(progressDialog.getButton(AlertDialog.BUTTON_NEGATIVE).getText().toString())
        .isEqualTo(context.getString(android.R.string.cancel));
    expect.that(progressDialog.isShowing()).isFalse();
    expect.that(webDavUploads.get()).isEqualTo(1);
    expect
        .that(auditEventTypes().reverse())
        .containsAtLeast("DESTINATION_HANDOVER_UPLOADED", "UPLOAD_DESTINATION_CONFIGURED")
        .inOrder();
    expect
        .that(
            new String(
                CrumblesMain.getLogsEncryptorInstance()
                    .decryptDataStoreEntry(
                        readSavedRemoteStorageConfig().getWebdavServerUrl(),
                        CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID),
                UTF_8))
        .isEqualTo(teamServerUrl);
  }

  @Test
  public void webDavDialog_afterAHandedOverChange_handsTheNextChangeOverToo() throws Exception {
    AtomicInteger webDavUploads = new AtomicInteger();
    ActivityController<CrumblesMain> controller =
        setUpWebDavDestinationWithExternalKey(HttpURLConnection.HTTP_CREATED, webDavUploads);
    String serverUrl = "http://localhost:" + webDavServer.getAddress().getPort() + "/dav/";
    saveWebDavSettings(openWebDavDialog(controller.get()), serverUrl + "team/", "bob", "pass");
    awaitDestinationHandover(controller.get());

    saveWebDavSettings(openWebDavDialog(controller.get()), serverUrl + "audit/", "eve", "pass");
    awaitDestinationHandover(controller.get());

    expect.that(webDavUploads.get()).isEqualTo(2);
  }

  /** Opens a main screen with an external key and, as destination, a counting WebDAV server. */
  private ActivityController<CrumblesMain> setUpWebDavDestinationWithExternalKey(
      int webDavStatus, AtomicInteger webDavUploads) throws Exception {
    String serverUrl = startWebDavServer(webDavStatus, webDavUploads);
    selectExternalKeyWithRealEncryptor(testExternalKeyPair.getPublic());
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    saveWebDavSettings(openWebDavDialog(controller.get()), serverUrl, "alice", "correct horse");
    return controller;
  }

  /**
   * Starts a WebDAV server that answers every request with {@code status} and counts the requests
   * in {@code requests}, and returns its URL.
   */
  private String startWebDavServer(int status, AtomicInteger requests) throws IOException {
    webDavServer =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    webDavServer.createContext(
        "/dav",
        exchange -> {
          requests.incrementAndGet();
          exchange.sendResponseHeaders(status, /* responseLength= */ -1);
          exchange.close();
        });
    webDavServer.start();
    return "http://localhost:" + webDavServer.getAddress().getPort() + "/dav/";
  }

  /**
   * Opens a main screen with an external key and, as destination, a folder of a storage app. The
   * external key is the device key, so that the tests can read the notices sealed to it.
   */
  private ActivityController<CrumblesMain> setUpFolderDestinationWithExternalKey()
      throws CrumblesKeysException {
    driveProvider =
        Robolectric.setupContentProvider(
            FakeGoogleDriveContentProvider.class, DRIVE_TREE_URI.getAuthority());
    // The storage app's documents count as writable only under a grant of the folder's prefix.
    context.grantUriPermission(
        context.getPackageName(),
        DRIVE_TREE_URI,
        Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
    saveUploadDestinationWithGrant(DRIVE_TREE_URI);
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    selectExternalKeyWithRealEncryptor(
        CrumblesMain.getLogsEncryptorInstance()
            .generateKeyPair(KEY_ALIAS, /* requireUserAuthentication= */ false)
            .getPublic());
    return Robolectric.buildActivity(CrumblesMain.class).setup();
  }

  /**
   * Selects {@code externalKey}. The key manager is a singleton that keeps the encryptor it was
   * made with. It is made again with the real one, which seals the notice, and dropped after the
   * test.
   */
  private void selectExternalKeyWithRealEncryptor(PublicKey externalKey)
      throws CrumblesKeysException {
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    ReflectionHelpers.setStaticField(CrumblesExternalPublicKeyManager.class, "instance", null);
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(externalKey);
  }

  /**
   * Makes the storage app of {@link #DRIVE_TREE_URI} hold each document it opens, as a provider
   * that never answers would, until {@link #driveProviderStall} opens. Returns a latch that opens
   * once the storage app holds the first document.
   */
  private CountDownLatch stallDriveProvider() {
    CountDownLatch stalled = new CountDownLatch(1);
    driveProvider.onOpenFile =
        () -> {
          stalled.countDown();
          try {
            driveProviderStall.await();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        };
    return stalled;
  }

  /** Returns the notices, decrypted, that the storage app holds in {@link #DRIVE_TREE_URI}. */
  private ImmutableList<String> readNoticesInDriveFolder() throws Exception {
    // FakeGoogleDriveContentProvider keeps the documents of its folder there.
    return decrypt(new File(context.getFilesDir(), "fake_remote_drive").listFiles());
  }

  /** Returns the batches, decrypted, that wait on this phone for background sync. */
  private ImmutableList<String> readPendingNotices() throws Exception {
    File logsDirectory =
        new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    return decrypt(
        logsDirectory.listFiles((directory, name) -> !name.endsWith(CrumblesConstants.SENT_SUFFIX)));
  }

  /** Returns the logs of {@code batches}, which the device key decrypts. */
  private static ImmutableList<String> decrypt(File[] batches) throws Exception {
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    ImmutableList.Builder<String> logs = ImmutableList.builder();
    for (File batch : batches) {
      logs.add(new String(encryptor.decryptLogs(encryptor.deserializeFile(batch.toPath())), UTF_8));
    }
    return logs.build();
  }

  /**
   * Returns the only notice in {@link #DRIVE_TREE_URI} that carries an activity record of {@code
   * eventType}.
   */
  private String readNoticeInDriveFolderThatRecords(String eventType) throws Exception {
    return Iterables.getOnlyElement(
        Iterables.filter(readNoticesInDriveFolder(), notice -> notice.contains(recordOf(eventType))));
  }

  /** Returns how an activity record of {@code eventType} names its type in a batch. */
  private static String recordOf(String eventType) {
    return "\"eventType\":\"" + eventType + "\"";
  }

  /** Returns the folders that this app holds a persisted grant to. */
  private ImmutableList<Uri> persistedGrants() {
    return context.getContentResolver().getPersistedUriPermissions().stream()
        .map(UriPermission::getUri)
        .collect(toImmutableList());
  }

  /** Taps the button {@code which} of the dialog shown last. */
  private static void clickOnLatestDialog(int which) {
    getLatestAppCompatAlertDialog().getButton(which).performClick();
    shadowOf(Looper.getMainLooper()).idle();
  }

  /** Lets the active network count as validated, that is, as reaching the internet. */
  private void validateActiveNetwork() {
    ConnectivityManager connectivityManager = context.getSystemService(ConnectivityManager.class);
    NetworkCapabilities validated = ShadowNetworkCapabilities.newInstance();
    shadowOf(validated).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
    shadowOf(connectivityManager)
        .setNetworkCapabilities(connectivityManager.getActiveNetwork(), validated);
  }

  /** Returns the upload folder that the app saved last, or an empty string if none. */
  private String savedUploadFolderUri() {
    return context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, /* defValue= */ "");
  }

  /** Sets up the WebDAV destination, then chooses a folder and waits for the handover. */
  @CanIgnoreReturnValue
  private ActivityController<CrumblesMain> switchFromWebDavToFolderWithExternalKey(
      int webDavStatus, AtomicInteger webDavUploads) throws Exception {
    ActivityController<CrumblesMain> controller =
        setUpWebDavDestinationWithExternalKey(webDavStatus, webDavUploads);
    chooseTeamLogsFolder(controller.get());
    awaitDestinationHandover(controller.get());
    return controller;
  }

  /** Chooses the folder of {@link #TEAM_LOGS_TREE_URI} as the upload destination. */
  private void chooseTeamLogsFolder(CrumblesMain activity) {
    int grantFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
    context.getContentResolver().takePersistableUriPermission(TEAM_LOGS_TREE_URI, grantFlags);
    activity.onActivityResult(
        CrumblesConstants.FILE_TREE_REQUEST_CODE,
        Activity.RESULT_OK,
        new Intent().setData(TEAM_LOGS_TREE_URI).addFlags(grantFlags));
  }

  /** Waits until the handover of the upload destination change on {@code activity} is done. */
  private static void awaitDestinationHandover(CrumblesMain activity) {
    ExecutorService handover = ReflectionHelpers.getField(activity, "destinationHandoverExecutor");
    Futures.getUnchecked(handover.submit(() -> {}));
    shadowOf(Looper.getMainLooper()).idle();
  }

  @Test
  public void uploadAndWipeButton_startsTheUploadAndWipe() throws Exception {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(activity -> activity.findViewById(R.id.btn_upload_and_wipe).performClick());

    expect
        .that(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesUploadAndWipeWorker.UNIQUE_WORK_NAME)
                .get())
        .hasSize(1);
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            "Uploading every pending batch now. This phone keeps a copy of each one until you tap"
                + " Wipe anyway.");
  }

  @Test
  public void uploadAndWipeButton_withWebDav_saysThatUploadedBatchesAreDeleted() throws Exception {
    stubSealing();
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    saveWebDavSettings(openWebDavDialog(activity), WEBDAV_SERVER_URL, "alice", "correct horse");

    activity.findViewById(R.id.btn_upload_and_wipe).performClick();

    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            "Uploading every pending batch now. Each one is deleted from this phone once it is"
                + " uploaded.");
  }

  @Test
  public void uploadIssue_whileUploadsKeepFailing_showsTheProblemAndThePendingBatches()
      throws Exception {
    leaveBatchThatCouldNotBeUploaded();

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          TextView uploadIssue = activity.findViewById(R.id.upload_issue_textview);
          expect.that(uploadIssue.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(uploadIssue.getText().toString())
              .isEqualTo(
                  "Upload problem: Background sync is paused. Open the app to finish setting it"
                      + " up. 1 batch is waiting on this phone.");
        });
  }

  @Test
  public void wipeAnywayButton_whenNoBatchIsLeft_isHidden() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          expect
              .that(activity.findViewById(R.id.btn_wipe_anyway).getVisibility())
              .isEqualTo(View.GONE);
          expect
              .that(activity.findViewById(R.id.text_saf_kept_copies).getVisibility())
              .isEqualTo(View.GONE);
          expect
              .that(activity.findViewById(R.id.upload_issue_textview).getVisibility())
              .isEqualTo(View.GONE);
        });
  }

  @Test
  public void wipeAnywayButton_whenOnlyKeptSafCopiesRemain_isVisibleAndWipesSentBatchesAfterAuth()
      throws Exception {
    File firstSent = createSentBatchOnDisk("crumbles_logs_encrypted_1_sent.bin");
    File secondSent = createSentBatchOnDisk("crumbles_logs_encrypted_2_sent.bin");

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          Button wipeAnywayButton = activity.findViewById(R.id.btn_wipe_anyway);
          TextView keptCopiesLabel = activity.findViewById(R.id.text_saf_kept_copies);
          expect.that(wipeAnywayButton.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(wipeAnywayButton.getText().toString())
              .isEqualTo("Wipe anyway (2 kept copies)");
          expect.that(keptCopiesLabel.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(keptCopiesLabel.getText().toString())
              .isEqualTo("2 uploaded copies stay on this device until Drive syncs them.");

          clickAndConfirmPrompt(activity, R.id.btn_wipe_anyway);
          expect.that(wipeAnywayButton.getVisibility()).isEqualTo(View.GONE);
          expect.that(keptCopiesLabel.getVisibility()).isEqualTo(View.GONE);
        });

    expect.that(firstSent.exists()).isFalse();
    expect.that(secondSent.exists()).isFalse();
    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Wiped 2 batches from this phone.");
  }

  @Test
  public void wipeAnywayButton_whenKeptSafCopiesExpireWhileBackgrounded_hidesOnResume()
      throws Exception {
    File sentBatch = createSentBatchOnDisk("crumbles_logs_encrypted_1_sent.bin");
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          Button wipeAnywayButton = activity.findViewById(R.id.btn_wipe_anyway);
          TextView keptCopiesLabel = activity.findViewById(R.id.text_saf_kept_copies);
          expect.that(wipeAnywayButton.getVisibility()).isEqualTo(View.VISIBLE);
          expect.that(wipeAnywayButton.getText().toString()).isEqualTo("Wipe anyway (1 kept copy)");
          expect.that(keptCopiesLabel.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(keptCopiesLabel.getText().toString())
              .isEqualTo("1 uploaded copy stays on this device until Drive syncs it.");
        });

    scenario.moveToState(Lifecycle.State.STARTED);
    assertThat(sentBatch.delete()).isTrue();
    scenario.moveToState(Lifecycle.State.RESUMED);

    scenario.onActivity(
        activity -> {
          expect
              .that(activity.findViewById(R.id.btn_wipe_anyway).getVisibility())
              .isEqualTo(View.GONE);
          expect
              .that(activity.findViewById(R.id.text_saf_kept_copies).getVisibility())
              .isEqualTo(View.GONE);
        });
  }

  @Test
  public void wipeAnywayButton_whenUnuploadedAndKeptSafCopiesExist_showsBoth() throws Exception {
    leaveBatchThatCouldNotBeUploaded();
    createSentBatchOnDisk("crumbles_logs_encrypted_2_sent.bin");

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          Button wipeAnywayButton = activity.findViewById(R.id.btn_wipe_anyway);
          TextView keptCopiesLabel = activity.findViewById(R.id.text_saf_kept_copies);
          expect.that(wipeAnywayButton.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(wipeAnywayButton.getText().toString())
              .isEqualTo("Wipe anyway (1 batch not uploaded)");
          expect.that(keptCopiesLabel.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(keptCopiesLabel.getText().toString())
              .isEqualTo("1 uploaded copy stays on this device until Drive syncs it.");
        });
  }

  @Test
  public void wipeAnywayButton_whenSwitchedToWebDav_keepsShowingKeptSafCopies() throws Exception {
    stubSealing();
    createSentBatchOnDisk("crumbles_logs_encrypted_1_sent.bin");
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    expect
        .that(activity.findViewById(R.id.btn_wipe_anyway).getVisibility())
        .isEqualTo(View.VISIBLE);
    expect
        .that(activity.findViewById(R.id.text_saf_kept_copies).getVisibility())
        .isEqualTo(View.VISIBLE);

    saveWebDavSettings(openWebDavDialog(activity), WEBDAV_SERVER_URL, "alice", "correct horse");

    // The copy went to the SAF folder, which may still be syncing it.
    expect
        .that(activity.findViewById(R.id.btn_wipe_anyway).getVisibility())
        .isEqualTo(View.VISIBLE);
    expect
        .that(activity.findViewById(R.id.text_saf_kept_copies).getVisibility())
        .isEqualTo(View.VISIBLE);
  }


  @Test
  public void wipeAnywayButton_whenBatchesAreLeft_showsHowMany() throws Exception {
    leaveBatchThatCouldNotBeUploaded();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          Button wipeAnywayButton = activity.findViewById(R.id.btn_wipe_anyway);
          expect.that(wipeAnywayButton.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(wipeAnywayButton.getText().toString())
              .isEqualTo("Wipe anyway (1 batch not uploaded)");
        });
  }

  @Test
  public void wipeAnywayButton_whileAnUploadAndWipeIsQueued_showsThePendingBatches()
      throws Exception {
    createSentBatchOnDisk("crumbles_logs_encrypted_1.bin");
    // Queued but not running yet, as while the system holds the job back.
    WorkManager.getInstance(context)
        .enqueueUniqueWork(
            CrumblesUploadAndWipeWorker.UNIQUE_WORK_NAME,
            ExistingWorkPolicy.KEEP,
            new OneTimeWorkRequest.Builder(CrumblesUploadAndWipeWorker.class)
                .setInitialDelay(Duration.ofHours(1))
                .build())
        .getResult()
        .get();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    AtomicReference<Button> wipeAnywayButton = new AtomicReference<>();
    scenario.onActivity(
        activity -> wipeAnywayButton.set(activity.findViewById(R.id.btn_wipe_anyway)));
    // WorkManager reports the queued work to the screen off the main thread.
    for (int attempt = 0;
        attempt < 50 && wipeAnywayButton.get().getVisibility() != View.VISIBLE;
        attempt++) {
      Uninterruptibles.sleepUninterruptibly(20, MILLISECONDS);
      shadowOf(Looper.getMainLooper()).idle();
    }

    expect.that(wipeAnywayButton.get().getVisibility()).isEqualTo(View.VISIBLE);
    expect
        .that(wipeAnywayButton.get().getText().toString())
        .isEqualTo("Wipe anyway (1 batch not uploaded)");
  }

  @Test
  public void wipeAnyway_withoutScreenLock_refusesAndKeepsTheBatches() throws Exception {
    File batch = leaveBatchThatCouldNotBeUploaded();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(activity -> activity.findViewById(R.id.btn_wipe_anyway).performClick());

    expect.that(batch.exists()).isTrue();
    expect.that(auditEventTypes()).contains("UPLOAD_AND_WIPE_FORCED_REFUSED");
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Set a screen lock first. Wiping batches that were not uploaded needs it.");
  }

  @Test
  public void wipeAnyway_withScreenLock_asksForTheDeviceCredential() throws Exception {
    leaveBatchThatCouldNotBeUploaded();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity -> {
          shadowOf(activity.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
          activity.findViewById(R.id.btn_wipe_anyway).performClick();
        });

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
  }

  @Test
  public void wipeAnyway_afterCredentialConfirmed_wipesEveryBatch() throws Exception {
    File batch = leaveBatchThatCouldNotBeUploaded();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    int[] wipeAnywayVisibility = new int[1];

    scenario.onActivity(
        activity -> {
          clickAndConfirmPrompt(activity, R.id.btn_wipe_anyway);
          wipeAnywayVisibility[0] = activity.findViewById(R.id.btn_wipe_anyway).getVisibility();
        });

    expect.that(batch.exists()).isFalse();
    expect.that(wipeAnywayVisibility[0]).isEqualTo(View.GONE);
    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Wiped 1 batch from this phone.");
  }

  @Test
  public void wipeAnyway_whenCredentialNotConfirmed_keepsTheBatches() throws Exception {
    File batch = leaveBatchThatCouldNotBeUploaded();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(activity -> clickAndCancelPrompt(activity, R.id.btn_wipe_anyway));

    expect.that(batch.exists()).isTrue();
    expect.that(auditEventTypes()).contains("UPLOAD_AND_WIPE_FORCED_AUTH_FAILED");
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Authentication cancelled. Nothing was wiped.");
  }

  @Test
  public void wipeAnyway_whenKeptCopiesAndPendingBatchesExist_countsBothAndWarnsOfTheLoss()
      throws Exception {
    for (int i = 1; i <= 3; i++) {
      createSentBatchOnDisk("crumbles_logs_encrypted_" + i + CrumblesConstants.SENT_SUFFIX);
    }
    createSentBatchOnDisk("crumbles_logs_encrypted_4.bin");
    createSentBatchOnDisk("crumbles_logs_encrypted_5.bin");
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    AtomicReference<String> label = new AtomicReference<>();

    scenario.onActivity(
        activity -> {
          label.set(((Button) activity.findViewById(R.id.btn_wipe_anyway)).getText().toString());
          clickToOpenPrompt(activity, R.id.btn_wipe_anyway);
        });

    expect.that(label.get()).isEqualTo("Wipe anyway (3 kept copies, 2 batches not uploaded)");
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getTitle().toString())
        .isEqualTo("Wipe batches that were not uploaded?");
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("They never left this phone and will be lost.");
  }

  @Test
  public void wipeAnyway_whenOnlyKeptCopiesExist_asksToWipeTheKeptCopies() throws Exception {
    createSentBatchOnDisk("crumbles_logs_encrypted_1" + CrumblesConstants.SENT_SUFFIX);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(activity -> clickToOpenPrompt(activity, R.id.btn_wipe_anyway));

    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getTitle().toString())
        .isEqualTo("Wipe the uploaded copies kept on this phone?");
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("Any copy that the storage app has not synced yet will be lost.");
  }

  /**
   * Runs an upload and wipe on one batch while no encryption key is available, which leaves the
   * batch on the device, and returns it.
   */
  @CanIgnoreReturnValue
  private File leaveBatchThatCouldNotBeUploaded() throws IOException {
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    File logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsDirectory.mkdirs()).isTrue();
    File batch = new File(logsDirectory, "crumbles_logs_encrypted_1.bin");
    Files.write(batch.toPath(), "encrypted batch".getBytes(UTF_8));
    @SuppressWarnings("unused")
    var unusedResult =
        TestListenableWorkerBuilder.from(context, CrumblesUploadAndWipeWorker.class)
            .build()
            .doWork();
    return batch;
  }

  @CanIgnoreReturnValue
  private File createSentBatchOnDisk(String fileName) throws IOException {
    File logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    @SuppressWarnings("unused")
    var unusedCreated = logsDirectory.mkdirs();
    File batch = new File(logsDirectory, fileName);
    Files.write(batch.toPath(), "encrypted sent batch".getBytes(UTF_8));
    return batch;
  }

  private static ImmutableList<String> auditEventTypes() {
    return CrumblesAppAuditLogger.getInstance(ApplicationProvider.getApplicationContext())
        .getMemoryCachedEvents()
        .stream()
        .map(CrumblesAuditEvent::getEventType)
        .collect(toImmutableList());
  }

  private static ImmutableList<String> auditEventMessages(String eventType) {
    return CrumblesAppAuditLogger.getInstance(ApplicationProvider.getApplicationContext())
        .getMemoryCachedEvents()
        .stream()
        .filter(event -> event.getEventType().equals(eventType))
        .map(CrumblesAuditEvent::getMessage)
        .collect(toImmutableList());
  }

  private static class ThrowingTreePickerActivity extends CrumblesMain {
    @Override
    public void startActivityForResult(Intent intent, int requestCode) {
      throw new ActivityNotFoundException("Simulated missing document tree picker");
    }
  }

  @Test
  public void launchDocumentTreePicker_whenActivityNotFound_showsToast() {
    ActivityController<ThrowingTreePickerActivity> controller =
        Robolectric.buildActivity(ThrowingTreePickerActivity.class).setup();
    ThrowingTreePickerActivity activity = controller.get();

    activity.launchDocumentTreePicker();

    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Could not open directory picker.");
  }

  @Test
  public void onResume_withExternalKey_doesNotCheckInternalKeyInvalidation() throws Exception {
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    Futures.getChecked(
        CrumblesDataStoreHolder.getInstance(context)
            .updateDataAsync(
                prefs ->
                    prefs.toBuilder()
                        .setInternalKeyFingerprint("fake")
                        .setActiveKeyId("fake_key_id")
                        .build()),
        Exception.class);

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            ExecutorService executor = ReflectionHelpers.getField(activity, "keyProbeExecutor");
            Futures.getUnchecked(executor.submit(() -> {}));
          });
      shadowOf(Looper.getMainLooper()).idle();

      NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
      assertThat(notificationManager.getActiveNotifications()).isEmpty();
    }
  }

  @Test
  public void onResume_whenInternalKeyDeleted_logsInvalidationAndNotifiesUser() throws Exception {
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(false);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    Futures.getChecked(
        CrumblesDataStoreHolder.getInstance(context)
            .updateDataAsync(
                prefs ->
                    prefs.toBuilder()
                        .setInternalKeyFingerprint("deleted_internal_key_fp")
                        .clearActiveKeyId()
                        .build()),
        Exception.class);

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            ExecutorService executor = ReflectionHelpers.getField(activity, "keyProbeExecutor");
            Futures.getUnchecked(executor.submit(() -> {}));
          });
      shadowOf(Looper.getMainLooper()).idle();

      expect.that(hasAuditEvent(CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED)).isTrue();
      NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
      expect
          .that(
              shadowOf(notificationManager)
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();
    }
  }

  @Test
  public void onResume_whenInternalKeyPermanentlyInvalidated_updatesKeyButtonsOnMainThread()
      throws Exception {
    KeyPair testKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    AtomicBoolean privateKeyExists = new AtomicBoolean(true);
    CountDownLatch allowInvalidationProbe = new CountDownLatch(1);
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(false);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenAnswer(inv -> privateKeyExists.get());
    when(mockLogsEncryptor.getPublicKey()).thenReturn(testKeyPair.getPublic());
    when(mockLogsEncryptor.isPrivateKeyPermanentlyInvalidated())
        .thenAnswer(
            inv -> {
              assertThat(allowInvalidationProbe.await(5, TimeUnit.SECONDS)).isTrue();
              privateKeyExists.set(false);
              return true;
            });

    try (ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true)) {
      scenario.onActivity(
          activity -> {
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            expect.that(decryptButton.isEnabled()).isTrue();
          });

      allowInvalidationProbe.countDown();
      scenario.onActivity(
          activity -> {
            ExecutorService executor = ReflectionHelpers.getField(activity, "keyProbeExecutor");
            Futures.getUnchecked(executor.submit(() -> {}));
          });
      shadowOf(Looper.getMainLooper()).idle();

      scenario.onActivity(
          activity -> {
            Button decryptButton = activity.findViewById(R.id.decrypt_logs_button);
            Button manageKeyButton = activity.findViewById(R.id.btn_manage_encryption_key);
            expect.that(decryptButton.isEnabled()).isFalse();
            expect
                .that(manageKeyButton.getText().toString())
                .isEqualTo(activity.getString(R.string.no_key_ready_generate_button));
          });
    }
  }

  @Test
  public void onDestroy_shutsDownKeyProbeExecutorWithoutInterruptingRunningProbe()
      throws Exception {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    ExecutorService executor = ReflectionHelpers.getField(controller.get(), "keyProbeExecutor");
    CountDownLatch probeStarted = new CountDownLatch(1);
    CountDownLatch releaseProbe = new CountDownLatch(1);
    AtomicBoolean wasInterrupted = new AtomicBoolean(false);
    var unused =
        executor.submit(
            () -> {
              probeStarted.countDown();
              try {
                var ignored = releaseProbe.await(5, TimeUnit.SECONDS);
              } catch (InterruptedException e) {
                wasInterrupted.set(true);
                Thread.currentThread().interrupt();
              }
            });
    assertThat(probeStarted.await(5, TimeUnit.SECONDS)).isTrue();

    controller.destroy();

    expect.that(executor.isShutdown()).isTrue();
    releaseProbe.countDown();
    expect.that(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    expect.that(wasInterrupted.get()).isFalse();
  }

  @Test
  public void onResume_withoutScreenLock_showsScreenLockWarning() {
    setPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_NONE);

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity ->
            assertThat(activity.findViewById(R.id.screen_lock_warning).getVisibility())
                .isEqualTo(View.VISIBLE));
  }

  @Test
  public void onResume_withScreenLock_hidesScreenLockWarning() {
    setPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_LOW);

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity ->
            assertThat(activity.findViewById(R.id.screen_lock_warning).getVisibility())
                .isEqualTo(View.GONE));
  }

  @Test
  public void onResume_afterScreenLockIsSet_hidesScreenLockWarning() {
    setPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_NONE);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    scenario.moveToState(Lifecycle.State.STARTED);
    setPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_HIGH);

    scenario.moveToState(Lifecycle.State.RESUMED);

    scenario.onActivity(
        activity ->
            assertThat(activity.findViewById(R.id.screen_lock_warning).getVisibility())
                .isEqualTo(View.GONE));
  }

  @Test
  public void onResume_whenNotificationsAreTurnedOff_showsAlertsBlockedWarning() {
    shadowOf(context.getSystemService(NotificationManager.class)).setNotificationsEnabled(false);

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity ->
            assertThat(activity.findViewById(R.id.alerts_blocked_warning).getVisibility())
                .isEqualTo(View.VISIBLE));
  }

  @Test
  public void onResume_whenNotificationsAreOn_hidesAlertsBlockedWarning() {
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);

    scenario.onActivity(
        activity ->
            assertThat(activity.findViewById(R.id.alerts_blocked_warning).getVisibility())
                .isEqualTo(View.GONE));
  }

  @Test
  public void setScreenLockButton_onClick_opensTheSystemScreenLockSettings() {
    setPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_NONE);
    addScreenLockActivity("com.example.claims.screen.lock", /* applicationFlags= */ 0);
    addScreenLockActivity("com.android.settings", ApplicationInfo.FLAG_SYSTEM);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] startedIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_set_screen_lock).performClick();
          startedIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    assertThat(startedIntent[0].getAction()).isEqualTo(DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
    assertThat(startedIntent[0].getComponent())
        .isEqualTo(new ComponentName("com.android.settings", "com.android.settings.SetScreenLock"));
  }

  @Test
  public void setScreenLockButton_whenSettingsScreenIsMissing_showsToast() {
    setPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_NONE);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Application application = ApplicationProvider.getApplicationContext();
    shadowOf(application).checkActivities(true);

    scenario.onActivity(activity -> activity.findViewById(R.id.btn_set_screen_lock).performClick());

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_screen_lock_settings_unavailable));
  }

  @Test
  public void onResume_asSecurityOrNetworkLoggingDelegateWithoutActiveAdmin_offersDeviceAdmin() {
    for (String scope : new String[]{
        DevicePolicyManager.DELEGATION_SECURITY_LOGGING,
        DevicePolicyManager.DELEGATION_NETWORK_LOGGING}) {
      setUpDelegate(scope);
      ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
      scenario.onActivity(
          activity ->
              assertThat(activity.findViewById(R.id.device_admin_offer).getVisibility())
                  .isEqualTo(View.VISIBLE));
      scenario.close();
    }
  }

  @Test
  public void onResume_whenAdminNotNeeded_hidesDeviceAdminOffer() {
    ActivityScenario<CrumblesMain> s1 = launchActivityWithNotificationPermission(true);
    s1.onActivity(a -> assertThat(a.findViewById(R.id.device_admin_offer).getVisibility()).isEqualTo(View.GONE));
    s1.close();

    setUpDeviceOwner();
    ActivityScenario<CrumblesMain> s2 = launchActivityWithNotificationPermission(true);
    s2.onActivity(a -> assertThat(a.findViewById(R.id.device_admin_offer).getVisibility()).isEqualTo(View.GONE));
    s2.close();

    ((DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE)).removeActiveAdmin(getAdminComponentName());
    setUpLoggingDelegate();
    shadowOf((DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE)).setActiveAdmin(getAdminComponentName());
    ActivityScenario<CrumblesMain> s3 = launchActivityWithNotificationPermission(true);
    s3.onActivity(a -> assertThat(a.findViewById(R.id.device_admin_offer).getVisibility()).isEqualTo(View.GONE));
    s3.close();
  }

  @Test
  public void activateDeviceAdminButton_onClick_asksTheSystemToActivateCrumblesAsDeviceAdmin() {
    setUpLoggingDelegate();
    addDeviceAdminActivity("com.example.claims.device.admin", /* applicationFlags= */ 0);
    addDeviceAdminActivity("com.android.settings", ApplicationInfo.FLAG_SYSTEM);
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Intent[] startedIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_activate_device_admin).performClick();
          startedIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    expect
        .that(startedIntent[0].getAction())
        .isEqualTo(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
    expect
        .that(startedIntent[0].getComponent())
        .isEqualTo(
            new ComponentName("com.android.settings", "com.android.settings.DeviceAdminAdd"));
    expect
        .that(
            startedIntent[0].getParcelableExtra(
                DevicePolicyManager.EXTRA_DEVICE_ADMIN, ComponentName.class))
        .isEqualTo(getAdminComponentName());
    expect
        .that(startedIntent[0].getStringExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION))
        .isEqualTo(context.getString(R.string.device_admin_explanation));
  }

  @Test
  public void activateDeviceAdminButton_whenActivationScreenIsMissing_showsToast() {
    setUpLoggingDelegate();
    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    Application application = ApplicationProvider.getApplicationContext();
    shadowOf(application).checkActivities(true);

    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_activate_device_admin).performClick());

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_device_admin_activation_unavailable));
  }

  private static void setPasswordComplexity(int passwordComplexity) {
    Application application = ApplicationProvider.getApplicationContext();
    DevicePolicyManager dpm =
        (DevicePolicyManager) application.getSystemService(Context.DEVICE_POLICY_SERVICE);
    shadowOf(dpm).setPasswordComplexity(passwordComplexity);
  }

  /** Makes the activity {@code SetScreenLock} of {@code packageName} set screen locks. */
  private static void addScreenLockActivity(String packageName, int applicationFlags) {
    ResolveInfo resolveInfo =
        ShadowResolveInfo.newResolveInfo(
            "Screen lock", packageName, packageName + ".SetScreenLock");
    resolveInfo.activityInfo.applicationInfo.flags = applicationFlags;
    Application application = ApplicationProvider.getApplicationContext();
    shadowOf(application.getPackageManager())
        .addResolveInfoForIntent(
            new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD), resolveInfo);
  }

  /** Makes the activity {@code DeviceAdminAdd} of {@code packageName} activate device admins. */
  private static void addDeviceAdminActivity(String packageName, int applicationFlags) {
    ResolveInfo resolveInfo =
        ShadowResolveInfo.newResolveInfo(
            "Device admin", packageName, packageName + ".DeviceAdminAdd");
    resolveInfo.activityInfo.applicationInfo.flags = applicationFlags;
    Application application = ApplicationProvider.getApplicationContext();
    shadowOf(application.getPackageManager())
        .addResolveInfoForIntent(
            new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN), resolveInfo);
  }

  /** Simulates a layout that lacks the app signing fingerprint view. */
  private static class CrumblesMainWithoutFingerprintView extends CrumblesMain {
    @Override
    public void setContentView(int layoutResId) {
      super.setContentView(layoutResId);
      findViewById(R.id.app_signing_fingerprint_textview).setId(View.NO_ID);
    }
  }

  @Test
  public void onCreate_whenFingerprintViewMissing_stillSchedulesPeriodicWork() throws Exception {
    PackageInfo packageInfo =
        shadowOf(context.getPackageManager())
            .getInternalMutablePackageInfo(context.getPackageName());
    packageInfo.signingInfo = new SigningInfo();
    shadowOf(packageInfo.signingInfo).setSignatures(new Signature[] {new Signature("c0ffee")});

    Robolectric.buildActivity(CrumblesMainWithoutFingerprintView.class).setup();

    assertThat(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesConstants.DELETE_WORK_TAG)
                .get())
        .isNotEmpty();
  }

  @Test
  public void onCreate_whenLaunchedAgain_keepsTheScheduledUpload() throws Exception {
    Robolectric.buildActivity(CrumblesMain.class).setup();
    UUID scheduledUpload = onlyUploadWork().getId();

    Robolectric.buildActivity(CrumblesMain.class).setup();

    WorkInfo upload = onlyUploadWork();
    expect.that(upload.getId()).isEqualTo(scheduledUpload);
    expect.that(upload.getState()).isEqualTo(WorkInfo.State.ENQUEUED);
  }

  private WorkInfo onlyUploadWork() throws Exception {
    List<WorkInfo> uploadWork =
        WorkManager.getInstance(context)
            .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
            .get();
    assertThat(uploadWork).hasSize(1);
    return uploadWork.get(0);
  }

  @Test
  public void
      onActivityResult_withRealCollectedNetworkLogs_encryptsDecryptsAndRendersReadableEntries()
          throws Exception {
    // 1. Construct real network event using reflection
    Constructor<ConnectEvent> constructor =
        ConnectEvent.class.getConstructor(String.class, int.class, String.class, long.class);
    ConnectEvent connectEvent =
        constructor.newInstance("192.168.1.100", 443, "com.android.test", 1672531200000L);
    List<String> formattedLogs =
        CrumblesDeviceAdminReceiver.getSerializableNetworkLogs(ImmutableList.of(connectEvent));
    byte[] plainLogsBytes = String.join("", formattedLogs).getBytes(UTF_8);

    // 2. Encrypt using real CrumblesLogsEncryptor and test key pair
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesLogsEncryptor realEncryptor = new CrumblesLogsEncryptor();
    LogBatch logBatch = realEncryptor.encryptLogs(plainLogsBytes, keyPair.getPublic());
    assertThat(logBatch).isNotNull();

    File testFile = new File(mockAdHocDir, "network_logs.bin");
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      logBatch.writeTo(fos);
    }
    Intent resultDataIntent = new Intent().setData(Uri.fromFile(testFile));

    // Mock decryptLogBatch to return the actual plainLogsBytes produced by receiver.logsToBytes
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenReturn(
            new DecryptedLogBatch(logBatch.getMetadata(), plainLogsBytes));

    ActivityScenario<CrumblesMain> scenario = launchActivityWithNotificationPermission(true);
    final Intent[] nextActivityIntent = new Intent[1];

    scenario.onActivity(
        activity -> {
          activity.onActivityResult(FILE_PICKER_REQUEST_CODE, Activity.RESULT_OK, resultDataIntent);
          awaitSelectionRead(activity);
          shadowOf(activity.getMainLooper()).idle();
          ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
          shadowOf(activity.getMainLooper()).idle();
          nextActivityIntent[0] = shadowOf(activity).getNextStartedActivity();
        });

    assertThat(nextActivityIntent[0]).isNotNull();
    long sessionId =
        nextActivityIntent[0].getLongExtra(
            CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, /* defaultValue= */ -1);
    List<CrumblesDecryptedLogEntry> logs =
        CrumblesDecryptedLogsSession.getSession(sessionId).orElseThrow().getEntries();
    assertThat(logs).isNotNull();
    assertThat(logs).hasSize(1);
    String renderedContent = logs.get(0).getContent();
    assertThat(renderedContent).contains("Network log ID: 0");
    assertThat(renderedContent).contains("Timestamp (UTC): 2023-01-01T00:00:00.000Z");
    assertThat(renderedContent).contains("Package name: com.android.test");
    assertThat(renderedContent).contains("Connect event ID: 0");
    assertThat(renderedContent).contains("Inet address: /192.168.1.100");
    assertThat(renderedContent).contains("Port: 443");
    // Verify no Java binary serialization stream markers are present
    assertThat(renderedContent).doesNotContain("\u00ac\u00ed");
    assertThat(renderedContent).doesNotContain("java.util.ArrayList");
  }

  /** Wraps {@link PackageManager} in a spy so tests can verify provider resolution flags. */
  private static class SpyPackageManagerActivity extends CrumblesMain {
    private PackageManager spyPackageManager;

    @Override
    public PackageManager getPackageManager() {
      if (spyPackageManager == null) {
        spyPackageManager = spy(super.getPackageManager());
      }
      return spyPackageManager;
    }
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

  /** A documents provider that names the folder only once the test lets it answer. */
  public static class StalledFolderProvider extends FakeContentProvider {
    final CountDownLatch answer = new CountDownLatch(1);
    final AtomicInteger queries = new AtomicInteger();

    @Override
    public Cursor query(
        Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
      queries.incrementAndGet();
      // Waiting here on the main thread would freeze the app, and the test with it.
      assertWithMessage("Asked for the folder name on the main thread")
          .that(Looper.getMainLooper().isCurrentThread())
          .isFalse();
      Uninterruptibles.awaitUninterruptibly(answer);
      MatrixCursor cursor =
          new MatrixCursor(new String[] {DocumentsContract.Document.COLUMN_DISPLAY_NAME});
      cursor.addRow(new Object[] {"Team Logs"});
      return cursor;
    }
  }

  @Test
  public void selectUploadDestination_showsSecureStorageTypeAndWebDavDialogs() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    clickAndConfirmPrompt(activity, R.id.btn_select_upload_dest);
    AlertDialog storageTypeDialog = getLatestAppCompatAlertDialog();
    expect
        .that(
            storageTypeDialog.getWindow().getAttributes().flags
                & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
    expect.that(hidesOverlayWindows(storageTypeDialog.getWindow())).isTrue();

    storageTypeDialog
        .getListView()
        .performItemClick(/* view= */ null, /* position= */ 1, /* id= */ 1);
    shadowOf(Looper.getMainLooper()).idle();
    AlertDialog webDavDialog = getLatestAppCompatAlertDialog();
    fillWebDavFields(webDavDialog, WEBDAV_SERVER_URL, "alice", "correct horse");

    EditText urlField = webDavDialog.findViewById(R.id.webdav_server_url_input);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
    View dialogContainer = (View) urlField.getParent();
    expect
        .that(dialogContainer.getImportantForAutofill())
        .isEqualTo(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
    expect.that(urlField.isImportantForAutofill()).isFalse();
    expect.that(usernameField.isImportantForAutofill()).isFalse();
    expect.that(passwordField.isImportantForAutofill()).isFalse();
    expect.that(urlField.isAccessibilityDataSensitive()).isTrue();
    expect.that(usernameField.isAccessibilityDataSensitive()).isTrue();
    expect.that(passwordField.isAccessibilityDataSensitive()).isTrue();
    expect.that(urlField.isSaveEnabled()).isFalse();
    expect.that(usernameField.isSaveEnabled()).isFalse();
    expect.that(passwordField.isSaveEnabled()).isFalse();
    expect
        .that(urlField.getImeOptions() & EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
        .isEqualTo(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
    expect
        .that(usernameField.getImeOptions() & EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
        .isEqualTo(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
    expect
        .that(passwordField.getImeOptions() & EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
        .isEqualTo(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
    expect
        .that(passwordField.getInputType())
        .isEqualTo(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
    expect
        .that(
            webDavDialog.getWindow().getAttributes().flags
                & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
    expect.that(hidesOverlayWindows(webDavDialog.getWindow())).isTrue();

    AlertDialog replacementDialog = openWebDavDialog(activity);
    expect.that(webDavDialog.isShowing()).isFalse();
    expect.that(usernameField.getText().toString()).isEmpty();
    expect.that(passwordField.getText().toString()).isEmpty();
    expect.that(replacementDialog.isShowing()).isTrue();
  }

  @Test
  public void webDavDialog_onStop_dismissesDialogAndClearsEnteredCredentials() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    AlertDialog webDavDialog = openWebDavDialog(controller.get());
    EditText urlField = webDavDialog.findViewById(R.id.webdav_server_url_input);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
    fillWebDavFields(webDavDialog, WEBDAV_SERVER_URL, "alice", "correct horse");

    controller.pause().stop();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(webDavDialog.isShowing()).isFalse();
    expect.that(controller.get().webDavDialog).isNull();
    expect.that(hasAuditEvent("UPLOAD_DESTINATION_ABANDONED")).isTrue();
    expect.that(urlField.getText().toString()).isEmpty();
    expect.that(usernameField.getText().toString()).isEmpty();
    expect.that(passwordField.getText().toString()).isEmpty();
  }

  @Test
  public void storageTypeDialog_onStop_dismissesDialogAndRecordsAbandonedChange() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    clickAndConfirmPrompt(controller.get(), R.id.btn_select_upload_dest);
    AlertDialog storageTypeDialog = getLatestAppCompatAlertDialog();

    controller.pause().stop();

    expect.that(storageTypeDialog.isShowing()).isFalse();
    expect.that(hasAuditEvent("UPLOAD_DESTINATION_ABANDONED")).isTrue();
  }

  @Test
  public void webDavDialog_onDestroy_dismissesDialogAndClearsEnteredCredentials() {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    AlertDialog webDavDialog = openWebDavDialog(controller.get());
    EditText urlField = webDavDialog.findViewById(R.id.webdav_server_url_input);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
    fillWebDavFields(webDavDialog, WEBDAV_SERVER_URL, "alice", "correct horse");

    controller.destroy();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(webDavDialog.isShowing()).isFalse();
    expect.that(controller.get().webDavDialog).isNull();
    expect.that(urlField.getText().toString()).isEmpty();
    expect.that(usernameField.getText().toString()).isEmpty();
    expect.that(passwordField.getText().toString()).isEmpty();
  }

  @Test
  public void webDavDialog_dismissingReplacedDialog_keepsNewerDialogReference() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    AlertDialog firstDialog = openWebDavDialog(activity);
    clickAndConfirmPrompt(activity, R.id.btn_select_upload_dest);
    AlertDialog storageTypeDialog = getLatestAppCompatAlertDialog();
    firstDialog.dismiss();
    // Open a replacement dialog before the main looper runs firstDialog's queued dismiss callback.
    storageTypeDialog
        .getListView()
        .performItemClick(/* view= */ null, /* position= */ 1, /* id= */ 1);
    AlertDialog secondDialog = activity.webDavDialog;

    shadowOf(Looper.getMainLooper()).idle();

    expect.that(secondDialog).isNotSameInstanceAs(firstDialog);
    expect.that(activity.webDavDialog).isSameInstanceAs(secondDialog);
  }

  @Test
  public void webDavDialog_whenSaved_storesEachValueSealedToItsOwnEntryAndWipesFields()
      throws Exception {
    stubSealing();
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    AlertDialog webDavDialog = openWebDavDialog(activity);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);

    saveWebDavSettings(webDavDialog, WEBDAV_SERVER_URL, "alice", "correct horse");

    expect.that(webDavDialog.isShowing()).isFalse();
    expect.that(usernameField.getText().toString()).isEmpty();
    expect.that(passwordField.getText().toString()).isEmpty();
    expect
        .that(readSavedRemoteStorageConfig())
        .isEqualTo(
            RemoteStorageConfig.newBuilder()
                .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
                .setWebdavServerUrl(
                    fakeSealedPayload(
                        WEBDAV_SERVER_URL, CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID))
                .setWebdavCredentials(
                    WebDavCredentials.newBuilder()
                        .setUsername(
                            fakeSealedPayload("alice", CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
                        .setPassword(
                            fakeSealedPayload(
                                "correct horse", CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID)))
                .build());
  }

  @Test
  public void webDavDialog_whenSaved_confirmsWithoutRevealingTheServerUrl() throws Exception {
    stubSealing();
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    saveWebDavSettings(openWebDavDialog(activity), WEBDAV_SERVER_URL, "alice", "correct horse");

    TextView statusTextView = activity.findViewById(R.id.upload_destination_status_textview);
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_webdav_config_success));
    expect.that(statusTextView.getText().toString()).isEqualTo("Upload Destination: WebDAV Server");
  }

  @Test
  public void webDavDialog_whenFieldsInvalid_savesNothingAndKeepsDialogOpenWithCredentials()
      throws Exception {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    AlertDialog webDavDialog = openWebDavDialog(activity);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);

    saveWebDavSettings(webDavDialog, "http://localhost.example.com/dav/", "alice", "correct horse");
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_webdav_invalid_fields));
    expect.that(webDavDialog.isShowing()).isTrue();
    expect.that(usernameField.getText().toString()).isEqualTo("alice");
    expect.that(passwordField.getText().toString()).isEqualTo("correct horse");

    ShadowToast.reset();
    saveWebDavSettings(webDavDialog, WEBDAV_SERVER_URL, "", "correct horse");
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_webdav_invalid_fields));
    expect.that(webDavDialog.isShowing()).isTrue();
    expect.that(passwordField.getText().toString()).isEqualTo("correct horse");

    ShadowToast.reset();
    saveWebDavSettings(webDavDialog, WEBDAV_SERVER_URL, "alice", "");
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_webdav_invalid_fields));
    expect.that(webDavDialog.isShowing()).isTrue();
    expect.that(usernameField.getText().toString()).isEqualTo("alice");
    expect.that(readSavedRemoteStorageConfig()).isEqualTo(RemoteStorageConfig.getDefaultInstance());
  }

  @Test
  public void webDavDialog_whenSealingFails_savesNothingAndKeepsDialogOpenWithCredentials()
      throws Exception {
    when(mockLogsEncryptor.encryptDataStoreEntry(any(byte[].class), anyString()))
        .thenThrow(new CrumblesKeysException("Keystore unavailable"));
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    AlertDialog webDavDialog = openWebDavDialog(activity);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);

    saveWebDavSettings(webDavDialog, WEBDAV_SERVER_URL, "alice", "correct horse");

    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_upload_dest_save_failed));
    expect.that(webDavDialog.isShowing()).isTrue();
    expect.that(usernameField.getText().toString()).isEqualTo("alice");
    expect.that(passwordField.getText().toString()).isEqualTo("correct horse");
    expect.that(readSavedRemoteStorageConfig()).isEqualTo(RemoteStorageConfig.getDefaultInstance());
  }

  @Test
  public void webDavDialog_whenCancelled_dismissesAndClearsCredentials() throws Exception {
    ActivityController<CrumblesMain> controller =
        Robolectric.buildActivity(CrumblesMain.class).setup();
    AlertDialog webDavDialog = openWebDavDialog(controller.get());
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
    fillWebDavFields(webDavDialog, WEBDAV_SERVER_URL, "alice", "correct horse");

    webDavDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();
    // Stopping after the dialog is already closed must not record an abandoned change.
    controller.pause().stop();

    expect.that(webDavDialog.isShowing()).isFalse();
    expect.that(usernameField.getText().toString()).isEmpty();
    expect.that(passwordField.getText().toString()).isEmpty();
    expect.that(readSavedRemoteStorageConfig()).isEqualTo(RemoteStorageConfig.getDefaultInstance());
    expect.that(auditEventTypes()).doesNotContain("UPLOAD_DESTINATION_ABANDONED");
  }

  @Test
  public void webDavDialog_onStopAndOnDestroy_dismissesDialogsAndClearsCredentials()
      throws Exception {
    CountDownLatch blockHandshake = new CountDownLatch(1);
    HttpsServer server =
        startHttpsServer(
            new AtomicReference<>(serverCertificate),
            new AtomicInteger(),
            /* onHandshake= */ () -> {
              try {
                blockHandshake.await(5, TimeUnit.SECONDS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            });
    try {
      String httpsUrl = "https://localhost:" + server.getAddress().getPort() + "/dav/";
      ActivityController<CrumblesMain> controller =
          Robolectric.buildActivity(CrumblesMain.class).setup();
      CrumblesMain activity = controller.get();

      AlertDialog webDavDialog = openWebDavDialog(activity);
      EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
      EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
      fillWebDavFields(webDavDialog, httpsUrl, "alice", "correct horse");
      webDavDialog.findViewById(R.id.webdav_test_connection_button).performClick();
      AlertDialog pinDialog = getLatestAppCompatAlertDialog();
      expect.that(webDavDialog.isShowing()).isTrue();
      expect.that(pinDialog.isShowing()).isTrue();

      controller.pause().stop();
      shadowOf(Looper.getMainLooper()).idle();

      expect.that(pinDialog.isShowing()).isFalse();
      expect.that(webDavDialog.isShowing()).isFalse();
      expect.that(usernameField.getText().toString()).isEmpty();
      expect.that(passwordField.getText().toString()).isEmpty();

      // Reopen them once restarted: the prompt that guards the dialog needs a started activity.
      controller.restart().resume();
      AlertDialog stoppedWebDavDialog = openWebDavDialog(activity);
      EditText stoppedUsername = stoppedWebDavDialog.findViewById(R.id.webdav_username_input);
      EditText stoppedPassword = stoppedWebDavDialog.findViewById(R.id.webdav_password_input);
      fillWebDavFields(stoppedWebDavDialog, httpsUrl, "bob", "hunter2");
      stoppedWebDavDialog.findViewById(R.id.webdav_test_connection_button).performClick();
      AlertDialog stoppedPinDialog = getLatestAppCompatAlertDialog();
      expect.that(stoppedWebDavDialog.isShowing()).isTrue();
      expect.that(stoppedPinDialog.isShowing()).isTrue();

      controller.destroy();
      shadowOf(Looper.getMainLooper()).idle();

      expect.that(stoppedPinDialog.isShowing()).isFalse();
      expect.that(stoppedWebDavDialog.isShowing()).isFalse();
      expect.that(stoppedUsername.getText().toString()).isEmpty();
      expect.that(stoppedPassword.getText().toString()).isEmpty();
    } finally {
      blockHandshake.countDown();
      server.stop(0);
    }
  }

  @Test
  public void webDavKeyConfirmation_showsKeyFingerprintAndSavesSettingsOnlyWhenConfirmed()
      throws Exception {
    stubSealing();
    HttpsServer server = startHttpsServer();
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
      EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
      String serverUrl = "HTTPS://localhost:" + server.getAddress().getPort() + "/dav/";

      saveWebDavSettings(webDavDialog, serverUrl, "alice", "correct horse");
      AlertDialog cancelledConfirmation = awaitServerKeyDialog(activity);
      cancelledConfirmation.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();

      expect.that(cancelledConfirmation.isShowing()).isFalse();
      expect.that(webDavDialog.isShowing()).isTrue();
      expect.that(usernameField.getText().toString()).isEqualTo("alice");
      expect.that(passwordField.getText().toString()).isEqualTo("correct horse");
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());

      webDavDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      AlertDialog confirmationDialog = awaitServerKeyDialog(activity);
      expect
          .that(
              confirmationDialog.getWindow().getAttributes().flags
                  & WindowManager.LayoutParams.FLAG_SECURE)
          .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
      expect
          .that(messageOf(confirmationDialog))
          .doesNotContain(activity.getString(R.string.webdav_server_key_changed));
      expect
          .that(messageOf(confirmationDialog))
          .endsWith(WebDavServerKeyPin.ofSha256(serverKeySha256()).fingerprint());
      expect.that(confirmationDialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled()).isTrue();
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());

      confirmationDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();

      verify(mockLogsEncryptor)
          .encryptDataStoreEntry(
              aryEq(serverKeySha256()), eq(CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID));
      RemoteStorageConfig savedConfig = readSavedRemoteStorageConfig();
      expect.that(savedConfig.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
      expect
          .that(savedConfig.getWebdavServerKeySha256())
          .isEqualTo(
              fakeSealedPayload(
                  new String(serverKeySha256(), UTF_8),
                  CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID));
      expect.that(confirmationDialog.isShowing()).isFalse();
      expect.that(webDavDialog.isShowing()).isFalse();
      expect.that(usernameField.getText().toString()).isEmpty();
      expect.that(passwordField.getText().toString()).isEmpty();
      expect
          .that(ShadowToast.getTextOfLatestToast())
          .isEqualTo(activity.getString(R.string.toast_webdav_config_success));
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void webDavKeyConfirmation_whenPinSealingFails_savesNothingAndKeepsDialogWithCredentials()
      throws Exception {
    when(mockLogsEncryptor.encryptDataStoreEntry(any(byte[].class), anyString()))
        .thenAnswer(
            invocation -> {
              String entryId = invocation.getArgument(1);
              if (entryId.equals(CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID)) {
                throw new CrumblesKeysException("Keystore unavailable when sealing server key pin");
              }
              byte[] plaintext = invocation.getArgument(0);
              return fakeSealedPayload(new String(plaintext, UTF_8), entryId);
            });
    HttpsServer server = startHttpsServer();
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
      EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
      saveWebDavSettings(
          webDavDialog,
          "https://localhost:" + server.getAddress().getPort() + "/dav/",
          "alice",
          "correct horse");

      AlertDialog confirmationDialog = awaitServerKeyDialog(activity);
      confirmationDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();

      expect
          .that(ShadowToast.getTextOfLatestToast())
          .isEqualTo(activity.getString(R.string.toast_upload_dest_save_failed));
      expect.that(webDavDialog.isShowing()).isTrue();
      expect.that(usernameField.getText().toString()).isEqualTo("alice");
      expect.that(passwordField.getText().toString()).isEqualTo("correct horse");
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void webDavKeyConfirmation_afterTestConnectionConfirmsKey_savesWithoutSecondNetworkProbe()
      throws Exception {
    stubSealing();
    AtomicInteger handshakesAttempted = new AtomicInteger();
    HttpsServer server =
        startHttpsServer(
            new AtomicReference<>(serverCertificate), handshakesAttempted, /* onHandshake= */ null);
    server.createContext(
        "/dav/",
        exchange -> {
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
      EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
      Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
      fillWebDavFields(
          webDavDialog,
          "https://localhost:" + server.getAddress().getPort() + "/dav/",
          "alice",
          "correct horse");

      testButton.performClick();
      awaitServerKeyDialog(activity).getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }
      int handshakesAfterTest = handshakesAttempted.get();
      server.stop(0);

      webDavDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();

      expect.that(handshakesAttempted.get()).isEqualTo(handshakesAfterTest);
      expect.that(webDavDialog.isShowing()).isFalse();
      expect.that(usernameField.getText().toString()).isEmpty();
      expect.that(passwordField.getText().toString()).isEmpty();
      RemoteStorageConfig savedConfig = readSavedRemoteStorageConfig();
      expect.that(savedConfig.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
      expect
          .that(savedConfig.getWebdavServerKeySha256())
          .isEqualTo(
              fakeSealedPayload(
                  new String(serverKeySha256(), UTF_8),
                  CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID));
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void webDavDialog_whenAnotherServerIsEntered_showsNoWarningAboutTheSavedKey()
      throws Exception {
    stubSealing();
    HttpsServer savedServer = startHttpsServer();
    HttpsServer otherServer =
        startHttpsServer(
            new AtomicReference<>(rotatedServerCertificate),
            new AtomicInteger(),
            /* onHandshake= */ null);
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      saveHttpsWebDavSettings(activity, savedServer)
          .getButton(AlertDialog.BUTTON_POSITIVE)
          .performClick();
      shadowOf(Looper.getMainLooper()).idle();

      saveWebDavSettings(
          openWebDavDialog(activity),
          "https://localhost:" + otherServer.getAddress().getPort() + "/dav/",
          "alice",
          "correct horse");
      AlertDialog confirmationDialog = awaitServerKeyDialog(activity);

      assertThat(messageOf(confirmationDialog))
          .isEqualTo(
              activity.getString(
                  R.string.webdav_server_key_dialog_message,
                  WebDavServerKeyPin.of(rotatedServerCertificate.keyPair().getPublic())
                      .fingerprint()));
    } finally {
      savedServer.stop(0);
      otherServer.stop(0);
    }
  }

  @Test
  public void webDavKeyConfirmation_whenUrlEditedOrDialogReopened_promptsForKeyConfirmation()
      throws Exception {
    stubSealing();
    HttpsServer server1 = startHttpsServer();
    server1.createContext(
        "/dav/",
        exchange -> {
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    HttpsServer server2 =
        startHttpsServer(
            new AtomicReference<>(rotatedServerCertificate),
            new AtomicInteger(),
            /* onHandshake= */ null);
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      String server1Url = "https://localhost:" + server1.getAddress().getPort() + "/dav/";
      String server2Url = "https://localhost:" + server2.getAddress().getPort() + "/dav/";
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      EditText urlField = webDavDialog.findViewById(R.id.webdav_server_url_input);
      Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
      fillWebDavFields(webDavDialog, server1Url, "alice", "correct horse");

      testButton.performClick();
      awaitServerKeyDialog(activity).getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }

      urlField.setText(server2Url);
      webDavDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      AlertDialog secondServerDialog = awaitServerKeyDialog(activity);
      expect.that(secondServerDialog.isShowing()).isTrue();
      expect
          .that(messageOf(secondServerDialog))
          .doesNotContain(activity.getString(R.string.webdav_server_key_changed));
      expect
          .that(messageOf(secondServerDialog))
          .endsWith(
              WebDavServerKeyPin.of(rotatedServerCertificate.keyPair().getPublic()).fingerprint());
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());

      secondServerDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      webDavDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();

      AlertDialog reopenedDialog = openWebDavDialog(activity);
      saveWebDavSettings(reopenedDialog, server1Url, "alice", "correct horse");
      AlertDialog reopenedPinDialog = awaitServerKeyDialog(activity);
      expect.that(reopenedPinDialog.isShowing()).isTrue();
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());
    } finally {
      server1.stop(0);
      server2.stop(0);
    }
  }

  @Test
  public void webDavKeyConfirmation_whenKeyUnchangedOrChangedOnRetest_skipsPromptOrWarnsUser()
      throws Exception {
    stubSealing();
    AtomicReference<HeldCertificate> activeCertificate = new AtomicReference<>(serverCertificate);
    HttpsServer server =
        startHttpsServer(activeCertificate, new AtomicInteger(), /* onHandshake= */ null);
    AtomicInteger responseStatus = new AtomicInteger(401);
    server.createContext(
        "/dav/",
        exchange -> {
          exchange.sendResponseHeaders(responseStatus.get(), -1);
          exchange.close();
        });
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      String serverUrl = "https://localhost:" + server.getAddress().getPort() + "/dav/";
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
      Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
      TextView statusText = webDavDialog.findViewById(R.id.webdav_status_text);
      fillWebDavFields(webDavDialog, serverUrl, "alice", "wrong password");

      testButton.performClick();
      awaitServerKeyDialog(activity).getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }
      expect
          .that(statusText.getText().toString())
          .isEqualTo(activity.getString(R.string.webdav_result_auth_failed));

      responseStatus.set(200);
      passwordField.setText("correct horse");
      testButton.performClick();
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }
      expect
          .that(statusText.getText().toString())
          .isEqualTo(activity.getString(R.string.webdav_result_success));

      activeCertificate.set(rotatedServerCertificate);
      testButton.performClick();
      AlertDialog warningDialog = awaitServerKeyDialog(activity);
      expect.that(warningDialog.isShowing()).isTrue();
      expect
          .that(messageOf(warningDialog))
          .contains(activity.getString(R.string.webdav_server_key_changed));
      expect
          .that(messageOf(warningDialog))
          .endsWith(
              WebDavServerKeyPin.of(rotatedServerCertificate.keyPair().getPublic()).fingerprint());

      // Cancelling after a key change clears lastConfirmedPin so Save cannot bypass confirmation.
      warningDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      activeCertificate.set(serverCertificate);
      webDavDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      AlertDialog savePinDialog = awaitServerKeyDialog(activity);
      expect.that(savePinDialog.isShowing()).isTrue();
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());
      savePinDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      expect.that(webDavDialog.isShowing()).isFalse();

      // Reopening with a persisted pin warns if the server presents a different key on Save, also
      // when the URL spells the same scheme, host and port differently.
      activeCertificate.set(rotatedServerCertificate);
      AlertDialog reopenedDialog = openWebDavDialog(activity);
      saveWebDavSettings(
          reopenedDialog,
          "https://LOCALHOST:" + server.getAddress().getPort() + "/dav",
          "alice",
          "new password");
      AlertDialog persistedWarningDialog = awaitServerKeyDialog(activity);
      expect.that(persistedWarningDialog.isShowing()).isTrue();
      expect
          .that(messageOf(persistedWarningDialog))
          .startsWith(
              activity.getString(
                  R.string.webdav_server_key_differs_from_saved,
                  WebDavServerKeyPin.of(serverCertificate.keyPair().getPublic()).fingerprint()));
      persistedWarningDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      reopenedDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void webDavKeyConfirmation_whenDialogDismissedWhileReadingKey_ignoresLateResult()
      throws Exception {
    stubSealing();
    CountDownLatch handshakeStarted = new CountDownLatch(1);
    CountDownLatch allowHandshake = new CountDownLatch(1);
    HttpsServer server =
        startHttpsServer(
            new AtomicReference<>(serverCertificate),
            new AtomicInteger(),
            () -> {
              handshakeStarted.countDown();
              try {
                allowHandshake.await(5, TimeUnit.SECONDS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            });
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      saveWebDavSettings(
          webDavDialog,
          "https://localhost:" + server.getAddress().getPort() + "/dav/",
          "alice",
          "correct horse");
      AlertDialog confirmationDialog = getLatestAppCompatAlertDialog();
      assertThat(handshakeStarted.await(5, TimeUnit.SECONDS)).isTrue();

      webDavDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      expect.that(webDavDialog.isShowing()).isFalse();
      expect.that(confirmationDialog.isShowing()).isFalse();

      allowHandshake.countDown();
      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 20; attempt++) {
        mainLooper.poll(/* timeout= */ 25);
        mainLooper.idle();
      }

      expect
          .that(messageOf(confirmationDialog))
          .isEqualTo(activity.getString(R.string.webdav_reading_server_key));
      expect.that(confirmationDialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled()).isFalse();
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());
    } finally {
      allowHandshake.countDown();
      server.stop(0);
    }
  }

  @Test
  public void webDavDialog_whenServerKeyIsNotVouchedForByATrustedCa_savesNothing()
      throws Exception {
    stubSealing();
    HttpsServer server = startHttpsServer();
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog confirmationDialog = saveHttpsWebDavSettings(activity, server);

      expect
          .that(messageOf(confirmationDialog))
          .isEqualTo(activity.getString(R.string.webdav_server_key_unreadable));
      expect.that(confirmationDialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled()).isFalse();
      expect
          .that(readSavedRemoteStorageConfig())
          .isEqualTo(RemoteStorageConfig.getDefaultInstance());
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void fileTreeResult_whenWebDavIsConfigured_replacesItWithTheFolder() throws Exception {
    stubSealing();
    Uri treeUri = Uri.parse("content://com.android.externalstorage.documents/tree/valid_folder");
    int grantFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
    context.getContentResolver().takePersistableUriPermission(treeUri, grantFlags);
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    saveWebDavSettings(openWebDavDialog(activity), WEBDAV_SERVER_URL, "alice", "correct horse");

    activity.onActivityResult(
        CrumblesConstants.FILE_TREE_REQUEST_CODE,
        Activity.RESULT_OK,
        new Intent().setData(treeUri).addFlags(grantFlags));

    assertThat(readSavedRemoteStorageConfig())
        .isEqualTo(
            RemoteStorageConfig.newBuilder()
                .setStorageType(StorageType.STORAGE_TYPE_GOOGLE_DRIVE)
                .setUploadDestinationUri(treeUri.toString())
                .build());
  }

  @Test
  public void fileTreeResult_releasesTheGrantOfThePreviousFolder() {
    Uri oldTreeUri = Uri.parse("content://com.android.externalstorage.documents/tree/old_folder");
    Uri newTreeUri = Uri.parse("content://com.android.externalstorage.documents/tree/new_folder");
    int grantFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
    context.getContentResolver().takePersistableUriPermission(oldTreeUri, grantFlags);
    context.getContentResolver().takePersistableUriPermission(newTreeUri, grantFlags);
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    activity.onActivityResult(
        CrumblesConstants.FILE_TREE_REQUEST_CODE,
        Activity.RESULT_OK,
        new Intent().setData(newTreeUri).addFlags(grantFlags));

    assertThat(
            context.getContentResolver().getPersistedUriPermissions().stream()
                .map(UriPermission::getUri)
                .toList())
        .containsExactly(newTreeUri);
  }

  @Test
  public void webDavSave_releasesTheGrantOfTheFolder() throws Exception {
    stubSealing();
    context
        .getContentResolver()
        .takePersistableUriPermission(
            Uri.parse("content://com.android.externalstorage.documents/tree/valid_folder"),
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();

    saveWebDavSettings(openWebDavDialog(activity), WEBDAV_SERVER_URL, "alice", "correct horse");

    assertThat(context.getContentResolver().getPersistedUriPermissions()).isEmpty();
  }

  @Test
  public void webDavTestConnection_whenFieldsInvalid_showsInvalidFieldsMessage() {
    CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
    AlertDialog webDavDialog = openWebDavDialog(activity);
    Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
    TextView statusText = webDavDialog.findViewById(R.id.webdav_status_text);

    fillWebDavFields(webDavDialog, "https://alice:secret@dav.example.com/dav/", "alice", "secret");
    testButton.performClick();
    expect
        .that(statusText.getText().toString())
        .isEqualTo(activity.getString(R.string.toast_webdav_invalid_fields));

    statusText.setText("");
    fillWebDavFields(webDavDialog, WEBDAV_SERVER_URL, "", "secret");
    testButton.performClick();
    expect
        .that(statusText.getText().toString())
        .isEqualTo(activity.getString(R.string.toast_webdav_invalid_fields));

    statusText.setText("");
    fillWebDavFields(webDavDialog, WEBDAV_SERVER_URL, "alice", "");
    testButton.performClick();
    expect
        .that(statusText.getText().toString())
        .isEqualTo(activity.getString(R.string.toast_webdav_invalid_fields));
  }

  @Test
  public void webDavTestConnection_whenServerReturns401_showsAuthFailedAndReEnablesButton()
      throws Exception {
    InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    HttpServer server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
    server.createContext(
        "/dav/",
        exchange -> {
          exchange.sendResponseHeaders(401, -1);
          exchange.close();
        });
    server.start();
    try {
      String serverUrl =
          "http://"
              + loopback.getHostAddress()
              + ":"
              + server.getAddress().getPort()
              + "/dav/";
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      fillWebDavFields(webDavDialog, serverUrl, "alice", "wrong password");
      Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
      TextView statusText = webDavDialog.findViewById(R.id.webdav_status_text);

      testButton.performClick();
      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }

      expect
          .that(statusText.getText().toString())
          .isEqualTo(activity.getString(R.string.webdav_result_auth_failed));
      expect.that(testButton.isEnabled()).isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void webDavTestConnection_whenServerReturns404_showsServerNotFoundWith404Code()
      throws Exception {
    InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    HttpServer server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
    server.createContext(
        "/dav/",
        exchange -> {
          exchange.sendResponseHeaders(404, -1);
          exchange.close();
        });
    server.start();
    try {
      String serverUrl =
          "http://"
              + loopback.getHostAddress()
              + ":"
              + server.getAddress().getPort()
              + "/dav/";
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      fillWebDavFields(webDavDialog, serverUrl, "alice", "correct horse");
      Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
      TextView statusText = webDavDialog.findViewById(R.id.webdav_status_text);

      testButton.performClick();
      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }

      expect
          .that(statusText.getText().toString())
          .isEqualTo(activity.getString(R.string.webdav_result_server_not_found, 404));
      expect.that(testButton.isEnabled()).isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void webDavTestConnection_forHttpsServer_sendsCredentialsOnlyAfterUserConfirmsKey()
      throws Exception {
    HttpsServer server = startHttpsServer();
    AtomicReference<String> receivedAuth = new AtomicReference<>();
    CountDownLatch requestArrived = new CountDownLatch(1);
    CountDownLatch releaseResponse = new CountDownLatch(1);
    server.createContext(
        "/dav/",
        exchange -> {
          receivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
          requestArrived.countDown();
          try {
            releaseResponse.await(5, TimeUnit.SECONDS);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      CrumblesMain activity = Robolectric.buildActivity(CrumblesMain.class).setup().get();
      AlertDialog webDavDialog = openWebDavDialog(activity);
      fillWebDavFields(
          webDavDialog,
          "HTTPS://localhost:" + server.getAddress().getPort() + "/dav/",
          "alice",
          "correct horse");
      Button testButton = webDavDialog.findViewById(R.id.webdav_test_connection_button);
      TextView statusText = webDavDialog.findViewById(R.id.webdav_status_text);

      testButton.performClick();
      expect.that(testButton.isEnabled()).isFalse();
      awaitServerKeyDialog(activity).getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
      shadowOf(Looper.getMainLooper()).idle();
      expect.that(testButton.isEnabled()).isTrue();
      expect.that(receivedAuth.get()).isNull();

      testButton.performClick();
      awaitServerKeyDialog(activity).getButton(AlertDialog.BUTTON_POSITIVE).performClick();
      assertThat(requestArrived.await(5, TimeUnit.SECONDS)).isTrue();
      shadowOf(Looper.getMainLooper()).idle();
      expect.that(testButton.isEnabled()).isFalse();
      releaseResponse.countDown();

      ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
      for (int attempt = 0; attempt < 50 && !testButton.isEnabled(); attempt++) {
        mainLooper.poll(/* timeout= */ 100);
        mainLooper.idle();
      }

      expect.that(receivedAuth.get()).isNotNull();
      expect
          .that(statusText.getText().toString())
          .isEqualTo(activity.getString(R.string.webdav_result_success));
    } finally {
      releaseResponse.countDown();
      server.stop(0);
    }
  }

  private static void clickAndConfirmPrompt(Activity activity, int viewId) {
    clickToOpenPrompt(activity, viewId);
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();
  }

  private static void clickAndCancelPrompt(Activity activity, int viewId) {
    clickToOpenPrompt(activity, viewId);
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Cancelled");
    shadowOf(Looper.getMainLooper()).idle();
  }

  private static void clickToOpenPrompt(Activity activity, int viewId) {
    shadowOf((KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(true);
    activity.findViewById(viewId).performClick();
  }

  /** Opens the WebDAV dialog after the user confirms their device credential. */
  private static AlertDialog openWebDavDialog(CrumblesMain activity) {
    clickAndConfirmPrompt(activity, R.id.btn_select_upload_dest);
    getLatestAppCompatAlertDialog()
        .getListView()
        .performItemClick(/* view= */ null, /* position= */ 1, /* id= */ 1);
    shadowOf(Looper.getMainLooper()).idle();
    return getLatestAppCompatAlertDialog();
  }

  /** Fills in the WebDAV dialog and taps its save button. */
  private static void saveWebDavSettings(
      AlertDialog webDavDialog, String serverUrl, String username, String password) {
    fillWebDavFields(webDavDialog, serverUrl, username, password);
    webDavDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();
  }

  private static void fillWebDavFields(
      AlertDialog webDavDialog, String serverUrl, String username, String password) {
    EditText urlField = webDavDialog.findViewById(R.id.webdav_server_url_input);
    EditText usernameField = webDavDialog.findViewById(R.id.webdav_username_input);
    EditText passwordField = webDavDialog.findViewById(R.id.webdav_password_input);
    urlField.setText(serverUrl);
    usernameField.setText(username);
    passwordField.setText(password);
  }

  private static AlertDialog saveHttpsWebDavSettings(CrumblesMain activity, HttpsServer server) {
    saveWebDavSettings(
        openWebDavDialog(activity),
        "https://localhost:" + server.getAddress().getPort() + "/dav/",
        "alice",
        "correct horse");
    return awaitServerKeyDialog(activity);
  }

  private static AlertDialog awaitServerKeyDialog(CrumblesMain activity) {
    AlertDialog dialog = getLatestAppCompatAlertDialog();
    String reading = activity.getString(R.string.webdav_reading_server_key);
    ShadowPausedLooper mainLooper = (ShadowPausedLooper) shadowOf(Looper.getMainLooper());
    for (int attempt = 0; attempt < 50 && messageOf(dialog).equals(reading); attempt++) {
      mainLooper.poll(/* timeout= */ 100);
      mainLooper.idle();
    }
    return dialog;
  }

  private static String messageOf(AlertDialog dialog) {
    return ((TextView) dialog.findViewById(android.R.id.message)).getText().toString();
  }

  private static HttpsServer startHttpsServer() throws Exception {
    return startHttpsServer(
        new AtomicReference<>(serverCertificate), new AtomicInteger(), /* onHandshake= */ null);
  }

  private static HttpsServer startHttpsServer(
      AtomicReference<HeldCertificate> activeCertificate,
      AtomicInteger handshakesAttempted,
      Runnable onHandshake)
      throws Exception {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        new KeyManager[] {new DynamicKeyManager(activeCertificate)},
        /* tm= */ null,
        /* random= */ null);
    HttpsServer server =
        HttpsServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.setHttpsConfigurator(
        new HttpsConfigurator(sslContext) {
          @Override
          public void configure(HttpsParameters params) {
            handshakesAttempted.incrementAndGet();
            if (onHandshake != null) {
              onHandshake.run();
            }
          }
        });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    return server;
  }

  private static final class DynamicKeyManager extends X509ExtendedKeyManager {
    private final AtomicReference<HeldCertificate> activeCertificate;

    DynamicKeyManager(AtomicReference<HeldCertificate> activeCertificate) {
      this.activeCertificate = activeCertificate;
    }

    private X509KeyManager current() {
      return new HandshakeCertificates.Builder()
          .heldCertificate(activeCertificate.get())
          .build()
          .keyManager();
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
      X509KeyManager delegate = current();
      return delegate instanceof X509ExtendedKeyManager extended
          ? extended.chooseEngineServerAlias(keyType, issuers, engine)
          : delegate.chooseServerAlias(keyType, issuers, /* socket= */ null);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      return current().chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      return current().getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
      return current().getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      return current().getServerAliases(keyType, issuers);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      return current().getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
      return current().chooseClientAlias(keyType, issuers, socket);
    }
  }

  private static byte[] serverKeySha256() throws Exception {
    return MessageDigest.getInstance("SHA-256")
        .digest(serverCertificate.keyPair().getPublic().getEncoded());
  }

  /** Makes the mock encryptor return {@link #fakeSealedPayload} for every value it seals. */
  private void stubSealing() throws CrumblesKeysException {
    Map<EncryptedPayload, byte[]> sealedPayloads = new HashMap<>();
    when(mockLogsEncryptor.encryptDataStoreEntry(any(byte[].class), anyString()))
        .thenAnswer(
            invocation -> {
              byte[] plaintext = invocation.getArgument(0);
              String entryId = invocation.getArgument(1);
              EncryptedPayload payload = fakeSealedPayload(new String(plaintext, UTF_8), entryId);
              sealedPayloads.put(payload, plaintext.clone());
              return payload;
            });
    when(mockLogsEncryptor.decryptDataStoreEntry(any(EncryptedPayload.class), anyString()))
        .thenAnswer(
            invocation -> {
              EncryptedPayload payload = invocation.getArgument(0);
              String entryId = invocation.getArgument(1);
              byte[] plaintext = sealedPayloads.get(payload);
              if (plaintext == null
                  || !payload.getCiphertext().toStringUtf8().startsWith(entryId + ":")) {
                throw new CrumblesKeysException("Unrecognized payload for " + entryId);
              }
              return plaintext.clone();
            });
  }

  /** Returns a stand-in for {@code plaintext} sealed to the DataStore entry {@code entryId}. */
  private static EncryptedPayload fakeSealedPayload(String plaintext, String entryId) {
    return EncryptedPayload.newBuilder()
        .setCiphertext(ByteString.copyFromUtf8(entryId + ":" + plaintext))
        .build();
  }

  private RemoteStorageConfig readSavedRemoteStorageConfig() throws Exception {
    return CrumblesDataStoreHolder.getInstance(context)
        .getDataAsync()
        .get()
        .getRemoteStorageConfig();
  }

  /** Returns whether {@code activity} keeps the overlay windows of other apps hidden. */
  private static boolean hidesOverlayWindows(Activity activity) {
    return hidesOverlayWindows(activity.getWindow());
  }

  /** Returns whether {@code window} keeps the overlay windows of other apps hidden. */
  private static boolean hidesOverlayWindows(Window window) {
    int hideOverlays =
        ReflectionHelpers.getStaticField(
            WindowManager.LayoutParams.class, "SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS");
    int privateFlags = ReflectionHelpers.getField(window.getAttributes(), "privateFlags");
    return (privateFlags & hideOverlays) == hideOverlays;
  }

  @Test
  public void onDestroy_shutsDownDecryptionInputExecutor() {
    ActivityController<CrumblesMain> controller = Robolectric.buildActivity(CrumblesMain.class);
    CrumblesMain activity = controller.setup().get();
    ExecutorService executor = ReflectionHelpers.getField(activity, "decryptionInputExecutor");

    controller.destroy();

    assertThat(executor.isShutdown()).isTrue();
  }

  private static final class TestRootTrustProvider extends Provider {
    static final String NAME = "CrumblesMainTestRootTrust";

    @SuppressWarnings("deprecation") // Android lacks Provider(String, String, String).
    TestRootTrustProvider() {
      super(NAME, 1.0, "Trusts only the test root CA");
      TrustManager[] trustManagers = {
        new HandshakeCertificates.Builder()
            .addTrustedCertificate(testRootCertificate.certificate())
            .build()
            .trustManager()
      };
      putService(
          new Service(
              this,
              "TrustManagerFactory",
              TrustManagerFactory.getDefaultAlgorithm(),
              TrustManagerFactorySpi.class.getName(),
              /* aliases= */ null,
              /* attributes= */ null) {
            @Override
            public Object newInstance(Object param) {
              return new TrustManagerFactorySpi() {
                @Override
                protected void engineInit(KeyStore keyStore) {}

                @Override
                protected void engineInit(ManagerFactoryParameters parameters) {}

                @Override
                protected TrustManager[] engineGetTrustManagers() {
                  return trustManagers;
                }
              };
            }
          });
    }
  }
}
