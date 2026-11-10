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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.app.Dialog;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.hardware.biometrics.BiometricPrompt;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleRegistry;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesLogsEncryptor.BulkDecryptPartition;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.truth.Expect;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.BatchSignature;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowBiometricPrompt;
import org.robolectric.shadows.ShadowDialog;
import org.robolectric.shadows.ShadowLooper;
import org.robolectric.shadows.ShadowResolveInfo;
import org.robolectric.shadows.ShadowToast;
import org.robolectric.util.ReflectionHelpers;

/** Unit tests for {@link CrumblesManageExternalKeysActivity}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesManageExternalKeysActivityTest {

  private static final String FOLDER_AUTHORITY = "com.android.securelogging.test.folder";
  private static final Uri FOLDER_URI =
      DocumentsContract.buildTreeDocumentUri(FOLDER_AUTHORITY, "chosen_folder");
  // No provider is registered for this authority, so nothing can be copied into the folder.
  private static final Uri UNREACHABLE_FOLDER_URI =
      DocumentsContract.buildTreeDocumentUri("com.android.securelogging.test.gone", "folder");
  // A document rather than a folder, so it cannot be opened as a document tree.
  private static final Uri NOT_A_FOLDER_URI =
      DocumentsContract.buildDocumentUri(FOLDER_AUTHORITY, "chosen_file");
  private static final String LOG_CONTENT = "encrypted log batch";
  private static final String THEATRE_TICKET_QR_PAYLOAD = "TICKET:Hamlet;ROW=F;SEAT=12";

  @Rule public final Expect expect = Expect.create();

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private KeyPair testExternalKeyPair;
  private PublicKey testPublicKey;
  private ActivityScenario<CrumblesManageExternalKeysActivity> scenario;
  private Context appContext;

  private static KeyPair generateTestRsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return kpg.generateKeyPair();
  }

  /** Returns the key's fingerprint as activity log events name it. */
  private static String fingerprintOf(PublicKey key) throws CrumblesKeysException {
    return CrumblesLogsEncryptor.getPublicKeyFingerprint(key).replace('\n', ':');
  }

  /**
   * Gets the most recently shown dialog and casts it to the support library's AlertDialog. This is
   * necessary because ShadowAlertDialog.getLatestAlertDialog() returns the native version.
   */
  private AlertDialog getLatestAppCompatAlertDialog() {
    List<Dialog> shownDialogs = ShadowDialog.getShownDialogs();
    if (shownDialogs.isEmpty()) {
      return null;
    }
    Dialog lastDialog = Iterables.getLast(shownDialogs);
    if (lastDialog instanceof AlertDialog alertDialog) {
      return alertDialog;
    }
    return null;
  }

  @Before
  public void setUp() throws Exception {
    // Given: Mocks are initialized.
    MockitoAnnotations.openMocks(this);
    appContext = ApplicationProvider.getApplicationContext();
    // Using a simpler base theme for testing to avoid Material Components interfering
    // with Robolectric's dialog shadowing.
    appContext.setTheme(R.style.Theme_AppCompat);
    shadowOf(appContext.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    // Declared in the manifest, so granted at install.
    shadowOf((Application) appContext).grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);

    testExternalKeyPair = generateTestRsaKeyPair();
    testPublicKey = testExternalKeyPair.getPublic();
    // Any key pair will do: the activity only reads the new Keystore key's public key, to record
    // its fingerprint.
    when(mockLogsEncryptor.generateKeyPair()).thenReturn(testExternalKeyPair);
    // Like the real encryptor, the mock never returns null plaintext.
    when(mockLogsEncryptor.decryptLogBatch(any())).thenReturn(decrypted(new byte[0]));
    // And: The static accessor for CrumblesLogsEncryptor in CrumblesMain is made to return our
    // mock.
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    // And: Each pending file holds its own batch, and every batch goes to the RSA key, as for
    // batches without batch-unwrap keys.
    when(mockLogsEncryptor.deserializeFile(any()))
        .thenAnswer(invocation -> LogBatch.newBuilder().build());
    when(mockLogsEncryptor.partitionForBulkDecrypt(any()))
        .thenAnswer(
            invocation ->
                new BulkDecryptPartition(
                    ImmutableList.of(),
                    ImmutableList.copyOf(invocation.<List<LogBatch>>getArgument(0)),
                    ImmutableList.of()));
    // And: The CrumblesAppAuditLogger singleton is replaced with our mock for this test class.
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);
  }

  @After
  @SuppressWarnings("ActivityScenarioNoAutoClose")
  public void tearDown() {
    // Given: Test environment might have mocks or state set.
    // When: Test finishes.
    // Then: Reset static mocks.
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    // And: Close activity scenario.
    if (scenario != null) {
      scenario.close();
    }
  }

  private void launchActivity() {
    scenario = ActivityScenario.launch(CrumblesManageExternalKeysActivity.class);
    // Inject mocks after launch but before the activity is resumed. Keys are generated on the
    // calling thread, so that each step of a key change has completed when the test checks it.
    scenario.onActivity(
        activity -> {
          activity.setPublicKeyManagerForTest(mockPublicKeyManager);
          activity.setKeyGenerationExecutorForTest(Runnable::run);
        });
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper(); // Ensure all initial UI tasks complete.
  }

  /**
   * Starts the key change of the button {@code buttonId}, whose key generation waits in {@code
   * keyGenerationTasks}.
   */
  private void startKeyChange(int buttonId, List<Runnable> keyGenerationTasks) {
    launchActivity();
    scenario.onActivity(
        activity -> {
          activity.updateStatusUi();
          activity.setKeyGenerationExecutorForTest(keyGenerationTasks::add);
          activity.findViewById(buttonId).performClick();
        });
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    keyGenerationTasks.remove(0).run();
    ShadowLooper.idleMainLooper();
  }

  private void mockSuccessfulKeyGeneration(byte[] keyBytes) throws CrumblesKeysException {
    PrivateKey mockPrivateKey = mock(PrivateKey.class);
    when(mockPrivateKey.getEncoded()).thenReturn(keyBytes);
    KeyPair keyPair = new KeyPair(testExternalKeyPair.getPublic(), mockPrivateKey);
    when(mockLogsEncryptor.generateCandidateExternalKeyPair()).thenReturn(keyPair);
  }

  /** Fake documents provider that saves the documents created in it to the app's cache folder. */
  private static final class FakeFolderProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
      return true;
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
      assertThat(method).isEqualTo("android:createDocument");
      Bundle result = new Bundle();
      result.putParcelable(
          "uri",
          DocumentsContract.buildDocumentUri(
              FOLDER_AUTHORITY, extras.getString(DocumentsContract.Document.COLUMN_DISPLAY_NAME)));
      return result;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      return ParcelFileDescriptor.open(
          new File(getContext().getCacheDir(), uri.getLastPathSegment()),
          ParcelFileDescriptor.parseMode(mode));
    }

    @Override
    public Cursor query(
        Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
      return null;
    }

    @Override
    public String getType(Uri uri) {
      return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
      return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
      return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
      return 0;
    }
  }

  /** Creates an encrypted log batch that is waiting to be uploaded. */
  private File createPendingLogFile(String fileName) throws IOException {
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsDir.isDirectory() || logsDir.mkdirs()).isTrue();
    File logFile = new File(logsDir, fileName);
    Files.writeString(logFile.toPath(), LOG_CONTENT);
    return logFile;
  }

  /** Starts a Keystore key change and picks "Upload As-Is" for the pending logs. */
  private void chooseUploadAsIs() {
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    getLatestAppCompatAlertDialog()
        .getListView()
        .performItemClick(/* view= */ null, /* position= */ 1, /* id= */ 1);
    ShadowLooper.idleMainLooper();
  }

  /** Ends the folder picker that "Upload As-Is" opened with the given result. */
  private void returnFromFolderPicker(int resultCode, Intent result) {
    scenario.onActivity(
        activity -> {
          Intent pickerIntent = shadowOf(activity).getNextStartedActivityForResult().intent;
          assertThat(pickerIntent.getAction()).isEqualTo(Intent.ACTION_OPEN_DOCUMENT_TREE);
          shadowOf(activity).receiveResult(pickerIntent, resultCode, result);
        });
    ShadowLooper.idleMainLooper();
  }

  @Test
  public void onGenerateKeystoreKey_clearsExternalAndGeneratesInternal() throws Exception {
    // Given: The activity is launched.
    launchActivity();

    // When: The "Generate Keystore Key Pair" button is clicked.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: The active external key is cleared from the manager and the encryptor.
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    verify(mockLogsEncryptor).setExternalEncryptionPublicKey(isNull(PublicKey.class));

    // And: A new internal key is generated.
    verify(mockLogsEncryptor).generateKeyPair();

    // And: An audit event is logged.
    verify(mockAuditLogger).logEvent("KEY_HANDOVER_NOT_NEEDED", "Changing to a new on-device key");
    verify(mockAuditLogger)
        .logEvent(
            "KEY_INTERNAL_GENERATED",
            "New internal Keystore key pair generated. Key fingerprint: "
                + fingerprintOf(testPublicKey)
                + ".");

    // And: A success toast is shown.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("New internal Keystore key generated successfully.");

    // And: The activity is finishing.
    // Check isFinishing() instead of lifecycle state for reliability.
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void onGenerateKeystoreKey_generatesOffTheMainThreadBehindProgressDialog()
      throws Exception {
    List<Runnable> keyGenerationTasks = new ArrayList<>();
    startKeyChange(R.id.btn_generate_keystore_key, keyGenerationTasks);
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();
    TextView progressMessage = progressDialog.findViewById(android.R.id.message);

    verify(mockLogsEncryptor, never()).generateKeyPair();
    expect.that(progressDialog.isShowing()).isTrue();
    expect.that(shadowOf(progressDialog).isCancelable()).isFalse();
    expect
        .that(progressMessage.getText().toString())
        .isEqualTo(appContext.getString(R.string.dialog_message_generating_key));
    scenario.onActivity(
        activity ->
            expect
                .that(activity.getRequestedOrientation())
                .isEqualTo(ActivityInfo.SCREEN_ORIENTATION_LOCKED));

    keyGenerationTasks.forEach(Runnable::run);

    verify(mockLogsEncryptor).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent(
            "KEY_INTERNAL_GENERATED",
            "New internal Keystore key pair generated. Key fingerprint: "
                + fingerprintOf(testPublicKey)
                + ".");
    expect.that(progressDialog.isShowing()).isFalse();
    scenario.onActivity(
        activity -> {
          expect
              .that(activity.getRequestedOrientation())
              .isEqualTo(ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED);
          expect.that(activity.isFinishing()).isTrue();
        });
  }

  @Test
  public void onGenerateKeystoreKey_whenScreenClosedBeforeGenerationEnds_completesKeyChange()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    List<Runnable> keyGenerationTasks = new ArrayList<>();
    startKeyChange(R.id.btn_generate_keystore_key, keyGenerationTasks);
    chooseReEncrypt();
    scenario.moveToState(Lifecycle.State.DESTROYED);
    assertThat(plaintext).isEqualTo(new byte[] {1, 2, 3});

    keyGenerationTasks.forEach(Runnable::run);
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor).generateKeyPair();
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(null);
    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), isNull());
    verify(mockAuditLogger).logEvent(eq("KEY_INTERNAL_GENERATED"), any());
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
  }

  @Test
  public void onGenerateExportableKey_generatesOffTheMainThreadThenOffersTheKey() throws Exception {
    mockSuccessfulKeyGeneration(new byte[] {1, 2, 3});
    List<Runnable> keyGenerationTasks = new ArrayList<>();
    startKeyChange(R.id.btn_generate_exportable_key, keyGenerationTasks);
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();

    verify(mockLogsEncryptor, never()).generateCandidateExternalKeyPair();
    expect.that(progressDialog.isShowing()).isTrue();

    keyGenerationTasks.forEach(Runnable::run);

    verify(mockLogsEncryptor).generateCandidateExternalKeyPair();
    expect.that(progressDialog.isShowing()).isFalse();
    TextView choiceMessage = getLatestAppCompatAlertDialog().findViewById(android.R.id.message);
    expect
        .that(choiceMessage.getText().toString())
        .isEqualTo(appContext.getString(R.string.dialog_message_choose_key_format));
  }

  @Test
  public void
      onGenerateKeystoreKey_whenUncheckedExceptionThrown_dismissesDialogAndUnlocksOrientation()
          throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    doThrow(new IllegalStateException("Unexpected provider failure"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    List<Runnable> keyGenerationTasks = new ArrayList<>();
    startKeyChange(R.id.btn_generate_keystore_key, keyGenerationTasks);
    chooseReEncrypt();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();

    assertThrows(IllegalStateException.class, () -> keyGenerationTasks.forEach(Runnable::run));
    ShadowLooper.idleMainLooper();

    expect.that(progressDialog.isShowing()).isFalse();
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
    scenario.onActivity(
        activity ->
            expect
                .that(activity.getRequestedOrientation())
                .isEqualTo(ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED));
  }

  @Test
  public void onClearActiveKey_clearsKeyAndUpdatesUi() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    // Given: An active key is mocked to exist.
    when(mockPublicKeyManager.getActiveExternalPublicKey())
        .thenReturn(testExternalKeyPair.getPublic());
    launchActivity();

    // When: The "Clear Active External Key" button is clicked.
    scenario.onActivity(
        activity -> {
          // Manually call updateStatusUi() after injection to refresh the view state.
          activity.updateStatusUi();

          // The button should be visible now.
          Button clearButton = activity.findViewById(R.id.btn_clear_active_external_key);
          assertThat(clearButton.getVisibility()).isEqualTo(View.VISIBLE);
          clearButton.performClick();
        });
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: The key is cleared from the manager and the encryptor.
    try {
      verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    } catch (CrumblesKeysException e) {
      throw new AssertionError("Test setup failed.", e);
    }
    verify(mockLogsEncryptor).setExternalEncryptionPublicKey(isNull(PublicKey.class));

    // And: An audit event is logged.
    verify(mockAuditLogger).logEvent("KEY_HANDOVER_NOT_NEEDED", "Clearing the external key");
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_CLEARED",
            "Active external key was cleared. Key fingerprint: "
                + fingerprintOf(testExternalKeyPair.getPublic())
                + ".");

    // And: A success toast is shown.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_external_key_cleared_successfully));
  }

  @Test
  public void onClearActiveKey_whenKeyBecameUnreadable_stillClearsIt() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    launchActivity();
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_clear_active_external_key).performClick());
    ShadowLooper.idleMainLooper();
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);

    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_CLEARED",
            "Active external key was cleared. Key fingerprint: unreadable.");

    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(isNull());
    clickClearActiveKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Error clearing active key: Storage unavailable");
  }

  @Test
  public void onClearActiveKey_handsOverOffTheMainThreadThenClearsTheKey() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    doAnswer(
            invocation -> {
              when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);
              return null;
            })
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(null);
    List<Runnable> backgroundTasks = new ArrayList<>();
    startKeyChange(R.id.btn_clear_active_external_key, backgroundTasks);
    chooseReEncrypt();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();
    TextView progressMessage = progressDialog.findViewById(android.R.id.message);

    verify(mockAuditLogger, never()).logEvent(eq("KEY_HANDOVER_NOT_NEEDED"), any());
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    expect.that(progressDialog.isShowing()).isTrue();
    expect
        .that(progressMessage.getText().toString())
        .isEqualTo(appContext.getString(R.string.dialog_message_handing_over_key));

    backgroundTasks.forEach(Runnable::run);

    InOrder inOrder = inOrder(mockAuditLogger, mockPublicKeyManager, mockLogsEncryptor);
    inOrder
        .verify(mockAuditLogger)
        .logEvent("KEY_HANDOVER_NOT_NEEDED", "Clearing the external key");
    inOrder.verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    inOrder.verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), isNull());
    expect.that(progressDialog.isShowing()).isFalse();
    scenario.onActivity(
        activity ->
            expect
                .that(activity.findViewById(R.id.btn_clear_active_external_key).getVisibility())
                .isEqualTo(View.GONE));
  }

  @Test
  public void onCreate_hidesOverlayWindows() {
    launchActivity();

    scenario.onActivity(activity -> assertThat(hidesOverlayWindows(activity)).isTrue());
  }

  @Test
  public void onCreate_setsFlagSecure() {
    launchActivity();
    scenario.onActivity(
        activity ->
            assertThat(
                    activity.getWindow().getAttributes().flags
                        & WindowManager.LayoutParams.FLAG_SECURE)
                .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE));
  }

  @Test
  public void onCreate_configuresSupportActionBarTitleAndUpNavigation() {
    launchActivity();

    scenario.onActivity(
        activity -> {
          ActionBar actionBar = activity.getSupportActionBar();
          assertThat(actionBar).isNotNull();
          expect
              .that(actionBar.getDisplayOptions() & ActionBar.DISPLAY_HOME_AS_UP)
              .isEqualTo(ActionBar.DISPLAY_HOME_AS_UP);
          expect
              .that(actionBar.getTitle().toString())
              .isEqualTo(appContext.getString(R.string.title_manage_external_keys));
        });
  }

  @Test
  public void onGenerateExportableKey_whenChoosingText_showsFragmentWithText() throws Exception {
    // Given: Key generation will succeed.
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();

    // When: All actions are performed on the UI thread first.
    scenario.onActivity(
        activity -> {
          // Perform the click that shows the choice dialog.
          activity.findViewById(R.id.btn_generate_exportable_key).performClick();
          ShadowLooper.idleMainLooper();
          confirmCredential(activity);

          // And: The user clicks "View as Text" in the choice dialog.
          AlertDialog choiceDialog = getLatestAppCompatAlertDialog();
          assertThat(choiceDialog).isNotNull();
          choiceDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
        });

    ShadowLooper.idleMainLooper();

    // Then: Perform assertions in a separate block to check the final state.
    scenario.onActivity(
        activity -> {
          activity.getSupportFragmentManager().executePendingTransactions();
          DialogFragment dialogFragment =
              (DialogFragment)
                  activity.getSupportFragmentManager().findFragmentByTag("private_key_viewer");
          assertThat(dialogFragment).isNotNull();
          Dialog dialog = dialogFragment.getDialog();
          assertThat(dialog).isNotNull();

          // And: It starts in the correct text view state.
          ScrollView textScrollView = dialog.findViewById(R.id.private_key_text_scrollview);
          ImageView qrCodeImageView = dialog.findViewById(R.id.private_key_qr_code_imageview);
          assertThat(textScrollView).isNotNull();
          assertThat(qrCodeImageView).isNotNull();
          assertThat(textScrollView.getVisibility()).isEqualTo(View.VISIBLE);
          assertThat(qrCodeImageView.getVisibility()).isEqualTo(View.GONE);
        });
  }

  @Test
  public void onGenerateExportableKey_whenChoosingQr_showsFragmentWithQr() throws Exception {
    // Given: Key generation will succeed.
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();

    // When: All actions are performed on the UI thread first.
    scenario.onActivity(
        activity -> {
          // Perform the click that shows the choice dialog.
          activity.findViewById(R.id.btn_generate_exportable_key).performClick();
          ShadowLooper.idleMainLooper();
          confirmCredential(activity);

          // And: The user clicks "View as QR Code" in the choice dialog.
          AlertDialog choiceDialog = getLatestAppCompatAlertDialog();
          assertThat(choiceDialog).isNotNull();
          choiceDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
        });

    ShadowLooper.idleMainLooper();

    // Then: Perform assertions in a separate block to check the final state.
    scenario.onActivity(
        activity -> {
          activity.getSupportFragmentManager().executePendingTransactions();
          DialogFragment dialogFragment =
              (DialogFragment)
                  activity.getSupportFragmentManager().findFragmentByTag("private_key_viewer");
          assertThat(dialogFragment).isNotNull();
          Dialog dialog = dialogFragment.getDialog();
          assertThat(dialog).isNotNull();

          // And: It starts in the correct QR view state.
          ScrollView textScrollView = dialog.findViewById(R.id.private_key_text_scrollview);
          ImageView qrCodeImageView = dialog.findViewById(R.id.private_key_qr_code_imageview);
          assertThat(textScrollView).isNotNull();
          assertThat(qrCodeImageView).isNotNull();
          assertThat(textScrollView.getVisibility()).isEqualTo(View.GONE);
          assertThat(qrCodeImageView.getVisibility()).isEqualTo(View.VISIBLE);
        });
  }

  private void triggerExportChoiceAndClick(int buttonId) {
    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_generate_exportable_key).performClick();
          ShadowLooper.idleMainLooper();
          confirmCredential(activity);
          AlertDialog choiceDialog = getLatestAppCompatAlertDialog();
          assertThat(choiceDialog).isNotNull();
          choiceDialog.getButton(buttonId).performClick();
        });
    ShadowLooper.idleMainLooper();
  }

  private DialogFragment getViewerDialogFragment() {
    AtomicReference<DialogFragment> fragmentRef = new AtomicReference<>();
    scenario.onActivity(
        activity -> {
          activity.getSupportFragmentManager().executePendingTransactions();
          fragmentRef.set(
              (DialogFragment)
                  activity.getSupportFragmentManager().findFragmentByTag("private_key_viewer"));
        });
    return fragmentRef.get();
  }

  @Test
  public void onChoiceDialog_whenCancelled_clearsTheKeyAndPreservesActiveKey() throws Exception {
    // Given: A candidate exportable key pair is generated.
    final byte[] privateKeyBytes = testExternalKeyPair.getPrivate().getEncoded();
    mockSuccessfulKeyGeneration(privateKeyBytes);
    launchActivity();

    // When: The user generates a key and cancels the export format choice dialog.
    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_generate_exportable_key).performClick();
          ShadowLooper.idleMainLooper();
          confirmCredential(activity);
          AlertDialog choiceDialog = getLatestAppCompatAlertDialog();
          assertThat(choiceDialog).isNotNull();
          choiceDialog.cancel();
          ShadowLooper.idleMainLooper();
        });

    // Then: The private key buffer is zeroed, candidate is rolled back, and toast is shown.
    assertThat(privateKeyBytes).isEqualTo(new byte[privateKeyBytes.length]);
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).commitExternalPublicKey(any());
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_key_export_cancelled_active_key_preserved));
    assertThat(getViewerDialogFragment()).isNull();

    // And: A subsequent custody confirmation does nothing because candidate key was cleared.
    scenario.onActivity(CrumblesManageExternalKeysActivity::onKeyCustodyConfirmed);
    ShadowLooper.idleMainLooper();
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).commitExternalPublicKey(any());
  }

  @Test
  public void onViewerDialog_whenDoneClicked_commitsAndActivatesCandidateKey() throws Exception {
    // Given: A candidate exportable key pair is generated.
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    doAnswer(
            invocation -> {
              when(mockPublicKeyManager.getActiveExternalPublicKey())
                  .thenReturn(testExternalKeyPair.getPublic());
              return null;
            })
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(testExternalKeyPair.getPublic());

    launchActivity();

    // When: The export format is chosen and the viewer "Done" button is clicked.
    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    DialogFragment dialogFragment = getViewerDialogFragment();
    assertThat(dialogFragment).isNotNull();
    Dialog dialog = dialogFragment.getDialog();
    assertThat(dialog).isNotNull();
    dialog.findViewById(R.id.btn_done).performClick();
    ShadowLooper.idleMainLooper();

    // Then: The candidate public key is saved and committed, and audit log is recorded.
    verify(mockAuditLogger)
        .logEvent(
            "KEY_HANDOVER_NOT_NEEDED",
            "Changing to a new exportable key with fingerprint "
                + CrumblesLogsEncryptor.getPublicKeyFingerprint(testExternalKeyPair.getPublic())
                    .replace('\n', ':'));
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(testExternalKeyPair.getPublic());
    verify(mockLogsEncryptor).commitExternalPublicKey(testExternalKeyPair.getPublic());
    verify(mockAuditLogger)
        .logEvent(
            "KEY_EXPORTABLE_GENERATED",
            "New exportable key pair generated and custody confirmed. Key fingerprint: "
                + fingerprintOf(testExternalKeyPair.getPublic())
                + ".");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_new_external_key_generated_successfully));

    // And: The UI status text and clear button are updated to reflect the active key.
    scenario.onActivity(
        activity -> {
          TextView tvStatus = activity.findViewById(R.id.tv_current_external_key_status);
          String expectedKeyHash =
              CrumblesLogsEncryptor.getPublicKeyHash(testExternalKeyPair.getPublic());
          assertThat(tvStatus.getText().toString())
              .isEqualTo(
                  appContext.getString(
                      R.string.status_external_key_active_formatted, expectedKeyHash));
          Button clearBtn = activity.findViewById(R.id.btn_clear_active_external_key);
          assertThat(clearBtn.getVisibility()).isEqualTo(View.VISIBLE);
        });
  }

  @Test
  public void onViewerDialog_whenDismissedWithoutDone_rollsBackCandidateKey() throws Exception {
    // Given: An active key is already present.
    when(mockPublicKeyManager.getActiveExternalPublicKey())
        .thenReturn(testExternalKeyPair.getPublic());
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();

    // When: The export dialog is shown and dismissed without clicking Done.
    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    DialogFragment dialogFragment = getViewerDialogFragment();
    assertThat(dialogFragment).isNotNull();
    scenario.onActivity(
        activity -> {
          TextView tvStatus = activity.findViewById(R.id.tv_current_external_key_status);
          tvStatus.setText("temporary_pending_state");
        });
    dialogFragment.dismiss();
    ShadowLooper.idleMainLooper();

    // Then: The candidate key is never committed, and UI status is restored.
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).commitExternalPublicKey(any());
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_key_export_cancelled_active_key_preserved));

    scenario.onActivity(
        activity -> {
          TextView tvStatus = activity.findViewById(R.id.tv_current_external_key_status);
          String expectedKeyHash =
              CrumblesLogsEncryptor.getPublicKeyHash(testExternalKeyPair.getPublic());
          assertThat(tvStatus.getText().toString())
              .isEqualTo(
                  appContext.getString(
                      R.string.status_external_key_active_formatted, expectedKeyHash));
        });

    // And: A subsequent custody confirmation does nothing because candidate key was cleared.
    scenario.onActivity(CrumblesManageExternalKeysActivity::onKeyCustodyConfirmed);
    ShadowLooper.idleMainLooper();
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).commitExternalPublicKey(any());
  }

  @Test
  public void onKeyCustodyConfirmed_whenNoPendingCandidatePublicKey_doesNothing() throws Exception {
    // Given: Activity is launched without any pending candidate key.
    launchActivity();

    // When: onKeyCustodyConfirmed is invoked directly.
    scenario.onActivity(CrumblesManageExternalKeysActivity::onKeyCustodyConfirmed);
    ShadowLooper.idleMainLooper();

    // Then: No public key is saved or committed.
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).commitExternalPublicKey(any());
  }

  @Test
  public void onKeyCustodyConfirmed_whenCommitFails_showsErrorToastAndClearsPending()
      throws Exception {
    // Given: Key generation succeeds but committing fails.
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    doThrow(new CrumblesKeysException("Commit failed"))
        .when(mockLogsEncryptor)
        .commitExternalPublicKey(any());

    launchActivity();

    // When: Format is chosen and Done is clicked.
    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    DialogFragment dialogFragment = getViewerDialogFragment();
    assertThat(dialogFragment).isNotNull();
    Dialog dialog = dialogFragment.getDialog();
    assertThat(dialog).isNotNull();
    dialog.findViewById(R.id.btn_done).performClick();
    ShadowLooper.idleMainLooper();

    // Then: Error toast is displayed.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Error activating external key: Commit failed");

    // And: The pending key was cleared, so a subsequent confirmation does nothing.
    scenario.onActivity(CrumblesManageExternalKeysActivity::onKeyCustodyConfirmed);
    ShadowLooper.idleMainLooper();
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(any());

    // And: A candidate key whose fingerprint cannot be computed fails before handover.
    when(mockLogsEncryptor.generateCandidateExternalKeyPair())
        .thenReturn(new KeyPair(mock(PublicKey.class), testExternalKeyPair.getPrivate()));
    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    clickViewerDone();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            "Error activating external key: Could not compute the fingerprint of a public key.");
  }

  @Test
  public void
      onGenerateKeystoreKey_whenPendingLogsExist_showsReEncryptDialogAndReEncryptsOnConfirmation()
          throws Exception {
    // Given: A pending log file exists in the logs subdirectory.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "test_log.bin");
    logFile.createNewFile();

    when(mockLogsEncryptor.decryptLogBatch(any())).thenReturn(decrypted(new byte[] {1, 2, 3}));
    when(mockLogsEncryptor.deserializeFile(any())).thenReturn(LogBatch.getDefaultInstance());
    when(mockLogsEncryptor.encryptLogsAttributedTo(any(), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());

    launchActivity();

    // When: The generate keystore key button is clicked.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: The re-encrypt confirmation dialog is shown.
    AlertDialog reEncryptDialog = getLatestAppCompatAlertDialog();
    assertThat(reEncryptDialog).isNotNull();

    // When: User clicks "Re-encrypt" (item 0).
    reEncryptDialog.getListView().performItemClick(null, 0, 0);
    ShadowLooper.idleMainLooper();

    // Then: Key pair generation proceeds.
    verify(mockLogsEncryptor).generateKeyPair();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Logs re-encrypted with new key pair.");

    // Cleanup test file.
    logFile.delete();
  }

  @Test
  public void onKeyCustodyConfirmed_whenReEncryptChosen_reEncryptsToCommittedKeyAndWipesLogs()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();

    clickViewerDone();

    InOrder inOrder = inOrder(mockLogsEncryptor);
    inOrder.verify(mockLogsEncryptor).commitExternalPublicKey(testPublicKey);
    inOrder.verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
    expect.that(plaintext).isEqualTo(new byte[plaintext.length]);
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_logs_re_encrypted));
  }

  @Test
  public void onKeyCustodyCancelled_whenReEncryptChosen_wipesLogsWithoutReEncrypting()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();

    getViewerDialogFragment().dismiss();
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor, never()).encryptLogsAttributedTo(any(), any(), any());
    expect.that(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFailsWithoutExternalKey_wipesLogsOnly()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    verify(mockLogsEncryptor, never()).encryptLogsAttributedTo(any(), any(), any());
    expect.that(plaintext).isEqualTo(new byte[plaintext.length]);
    verify(mockAuditLogger)
        .logEvent(
            "RE_ENCRYPT_FAILED",
            "1 pending log batch(es) (pending_batch.bin) could not be re-encrypted after key"
                + " change.");
    verify(mockAuditLogger)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST,
            "1 pending log batch(es) were lost after re-encryption and staging failed.");
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFailsAndActivityLogThrows_stillStagesLogs()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File processing = new File(logsDir, "pending_batch" + CrumblesConstants.PROCESSING_SUFFIX);
    assertThat(processing.createNewFile()).isTrue();
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    doThrow(new ProviderException()).when(mockAuditLogger).logEvent(eq("RE_ENCRYPT_FAILED"), any());
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    try {
      launchActivity();
      clickGenerateKeystoreKey();
      scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
      assertThrows(ProviderException.class, this::chooseReEncrypt);
    } finally {
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }

    expect.that(new CrumblesLogStaging(appContext).isEmpty()).isFalse();
    expect.that(new File(logsDir, "pending_batch.bin").exists()).isFalse();
    expect.that(processing.exists()).isFalse();
    verify(mockAuditLogger, never())
        .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST), anyString());
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFailsWithoutExternalKey_namesTheStagedBatches()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    when(mockLogsEncryptor.deserializeFile(any()))
        .thenReturn(
            LogBatch.newBuilder()
                .setSequenceNumber(7)
                .setSignature(BatchSignature.getDefaultInstance())
                .build());
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    launchActivity();
    clickAndConfirmKeystoreKey();

    chooseReEncrypt();

    verify(mockAuditLogger)
        .logEvent(
            CrumblesManageExternalKeysActivity.AUDIT_EVENT_RE_ENCRYPT_FAILED,
            "1 pending log batch(es) (seq 7) could not be re-encrypted after key change.");
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFailsAndActivityLogThrows_stillStagesHeldBatch()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    File pendingBatch =
        new File(
            appContext.getFilesDir(),
            CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY + "/pending_batch.bin");
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    doThrow(new ProviderException("Keystore operation failed"))
        .when(mockAuditLogger)
        .logEvent(eq(CrumblesManageExternalKeysActivity.AUDIT_EVENT_RE_ENCRYPT_FAILED), any());
    launchActivity();
    clickAndConfirmKeystoreKey();
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    try {
      assertThrows(ProviderException.class, this::chooseReEncrypt);

      expect.that(new CrumblesLogStaging(appContext).isEmpty()).isFalse();
    } finally {
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
    expect.that(pendingBatch.exists()).isFalse();
  }

  @Test
  public void onGenerateKeystoreKey_whenClearingTheExternalKeyRecordFails_usesTheNewKeyIfNoneLeft()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(isNull());
    launchActivity();
    clickAndConfirmKeystoreKey();

    chooseReEncrypt();

    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), isNull());
    verify(mockAuditLogger).logEvent(eq("KEY_INTERNAL_GENERATED"), any());
    verify(mockAuditLogger, never()).logEvent(eq("KEY_INTERNAL_GENERATION_FAILED"), any());
  }

  @Test
  public void onGenerateKeystoreKey_whenTheActiveExternalKeyCannotBeCleared_keepsItForTheLogs()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(isNull());
    launchActivity();
    clickAndConfirmKeystoreKey();

    chooseReEncrypt();

    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
    verify(mockAuditLogger, never()).logEvent(eq("KEY_INTERNAL_GENERATED"), any());
  }

  @Test
  public void onGenerateKeystoreKey_whenAnUnreadableSelectionCannotBeCleared_failsTheSwitch()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    // An external key is selected, but it cannot be read.
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(isNull());
    launchActivity();
    clickAndConfirmKeystoreKey();

    chooseReEncrypt();

    verify(mockLogsEncryptor, never()).encryptLogsAttributedTo(any(), any(), any());
    verify(mockAuditLogger).logEvent(eq("KEY_INTERNAL_GENERATION_FAILED"), any());
    verify(mockAuditLogger, never()).logEvent(eq("KEY_INTERNAL_GENERATED"), any());
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFails_reEncryptsLogsToActiveExternalKey()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFailsWithoutExternalKey_namesHeldBatches()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    when(mockLogsEncryptor.deserializeFile(any()))
        .thenReturn(
            LogBatch.newBuilder()
                .setSequenceNumber(7)
                .setSignature(BatchSignature.getDefaultInstance())
                .build());
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    InOrder inOrder = inOrder(mockAuditLogger);
    inOrder
        .verify(mockAuditLogger)
        .logEvent(
            "RE_ENCRYPT_FAILED",
            "1 pending log batch(es) (seq 7) could not be re-encrypted after key change.");
    inOrder
        .verify(mockAuditLogger)
        .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST), anyString());
  }

  @Test
  public void onGenerateKeystoreKey_whenSavingPreferencesFailsWithoutExternalKey_keepsNewKey()
      throws Exception {
    doThrow(new CrumblesKeysException("Preferences unwritable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(isNull());
    launchActivity();

    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    verify(mockLogsEncryptor).setExternalEncryptionPublicKey(isNull(PublicKey.class));
    verify(mockAuditLogger).logEvent(eq("KEY_INTERNAL_GENERATED"), anyString());
    verify(mockAuditLogger, never()).logEvent(eq("KEY_INTERNAL_GENERATION_FAILED"), anyString());
  }

  @Test
  public void onGenerateKeystoreKey_whenUnreadableSelectionCannotBeCleared_reportsFailure()
      throws Exception {
    doThrow(new CrumblesKeysException("Preferences unwritable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(isNull());
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    launchActivity();

    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    verify(mockLogsEncryptor, never()).setExternalEncryptionPublicKey(any());
    verify(mockAuditLogger).logEvent(eq("KEY_INTERNAL_GENERATION_FAILED"), anyString());
  }

  @Test
  public void processScannedPublicKey_whenReEncryptChosen_reEncryptsToScannedKeyOnceSaved()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    InOrder inOrder = inOrder(mockPublicKeyManager, mockLogsEncryptor);
    inOrder.verify(mockPublicKeyManager).saveActiveExternalPublicKey(testPublicKey);
    inOrder.verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
  }

  @Test
  public void processScannedPublicKey_whenSignedBatchIsReEncrypted_signsItAgain()
      throws Exception {
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    try {
      givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
      LogBatch signedOriginal =
          new CrumblesBatchSigner(appContext).sign(LogBatch.getDefaultInstance());
      when(mockLogsEncryptor.deserializeFile(any())).thenReturn(signedOriginal);
      when(mockLogsEncryptor.encryptLogs(any(), any(), any()))
          .thenAnswer(
              invocation -> {
                Context context = invocation.getArgument(0);
                return LogBatch.newBuilder()
                    .setMetadata(
                        LogMetadata.newBuilder()
                            .setBlobSize(3)
                            .setDevice(
                                DeviceId.newBuilder()
                                    .setDeviceId(CrumblesDeviceIdManager.getDeviceId(context))))
                    .build();
              });
      launchActivity();
      processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
      getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
      ShadowLooper.idleMainLooper();
      scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

      chooseReEncrypt();

      ArgumentCaptor<LogBatch> writtenBatch = ArgumentCaptor.forClass(LogBatch.class);
      verify(mockLogsEncryptor).serializeBytes(writtenBatch.capture(), any(), any());
      expect.that(writtenBatch.getValue().getSequenceNumber()).isEqualTo(1);
      expect
          .that(writtenBatch.getValue().getMetadata().getDevice().getDeviceId())
          .isEqualTo(CrumblesDeviceIdManager.getDeviceId(appContext));
      expect
          .that(
              new CrumblesBatchSigningKey(appContext)
                  .verifies(
                      writtenBatch.getValue().toBuilder().clearSignature().build().toByteArray(),
                      writtenBatch.getValue().getSignature().getSignature().toByteArray()))
          .isTrue();
      verify(mockAuditLogger, never())
          .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED), any());
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void processScannedPublicKey_whenSignedBatchCannotBeSignedAgain_writesItUnsigned()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    when(mockLogsEncryptor.deserializeFile(any()))
        .thenReturn(
            LogBatch.newBuilder()
                .setSequenceNumber(7)
                .setSignature(BatchSignature.getDefaultInstance())
                .build());
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    ArgumentCaptor<LogBatch> writtenBatch = ArgumentCaptor.forClass(LogBatch.class);
    verify(mockLogsEncryptor).serializeBytes(writtenBatch.capture(), any(), any());
    assertThat(writtenBatch.getValue().hasSignature()).isFalse();
    verify(mockLogsEncryptor, never()).encryptLogs(any(), any(), any());
    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
    verify(mockAuditLogger)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED,
            "Re-encrypted log batch 7 written without a signature: signing it again failed.");
  }

  @Test
  public void processScannedPublicKey_whenBatchSignedByAnotherKeyIsReEncrypted_createsNoKey()
      throws Exception {
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    try {
      givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
      LogBatch signedOriginal =
          new CrumblesBatchSigner(appContext).sign(LogBatch.getDefaultInstance());
      // As when the device ID changes, which deletes the batch-signing key.
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      when(mockLogsEncryptor.deserializeFile(any())).thenReturn(signedOriginal);
      launchActivity();
      processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
      getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
      ShadowLooper.idleMainLooper();
      scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

      chooseReEncrypt();

      verify(mockLogsEncryptor, never()).encryptLogs(any(), any(), any());
      verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
      expect
          .that(FakeAndroidKeyStoreSpi.keystoreEntries)
          .doesNotContainKey(CrumblesBatchSigningKey.ALIAS);
      verify(mockAuditLogger)
          .logEvent(
              CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED,
              "Re-encrypted log batch 1 written without a signature: signing it again failed.");
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void processScannedPublicKey_whenSignedBatchCannotBeReEncrypted_reportsItBySequence()
      throws Exception {
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    try {
      givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
      when(mockLogsEncryptor.deserializeFile(any()))
          .thenReturn(new CrumblesBatchSigner(appContext).sign(LogBatch.getDefaultInstance()));
      when(mockLogsEncryptor.encryptLogs(any(), any(), any())).thenReturn(null);
      launchActivity();
      processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
      getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
      ShadowLooper.idleMainLooper();
      scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

      chooseReEncrypt();

      verify(mockLogsEncryptor, never()).serializeBytes(any(), any(), any());
      verify(mockAuditLogger, never())
          .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED), any());
      verify(mockAuditLogger)
          .logEvent(
              CrumblesManageExternalKeysActivity.AUDIT_EVENT_RE_ENCRYPT_FAILED,
              "1 pending log batch(es) (seq 1) could not be re-encrypted after key change.");
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void processScannedPublicKey_whenUnsignedBatchIsReEncrypted_reportsNoSigningFailure()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    verify(mockLogsEncryptor).serializeBytes(eq(LogBatch.getDefaultInstance()), any(), any());
    verify(mockAuditLogger, never())
        .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED), any());
  }

  @Test
  public void processScannedPublicKey_whenUnsignedVersion2BatchIsReEncrypted_keepsItsSealedId()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    // A format version 2 batch seals its device ID, which may not be this device's current one.
    when(mockLogsEncryptor.decryptLogBatch(any()))
        .thenReturn(
            new DecryptedLogBatch(
                LogMetadata.newBuilder()
                    .setDevice(DeviceId.newBuilder().setDeviceId("sealed-device"))
                    .build(),
                new byte[] {1, 2, 3}));
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    chooseReEncrypt();

    verify(mockLogsEncryptor)
        .encryptLogsAttributedTo(eq("sealed-device"), any(), eq(testPublicKey));
    verify(mockLogsEncryptor, never()).encryptLogs(any(), any(), any());
  }

  @Test
  public void onDestroy_whileExportableKeyAwaitsCustody_wipesHeldLogsAndDisplayedKey()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();
    TextView displayedKey =
        getViewerDialogFragment().getDialog().findViewById(R.id.private_key_text_view);

    scenario.moveToState(Lifecycle.State.DESTROYED);

    expect.that(plaintext).isEqualTo(new byte[plaintext.length]);
    expect.that(displayedKey.getText().toString()).isEmpty();
  }

  @Test
  public void onClearActiveKey_afterHeldLogsWereReEncrypted_doesNotReEncryptThemAgain()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();
    clickViewerDone();

    clearActiveKeyDiscardingPendingLogs();

    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
    verify(mockLogsEncryptor, never()).encryptLogsAttributedTo(any(), any(), isNull());
  }

  @Test
  public void onClearActiveKey_afterHeldLogsWereDropped_doesNotReEncryptThem() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();
    getViewerDialogFragment().dismiss();
    ShadowLooper.idleMainLooper();

    clearActiveKeyDiscardingPendingLogs();

    verify(mockLogsEncryptor, never()).encryptLogsAttributedTo(any(), any(), any());
  }

  /** Clears the active key and picks "Discard Logs" for the pending logs. */
  private void clearActiveKeyDiscardingPendingLogs() {
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_clear_active_external_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    getLatestAppCompatAlertDialog().getListView().performItemClick(null, 2, 2);
    ShadowLooper.idleMainLooper();
  }

  /** Returns {@code logs} as decrypted from a batch without metadata. */
  private static DecryptedLogBatch decrypted(byte[] logs) {
    return new DecryptedLogBatch(LogMetadata.getDefaultInstance(), logs);
  }

  /** Creates one pending batch that the mock encryptor decrypts to {@code plaintext}. */
  private void givenPendingBatchDecryptingTo(byte[] plaintext) throws Exception {
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    new File(logsDir, "pending_batch.bin").createNewFile();
    when(mockLogsEncryptor.decryptLogBatch(any())).thenReturn(decrypted(plaintext));
    when(mockLogsEncryptor.deserializeFile(any())).thenReturn(LogBatch.getDefaultInstance());
    when(mockLogsEncryptor.encryptLogs(any(), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
    when(mockLogsEncryptor.encryptLogsAttributedTo(any(), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
  }

  /** Picks "Re-encrypt" in the dialog that asks what to do with the pending logs. */
  private void chooseReEncrypt() {
    getLatestAppCompatAlertDialog().getListView().performItemClick(null, 0, 0);
    ShadowLooper.idleMainLooper();
  }

  private void chooseReEncryptForExportableKeyAndViewItAsText() {
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_exportable_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    chooseReEncrypt();
    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
  }

  private void clickViewerDone() {
    getViewerDialogFragment().getDialog().findViewById(R.id.btn_done).performClick();
    ShadowLooper.idleMainLooper();
  }

  @Test
  public void onReEncryptDialog_whenUploadAsIsChosen_wipesDecryptedLogs() throws Exception {
    byte[] plaintext = {1, 2, 3};
    startKeystoreKeyChangeWithPendingBatchDecryptingTo(plaintext);

    getLatestAppCompatAlertDialog().getListView().performItemClick(null, 1, 1);
    ShadowLooper.idleMainLooper();

    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onReEncryptDialog_whenDiscardChosen_wipesDecryptedLogs() throws Exception {
    byte[] plaintext = {1, 2, 3};
    startKeystoreKeyChangeWithPendingBatchDecryptingTo(plaintext);

    getLatestAppCompatAlertDialog().getListView().performItemClick(null, 2, 2);
    ShadowLooper.idleMainLooper();

    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onReEncryptDialog_whenCancelClicked_wipesDecryptedLogs() throws Exception {
    byte[] plaintext = {1, 2, 3};
    startKeystoreKeyChangeWithPendingBatchDecryptingTo(plaintext);

    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_NEGATIVE).performClick();
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onReEncryptDialog_whenDismissedWithBack_wipesDecryptedLogs() throws Exception {
    byte[] plaintext = {1, 2, 3};
    startKeystoreKeyChangeWithPendingBatchDecryptingTo(plaintext);

    getLatestAppCompatAlertDialog().cancel();
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onGenerateKeystoreKey_whenAnotherPendingLogFailsToDecrypt_wipesDecryptedLogs()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchesDecryptingToThenThrowing(
        plaintext, new CrumblesKeysException("Keys did not match"));
    launchActivity();

    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    assertThat(
            getLatestAppCompatAlertDialog()
                .getButton(AlertDialog.BUTTON_NEUTRAL)
                .getText()
                .toString())
        .isEqualTo("Discard Logs");
    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onGenerateKeystoreKey_whenPromptForAnotherPendingLogIsCancelled_wipesDecryptedLogs()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchesDecryptingToThenThrowing(
        plaintext, new UserNotAuthenticatedException("User authentication required"));
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Authentication canceled");
    ShadowLooper.idleMainLooper();

    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onStop_whilePromptForAnotherPendingLogIsOpen_wipesDecryptedLogs() throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchesDecryptingToThenThrowing(
        plaintext, new UserNotAuthenticatedException("User authentication required"));
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    scenario.moveToState(Lifecycle.State.CREATED);

    assertThat(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  /** Creates two pending batches: one decrypts to {@code plaintext}, the other throws. */
  private void givenPendingBatchesDecryptingToThenThrowing(byte[] plaintext, Exception failure)
      throws Exception {
    givenPendingBatchDecryptingTo(plaintext);
    assertThat(createPendingLogFile("other_batch.bin").exists()).isTrue();
    when(mockLogsEncryptor.decryptLogBatch(any()))
        .thenReturn(decrypted(plaintext))
        .thenThrow(failure);
  }

  /** Starts a Keystore key change while one pending batch decrypts to {@code plaintext}. */
  private void startKeystoreKeyChangeWithPendingBatchDecryptingTo(byte[] plaintext)
      throws Exception {
    givenPendingBatchDecryptingTo(plaintext);
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
  }

  @Test
  public void onGenerateKeystoreKey_whenUploadAsIsCopiesAllLogs_marksThemSentAndChangesKey()
      throws Exception {
    File logFile = createPendingLogFile("test_log_asis.bin");
    Robolectric.buildContentProvider(FakeFolderProvider.class).create(FOLDER_AUTHORITY);
    launchActivity();
    chooseUploadAsIs();

    returnFromFolderPicker(Activity.RESULT_OK, new Intent().setData(FOLDER_URI));

    verify(mockLogsEncryptor).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent(
            "LOGS_COPIED_BEFORE_KEY_CHANGE",
            "1 pending log file(s) copied to a chosen folder before key rotation.");
    File copiedFile = new File(appContext.getCacheDir(), "test_log_asis.bin");
    expect.that(Files.readString(copiedFile.toPath())).isEqualTo(LOG_CONTENT);
    expect.that(new File(logFile.getParentFile(), "test_log_asis_sent.bin").exists()).isTrue();
    expect.that(logFile.exists()).isFalse();
    expect
        .that(
            ShadowToast.showedToast(
                appContext.getString(R.string.toast_logs_copied_before_key_change)))
        .isTrue();
  }

  @Test
  public void onGenerateKeystoreKey_whenUploadAsIs_recordsTheOutgoingKey() throws Exception {
    File logFile = createPendingLogFile("test_log_asis.bin");
    AtomicReference<PublicKey> internalKey = new AtomicReference<>(testPublicKey);
    when(mockLogsEncryptor.getPublicKey()).thenAnswer(invocation -> internalKey.get());
    KeyPair newKeyPair = generateTestRsaKeyPair();
    when(mockLogsEncryptor.generateKeyPair())
        .thenAnswer(
            invocation -> {
              internalKey.set(newKeyPair.getPublic());
              return newKeyPair;
            });
    Robolectric.buildContentProvider(FakeFolderProvider.class).create(FOLDER_AUTHORITY);
    launchActivity();
    chooseUploadAsIs();

    returnFromFolderPicker(Activity.RESULT_OK, new Intent().setData(FOLDER_URI));

    verify(mockLogsEncryptor).generateKeyPair();
    expect.that(logFile.exists()).isFalse();
    expect
        .that(
            appContext
                .getSharedPreferences(
                    CrumblesDeleteSentFilesWorker.SENT_KEY_PREFS, Context.MODE_PRIVATE)
                .getString("test_log_asis_sent.bin", null))
        .isEqualTo(CrumblesLogsEncryptor.getPublicKeyFingerprint(testPublicKey));
  }

  @Test
  public void onGenerateKeystoreKey_whenUploadFolderNotChosen_keepsKeyAndLogs() throws Exception {
    File logFile = createPendingLogFile("test_log_no_folder.bin");
    launchActivity();
    chooseUploadAsIs();

    returnFromFolderPicker(Activity.RESULT_CANCELED, /* result= */ null);

    verify(mockLogsEncryptor, never()).generateKeyPair();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_upload_folder_not_chosen));
    expect.that(logFile.exists()).isTrue();
  }

  @Test
  public void
      onGenerateKeystoreKey_whenPendingLogsExist_andUserSelectsDiscard_discardsLogsAndProceeds()
          throws Exception {
    // Given: A pending log file exists.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "test_log_discard.bin");
    logFile.createNewFile();

    launchActivity();

    // When: User clicks generate key.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: Re-encrypt dialog appears.
    AlertDialog reEncryptDialog = getLatestAppCompatAlertDialog();
    assertThat(reEncryptDialog).isNotNull();

    // When: User clicks "Discard Logs" (item 2).
    reEncryptDialog.getListView().performItemClick(null, 2, 2);
    ShadowLooper.idleMainLooper();

    // Then: Key pair generation proceeds and log file is deleted.
    verify(mockLogsEncryptor).generateKeyPair();
    assertThat(logFile.exists()).isFalse();
    verify(mockAuditLogger)
        .logEvent("LOGS_DISCARDED", "1 pending log file(s) discarded prior to key rotation.");

    // Cleanup test file.
    logFile.delete();
  }

  @Test
  public void onGenerateKeystoreKey_whenDecryptionFailsAndCopyFails_asksBeforeChangingKey()
      throws Exception {
    File logFile = createPendingLogFile("corrupt_log.bin");
    when(mockLogsEncryptor.deserializeFile(any())).thenThrow(new RuntimeException("Corrupt file"));
    launchActivity();
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    // Picks "Upload As-Is" in the decryption warning.
    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();

    returnFromFolderPicker(Activity.RESULT_OK, new Intent().setData(UNREACHABLE_FOLDER_URI));

    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent(
            "LOGS_COPY_BEFORE_KEY_CHANGE_FAILED",
            "1 of 1 pending log file(s) could not be copied before key rotation; kept on device.");
    Button confirmButton = getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE);
    expect
        .that(confirmButton.getText().toString())
        .isEqualTo(appContext.getString(R.string.dialog_logs_not_copied_confirm));
    expect.that(logFile.exists()).isTrue();
  }

  @Test
  public void onGenerateKeystoreKey_whenCopyFailsAndUserConfirms_changesKeyAndKeepsLogs()
      throws Exception {
    File logFile = createPendingLogFile("test_log_not_copied.bin");
    launchActivity();
    chooseUploadAsIs();
    returnFromFolderPicker(Activity.RESULT_OK, new Intent().setData(UNREACHABLE_FOLDER_URI));

    getLatestAppCompatAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor).generateKeyPair();
    assertThat(logFile.exists()).isTrue();
  }

  @Test
  public void onGenerateKeystoreKey_whenChosenLocationIsNotAFolder_keepsKeyAndLogs()
      throws Exception {
    File logFile = createPendingLogFile("test_log_not_a_folder.bin");
    launchActivity();
    chooseUploadAsIs();

    returnFromFolderPicker(Activity.RESULT_OK, new Intent().setData(NOT_A_FOLDER_URI));

    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent(
            "LOGS_COPY_BEFORE_KEY_CHANGE_FAILED",
            "1 of 1 pending log file(s) could not be copied before key rotation; kept on device.");
    expect.that(logFile.exists()).isTrue();
  }

  @Test
  public void onGenerateKeystoreKey_whenNoFolderPickerInstalled_asksBeforeChangingKey()
      throws Exception {
    File logFile = createPendingLogFile("test_log_no_picker.bin");
    launchActivity();
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    shadowOf((Application) appContext).checkActivities(true);

    getLatestAppCompatAlertDialog()
        .getListView()
        .performItemClick(/* view= */ null, /* position= */ 1, /* id= */ 1);
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent(
            "LOGS_COPY_BEFORE_KEY_CHANGE_FAILED",
            "1 of 1 pending log file(s) could not be copied before key rotation; kept on device.");
    expect.that(logFile.exists()).isTrue();
  }

  @Test
  public void onGenerateKeystoreKey_whenRecreatedWhileFolderPickerOpen_keepsKeyAndLogs()
      throws Exception {
    File logFile = createPendingLogFile("test_log_recreated.bin");
    Robolectric.buildContentProvider(FakeFolderProvider.class).create(FOLDER_AUTHORITY);
    launchActivity();
    chooseUploadAsIs();
    AtomicReference<Intent> pickerIntentRef = new AtomicReference<>();
    scenario.onActivity(
        activity ->
            pickerIntentRef.set(shadowOf(activity).getNextStartedActivityForResult().intent));

    scenario.recreate();
    scenario.onActivity(
        activity -> {
          activity.setPublicKeyManagerForTest(mockPublicKeyManager);
          shadowOf(activity)
              .receiveResult(
                  pickerIntentRef.get(), Activity.RESULT_OK, new Intent().setData(FOLDER_URI));
        });
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    expect.that(logFile.exists()).isTrue();
  }

  @Test
  public void
      onGenerateKeystoreKey_whenDecryptionFails_andUserSelectsDiscard_discardsLogsAndProceeds()
          throws Exception {
    // Given: A corrupt pending log file exists that cannot be decrypted.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "corrupt_log_discard.bin");
    logFile.createNewFile();

    when(mockLogsEncryptor.deserializeFile(any())).thenThrow(new RuntimeException("Corrupt file"));

    launchActivity();

    // When: User clicks generate key.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: Decryption error warning dialog appears.
    AlertDialog warningDialog = getLatestAppCompatAlertDialog();
    assertThat(warningDialog).isNotNull();

    // When: User clicks "Discard Logs" (BUTTON_NEUTRAL).
    warningDialog.getButton(AlertDialog.BUTTON_NEUTRAL).performClick();
    ShadowLooper.idleMainLooper();

    // Then: Key pair generation proceeds and log file is deleted.
    verify(mockLogsEncryptor).generateKeyPair();
    assertThat(logFile.exists()).isFalse();
    verify(mockAuditLogger)
        .logEvent("LOGS_DISCARDED", "1 pending log file(s) discarded prior to key rotation.");

    // Cleanup test file.
    logFile.delete();
  }

  @Test
  public void onGenerateKeystoreKey_whenDecryptionFails_showsErrorDialogAndCancelsOnNegativeButton()
      throws Exception {
    // Given: A corrupt pending log file exists that cannot be decrypted.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "corrupt_log.bin");
    logFile.createNewFile();

    when(mockLogsEncryptor.deserializeFile(any())).thenThrow(new RuntimeException("Corrupt file"));

    launchActivity();

    // When: User clicks generate key.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: Decryption error warning dialog appears.
    AlertDialog warningDialog = getLatestAppCompatAlertDialog();
    assertThat(warningDialog).isNotNull();

    // When: User clicks "Cancel" (BUTTON_NEGATIVE).
    warningDialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
    ShadowLooper.idleMainLooper();

    // Then: Key pair generation was aborted (never called).
    verify(mockLogsEncryptor, never()).generateKeyPair();

    // Cleanup test file.
    logFile.delete();
  }

  @Test
  public void onGenerateKeystoreKey_whenDecryptionPromptIsCancelled_keepsKeyAndRecordsFailure()
      throws Exception {
    // Given: A pending log file exists, and the time window of the key is closed.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "auth_req_log.bin");
    logFile.createNewFile();

    when(mockLogsEncryptor.decryptLogBatch(any()))
        .thenThrow(new UserNotAuthenticatedException("User authentication required"));

    launchActivity();

    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // When: The user cancels the prompt that decrypting the pending logs needs.
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Authentication canceled");
    ShadowLooper.idleMainLooper();

    // Then: The key is unchanged and the failure is recorded.
    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent(
            "KEY_CHANGE_AUTH_FAILED", "Key unchanged because the pending logs were not decrypted.");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_key_change_auth_cancelled));

    logFile.delete();
  }

  @Test
  public void onActivityResult_whenCredentialConfirmedWithoutPendingChange_keepsKeys()
      throws Exception {
    launchActivity();

    scenario.onActivity(
        activity -> {
          activity.onSaveInstanceState(new Bundle());
          activity.findViewById(R.id.btn_clear_active_external_key).performClick();
        });
    ShadowLooper.idleMainLooper();

    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockAuditLogger)
        .logEvent(
            "KEY_CHANGE_AUTH_FAILED",
            "Key unchanged because no device credential was confirmed for the change.");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_key_change_auth_cancelled));
  }

  @Test
  public void getPendingLogFiles_whenPathIsAFileNotDirectory_returnsEmptyList() throws Exception {
    // Given: A file exists at the logs subdirectory path instead of a directory.
    File logsPath =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsPath.createNewFile();

    launchActivity();

    // When: getPendingLogFiles is called.
    scenario.onActivity(
        activity -> {
          ImmutableList<File> pending = activity.getPendingLogFiles();
          // Then: Returns empty list because logsPath is a file, not a directory.
          assertThat(pending).isEmpty();
        });

    logsPath.delete();
  }

  @Test
  public void getPendingLogFiles_filtersNonBinSentAndProcessingFiles() throws Exception {
    // Given: A directory containing a valid .bin file, a .txt file, a .sent.bin file, and a
    // .processing.bin file currently being uploaded by the background worker.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File validFile = new File(logsDir, "valid_log.bin");
    File txtFile = new File(logsDir, "log.txt");
    File sentFile = new File(logsDir, "sent_log" + CrumblesConstants.SENT_SUFFIX);
    File processingFile =
        new File(logsDir, "processing_log" + CrumblesConstants.PROCESSING_SUFFIX);
    validFile.createNewFile();
    txtFile.createNewFile();
    sentFile.createNewFile();
    processingFile.createNewFile();

    launchActivity();

    // When: getPendingLogFiles is called.
    scenario.onActivity(
        activity -> {
          ImmutableList<File> pending = activity.getPendingLogFiles();
          // Then: Only valid_log.bin is included; .txt, .sent.bin, and .processing.bin are
          // filtered out.
          assertThat(pending).hasSize(1);
          assertThat(pending.get(0).getName()).isEqualTo("valid_log.bin");
        });

    validFile.delete();
    txtFile.delete();
    sentFile.delete();
    processingFile.delete();
  }

  @Test
  public void processScannedPublicKey_promptsForFingerprintAndDoesNotAdoptKeyYet()
      throws Exception {
    // Given: the activity is launched and a public key has been scanned.
    launchActivity();
    String scannedKeyBase64 = CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey);

    // When: the scan result is processed.
    processScannedKey(scannedKeyBase64);

    // Then: the user is asked to verify the fingerprint before anything is adopted.
    AlertDialog dialog = getLatestAppCompatAlertDialog();
    assertThat(dialog).isNotNull();
    assertThat(dialog.isShowing()).isTrue();
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any(PublicKey.class));
    verify(mockLogsEncryptor, never()).setExternalEncryptionPublicKey(any(PublicKey.class));
  }

  @Test
  public void processScannedPublicKey_whenFingerprintConfirmed_adoptsScannedKey() throws Exception {
    // Given: a scanned key is awaiting fingerprint verification.
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));

    // When: the user confirms that the fingerprint matches the one they were given.
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    // Then: the scanned key becomes the active recipient key, the adoption is recorded, and the
    // screen reports the outcome and closes.
    verify(mockAuditLogger)
        .logEvent(
            "KEY_HANDOVER_NOT_NEEDED",
            "Changing to an imported key with fingerprint "
                + CrumblesLogsEncryptor.getPublicKeyFingerprint(testPublicKey).replace('\n', ':'));
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(any(PublicKey.class));
    verify(mockLogsEncryptor).setExternalEncryptionPublicKey(any(PublicKey.class));
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_IMPORTED",
            "External public key imported via QR scan after fingerprint confirmation. Key"
                + " fingerprint: "
                + fingerprintOf(testPublicKey)
                + ".");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_external_key_imported_successfully));
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void processScannedPublicKey_whenFingerprintRejected_leavesActiveKeyUnchanged()
      throws Exception {
    // Given: a scanned key is awaiting fingerprint verification.
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));

    // When: the user cannot match the fingerprint and cancels.
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_NEGATIVE).performClick();
    ShadowLooper.idleMainLooper();

    // Then: the key is discarded and the rejection is recorded.
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any(PublicKey.class));
    verify(mockLogsEncryptor, never()).setExternalEncryptionPublicKey(any(PublicKey.class));
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_IMPORT_REJECTED",
            "User did not confirm the fingerprint of a scanned key.");
  }

  @Test
  public void onGenerateKeystoreKey_whenNoScreenLock_keepsKeysAndPostsDismissibleNotification()
      throws Exception {
    shadowOf(appContext.getSystemService(KeyguardManager.class)).setIsDeviceSecure(false);
    addScreenLockActivity("com.example.claims.screen.lock", /* applicationFlags= */ 0);
    addScreenLockActivity("com.android.settings", ApplicationInfo.FLAG_SYSTEM);
    CrumblesAppAuditLogger auditLogger = useRealAuditLogger();
    launchActivity();

    clickGenerateKeystoreKey();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    Notification notification =
        Iterables.getOnlyElement(
            shadowOf(appContext.getSystemService(NotificationManager.class)).getAllNotifications());
    expect
        .that(notification.extras.getString(Notification.EXTRA_TEXT))
        .isEqualTo(appContext.getString(R.string.notification_text_no_screen_lock));
    expect.that(notification.flags & Notification.FLAG_AUTO_CANCEL).isNotEqualTo(0);
    expect.that(notification.flags & Notification.FLAG_ONGOING_EVENT).isEqualTo(0);
    expect.that(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    expect
        .that(shadowOf(notification.contentIntent).getSavedIntent().getAction())
        .isEqualTo(DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
    expect
        .that(shadowOf(notification.contentIntent).getSavedIntent().getComponent())
        .isEqualTo(new ComponentName("com.android.settings", "com.android.settings.SetScreenLock"));
    expect.that(shadowOf(notification.contentIntent).getRequestCode()).isEqualTo(0);
    expect
        .that(recordedEvents(auditLogger))
        .contains(
            "KEY_INTERNAL_GENERATION_FAILED: Internal Keystore key pair not generated: no screen"
                + " lock is set on this device.");
  }

  @Test
  public void onGenerateKeystoreKey_whenNoScreenLockAndNotificationsOff_showsDialog() {
    shadowOf(appContext.getSystemService(KeyguardManager.class)).setIsDeviceSecure(false);
    shadowOf(appContext.getSystemService(NotificationManager.class)).setNotificationsEnabled(false);
    addScreenLockActivity("com.android.settings", ApplicationInfo.FLAG_SYSTEM);
    launchActivity();

    clickGenerateKeystoreKey();

    expect
        .that(latestDialogMessage())
        .isEqualTo(appContext.getString(R.string.notification_text_no_screen_lock));
    expect
        .that(
            shadowOf(appContext.getSystemService(NotificationManager.class)).getAllNotifications())
        .isEmpty();
  }

  @Test
  public void onGenerateKeystoreKey_whenOnlyAnotherAppSetsScreenLocks_showsDialog() {
    shadowOf(appContext.getSystemService(KeyguardManager.class)).setIsDeviceSecure(false);
    addScreenLockActivity("com.example.claims.screen.lock", /* applicationFlags= */ 0);
    launchActivity();

    clickGenerateKeystoreKey();

    expect
        .that(latestDialogMessage())
        .isEqualTo(appContext.getString(R.string.notification_text_no_screen_lock));
    expect
        .that(
            shadowOf(appContext.getSystemService(NotificationManager.class)).getAllNotifications())
        .isEmpty();
  }

  /** Makes the activity {@code SetScreenLock} of {@code packageName} set screen locks. */
  private void addScreenLockActivity(String packageName, int applicationFlags) {
    ResolveInfo resolveInfo =
        ShadowResolveInfo.newResolveInfo(
            "Screen lock", packageName, packageName + ".SetScreenLock");
    resolveInfo.activityInfo.applicationInfo.flags = applicationFlags;
    shadowOf(appContext.getPackageManager())
        .addResolveInfoForIntent(
            new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD), resolveInfo);
  }

  @Test
  public void onGenerateKeystoreKey_whenGenerationFails_keepsExternalKeyAndShowsDialog()
      throws Exception {
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    CrumblesAppAuditLogger auditLogger = useRealAuditLogger();
    launchActivity();

    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).setExternalEncryptionPublicKey(any());
    expect
        .that(latestDialogMessage())
        .isEqualTo(appContext.getString(R.string.dialog_message_key_generation_failed));
    expect
        .that(recordedEvents(auditLogger))
        .contains(
            "KEY_INTERNAL_GENERATION_FAILED: Switching to a new internal Keystore key pair"
                + " failed.");
  }

  @Test
  public void qrScanResult_whenQrCodeIsNotAPublicKey_recordsRejectionWithoutPayload() {
    shadowOf((Application) appContext).grantPermissions(Manifest.permission.CAMERA);
    CrumblesAppAuditLogger auditLogger = useRealAuditLogger();
    launchActivity();
    Intent scanResult =
        new Intent().putExtra(CrumblesConstants.SCAN_RESULT_EXTRA, THEATRE_TICKET_QR_PAYLOAD);

    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_import_external_public_key_qr).performClick();
          ShadowActivity shadowActivity = shadowOf(activity);
          shadowActivity.receiveResult(
              shadowActivity.getNextStartedActivityForResult().intent,
              Activity.RESULT_OK,
              scanResult);
        });
    ShadowLooper.idleMainLooper();

    expect
        .that(latestDialogMessage())
        .isEqualTo(appContext.getString(R.string.dialog_message_qr_not_a_key));
    expect
        .that(recordedEvents(auditLogger))
        .contains("EXTERNAL_KEY_IMPORT_REJECTED: Scanned QR code is not a valid public key.");
    expect.that(String.join("\n", recordedEvents(auditLogger))).doesNotContain("Hamlet");
  }

  @Test
  public void processScannedPublicKey_whenSavingConfirmedKeyFails_recordsImportFailure()
      throws Exception {
    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(any());
    CrumblesAppAuditLogger auditLogger = useRealAuditLogger();
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));

    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    expect
        .that(recordedEvents(auditLogger))
        .contains("EXTERNAL_KEY_IMPORT_FAILED: Scanned public key could not be saved.");
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Error importing key: Storage unavailable");
  }

  @Test
  public void onGenerateKeystoreKey_waitsForDeviceCredentialBeforeGenerating() throws Exception {
    launchActivity();

    clickGenerateKeystoreKey();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent("KEY_CHANGE_REQUESTED", "User asked to generate a new Keystore key pair.");
  }

  @Test
  public void onGenerateExportableKey_waitsForDeviceCredentialBeforeGenerating() throws Exception {
    launchActivity();

    clickGenerateExportableKey();

    verify(mockLogsEncryptor, never()).generateCandidateExternalKeyPair();
    verify(mockAuditLogger)
        .logEvent("KEY_CHANGE_REQUESTED", "User asked to generate a new exportable key pair.");
  }

  @Test
  public void processScannedPublicKey_whenFingerprintConfirmed_waitsForDeviceCredential()
      throws Exception {
    launchActivity();
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));

    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();

    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockAuditLogger)
        .logEvent("KEY_CHANGE_REQUESTED", "User asked to import a scanned public key.");
  }

  @Test
  public void onClearActiveKey_recordsRequestBeforeClearingOnceCredentialConfirmed()
      throws Exception {
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    launchActivity();
    clickClearActiveKey();

    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    InOrder inOrder = inOrder(mockAuditLogger, mockPublicKeyManager);
    inOrder
        .verify(mockAuditLogger)
        .logEvent("KEY_CHANGE_REQUESTED", "User asked to clear the active external key.");
    inOrder.verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
  }

  @Test
  public void onClearActiveKey_whenCredentialNotConfirmed_keepsKeyAndRecordsFailure()
      throws Exception {
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    launchActivity();
    clickClearActiveKey();

    scenario.onActivity(activity -> answerCredentialPrompt(activity, Activity.RESULT_CANCELED));

    verify(mockPublicKeyManager, never()).saveActiveExternalPublicKey(any());
    verify(mockLogsEncryptor, never()).setExternalEncryptionPublicKey(any());
    verify(mockAuditLogger)
        .logEvent(
            "KEY_CHANGE_AUTH_FAILED",
            "Key unchanged because no device credential was confirmed for the change.");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_key_change_auth_cancelled));
  }

  @Test
  public void onGenerateExportableKey_withoutScreenLock_refusesAndRecordsRefusal()
      throws Exception {
    shadowOf(appContext.getSystemService(KeyguardManager.class)).setIsDeviceSecure(false);
    launchActivity();

    clickGenerateExportableKey();

    verify(mockLogsEncryptor, never()).generateCandidateExternalKeyPair();
    verify(mockAuditLogger)
        .logEvent("KEY_CHANGE_REFUSED", "Key unchanged because no secure lock screen is set up.");
    expect
        .that(latestDialogMessage())
        .isEqualTo(appContext.getString(R.string.dialog_message_key_change_requires_screen_lock));
    expect.that(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
  }

  @Test
  public void
      onGenerateKeystoreKey_recordsInternalFingerprintAndCancelsNotificationAfterClearingExternal()
          throws Exception {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    try {
      NotificationManager notificationManager =
          appContext.getSystemService(NotificationManager.class);
      CrumblesDeviceAdminReceiver.reportInvalidatedKey(
          appContext, "invalidated_before_keystore_switch");
      assertThat(
              shadowOf(notificationManager)
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();

      AtomicReference<String> fingerprintDuringClear = new AtomicReference<>();
      AtomicReference<Notification> notificationDuringClear = new AtomicReference<>();
      doAnswer(
              invocation -> {
                fingerprintDuringClear.set(readStoredInternalKeyFingerprint());
                notificationDuringClear.set(
                    shadowOf(notificationManager)
                        .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID));
                return null;
              })
          .when(mockPublicKeyManager)
          .saveActiveExternalPublicKey(isNull());

      launchActivity();
      clickGenerateKeystoreKey();
      scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

      expect.that(fingerprintDuringClear.get()).isEmpty();
      expect.that(notificationDuringClear.get()).isNotNull();
      expect
          .that(readStoredInternalKeyFingerprint())
          .isEqualTo(CrumblesLogsEncryptor.getPublicKeyFingerprint(testPublicKey));
      expect
          .that(
              shadowOf(notificationManager)
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNull();
    } finally {
      if (scenario != null) {
        scenario.close();
        scenario = null;
      }
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void
      onGenerateKeystoreKey_whenClearingExternalKeyFails_rollsBackLogsClearsFingerprintAndKeepsNotification()
          throws Exception {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    try {
      CrumblesDataStoreHolder.getInstance(appContext)
          .updateDataAsync(
              prefs -> prefs.toBuilder().setInternalKeyFingerprint("stale_internal_fp").build())
          .get();
      NotificationManager notificationManager =
          appContext.getSystemService(NotificationManager.class);
      CrumblesDeviceAdminReceiver.reportInvalidatedKey(
          appContext, "invalidated_before_failed_keystore_switch");
      assertThat(
              shadowOf(notificationManager)
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();

      givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
      when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
      when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
      when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
      doThrow(new CrumblesKeysException("Storage unavailable"))
          .when(mockPublicKeyManager)
          .saveActiveExternalPublicKey(isNull());
      launchActivity();

      clickGenerateKeystoreKey();
      scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
      chooseReEncrypt();

      expect.that(readStoredInternalKeyFingerprint()).isEmpty();
      expect
          .that(
              shadowOf(notificationManager)
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();
      verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));
      verify(mockLogsEncryptor, never()).setExternalEncryptionPublicKey(any());
      expect
          .that(latestDialogMessage())
          .isEqualTo(appContext.getString(R.string.dialog_message_key_generation_failed));
      scenario.onActivity(activity -> expect.that(activity.isFinishing()).isFalse());
    } finally {
      if (scenario != null) {
        scenario.close();
        scenario = null;
      }
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void processScannedPublicKey_cancelsInvalidatedNotificationOnlyOnceKeyIsSaved()
      throws Exception {
    NotificationManager notificationManager =
        appContext.getSystemService(NotificationManager.class);
    CrumblesDeviceAdminReceiver.reportInvalidatedKey(
        appContext, "invalidated_before_scanned_import");
    assertThat(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
        .isNotNull();
    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(any());
    launchActivity();

    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    expect
        .that(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
        .isNotNull();

    doNothing().when(mockPublicKeyManager).saveActiveExternalPublicKey(any());
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    expect
        .that(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
        .isNull();
  }

  @Test
  public void onKeyCustodyConfirmed_cancelsInvalidatedNotificationOnlyOnceKeyIsSaved()
      throws Exception {
    NotificationManager notificationManager =
        appContext.getSystemService(NotificationManager.class);
    CrumblesDeviceAdminReceiver.reportInvalidatedKey(
        appContext, "invalidated_before_exportable_commit");
    assertThat(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
        .isNotNull();
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    doThrow(new CrumblesKeysException("Storage unavailable"))
        .when(mockPublicKeyManager)
        .saveActiveExternalPublicKey(any());
    launchActivity();

    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    clickViewerDone();

    expect
        .that(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
        .isNotNull();

    doNothing().when(mockPublicKeyManager).saveActiveExternalPublicKey(any());
    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    clickViewerDone();

    expect
        .that(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
        .isNull();
  }

  private String readStoredInternalKeyFingerprint() throws Exception {
    return CrumblesDataStoreHolder.getInstance(appContext)
        .getDataAsync()
        .get()
        .getInternalKeyFingerprint();
  }

  private void clickGenerateExportableKey() {
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_exportable_key).performClick());
    ShadowLooper.idleMainLooper();
  }

  private void clickClearActiveKey() {
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_clear_active_external_key).performClick());
    ShadowLooper.idleMainLooper();
  }

  /** Confirms the device credential prompt that every key change opens first. */
  private static void confirmCredential(Activity activity) {
    answerCredentialPrompt(activity, Activity.RESULT_OK);
  }

  private static void answerCredentialPrompt(Activity activity, int resultCode) {
    Fragment promptFragment =
        ((AppCompatActivity) activity)
            .getSupportFragmentManager()
            .findFragmentByTag("androidx.biometric.internal.BiometricFragment");
    if (promptFragment != null) {
      ((LifecycleRegistry) promptFragment.getLifecycle()).setCurrentState(Lifecycle.State.STARTED);
    }
    if (resultCode == Activity.RESULT_OK) {
      ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    } else {
      ShadowBiometricPrompt.authenticateCurrentSessionWithError(
          BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Cancelled");
    }
    shadowOf(activity.getMainLooper()).idle();
  }

  private void clickGenerateKeystoreKey() {
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();
  }

  /** Replaces the mock audit logger with the real one so a test can read the events it records. */
  private CrumblesAppAuditLogger useRealAuditLogger() {
    CrumblesAppAuditLogger.setInstanceForTest(null);
    return CrumblesAppAuditLogger.getInstance(appContext);
  }

  private static ImmutableList<String> recordedEvents(CrumblesAppAuditLogger auditLogger) {
    return auditLogger.getMemoryCachedEvents().stream()
        .map(event -> event.getEventType() + ": " + event.getMessage())
        .collect(toImmutableList());
  }

  private String latestDialogMessage() {
    TextView message = getLatestAppCompatAlertDialog().findViewById(android.R.id.message);
    return message.getText().toString();
  }

  /** Feeds a Base64 public key through the QR scan result handler. */
  private void processScannedKey(String scannedKeyBase64) {
    scenario.onActivity(
        activity -> {
          try {
            activity.processScannedPublicKeyInternal(scannedKeyBase64);
          } catch (CrumblesKeysException e) {
            throw new AssertionError("Processing a valid scanned key should not fail.", e);
          }
        });
    ShadowLooper.idleMainLooper();
  }

  @Test
  public void updateStatusUi_whenExternalKeySelectedButUnreadable_showsUnreadableAndClearButton() {
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    launchActivity();

    scenario.onActivity(
        activity -> {
          activity.updateStatusUi();
          TextView tvStatus = activity.findViewById(R.id.tv_current_external_key_status);
          Button clearBtn = activity.findViewById(R.id.btn_clear_active_external_key);
          expect
              .that(tvStatus.getText().toString())
              .isEqualTo(appContext.getString(R.string.status_external_key_unreadable));
          expect.that(clearBtn.getVisibility()).isEqualTo(View.VISIBLE);
          expect
              .that(clearBtn.getText().toString())
              .isEqualTo(appContext.getString(R.string.btn_choose_key_clear_sentinel));

          when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
          activity.updateStatusUi();
          expect
              .that(clearBtn.getText().toString())
              .isEqualTo(appContext.getString(R.string.generate_keystore_key_pair_button));
        });
  }

  private ActivityController<CrumblesManageExternalKeysActivity> createCreatedActivity(
      Executor executor) {
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        Robolectric.buildActivity(CrumblesManageExternalKeysActivity.class).create();
    controller.get().setPublicKeyManagerForTest(mockPublicKeyManager);
    controller.get().setKeyGenerationExecutorForTest(executor);
    return controller;
  }

  private ActivityController<CrumblesManageExternalKeysActivity> startCreatedKeyChange(
      int buttonId, Executor executor) {
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        createCreatedActivity(executor);
    controller.get().findViewById(buttonId).performClick();
    confirmCredential(controller.get());
    return controller;
  }

  private static String statusText(Activity activity) {
    return ((TextView) activity.findViewById(R.id.tv_current_external_key_status))
        .getText()
        .toString();
  }

  @Test
  public void onStop_dismissesExportChoiceDialogAndZeroesKey() throws Exception {
    byte[] plaintext = {4, 5, 6};
    byte[] keyBytes = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(keyBytes);
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        createCreatedActivity(Runnable::run).start().resume();
    controller.get().findViewById(R.id.btn_generate_exportable_key).performClick();
    confirmCredential(controller.get());
    chooseReEncrypt();
    AlertDialog dialog = getLatestAppCompatAlertDialog();
    assertThat(dialog.isShowing()).isTrue();
    Bundle savedState = new Bundle();

    controller.pause().stop().saveInstanceState(savedState);

    expect.that(dialog.isShowing()).isFalse();
    expect
        .that(dialog.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
    expect.that(keyBytes).isEqualTo(new byte[] {0, 0, 0});
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
    expect.that(savedState.containsKey("pending_candidate_public_key")).isFalse();
  }

  @Test
  public void onStop_dismissesPrivateKeyViewerAndWipesKey() {
    launchActivity();
    AtomicReference<TextView> keyTextView = new AtomicReference<>();
    scenario.onActivity(
        activity -> {
          activity.showPrivateKeyViewer(new byte[] {4, 5, 6}, /* showQrInitially= */ false);
          activity.getSupportFragmentManager().executePendingTransactions();
        });
    ShadowLooper.idleMainLooper();
    scenario.onActivity(
        activity -> {
          DialogFragment viewer =
              (DialogFragment)
                  activity.getSupportFragmentManager().findFragmentByTag("private_key_viewer");
          expect.that(viewer).isNotNull();
          expect.that(viewer.requireDialog().isShowing()).isTrue();
          keyTextView.set(viewer.requireDialog().findViewById(R.id.private_key_text_view));
          expect.that(keyTextView.get().getText().toString()).isNotEmpty();
        });

    scenario.moveToState(Lifecycle.State.CREATED);
    ShadowLooper.idleMainLooper();

    expect.that(keyTextView.get().getText().toString()).isEmpty();
    scenario.onActivity(
        activity ->
            expect
                .that(activity.getSupportFragmentManager().findFragmentByTag("private_key_viewer"))
                .isNull());
  }

  @Test
  public void onDestroy_whenCreatedWithoutStop_zeroesPendingExportChoiceKey() throws Exception {
    byte[] plaintext = {4, 5, 6};
    byte[] keyBytes = {7, 8, 9};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(keyBytes);
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        startCreatedKeyChange(R.id.btn_generate_exportable_key, Runnable::run);
    chooseReEncrypt();
    assertThat(keyBytes).isEqualTo(new byte[] {7, 8, 9});

    controller.destroy();

    expect.that(keyBytes).isEqualTo(new byte[] {0, 0, 0});
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
  }

  @Test
  public void
      onGenerateExportableKey_whenDestroyedBeforeStartAndGenerationEnds_zeroesKeyAndHeldLogs()
          throws Exception {
    byte[] plaintext = {4, 5, 6};
    byte[] privateKeyBytes = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(privateKeyBytes);
    List<Runnable> keyGenerationTasks = new ArrayList<>();
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        startCreatedKeyChange(R.id.btn_generate_exportable_key, keyGenerationTasks::add);
    keyGenerationTasks.remove(0).run();
    ShadowLooper.idleMainLooper();
    chooseReEncrypt();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();
    controller.destroy();

    keyGenerationTasks.forEach(Runnable::run);
    ShadowLooper.idleMainLooper();

    expect.that(privateKeyBytes).isEqualTo(new byte[] {0, 0, 0});
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
    expect.that(getLatestAppCompatAlertDialog()).isSameInstanceAs(progressDialog);
  }

  @Test
  public void onStop_afterCompletedKeyChange_dismissesReEncryptDialogAndDropsLogs()
      throws Exception {
    byte[] plaintext = {4, 5, 6};
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        createCreatedActivity(Runnable::run).start().resume();
    controller.get().updateStatusUi();
    controller.get().findViewById(R.id.btn_clear_active_external_key).performClick();
    confirmCredential(controller.get());
    givenPendingBatchDecryptingTo(plaintext);
    controller.get().findViewById(R.id.btn_generate_keystore_key).performClick();
    confirmCredential(controller.get());
    AlertDialog dialog = getLatestAppCompatAlertDialog();

    controller.pause().stop();

    expect.that(dialog.isShowing()).isFalse();
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
  }

  @Test
  public void onDestroy_whenCreatedWithoutStop_dropsHeldLogs() throws Exception {
    byte[] plaintext = {4, 5, 6};
    givenPendingBatchDecryptingTo(plaintext);
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        createCreatedActivity(Runnable::run);
    controller.get().findViewById(R.id.btn_generate_keystore_key).performClick();
    confirmCredential(controller.get());

    controller.destroy();

    assertThat(plaintext).isEqualTo(new byte[] {0, 0, 0});
  }

  @Test
  public void updateStatusUi_whenStopped_doesNotUpdateView() {
    launchActivity();
    scenario.moveToState(Lifecycle.State.CREATED);
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);

    scenario.onActivity(CrumblesManageExternalKeysActivity::updateStatusUi);

    scenario.onActivity(
        activity ->
            assertThat(statusText(activity))
                .isEqualTo(appContext.getString(R.string.status_no_external_key)));
  }

  @Test
  public void updateStatusUi_whenDestroyedBeforeStart_doesNotUpdateView() {
    CrumblesManageExternalKeysActivity activity =
        createCreatedActivity(Runnable::run).destroy().get();
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);

    activity.updateStatusUi();

    assertThat(statusText(activity))
        .isEqualTo(appContext.getString(R.string.status_no_external_key));
  }

  @Test
  public void onStart_afterStop_resumesStatusUiUpdates() {
    launchActivity();
    scenario.moveToState(Lifecycle.State.CREATED);
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);

    scenario.moveToState(Lifecycle.State.RESUMED);

    String expectedStatus =
        appContext.getString(
            R.string.status_external_key_active_formatted,
            CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey));
    scenario.onActivity(activity -> assertThat(statusText(activity)).isEqualTo(expectedStatus));
  }

  @Test
  public void processScannedPublicKey_whenStoppedBeforeHandoverEnds_doesNotFinish()
      throws Exception {
    List<Runnable> tasks = new ArrayList<>();
    launchActivity();
    scenario.onActivity(activity -> activity.setKeyGenerationExecutorForTest(tasks::add));
    processScannedKey(CrumblesLogsEncryptor.publicKeyToBase64(testPublicKey));
    getLatestAppCompatAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    scenario.moveToState(Lifecycle.State.CREATED);

    tasks.forEach(Runnable::run);
    ShadowLooper.idleMainLooper();

    expect.that(ShadowToast.getTextOfLatestToast()).isNull();
    scenario.onActivity(activity -> expect.that(activity.isFinishing()).isFalse());
  }

  @Test
  public void onGenerateKeystoreKey_whenDestroyedBeforeStart_doesNotUnlockOrFinish() {
    List<Runnable> tasks = new ArrayList<>();
    ActivityController<CrumblesManageExternalKeysActivity> controller =
        createCreatedActivity(tasks::add);
    controller.get().findViewById(R.id.btn_generate_keystore_key).performClick();
    confirmCredential(controller.get());
    CrumblesManageExternalKeysActivity activity = controller.destroy().get();

    tasks.forEach(Runnable::run);
    ShadowLooper.idleMainLooper();

    expect.that(ShadowToast.getTextOfLatestToast()).isNull();
    expect.that(activity.isFinishing()).isFalse();
    expect
        .that(activity.getRequestedOrientation())
        .isEqualTo(ActivityInfo.SCREEN_ORIENTATION_LOCKED);
  }

  @Test
  public void onGenerateKeystoreKey_whenFailureFinishesAfterStop_skipsPersistentErrorDialog()
      throws Exception {
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    List<Runnable> tasks = new ArrayList<>();
    startKeyChange(R.id.btn_generate_keystore_key, tasks);
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();
    scenario.moveToState(Lifecycle.State.CREATED);

    tasks.forEach(Runnable::run);
    ShadowLooper.idleMainLooper();

    expect.that(progressDialog.isShowing()).isFalse();
    expect.that(getLatestAppCompatAlertDialog()).isSameInstanceAs(progressDialog);
  }

  @Test
  public void onGenerateExportableKey_whenScreenStoppedBeforeGenerationEnds_zeroesKeyAndHeldLogs()
      throws Exception {
    byte[] plaintext = {4, 5, 6};
    byte[] privateKeyBytes = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    mockSuccessfulKeyGeneration(privateKeyBytes);
    List<Runnable> tasks = new ArrayList<>();
    startKeyChange(R.id.btn_generate_exportable_key, tasks);
    chooseReEncrypt();
    AlertDialog progressDialog = getLatestAppCompatAlertDialog();
    scenario.moveToState(Lifecycle.State.CREATED);

    tasks.forEach(Runnable::run);
    ShadowLooper.idleMainLooper();

    expect.that(privateKeyBytes).isEqualTo(new byte[] {0, 0, 0});
    expect.that(plaintext).isEqualTo(new byte[] {0, 0, 0});
    expect.that(getLatestAppCompatAlertDialog()).isSameInstanceAs(progressDialog);
  }

  private void clickAndConfirmKeystoreKey() {
    clickGenerateKeystoreKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
  }

  @Test
  @SuppressWarnings("unused")
  public void onGenerateKeystoreKey_withRealPerOpRsaKey_promptsOutsideLockAndReEncryptsInFlight()
      throws Exception {
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    try {
      CrumblesLogsEncryptor real = new CrumblesLogsEncryptor();
      PublicKey oldPublic = real.generateKeyPair().getPublic();
      CrumblesBatchKeyStore.deleteKeys();
      File dir = createPendingLogFile("b1.bin").getParentFile();
      String p2 = "b2" + CrumblesConstants.PROCESSING_SUFFIX;
      Object u1 = real.serializeBytes(real.encryptLogs(new byte[] {1}, null), dir, "b1.bin");
      Object u2 = real.serializeBytes(real.encryptLogs(new byte[] {2}, null), dir, p2);
      new File(dir, "b1.bin").setLastModified(123456000L);
      CrumblesMain.setLogsEncryptorInstanceForTest(real);
      launchActivity();
      clickAndConfirmKeystoreKey();
      assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
      assertThat(Thread.holdsLock(CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK)).isFalse();
      for (int i = 0; i < 2; i++) {
        ShadowLooper.idleMainLooper();
        FakeAndroidKeyStoreSpi.authorizeLatestPendingCipher();
        ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
      }
      ShadowLooper.idleMainLooper();
      chooseReEncrypt();
      assertThat(real.getPublicKey()).isNotEqualTo(oldPublic);
      assertThat(new File(dir, "b1.bin").lastModified()).isEqualTo(123456000L);
      assertThat(new File(dir, p2).exists()).isFalse();
      for (String name : new String[] {"b1.bin", "b2_reencrypted.bin"}) {
        LogBatch b = real.deserializeFile(new File(dir, name).toPath());
        Cipher c = real.createUnwrapCipher(b);
        FakeAndroidKeyStoreSpi.authorizeLatestPendingCipher();
        assertThat(real.decryptLogs(b, c)).isEqualTo(new byte[] {(byte) (name.charAt(1) - '0')});
        new File(dir, name).delete();
      }
    } finally {
      CrumblesBatchKeyStore.deleteKeys();
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void onGenerateKeystoreKey_whenNewLogsArriveDuringTheChange_recordsTheRefusal()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    launchActivity();
    clickAndConfirmKeystoreKey();
    assertThat(createPendingLogFile("arrived.bin").exists()).isTrue();

    chooseReEncrypt();

    verify(mockLogsEncryptor, never()).generateKeyPair();
    verify(mockAuditLogger)
        .logEvent("KEY_CHANGE_REFUSED", "Key unchanged: new logs arrived during the key change.");
  }

  @Test
  public void pendingLogsArrivalAndInFlightDiscard_abortsOnlyWhenInternalKeyWouldBeDeleted()
      throws Exception {
    byte[] plain = {9};
    givenPendingBatchDecryptingTo(plain);
    File inFlight = createPendingLogFile("flight" + CrumblesConstants.PROCESSING_SUFFIX);
    launchActivity();
    clickAndConfirmKeystoreKey();
    File arrived1 = createPendingLogFile("arrived1.bin");
    getLatestAppCompatAlertDialog().getListView().performItemClick(null, 2, 2);
    ShadowLooper.idleMainLooper();
    String retryToast = appContext.getString(R.string.toast_pending_logs_changed_retry);
    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo(retryToast);
    assertThat(inFlight.exists()).isTrue();
    assertThat(arrived1.exists()).isTrue();
    clickAndConfirmKeystoreKey();
    assertThat(createPendingLogFile("arrived2.bin").exists()).isTrue();
    chooseReEncrypt();
    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo(retryToast);
    assertThat(plain).isEqualTo(new byte[] {0});
    verify(mockLogsEncryptor, never()).generateKeyPair();
    mockSuccessfulKeyGeneration(new byte[] {5});
    chooseReEncryptForExportableKeyAndViewItAsText();
    Bundle saved = new Bundle();
    scenario.onActivity(a -> a.onSaveInstanceState(saved));
    scenario.onActivity(CrumblesManageExternalKeysActivity::onStateNotSaved);
    assertThat(createPendingLogFile("arrived3.bin").exists()).isTrue();
    var rc = Robolectric.buildActivity(CrumblesManageExternalKeysActivity.class).create(saved);
    rc.get().setPublicKeyManagerForTest(mockPublicKeyManager);
    rc.get().setKeyGenerationExecutorForTest(Runnable::run);
    rc.start().resume().get().onKeyCustodyConfirmed();
    ShadowLooper.idleMainLooper();
    verify(mockLogsEncryptor, never()).commitExternalPublicKey(testPublicKey);
    when(mockPublicKeyManager.isExternalKeySelected()).thenReturn(true);
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(testPublicKey);
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    clickClearActiveKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);
    assertThat(createPendingLogFile("arrived4.bin").exists()).isTrue();
    getLatestAppCompatAlertDialog().getListView().performItemClick(null, 2, 2);
    ShadowLooper.idleMainLooper();
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    assertThat(inFlight.exists()).isFalse();
    clickAndConfirmKeystoreKey();
    assertThat(createPendingLogFile("arrived5.bin").exists()).isTrue();
    chooseReEncrypt();
    verify(mockLogsEncryptor).generateKeyPair();
    ImmutableList.copyOf(inFlight.getParentFile().listFiles()).forEach(File::delete);
    byte[] plain1 = {1, 2, 3};
    givenPendingBatchDecryptingTo(plain1);
    launchActivity();
    scenario.onActivity(activity -> activity.setUsableSpaceSupplierForTest(() -> 1024L));
    clickAndConfirmKeystoreKey();
    chooseReEncrypt();
    String failEvt = CrumblesManageExternalKeysActivity.AUDIT_EVENT_RE_ENCRYPT_FAILED;
    String refused = "Key unchanged: insufficient storage space to re-encrypt pending logs.";
    verify(mockAuditLogger).logEvent("KEY_CHANGE_REFUSED", refused);
    expect.that(plain1).isEqualTo(new byte[] {0, 0, 0});
    givenPendingBatchDecryptingTo(new byte[] {4, 5, 6});
    when(mockPublicKeyManager.getActiveExternalPublicKey()).thenReturn(null);
    scenario.onActivity(CrumblesManageExternalKeysActivity::updateStatusUi);
    scenario.onActivity(a -> expect.that(statusText(a)).contains("unreadable"));
    scenario.onActivity(a -> a.setUsableSpaceSupplierForTest(() -> 10_000_000L));
    when(mockLogsEncryptor.encryptLogsAttributedTo(any(), any(), any())).thenReturn(null);
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    try {
      clickAndConfirmKeystoreKey();
      chooseReEncrypt();
      expect.that(new CrumblesLogStaging(appContext).isEmpty()).isFalse();
    } finally {
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
    String failMsg =
        "1 pending log batch(es) (pending_batch.bin) could not be re-encrypted after key change.";
    verify(mockAuditLogger).logEvent(failEvt, failMsg);
    byte[] plain2 = {7, 8, 9};
    givenPendingBatchDecryptingTo(plain2);
    launchActivity();
    doThrow(new CrumblesKeysException("Fail")).when(mockLogsEncryptor).generateKeyPair();
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    FakeAndroidKeyStoreSpi.isSecretKeyGenerationFailing = true;
    try {
      clickAndConfirmKeystoreKey();
      chooseReEncrypt();
    } finally {
      FakeAndroidKeyStoreSpi.isSecretKeyGenerationFailing = false;
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
    expect.that(plain2).isEqualTo(new byte[] {0, 0, 0});
    String lostMsg = "1 pending log batch(es) were lost after re-encryption and staging failed.";
    verify(mockAuditLogger).logEvent(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST, lostMsg);
  }

  @Test
  public void onCreate_whenRestoredWithKeyViewer_cancelsCustodyOnceTheViewerIsDismissed()
      throws Exception {
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    triggerExportChoiceAndClick(AlertDialog.BUTTON_POSITIVE);
    assertThat(getViewerDialogFragment()).isNotNull();
    Bundle saved = new Bundle();
    scenario.onActivity(activity -> activity.onSaveInstanceState(saved));
    scenario.onActivity(CrumblesManageExternalKeysActivity::onStateNotSaved);
    var restored =
        Robolectric.buildActivity(CrumblesManageExternalKeysActivity.class).create(saved);
    restored.get().setPublicKeyManagerForTest(mockPublicKeyManager);
    restored.get().setKeyGenerationExecutorForTest(Runnable::run);
    restored.start().resume();
    ShadowLooper.idleMainLooper();
    DialogFragment restoredViewer =
        (DialogFragment)
            restored.get().getSupportFragmentManager().findFragmentByTag("private_key_viewer");
    assertThat(restoredViewer).isNotNull();

    restoredViewer.dismiss();
    ShadowLooper.idleMainLooper();
    restored.get().onKeyCustodyConfirmed();
    ShadowLooper.idleMainLooper();

    verify(mockLogsEncryptor, never()).commitExternalPublicKey(any());
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_key_export_cancelled_active_key_preserved));
  }

  @Test
  public void onGenerateKeystoreKey_whenReEncryptFails_stagesTheBatchAndDeletesItsPendingFile()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    File pendingFile =
        new File(
            new File(
                appContext.getFilesDir(),
                CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY),
            "pending_batch.bin");
    File processingFile =
        createPendingLogFile("pending_batch" + CrumblesConstants.PROCESSING_SUFFIX);
    when(mockLogsEncryptor.encryptLogsAttributedTo(any(), any(), any())).thenReturn(null);
    launchActivity();
    scenario.onActivity(activity -> activity.setUsableSpaceSupplierForTest(() -> 10_000_000L));
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    try {
      clickAndConfirmKeystoreKey();
      chooseReEncrypt();

      expect.that(new CrumblesLogStaging(appContext).isEmpty()).isFalse();
    } finally {
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
    expect.that(pendingFile.exists()).isFalse();
    expect.that(processingFile.exists()).isFalse();
    verify(mockAuditLogger, never())
        .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST), any());
  }

  @Test
  public void onGenerateKeystoreKey_whenReEncryptAndStagingBothFail_recordsLogsLost()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    File pendingFile =
        new File(
            new File(
                appContext.getFilesDir(),
                CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY),
            "pending_batch.bin");
    when(mockLogsEncryptor.encryptLogsAttributedTo(any(), any(), any())).thenReturn(null);
    launchActivity();
    scenario.onActivity(activity -> activity.setUsableSpaceSupplierForTest(() -> 10_000_000L));
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    FakeAndroidKeyStoreSpi.isSecretKeyGenerationFailing = true;
    try {
      clickAndConfirmKeystoreKey();
      chooseReEncrypt();
    } finally {
      FakeAndroidKeyStoreSpi.isSecretKeyGenerationFailing = false;
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
    expect.that(pendingFile.exists()).isTrue();
    verify(mockAuditLogger)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST,
            "1 pending log batch(es) were lost after re-encryption and staging failed.");
  }

  @Test
  public void onKeyCustodyConfirmed_afterReEncryptingHeldLogs_savesNoPendingReEncryptChoice()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();
    clickViewerDone();
    verify(mockLogsEncryptor).encryptLogsAttributedTo(any(), any(), eq(testPublicKey));

    Bundle saved = new Bundle();
    scenario.onActivity(activity -> activity.onSaveInstanceState(saved));
    scenario.onActivity(CrumblesManageExternalKeysActivity::onStateNotSaved);

    assertThat(saved.get("re_encrypt_chosen")).isEqualTo(false);
  }

  @Test
  public void onKeyCustodyCancelled_whenReEncryptChosen_savesNoPendingReEncryptChoice()
      throws Exception {
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    mockSuccessfulKeyGeneration(testExternalKeyPair.getPrivate().getEncoded());
    launchActivity();
    chooseReEncryptForExportableKeyAndViewItAsText();

    getViewerDialogFragment().dismiss();
    ShadowLooper.idleMainLooper();

    Bundle saved = new Bundle();
    scenario.onActivity(activity -> activity.onSaveInstanceState(saved));
    scenario.onActivity(CrumblesManageExternalKeysActivity::onStateNotSaved);
    assertThat(saved.get("re_encrypt_chosen")).isEqualTo(false);
  }

  @Test
  public void onClearActiveKey_afterFailedKeystoreSwitchStagedHeldLogs_doesNotReEncryptThem()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    givenPendingBatchDecryptingTo(new byte[] {1, 2, 3});
    doThrow(new CrumblesKeysException("Keystore unavailable"))
        .when(mockLogsEncryptor)
        .generateKeyPair();
    launchActivity();
    scenario.onActivity(activity -> activity.setUsableSpaceSupplierForTest(() -> 10_000_000L));
    ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    try {
      clickAndConfirmKeystoreKey();
      chooseReEncrypt();
    } finally {
      ReflectionHelpers.setStaticField(CrumblesDataStoreHolder.class, "instance", null);
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }

    scenario.onActivity(activity -> activity.setUsableSpaceSupplierForTest(() -> 0L));
    clickClearActiveKey();
    scenario.onActivity(CrumblesManageExternalKeysActivityTest::confirmCredential);

    verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    verify(mockLogsEncryptor, never()).encryptLogsAttributedTo(any(), any(), isNull());
  }

  @Test
  public void onGenerateKeystoreKey_whenStorageRunsLowDuringHandover_keepsTheActiveKey()
      throws Exception {
    byte[] plaintext = {1, 2, 3};
    givenPendingBatchDecryptingTo(plaintext);
    launchActivity();
    AtomicInteger storageChecks = new AtomicInteger();
    scenario.onActivity(
        activity ->
            activity.setUsableSpaceSupplierForTest(
                () -> storageChecks.getAndIncrement() == 0 ? 10_000_000L : 1024L));

    clickAndConfirmKeystoreKey();
    chooseReEncrypt();

    expect.that(storageChecks.get()).isEqualTo(2);
    verify(mockAuditLogger)
        .logEvent(
            "KEY_CHANGE_REFUSED",
            "Key unchanged: insufficient storage space to re-encrypt pending logs.");
    verify(mockLogsEncryptor, never()).generateKeyPair();
    expect.that(plaintext).isEqualTo(new byte[plaintext.length]);
  }

  @Test
  public void onGenerateKeystoreKey_whenSpaceFitsBatchesButNotTheirLogs_refusesAndForgetsChoice()
      throws Exception {
    byte[] plaintext = new byte[4096];
    Arrays.fill(plaintext, (byte) 7);
    givenPendingBatchDecryptingTo(plaintext);
    launchActivity();
    // Room for the fixed allowance of the one held batch, but not for its 4 KiB of logs as well.
    scenario.onActivity(activity -> activity.setUsableSpaceSupplierForTest(() -> 131_072L + 1024));

    clickAndConfirmKeystoreKey();
    chooseReEncrypt();

    verify(mockAuditLogger)
        .logEvent(
            "KEY_CHANGE_REFUSED",
            "Key unchanged: insufficient storage space to re-encrypt pending logs.");
    verify(mockLogsEncryptor, never()).generateKeyPair();
    expect.that(plaintext).isEqualTo(new byte[plaintext.length]);
    Bundle saved = new Bundle();
    scenario.onActivity(activity -> activity.onSaveInstanceState(saved));
    scenario.onActivity(CrumblesManageExternalKeysActivity::onStateNotSaved);
    assertThat(saved.get("re_encrypt_chosen")).isEqualTo(false);
  }

  /** Returns whether {@code activity} keeps the overlay windows of other apps hidden. */
  private static boolean hidesOverlayWindows(Activity activity) {
    int hideOverlays =
        ReflectionHelpers.getStaticField(
            WindowManager.LayoutParams.class, "SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS");
    int privateFlags =
        ReflectionHelpers.getField(activity.getWindow().getAttributes(), "privateFlags");
    return (privateFlags & hideOverlays) == hideOverlays;
  }
}
