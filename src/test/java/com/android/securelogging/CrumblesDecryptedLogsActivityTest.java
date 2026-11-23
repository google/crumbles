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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.Fragment;
import android.content.ClipDescription;
import android.content.ComponentCallbacks2;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.ProviderInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Looper;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.core.content.IntentCompat;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.Timestamp;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.SealedLogs;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Map;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.shadows.ShadowActivity.IntentForResult;
import org.robolectric.shadows.ShadowAlertDialog;
import org.robolectric.shadows.ShadowPackageManager;
import org.robolectric.shadows.ShadowToast;
import org.robolectric.util.ReflectionHelpers;

/** Tests for {@link CrumblesDecryptedLogsActivity}. */
@RunWith(AndroidJUnit4.class)
public class CrumblesDecryptedLogsActivityTest {

  private static final String TEST_FILE_NAME_1 = "log1.txt";
  private static final String TEST_DEVICE_ID = "original-device";
  private static final LogMetadata TEST_RECORDED_METADATA =
      LogMetadata.newBuilder().setDevice(DeviceId.newBuilder().setDeviceId(TEST_DEVICE_ID)).build();
  private static final Timestamp TEST_RECORDED_TIME =
      Timestamp.newBuilder().setSeconds(1_600_000_000L).build();
  private static final byte[] testRawBytes1 = "decrypted log content".getBytes(UTF_8);
  private static final ComponentName SHARE_TARGET =
      new ComponentName("com.example.mail", "com.example.mail.ComposeActivity");
  private static final String SHARE_TARGET_LABEL = "Mail";

  @Rule public final Expect expect = Expect.create();
  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;

  private ActivityScenario<CrumblesDecryptedLogsActivity> scenario;

  @BeforeClass
  public static void installFakeKeystore() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
  }

  @AfterClass
  public static void removeFakeKeystore() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Before
  public void setUp() throws Exception {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isCertificateChainNull = false;

    MockitoAnnotations.openMocks(this);
    Context context = ApplicationProvider.getApplicationContext();
    // Declared in the manifest, so granted at install.
    shadowOf((Application) context).grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    CrumblesDecryptedLogsActivity.publicKeyManagerForTest = mockPublicKeyManager;
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);

    ProviderInfo providerInfo = new ProviderInfo();
    providerInfo.name = FileProvider.class.getName();
    providerInfo.authority = CrumblesConstants.FILE_PROVIDER_AUTHORITY;
    providerInfo.packageName = context.getPackageName();
    providerInfo.exported = false;
    providerInfo.grantUriPermissions = true;
    providerInfo.metaData = new Bundle();
    providerInfo.metaData.putInt("android.support.FILE_PROVIDER_PATHS", R.xml.file_paths);
    ShadowPackageManager shadowPackageManager = shadowOf(context.getPackageManager());
    shadowPackageManager.addOrUpdateProvider(providerInfo);
    // FileProvider caches its roots per authority, but each Robolectric test has new app dirs.
    Field fileProviderRoots = FileProvider.class.getDeclaredField("sCache");
    fileProviderRoots.setAccessible(true);
    ((Map<?, ?>) fileProviderRoots.get(null)).clear();
  }

  @After
  public void tearDown() {
    if (scenario != null) {
      scenario.close();
    }
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesDecryptedLogsActivity.publicKeyManagerForTest = null;
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesDecryptedLogsSession.destroyActiveSession();
  }

  private Intent createTestIntent(String fileName) {
    ArrayList<CrumblesDecryptedLogEntry> entries = new ArrayList<>();
    entries.add(
        new CrumblesDecryptedLogEntry(
            fileName, testRawBytes1.clone(), TEST_DEVICE_ID, /* originalBatch= */ null));
    long sessionId = CrumblesDecryptedLogsSession.startSession(entries);
    Intent intent =
        new Intent(
            ApplicationProvider.getApplicationContext(), CrumblesDecryptedLogsActivity.class);
    intent.putExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, sessionId);
    return intent;
  }

  /** Starts a session holding one log entry backed by {@code rawBytes}, as a decryption does. */
  private static long startSession(byte[] rawBytes) {
    return CrumblesDecryptedLogsSession.startSession(
        ImmutableList.of(
            new CrumblesDecryptedLogEntry(
                TEST_FILE_NAME_1, rawBytes, TEST_DEVICE_ID, /* originalBatch= */ null)));
  }

  /** Opens the viewer on {@code sessionId} and brings it to the resumed state. */
  private static ActivityController<CrumblesDecryptedLogsActivity> launchViewer(long sessionId) {
    Intent intent =
        new Intent(ApplicationProvider.getApplicationContext(), CrumblesDecryptedLogsActivity.class)
            .putExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, sessionId);
    return Robolectric.buildActivity(CrumblesDecryptedLogsActivity.class, intent).setup();
  }

  private static String logText(Activity viewer) {
    return ((TextView) viewer.findViewById(R.id.decrypted_logs_text_view)).getText().toString();
  }

  private static void openKeyPicker(Activity viewer) {
    viewer.findViewById(R.id.reencrypt_and_share_button).performClick();
  }

  /**
   * Picks a recipient key in {@code viewer}, which stages the re-encrypted log and lists the apps
   * that can receive it.
   */
  private void pickKey(Activity viewer) throws Exception {
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(recipientKey));
    stageReEncryptedBatches();
    openKeyPicker(viewer);
    IntentForResult keyPicker = shadowOf(viewer).getNextStartedActivityForResult();
    shadowOf(viewer)
        .receiveResult(
            keyPicker.intent,
            Activity.RESULT_OK,
            new Intent()
                .putExtra(
                    CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS,
                    CrumblesLogsEncryptor.getPublicKeyFingerprint(recipientKey)));
  }

  /** Has the mock encryptor re-encrypt batches, and write them where the viewer stages them. */
  private void stageReEncryptedBatches() throws Exception {
    when(mockLogsEncryptor.reEncryptLogBatch(any(), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
    when(mockLogsEncryptor.serializeBytes(any(), any(), any()))
        .thenAnswer(
            invocation ->
                Files.write(
                    new File(invocation.<File>getArgument(1), invocation.<String>getArgument(2))
                        .toPath(),
                    "re-encrypted".getBytes(UTF_8),
                    StandardOpenOption.WRITE));
  }

  /** Installs an app whose activity {@code component}, named {@code label}, accepts the log. */
  private static void addShareTarget(ComponentName component, String label) throws Exception {
    ActivityInfo activity = new ActivityInfo();
    activity.packageName = component.getPackageName();
    activity.name = component.getClassName();
    activity.nonLocalizedLabel = label;
    ShadowPackageManager packageManager =
        shadowOf(ApplicationProvider.getApplicationContext().getPackageManager());
    packageManager.addOrUpdateActivity(activity);
    IntentFilter filter = new IntentFilter(Intent.ACTION_SEND, "application/octet-stream");
    filter.addCategory(Intent.CATEGORY_DEFAULT);
    packageManager.addIntentFilterForActivity(component, filter);
  }

  /**
   * Has {@code viewer} send the re-encrypted log to {@link #SHARE_TARGET}, picked and confirmed.
   */
  private void shareWithTarget(Activity viewer) throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    pickKey(viewer);
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);
    clickDialogButton(DialogInterface.BUTTON_POSITIVE);
  }

  private static void clickDialogButton(int whichButton) {
    ShadowAlertDialog.getLatestAlertDialog().getButton(whichButton).performClick();
    shadowOf(Looper.getMainLooper()).idle();
  }

  private static File onlyStagedFile(Context context) {
    File[] stagedFiles = CrumblesReEncryptedCache.getDirectory(context).listFiles();
    assertThat(stagedFiles).hasLength(1);
    return stagedFiles[0];
  }

  /** Decrypts the {@link SealedLogs} of the format version 2 {@code batch} as {@code recipient}. */
  private static SealedLogs sealedLogsOf(LogBatch batch, KeyPair recipient) throws Exception {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsaCipher.init(
        Cipher.UNWRAP_MODE,
        recipient.getPrivate(),
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    Key aesKey =
        rsaCipher.unwrap(
            batch.getKey().getEncryptedSymmetricKey().toByteArray(), "AES", Cipher.SECRET_KEY);
    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    aesCipher.init(
        Cipher.DECRYPT_MODE,
        aesKey,
        new GCMParameterSpec(
            CrumblesLogsEncryptor.GCM_TAG_LEN_BITS, batch.getKey().getIv().toByteArray()));
    aesCipher.updateAAD(
        CrumblesLogsEncryptor.computeAssociatedData(
            batch.getMetadata(), batch.getKey().getKeyEncryptionType(), recipient.getPublic()));
    ByteBuffer paddedSealedLogs =
        ByteBuffer.wrap(aesCipher.doFinal(batch.getData().getLogBlob().toByteArray()));
    byte[] sealedLogs = new byte[paddedSealedLogs.getInt()];
    paddedSealedLogs.get(sealedLogs);
    return SealedLogs.parseFrom(sealedLogs, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Test
  public void onCreate_usesInjectedPublicKeyManager() {
    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));
    scenario.onActivity(activity -> activity.handleReEncryption("some_id", false));
    shadowOf(Looper.getMainLooper()).idle();
    verify(mockPublicKeyManager).getExternalReEncryptPublicKeys();
  }

  @Test
  public void onCreate_withNoTestManager_usesRealManager() {
    CrumblesDecryptedLogsActivity.publicKeyManagerForTest = null;
    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));
    scenario.onActivity(
        activity -> {
          Button reEncryptButton = activity.findViewById(R.id.reencrypt_and_share_button);
          assertThat(reEncryptButton.isEnabled()).isTrue();
        });
  }

  @Test
  public void onActivityResult_withWrongRequestCode_doesNothing() throws Exception {
    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));
    scenario.onActivity(
        activity -> {
          activity.onActivityResult(999, Activity.RESULT_OK, new Intent());
          shadowOf(Looper.getMainLooper()).idle();
          try {
            verify(mockLogsEncryptor, never()).reEncryptLogBatch(any(), any(), any());
          } catch (CrumblesKeysException e) {
            throw new AssertionError("Test setup failed.", e);
          }
        });
  }

  @Test
  public void handleReEncryption_withExternalKey_reEncryptsAndShares() throws Exception {
    // Given: A valid external key and its hash are mocked.
    PublicKey mockExternalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    String keyHash = CrumblesLogsEncryptor.getPublicKeyFingerprint(mockExternalKey);
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(mockExternalKey));

    when(mockLogsEncryptor.reEncryptLogBatch(any(), any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
    File tempFile = tempFolder.newFile("reencrypted.bin");
    when(mockLogsEncryptor.serializeBytes(any(), any(), any())).thenReturn(tempFile.toPath());

    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));
    File staleInShare =
        new File(
            CrumblesReEncryptedCache.getDirectory(ApplicationProvider.getApplicationContext()),
            "prior_share.bin");
    assertThat(staleInShare.getParentFile().mkdirs()).isTrue();
    assertThat(staleInShare.createNewFile()).isTrue();

    // When: The handler is called with the external key's hash, any prior cache file is swept.
    scenario.onActivity(
        activity -> {
          activity.handleReEncryption(keyHash, false);
          assertThat(staleInShare.exists()).isFalse();
          shadowOf(Looper.getMainLooper()).idle();

          // Then: The manager is queried for external keys.
          verify(mockPublicKeyManager).getExternalReEncryptPublicKeys();
          // And: The encryptor is called with the correct external key and original device id.
          try {
            verify(mockLogsEncryptor)
                .reEncryptLogBatch(testRawBytes1, mockExternalKey, TEST_RECORDED_METADATA);
          } catch (CrumblesKeysException e) {
            throw new AssertionError("Test setup failed.", e);
          }
        });
  }

  @Test
  public void handleReEncryption_withExternalKey_recordsTheExportInTheActivityLog()
      throws Exception {
    PublicKey externalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(externalKey));
    stageReEncryptedBatches();
    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));

    String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(externalKey);
    scenario.onActivity(activity -> activity.handleReEncryption(fingerprint, false));
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockAuditLogger)
        .logEvent(
            "LOGS_RE_ENCRYPTED",
            "Re-encrypted 1 batch(es) to share them, to the key with fingerprint "
                + fingerprint
                + ".");
  }

  @Test
  public void handleReEncryption_whenAnEarlierKeyCannotBeFingerprinted_stillFindsTheSelectedKey()
      throws Exception {
    // A mock key has no encoding, so its fingerprint cannot be computed.
    PublicKey unreadableKey = mock(PublicKey.class);
    PublicKey selectedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(unreadableKey, selectedKey));
    stageReEncryptedBatches();
    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));

    String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(selectedKey);
    scenario.onActivity(activity -> activity.handleReEncryption(fingerprint, false));
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockLogsEncryptor).reEncryptLogBatch(testRawBytes1, selectedKey, TEST_RECORDED_METADATA);
  }

  @Test
  public void reEncryptAndOfferToShareLogs_toAKeyWithoutEncoding_recordsTheExportAnyway()
      throws Exception {
    PublicKey unencodableKey =
        new PublicKey() {
          @Override
          public String getAlgorithm() {
            return "RSA";
          }

          @Override
          public String getFormat() {
            return null;
          }

          @Override
          public byte[] getEncoded() {
            return null;
          }
        };
    stageReEncryptedBatches();
    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));

    scenario.onActivity(activity -> activity.reEncryptAndOfferToShareLogs(unencodableKey));
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockAuditLogger)
        .logEvent(
            "LOGS_RE_ENCRYPTED",
            "Re-encrypted 1 batch(es) to share them, to the key with fingerprint unavailable.");
  }

  @Test
  public void handleReEncryption_withMismatchedKey_showsToast() throws Exception {
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys()).thenReturn(ImmutableList.of());

    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));

    scenario.onActivity(activity -> activity.handleReEncryption("non_existent_id", false));
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Selected re-encryption key could not be found.");
    verify(mockLogsEncryptor, never()).reEncryptLogBatch(any(), any(), any());
  }

  @Test
  public void onCreate_withoutSession_disablesReencryptButton() {
    Context ctx = ApplicationProvider.getApplicationContext();
    scenario = ActivityScenario.launch(new Intent(ctx, CrumblesDecryptedLogsActivity.class));
    scenario.onActivity(
        a -> assertThat(a.findViewById(R.id.reencrypt_and_share_button).isEnabled()).isFalse());
  }

  @Test
  public void activityLifecycle_withSession_enforcesSecurityDisplaysLogsAndCleansUp()
      throws Exception {
    Context ctx = ApplicationProvider.getApplicationContext();
    byte[] mutableBytes = "secret_to_wipe".getBytes(UTF_8);
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(new CrumblesDecryptedLogEntry("to_wipe.bin", mutableBytes)));
    Intent intent =
        new Intent(ctx, CrumblesDecryptedLogsActivity.class)
            .putExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, sessionId);

    File staleBeforeCreate = new File(CrumblesReEncryptedCache.getDirectory(ctx), "stale1.bin");
    assertThat(staleBeforeCreate.getParentFile().mkdirs()).isTrue();
    assertThat(staleBeforeCreate.createNewFile()).isTrue();
    scenario = ActivityScenario.launch(intent);
    assertThat(staleBeforeCreate.exists()).isFalse();
    File staleBeforeDestroy = new File(CrumblesReEncryptedCache.getDirectory(ctx), "stale2.bin");
    assertThat(staleBeforeDestroy.getParentFile().mkdirs()).isTrue();
    assertThat(staleBeforeDestroy.createNewFile()).isTrue();
    scenario.onActivity(
        a -> {
          assertThat(a.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE)
              .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
          assertThat(hidesOverlayWindows(a)).isTrue();
          assertThat(
                  ((TextView) a.findViewById(R.id.decrypted_logs_text_view)).getText().toString())
              .contains("to_wipe.bin");
        });
    scenario.close();
    assertThat(staleBeforeDestroy.exists()).isFalse();
    scenario = null;

    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    assertThat(mutableBytes).isEqualTo(new byte[mutableBytes.length]);
  }

  @Test
  public void logText_cannotBeSelectedOrLongClicked() {
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();

    TextView logTextView = viewer.findViewById(R.id.decrypted_logs_text_view);

    expect.that(logTextView.isTextSelectable()).isFalse();
    expect.that(logTextView.isLongClickable()).isFalse();
  }

  @Test
  public void logText_isHiddenFromAccessibilityServicesOtherThanTools() {
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();

    TextView logTextView = viewer.findViewById(R.id.decrypted_logs_text_view);

    assertThat(logTextView.isAccessibilityDataSensitive()).isTrue();
  }

  @Test
  public void onStop_wipesLogsAndFinishes() {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);

    controller.pause().stop();

    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    expect.that(logText(controller.get())).isEmpty();
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void configurationChange_keepsLogsForRecreatedViewer() {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);
    RuntimeEnvironment.setQualifiers("+land");

    controller.configurationChange();

    expect.that(rawBytes).isEqualTo(testRawBytes1);
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isPresent();
    expect.that(logText(controller.get())).contains(TEST_FILE_NAME_1);
    expect.that(controller.get().isFinishing()).isFalse();
  }

  @Test
  public void onStop_whileKeyPickerIsOpen_keepsLogs() {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);
    openKeyPicker(controller.get());

    controller.pause().stop();

    expect.that(rawBytes).isEqualTo(testRawBytes1);
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isPresent();
    expect.that(logText(controller.get())).contains(TEST_FILE_NAME_1);
    expect.that(controller.get().isFinishing()).isFalse();
  }

  @Test
  public void onStop_afterKeyPickerIsCancelled_wipesLogsAndFinishes() {
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    openKeyPicker(controller.get());
    IntentForResult keyPicker = shadowOf(controller.get()).getNextStartedActivityForResult();
    controller.pause().stop().restart();
    shadowOf(controller.get()).receiveResult(keyPicker.intent, Activity.RESULT_CANCELED, null);
    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Re-encryption cancelled.");
    expect.that(controller.get().isFinishing()).isFalse();

    controller.pause().stop();

    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onActivityResult_whenKeyPickerReturnsWithNoSession_wipesLogsAndFinishes() throws Exception {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);
    openKeyPicker(controller.get());
    IntentForResult keyPicker = shadowOf(controller.get()).getNextStartedActivityForResult();
    
    CrumblesDecryptedLogsSession.destroyActiveSession();
    
    shadowOf(controller.get()).receiveResult(keyPicker.intent, Activity.RESULT_OK, new Intent()
        .putExtra(CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS, "some_alias"));

    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onActivityResult_whenKeyPickerCancels_showsToastAndDoesNotWipe() {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);
    openKeyPicker(controller.get());
    IntentForResult keyPicker = shadowOf(controller.get()).getNextStartedActivityForResult();
    controller.pause().stop();

    controller.start();
    shadowOf(controller.get()).receiveResult(keyPicker.intent, Activity.RESULT_CANCELED, null);

    expect.that(rawBytes).isNotEqualTo(new byte[rawBytes.length]);
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isPresent();
    expect.that(logText(controller.get())).isNotEmpty();
    expect.that(controller.get().isFinishing()).isFalse();
    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Re-encryption cancelled.");
  }

  @Test
  public void onDestroy_whileKeyPickerIsOpen_wipesLogs() {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);
    openKeyPicker(controller.get());

    controller.pause().stop().destroy();

    expect.that(controller.get().isDestroyed()).isTrue();
    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
  }

  /**
   * Records the lifecycle and trim-memory callbacks that {@link Activity} forwards to fragments.
   */
  @SuppressWarnings("deprecation") // CrumblesDecryptedLogsActivity extends android.app.Activity.
  public static final class TrimMemoryFragment extends Fragment {
    boolean stopped;
    int trimmedLevel;

    @Override
    public void onStop() {
      super.onStop();
      stopped = true;
    }

    @Override
    public void onTrimMemory(int level) {
      super.onTrimMemory(level);
      trimmedLevel = level;
    }
  }

  @Test
  @SuppressWarnings("deprecation") // CrumblesDecryptedLogsActivity extends android.app.Activity.
  public void onTrimMemory_uiHiddenWhileKeyPickerIsOpen_wipesLogsAndFinishes() {
    byte[] rawBytes = testRawBytes1.clone();
    long sessionId = startSession(rawBytes);
    ActivityController<CrumblesDecryptedLogsActivity> controller = launchViewer(sessionId);
    TrimMemoryFragment listener = new TrimMemoryFragment();
    controller.get().getFragmentManager().beginTransaction().add(listener, "trim").commitNow();
    openKeyPicker(controller.get());
    controller.pause().stop();

    controller.get().onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN);

    expect.that(listener.stopped).isTrue();
    expect.that(listener.trimmedLevel).isEqualTo(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN);
    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onTrimMemory_whileKeyPickerIsVisible_keepsLogs() {
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    openKeyPicker(controller.get());
    controller.pause().stop();

    controller.get().onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW);

    expect.that(rawBytes).isEqualTo(testRawBytes1);
    expect.that(controller.get().isFinishing()).isFalse();
  }

  @Test
  public void onStop_whileShareTargetIsOpen_wipesLogsButKeepsStagedCopy() throws Exception {
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    shareWithTarget(controller.get());
    File stagedFile = onlyStagedFile(controller.get());

    controller.pause().stop();
    controller.get().onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN);

    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(logText(controller.get())).isEmpty();
    expect.that(stagedFile.exists()).isTrue();
    expect.that(controller.get().isFinishing()).isFalse();
  }

  @Test
  public void onActivityResult_afterShareTargetCoveredViewer_deletesStagedCopyAndFinishes()
      throws Exception {
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(testRawBytes1.clone()));
    shareWithTarget(controller.get());
    IntentForResult shareTarget = shadowOf(controller.get()).getNextStartedActivityForResult();
    File stagedFile = onlyStagedFile(controller.get());
    controller.pause().stop();

    controller.restart();
    shadowOf(controller.get()).receiveResult(shareTarget.intent, Activity.RESULT_OK, null);

    expect.that(stagedFile.exists()).isFalse();
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onActivityResult_beforeViewerStops_wipesLogsAndFinishes() throws Exception {
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    shareWithTarget(controller.get());
    IntentForResult shareTarget = shadowOf(controller.get()).getNextStartedActivityForResult();
    File stagedFile = onlyStagedFile(controller.get());

    shadowOf(controller.get()).receiveResult(shareTarget.intent, Activity.RESULT_CANCELED, null);

    expect.that(stagedFile.exists()).isFalse();
    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onStop_afterShareTargetReturned_wipesLogsAndFinishes() throws Exception {
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    shareWithTarget(controller.get());
    IntentForResult shareTarget = shadowOf(controller.get()).getNextStartedActivityForResult();
    shadowOf(controller.get()).receiveResult(shareTarget.intent, Activity.RESULT_CANCELED, null);

    controller.pause().stop();

    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void share_listsAppsThatAcceptTheLogByName() throws Exception {
    addShareTarget(new ComponentName("com.example.a", "com.example.a.Share"), "Zeta");
    addShareTarget(new ComponentName("com.example.z", "com.example.z.Share"), "Alpha");
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();

    pickKey(viewer);

    assertThat(shadowOf(ShadowAlertDialog.getLatestAlertDialog()).getItems())
        .asList()
        .containsExactly("Alpha (com.example.z)", "Zeta (com.example.a)")
        .inOrder();
  }

  @Test
  public void share_namesPickedAppAndItsPackageBeforeSendingTheLog() throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);

    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);

    ShadowAlertDialog confirmation = shadowOf(ShadowAlertDialog.getLatestAlertDialog());
    expect
        .that(confirmation.getTitle().toString())
        .isEqualTo(
            viewer.getString(
                R.string.dialog_title_confirm_share_target, "Mail", "com.example.mail"));
    expect
        .that(confirmation.getMessage().toString())
        .isEqualTo(
            viewer.getString(
                R.string.dialog_message_confirm_share_target, "Mail", "com.example.mail"));
    expect.that(shadowOf(viewer).getNextStartedActivityForResult()).isNull();
  }

  @Test
  public void share_escapesLineBreaksAndBidiControlsInAppLabels() throws Exception {
    addShareTarget(SHARE_TARGET, "Mail\n\u202e");
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    ShadowAlertDialog chooser = shadowOf(ShadowAlertDialog.getLatestAlertDialog());
    expect
        .that(chooser.getItems())
        .asList()
        .containsExactly("Mail\\u000a\\u202e (com.example.mail)");

    chooser.clickOnItem(0);

    ShadowAlertDialog confirmation = shadowOf(ShadowAlertDialog.getLatestAlertDialog());
    expect
        .that(confirmation.getTitle().toString())
        .isEqualTo(
            viewer.getString(
                R.string.dialog_title_confirm_share_target,
                "Mail\\u000a\\u202e",
                "com.example.mail"));
    expect
        .that(confirmation.getMessage().toString())
        .isEqualTo(
            viewer.getString(
                R.string.dialog_message_confirm_share_target,
                "Mail\\u000a\\u202e",
                "com.example.mail"));
  }

  @Test
  public void share_capsPaddedAppLabelBeforePackageName() throws Exception {
    addShareTarget(SHARE_TARGET, "Signal (org.thoughtcrime.securesms)" + "\u2800".repeat(300));
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    ShadowAlertDialog chooser = shadowOf(ShadowAlertDialog.getLatestAlertDialog());
    String expectedLabel =
        "Signal (org.thoughtcrime.securesms)" + "\u2800".repeat(5) + "… (com.example.mail)";
    expect.that(chooser.getItems()).asList().containsExactly(expectedLabel);

    chooser.clickOnItem(0);

    ShadowAlertDialog confirmation = shadowOf(ShadowAlertDialog.getLatestAlertDialog());
    String expectedEscapedLabel = "Signal (org.thoughtcrime.securesms)" + "\u2800".repeat(5) + "…";
    expect
        .that(confirmation.getTitle().toString())
        .isEqualTo(
            viewer.getString(
                R.string.dialog_title_confirm_share_target,
                expectedEscapedLabel,
                "com.example.mail"));
    expect
        .that(confirmation.getMessage().toString())
        .isEqualTo(
            viewer.getString(
                R.string.dialog_message_confirm_share_target,
                expectedEscapedLabel,
                "com.example.mail"));
  }

  @Test
  public void share_capsExpandedFormatEscapesWithoutSplittingTokens() throws Exception {
    addShareTarget(SHARE_TARGET, "\u200b".repeat(40));
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    ShadowAlertDialog chooser = shadowOf(ShadowAlertDialog.getLatestAlertDialog());
    String expectedEscapedLabel = "\\u200b".repeat(6) + "…";
    expect
        .that(chooser.getItems())
        .asList()
        .containsExactly(expectedEscapedLabel + " (com.example.mail)");
    expect
        .that(CrumblesDeviceAdminReceiver.escapeLabel("\udb40\udc01".repeat(10)))
        .isEqualTo("\\udb40\\udc01".repeat(3) + "…");
    expect
        .that(CrumblesDeviceAdminReceiver.escapeLabel("a".repeat(38) + "\""))
        .isEqualTo("a".repeat(38) + "\\\"");
    expect
        .that(CrumblesDeviceAdminReceiver.escapeLabel("a".repeat(39) + "\""))
        .isEqualTo("a".repeat(39) + "…");
    expect
        .that(CrumblesDeviceAdminReceiver.escapeLabel("\uD83D\uDE00".repeat(40)))
        .isEqualTo("\uD83D\uDE00".repeat(40));
    expect
        .that(CrumblesDeviceAdminReceiver.escapeLabel("\uD83D\uDE00".repeat(41)))
        .isEqualTo("\uD83D\uDE00".repeat(40) + "…");
  }

  @Test
  public void share_confirmed_sendsLogToPickedAppOnly() throws Exception {
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();

    shareWithTarget(viewer);

    Intent sent = shadowOf(viewer).getNextStartedActivityForResult().intent;
    Uri expectedUri =
        Uri.parse(
            "content://com.android.securelogging.fileprovider/shared_logs/"
                + onlyStagedFile(viewer).getName());
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo("All logs re-encrypted. Choose an app to share.");
    expect.that(sent.getComponent()).isEqualTo(SHARE_TARGET);
    expect
        .that(IntentCompat.getParcelableExtra(sent, Intent.EXTRA_STREAM, Uri.class))
        .isEqualTo(expectedUri);
    expect.that(sent.getClipData()).isNotNull();
    expect
        .that(
            sent.getClipData().getDescription().hasMimeType(ClipDescription.MIMETYPE_TEXT_URILIST))
        .isTrue();
    expect.that(sent.getClipData().getItemCount()).isEqualTo(1);
    expect.that(sent.getClipData().getItemAt(0).getUri()).isEqualTo(expectedUri);
    expect.that(sent.getFlags()).isEqualTo(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  }

  @Test
  public void share_confirmedWithMultipleLogs_attachesAllUrisToClipData() throws Exception {
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "first.bin", testRawBytes1.clone(), TEST_DEVICE_ID, /* originalBatch= */ null),
                new CrumblesDecryptedLogEntry(
                    "second.bin",
                    testRawBytes1.clone(),
                    TEST_DEVICE_ID,
                    /* originalBatch= */ null)));
    Activity viewer = launchViewer(sessionId).get();
    ActivityInfo activity = new ActivityInfo();
    activity.packageName = SHARE_TARGET.getPackageName();
    activity.name = SHARE_TARGET.getClassName();
    activity.nonLocalizedLabel = SHARE_TARGET_LABEL;
    ShadowPackageManager packageManager =
        shadowOf(ApplicationProvider.getApplicationContext().getPackageManager());
    packageManager.addOrUpdateActivity(activity);
    IntentFilter filter = new IntentFilter(Intent.ACTION_SEND_MULTIPLE, "*/*");
    filter.addCategory(Intent.CATEGORY_DEFAULT);
    packageManager.addIntentFilterForActivity(SHARE_TARGET, filter);

    pickKey(viewer);
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);
    clickDialogButton(DialogInterface.BUTTON_POSITIVE);

    Intent sent = shadowOf(viewer).getNextStartedActivityForResult().intent;
    ArrayList<Uri> streamUris =
        IntentCompat.getParcelableArrayListExtra(sent, Intent.EXTRA_STREAM, Uri.class);
    expect.that(sent.getAction()).isEqualTo(Intent.ACTION_SEND_MULTIPLE);
    expect.that(streamUris).hasSize(2);
    expect.that(sent.getClipData()).isNotNull();
    expect.that(sent.getClipData().getItemCount()).isEqualTo(2);
    expect
        .that(
            ImmutableList.of(
                sent.getClipData().getItemAt(0).getUri(), sent.getClipData().getItemAt(1).getUri()))
        .containsExactlyElementsIn(streamUris)
        .inOrder();
    expect.that(sent.getFlags()).isEqualTo(Intent.FLAG_GRANT_READ_URI_PERMISSION);
  }

  @Test
  public void share_logsWithTheSameName_sendsADistinctFileForEach() throws Exception {
    // Re-encrypted within a few milliseconds of each other, under the fallback display name.
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            Stream.generate(
                    () ->
                        new CrumblesDecryptedLogEntry(
                            "Unknown_File",
                            testRawBytes1.clone(),
                            TEST_DEVICE_ID,
                            /* originalBatch= */ null))
                .limit(10)
                .collect(toImmutableList()));
    Activity viewer = launchViewer(sessionId).get();
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    IntentFilter sendMultiple = new IntentFilter(Intent.ACTION_SEND_MULTIPLE, "*/*");
    sendMultiple.addCategory(Intent.CATEGORY_DEFAULT);
    shadowOf(viewer.getPackageManager()).addIntentFilterForActivity(SHARE_TARGET, sendMultiple);

    pickKey(viewer);
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);
    clickDialogButton(DialogInterface.BUTTON_POSITIVE);

    ArrayList<Uri> streamUris =
        IntentCompat.getParcelableArrayListExtra(
            shadowOf(viewer).getNextStartedActivityForResult().intent,
            Intent.EXTRA_STREAM,
            Uri.class);
    expect.that(streamUris).hasSize(10);
    expect.that(streamUris).containsNoDuplicates();
    expect.that(CrumblesReEncryptedCache.getDirectory(viewer).list()).hasLength(10);
  }

  @Test
  public void share_whenAppListIsCancelled_deletesStagedLog() throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    File stagedFile = onlyStagedFile(viewer);

    ShadowAlertDialog.getLatestAlertDialog().cancel();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(stagedFile.exists()).isFalse();
  }

  @Test
  public void share_whenUserDeclinesPickedApp_deletesStagedLogWithoutSendingIt() throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    File stagedFile = onlyStagedFile(viewer);
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);

    clickDialogButton(DialogInterface.BUTTON_NEGATIVE);

    expect.that(stagedFile.exists()).isFalse();
    expect.that(shadowOf(viewer).getNextStartedActivityForResult()).isNull();
  }

  @Test
  public void share_whenConfirmationIsCancelled_deletesStagedLog() throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    File stagedFile = onlyStagedFile(viewer);
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);

    ShadowAlertDialog.getLatestAlertDialog().cancel();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(stagedFile.exists()).isFalse();
  }

  @Test
  public void share_withoutAppForTheLog_deletesStagedLogAndSaysSo() throws Exception {
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();

    pickKey(viewer);

    expect.that(CrumblesReEncryptedCache.getDirectory(viewer).exists()).isFalse();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(viewer.getString(R.string.toast_no_app_for_re_encrypted_logs));
  }

  @Test
  public void share_whenPickedAppIsGoneBeforeSending_deletesStagedLogAndSaysSo() throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    Activity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);
    shadowOf(RuntimeEnvironment.getApplication()).checkActivities(true);
    shadowOf(viewer.getPackageManager()).removeActivity(SHARE_TARGET);

    clickDialogButton(DialogInterface.BUTTON_POSITIVE);

    expect.that(CrumblesReEncryptedCache.getDirectory(viewer).exists()).isFalse();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(viewer.getString(R.string.toast_no_app_for_re_encrypted_logs));
  }

  @Test
  public void
      reEncryptAndOfferToShareLogs_whenOriginalBatchWasSigned_reSignsUnderSameSequenceNumber()
          throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesBatchSigner signer = new CrumblesBatchSigner(context);
    assertThat(signer.sign(LogBatch.getDefaultInstance()).getSequenceNumber()).isEqualTo(1);
    LogBatch signedOriginal =
        signer.sign(
            LogBatch.newBuilder()
                .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("ciphertext")))
                .build());
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    LogBatch reEncryptedBatch =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("new ciphertext")))
            .build();
    when(mockLogsEncryptor.reEncryptLogBatchForSigning(any(), any(), any(), any(), any()))
        .thenReturn(reEncryptedBatch);
    File stagedFile = tempFolder.newFile("signed_share.bin");
    when(mockLogsEncryptor.serializeBytes(any(), any(), any())).thenReturn(stagedFile.toPath());
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    TEST_FILE_NAME_1, testRawBytes1.clone(), TEST_DEVICE_ID, signedOriginal)));
    CrumblesDecryptedLogsActivity viewer = launchViewer(sessionId).get();

    viewer.reEncryptAndOfferToShareLogs(recipientKey);

    verify(mockLogsEncryptor)
        .reEncryptLogBatchForSigning(
            eq(viewer), eq(testRawBytes1), eq(recipientKey), eq(TEST_RECORDED_METADATA), any());
    verify(mockLogsEncryptor, never()).reEncryptLogBatch(any(), any(), any());
    ArgumentCaptor<LogBatch> batchCaptor = ArgumentCaptor.forClass(LogBatch.class);
    verify(mockLogsEncryptor).serializeBytes(batchCaptor.capture(), any(), any());
    LogBatch writtenBatch = batchCaptor.getValue();
    expect.that(writtenBatch.getSequenceNumber()).isEqualTo(2);
    expect.that(writtenBatch.hasSignature()).isTrue();
    expect.that(writtenBatch.getData()).isEqualTo(reEncryptedBatch.getData());
    expect
        .that(
            new CrumblesBatchSigningKey(viewer)
                .verifies(
                    writtenBatch.toBuilder().clearSignature().build().toByteArray(),
                    writtenBatch.getSignature().getSignature().toByteArray()))
        .isTrue();
  }

  @Test
  public void reEncryptAndOfferToShareLogs_ofSignedV2Batch_sealsLocalIdChainAndRecordedTime()
      throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    Context context = ApplicationProvider.getApplicationContext();
    // Like CrumblesMain's encryptor, which has no context of its own, before any caches one.
    CrumblesLogsEncryptor.setApplicationContext(null);
    CrumblesLogsEncryptor spyEncryptor = spy(new CrumblesLogsEncryptor());
    CrumblesMain.setLogsEncryptorInstanceForTest(spyEncryptor);
    CrumblesBatchSigner signer = new CrumblesBatchSigner(context);
    LogBatch signedV2Original =
        signer.sign(
            LogBatch.newBuilder()
                .setMetadata(
                    LogMetadata.newBuilder()
                        .setBlobSize(4112)
                        .setEncryptionType(
                            LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA))
                .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("v2-cipher")))
                .build(),
            signer.attestationChainToSeal());
    assertThat(signedV2Original.getMetadata().getDevice().getDeviceId()).isEmpty();
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    TEST_FILE_NAME_1,
                    testRawBytes1.clone(),
                    signedV2Original.getMetadata().getDevice().getDeviceId(),
                    TEST_RECORDED_TIME,
                    signedV2Original)));
    CrumblesDecryptedLogsActivity viewer = launchViewer(sessionId).get();

    viewer.reEncryptAndOfferToShareLogs(recipientKeyPair.getPublic());

    verify(spyEncryptor)
        .reEncryptLogBatchForSigning(
            eq(viewer), eq(testRawBytes1), eq(recipientKeyPair.getPublic()), any(), any());
    verify(spyEncryptor, never()).reEncryptLogBatch(any(), any(), any());
    LogBatch writtenBatch =
        LogBatch.parseFrom(
            Files.readAllBytes(onlyStagedFile(viewer).toPath()),
            ExtensionRegistryLite.getEmptyRegistry());
    SealedLogs sealedLogs = sealedLogsOf(writtenBatch, recipientKeyPair);
    ImmutableList<ByteString> batchSigningKeyChain =
        new CrumblesBatchSigningKey(viewer).attestationChain();
    assertThat(batchSigningKeyChain).isNotEmpty();
    expect.that(writtenBatch.getSequenceNumber()).isEqualTo(1);
    expect.that(writtenBatch.getSignature().getAttestationChainList()).isEmpty();
    expect
        .that(
            new CrumblesBatchSigningKey(viewer)
                .verifies(
                    writtenBatch.toBuilder().clearSignature().build().toByteArray(),
                    writtenBatch.getSignature().getSignature().toByteArray()))
        .isTrue();
    expect
        .that(sealedLogs.getMetadata().getDevice().getDeviceId())
        .isEqualTo(CrumblesDeviceIdManager.getDeviceId(context));
    expect.that(sealedLogs.getMetadata().getTimestamp()).isEqualTo(TEST_RECORDED_TIME);
    expect
        .that(sealedLogs.getAttestationChainList())
        .containsExactlyElementsIn(batchSigningKeyChain)
        .inOrder();
  }

  @Test
  public void reEncryptAndOfferToShareLogs_whenOriginalBatchIsUnsigned_writesBatchUnsigned()
      throws Exception {
    LogBatch unsignedOriginal =
        LogBatch.newBuilder()
            .setSequenceNumber(5)
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("ciphertext")))
            .build();
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    LogBatch reEncryptedBatch =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("new ciphertext")))
            .build();
    when(mockLogsEncryptor.reEncryptLogBatch(
            testRawBytes1,
            recipientKey,
            TEST_RECORDED_METADATA.toBuilder().setTimestamp(TEST_RECORDED_TIME).build()))
        .thenReturn(reEncryptedBatch);
    File stagedFile = tempFolder.newFile("unsigned_share.bin");
    when(mockLogsEncryptor.serializeBytes(any(), any(), any())).thenReturn(stagedFile.toPath());
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    TEST_FILE_NAME_1,
                    testRawBytes1.clone(),
                    TEST_DEVICE_ID,
                    TEST_RECORDED_TIME,
                    unsignedOriginal)));
    CrumblesDecryptedLogsActivity viewer = launchViewer(sessionId).get();

    viewer.reEncryptAndOfferToShareLogs(recipientKey);

    verify(mockLogsEncryptor, never())
        .reEncryptLogBatchForSigning(any(), any(), any(), any(), any());
    ArgumentCaptor<LogBatch> batchCaptor = ArgumentCaptor.forClass(LogBatch.class);
    verify(mockLogsEncryptor).serializeBytes(batchCaptor.capture(), any(), any());
    expect.that(batchCaptor.getValue()).isEqualTo(reEncryptedBatch);
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesBatchSigningKey.ALIAS);
    verify(mockAuditLogger, never())
        .logEvent(eq(CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED), any());
  }

  @Test
  public void
      reEncryptAndOfferToShareLogs_whenOriginalBatchIsSignedByAnotherKey_writesItUnsignedKeyless()
          throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    LogBatch signedOriginal =
        new CrumblesBatchSigner(context)
            .sign(
                LogBatch.newBuilder()
                    .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("ciphertext")))
                    .build());
    // As when the device ID changes, which deletes the batch-signing key.
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    LogBatch fallbackBatch =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("fallback unsigned")))
            .build();
    when(mockLogsEncryptor.reEncryptLogBatch(testRawBytes1, recipientKey, TEST_RECORDED_METADATA))
        .thenReturn(fallbackBatch);
    File stagedFile = tempFolder.newFile("foreign_share.bin");
    when(mockLogsEncryptor.serializeBytes(any(), any(), any())).thenReturn(stagedFile.toPath());
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    TEST_FILE_NAME_1, testRawBytes1.clone(), TEST_DEVICE_ID, signedOriginal)));
    CrumblesDecryptedLogsActivity viewer = launchViewer(sessionId).get();

    viewer.reEncryptAndOfferToShareLogs(recipientKey);

    verify(mockLogsEncryptor, never())
        .reEncryptLogBatchForSigning(any(), any(), any(), any(), any());
    ArgumentCaptor<LogBatch> batchCaptor = ArgumentCaptor.forClass(LogBatch.class);
    verify(mockLogsEncryptor).serializeBytes(batchCaptor.capture(), any(), any());
    expect.that(batchCaptor.getValue()).isEqualTo(fallbackBatch);
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesBatchSigningKey.ALIAS);
    verify(mockAuditLogger)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED,
            "Re-encrypted log batch 1 written without a signature: signing it again failed.");
  }

  @Test
  public void
      reEncryptAndOfferToShareLogs_whenSigningAgainFails_writesUnsignedBatchAndLogsAuditEvent()
          throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesBatchSigner signer = new CrumblesBatchSigner(context);
    assertThat(signer.sign(LogBatch.getDefaultInstance()).getSequenceNumber()).isEqualTo(1);
    LogBatch signedOriginal =
        signer.sign(
            LogBatch.newBuilder()
                .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("ciphertext")))
                .build());
    // The key still verifies the original, but cannot sign without its certificate chain.
    FakeAndroidKeyStoreSpi.isCertificateChainNull = true;
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    LogBatch localCandidateBatch =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("local candidate")))
            .build();
    LogBatch fallbackBatch =
        LogBatch.newBuilder()
            .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("fallback unsigned")))
            .build();
    when(mockLogsEncryptor.reEncryptLogBatchForSigning(any(), any(), any(), any(), any()))
        .thenReturn(localCandidateBatch);
    when(mockLogsEncryptor.reEncryptLogBatch(testRawBytes1, recipientKey, TEST_RECORDED_METADATA))
        .thenReturn(fallbackBatch);
    File stagedFile = tempFolder.newFile("fallback_share.bin");
    when(mockLogsEncryptor.serializeBytes(any(), any(), any())).thenReturn(stagedFile.toPath());
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    TEST_FILE_NAME_1, testRawBytes1.clone(), TEST_DEVICE_ID, signedOriginal)));
    CrumblesDecryptedLogsActivity viewer = launchViewer(sessionId).get();

    viewer.reEncryptAndOfferToShareLogs(recipientKey);

    ArgumentCaptor<LogBatch> batchCaptor = ArgumentCaptor.forClass(LogBatch.class);
    verify(mockLogsEncryptor).serializeBytes(batchCaptor.capture(), any(), any());
    expect.that(batchCaptor.getValue()).isEqualTo(fallbackBatch);
    verify(mockAuditLogger)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED,
            "Re-encrypted log batch 2 written without a signature: signing it again failed.");
  }

  @Test
  public void share_appListDialog_setsFlagSecureHidesOverlayWindowsAndClearsReferenceOnDismiss()
      throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    CrumblesDecryptedLogsActivity viewer = launchViewer(startSession(testRawBytes1.clone())).get();

    pickKey(viewer);

    AlertDialog appListDialog = ShadowAlertDialog.getLatestAlertDialog();
    Window dialogWindow = appListDialog.getWindow();
    expect.that(viewer.activeShareDialog).isSameInstanceAs(appListDialog);
    expect
        .that(dialogWindow.getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
    expect.that(hidesOverlayWindows(dialogWindow)).isTrue();

    appListDialog.dismiss();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(viewer.activeShareDialog).isNull();
  }

  @Test
  public void share_confirmationDialog_setsFlagSecureHidesOverlayWindowsAndTracksReplacementDialog()
      throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    CrumblesDecryptedLogsActivity viewer = launchViewer(startSession(testRawBytes1.clone())).get();
    pickKey(viewer);

    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);
    shadowOf(Looper.getMainLooper()).idle();

    AlertDialog confirmationDialog = ShadowAlertDialog.getLatestAlertDialog();
    Window dialogWindow = confirmationDialog.getWindow();
    expect.that(viewer.activeShareDialog).isSameInstanceAs(confirmationDialog);
    expect
        .that(dialogWindow.getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
    expect.that(hidesOverlayWindows(dialogWindow)).isTrue();

    confirmationDialog.dismiss();
    shadowOf(Looper.getMainLooper()).idle();

    expect.that(viewer.activeShareDialog).isNull();
  }

  @Test
  public void onStop_whileAppListDialogIsShowing_dismissesDialogDeletesStagedLogAndWipesLogs()
      throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    pickKey(controller.get());
    AlertDialog appListDialog = ShadowAlertDialog.getLatestAlertDialog();
    File stagedFile = onlyStagedFile(controller.get());

    controller.pause().stop();

    expect.that(appListDialog.isShowing()).isFalse();
    expect.that(stagedFile.exists()).isFalse();
    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onStop_whileConfirmationDialogIsShowing_dismissesDialogDeletesStagedLogAndWipesLogs()
      throws Exception {
    addShareTarget(SHARE_TARGET, SHARE_TARGET_LABEL);
    byte[] rawBytes = testRawBytes1.clone();
    ActivityController<CrumblesDecryptedLogsActivity> controller =
        launchViewer(startSession(rawBytes));
    pickKey(controller.get());
    shadowOf(ShadowAlertDialog.getLatestAlertDialog()).clickOnItem(0);
    AlertDialog confirmationDialog = ShadowAlertDialog.getLatestAlertDialog();
    File stagedFile = onlyStagedFile(controller.get());

    controller.pause().stop();

    expect.that(confirmationDialog.isShowing()).isFalse();
    expect.that(stagedFile.exists()).isFalse();
    expect.that(rawBytes).isEqualTo(new byte[rawBytes.length]);
    expect.that(controller.get().isFinishing()).isTrue();
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
}
