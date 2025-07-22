package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ProviderInfo;
import android.os.Looper;
import android.widget.Button;
import androidx.core.content.FileProvider;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.shadows.ShadowPackageManager;
import org.robolectric.shadows.ShadowToast;

/** Tests for {@link CrumblesDecryptedLogsActivity}. */
@RunWith(AndroidJUnit4.class)
public class CrumblesDecryptedLogsActivityTest {

  private static final String TEST_FILE_NAME_1 = "log1.txt";
  private static final byte[] testRawBytes1 = "decrypted log content".getBytes(UTF_8);

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private ActivityScenario<CrumblesDecryptedLogsActivity> scenario;

  @Before
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    CrumblesDecryptedLogsActivity.publicKeyManagerForTest = mockPublicKeyManager;

    ProviderInfo providerInfo = new ProviderInfo();
    providerInfo.name = FileProvider.class.getName();
    providerInfo.authority = CrumblesConstants.FILE_PROVIDER_AUTHORITY;
    providerInfo.packageName = context.getPackageName();
    providerInfo.exported = false;
    providerInfo.grantUriPermissions = true;
    ShadowPackageManager shadowPackageManager = shadowOf(context.getPackageManager());
    shadowPackageManager.addOrUpdateProvider(providerInfo);
  }

  @After
  public void tearDown() {
    if (scenario != null) {
      scenario.close();
    }
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesDecryptedLogsActivity.publicKeyManagerForTest = null;
  }

  private Intent createTestIntent(String fileName) {
    ArrayList<CrumblesDecryptedLogEntry> entries = new ArrayList<>();
    entries.add(
        new CrumblesDecryptedLogEntry(fileName, new String(testRawBytes1, UTF_8), testRawBytes1));
    Intent intent =
        new Intent(
            ApplicationProvider.getApplicationContext(), CrumblesDecryptedLogsActivity.class);
    intent.putExtra(CrumblesConstants.EXTRA_DECRYPTED_LOGS, entries);
    return intent;
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
            verify(mockLogsEncryptor, never()).reEncryptLogBatch(any(), any());
          } catch (CrumblesKeysException e) {
            throw new AssertionError("Test setup failed.", e);
          }
        });
  }

  @Test
  public void handleReEncryption_withExternalKey_reEncryptsAndShares() throws Exception {
    // Given: A valid external key and its hash are mocked.
    PublicKey mockExternalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    String keyHash = CrumblesLogsEncryptor.getPublicKeyHash(mockExternalKey);
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(mockExternalKey));

    when(mockLogsEncryptor.reEncryptLogBatch(any(), any()))
        .thenReturn(LogBatch.getDefaultInstance());
    File tempFile = tempFolder.newFile("reencrypted.bin");
    when(mockLogsEncryptor.serializeBytes(any(), any(), any())).thenReturn(tempFile.toPath());

    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));

    // When: The handler is called with the external key's hash.
    scenario.onActivity(
        activity -> {
          activity.handleReEncryption(keyHash, false);
          shadowOf(Looper.getMainLooper()).idle();

          // Then: The manager is queried for external keys.
          verify(mockPublicKeyManager).getExternalReEncryptPublicKeys();
          // And: The encryptor is called with the correct external key.
          try {
            verify(mockLogsEncryptor).reEncryptLogBatch(testRawBytes1, mockExternalKey);
          } catch (CrumblesKeysException e) {
            throw new AssertionError("Test setup failed.", e);
          }
        });
  }

  @Test
  public void handleReEncryption_withMismatchedKey_showsToast() throws Exception {
    when(mockLogsEncryptor.getPublicKey(anyString())).thenReturn(null);
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys()).thenReturn(ImmutableList.of());

    scenario = ActivityScenario.launch(createTestIntent(TEST_FILE_NAME_1));

    scenario.onActivity(activity -> activity.handleReEncryption("non_existent_id", true));
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Selected re-encryption key could not be found.");
    verify(mockLogsEncryptor, never()).reEncryptLogBatch(any(), any());
  }
}
