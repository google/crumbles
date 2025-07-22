package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Looper;
import android.support.v7.app.ActionBar;
import android.view.View;
import android.widget.ListView;
import android.widget.TextView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowToast;

/** Unit tests for {@link CrumblesReEncryptKeysActivity}. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesReEncryptKeysActivityTest {

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private ActivityScenario<CrumblesReEncryptKeysActivity> scenario;
  private static Provider fakeProviderInstance;

  @BeforeClass
  public static void setUpClass() {
    // Given: A test environment requires a fake AndroidKeyStore provider.
    // When: The test class is being set up.
    // Then: The fake provider is inserted to intercept Keystore calls.
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    fakeProviderInstance = new FakeAndroidKeyStoreProvider();
    Security.insertProviderAt(fakeProviderInstance, 1);
  }

  @AfterClass
  public static void tearDownClass() {
    // Given: The fake provider was used for tests.
    // When: All tests in the class are finished.
    // Then: The fake provider is removed to clean up the security environment.
    if (fakeProviderInstance != null) {
      Security.removeProvider(fakeProviderInstance.getName());
      fakeProviderInstance = null;
    }
  }

  @Before
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    ApplicationProvider.getApplicationContext().setTheme(R.style.Theme_AppCompat);
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    // This is a simple way to inject the mock. A real app might use a DI framework.
    CrumblesReEncryptKeysActivity.publicKeyManagerForTest = mockPublicKeyManager;
    FakeAndroidKeyStoreSpi.keystoreEntries.clear(); // Clear the fake keystore before each test.
  }

  @After
  public void tearDown() {
    if (scenario != null) {
      scenario.close();
    }
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesReEncryptKeysActivity.publicKeyManagerForTest = null;
    FakeAndroidKeyStoreSpi.keystoreEntries.clear(); // Clear the fake keystore after each test.
  }

  private void launchActivity() {
    Context context = ApplicationProvider.getApplicationContext();
    // Use an explicit intent to launch the non-launcher activity.
    Intent intent = new Intent(context, CrumblesReEncryptKeysActivity.class);
    scenario = ActivityScenario.launch(intent);
    shadowOf(Looper.getMainLooper()).idle(); // Ensure UI updates complete.
  }

  @Test
  public void onCreate_setsUpActionBarCorrectly() {
    // Given: An activity will be launched.
    launchActivity();

    // Then: The ActionBar is configured correctly.
    scenario.onActivity(
        activity -> {
          ActionBar actionBar = activity.getSupportActionBar();
          assertThat(actionBar).isNotNull();
          assertThat(actionBar.getTitle().toString()).isEqualTo("Select Re-encryption Key");
          // Check if the home-as-up display option is enabled.
          int displayOptions = actionBar.getDisplayOptions();
          assertThat((displayOptions & ActionBar.DISPLAY_HOME_AS_UP)).isNotEqualTo(0);
        });
  }

  @Test
  public void onResume_keyInfoAdapter_setsCorrectText() throws Exception {
    // Given: An internal and an external key are set up.
    String internalKeyAlias = CrumblesLogsEncryptor.RE_ENCRYPT_KEY_ALIAS_PREFIX + "internal1";
    KeyPair internalKeyPair = new CrumblesLogsEncryptor().generateKeyPair(internalKeyAlias, false);
    PublicKey internalKey = internalKeyPair.getPublic();
    when(mockLogsEncryptor.getInternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(internalKey));

    PublicKey externalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(externalKey));
    String externalKeyHash = CrumblesLogsEncryptor.getPublicKeyHash(externalKey);

    // When: The activity is launched.
    launchActivity();

    // Then: The adapter correctly displays the text for both key types.
    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          View internalKeyView = listView.getChildAt(0);
          TextView internalText1 = internalKeyView.findViewById(android.R.id.text1);
          TextView internalText2 = internalKeyView.findViewById(android.R.id.text2);
          assertThat(internalText1.getText().toString()).isEqualTo(internalKeyAlias);
          assertThat(internalText2.getText().toString()).isEqualTo("Keystore Key");

          View externalKeyView = listView.getChildAt(1);
          TextView externalText1 = externalKeyView.findViewById(android.R.id.text1);
          TextView externalText2 = externalKeyView.findViewById(android.R.id.text2);
          assertThat(externalText1.getText().toString()).isEqualTo(externalKeyHash);
          assertThat(externalText2.getText().toString()).isEqualTo("External Key");
        });
  }

  @Test
  public void onListItemClick_forInternalKey_setsResultAndFinishes() throws Exception {
    // Given: An internal key is created in the fake keystore.
    String internalKeyAlias = CrumblesLogsEncryptor.RE_ENCRYPT_KEY_ALIAS_PREFIX + "internal1";
    KeyPair internalKeyPair = new CrumblesLogsEncryptor().generateKeyPair(internalKeyAlias, false);
    PublicKey internalKey = internalKeyPair.getPublic();

    // And: The mock is configured to return this key.
    when(mockLogsEncryptor.getInternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(internalKey));

    launchActivity();
    shadowOf(Looper.getMainLooper()).idle();

    // When: The first item (the internal key) is clicked.
    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          shadowOf(listView).performItemClick(0);

          // Then: The activity finishes with the correct result data.
          assertThat(shadowOf(activity).getResultCode()).isEqualTo(Activity.RESULT_OK);
          Intent resultData = shadowOf(activity).getResultIntent();
          assertThat(resultData).isNotNull();
          assertThat(
                  resultData.getStringExtra(CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS))
              .isEqualTo(internalKeyAlias);
          assertThat(
                  resultData.getBooleanExtra(
                      CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_IS_INTERNAL, false))
              .isTrue();
        });
  }

  @Test
  public void createInternalKey_onClick_generatesKeyAndRefreshesList() throws Exception {
    // Given: The activity is launched.
    launchActivity();

    // When: The "Create New Internal Key" button is clicked.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_create_internal_re_encrypt_key).performClick());
    shadowOf(Looper.getMainLooper()).idle();

    // Then: The encryptor is called to generate a new key pair.
    verify(mockLogsEncryptor).generateKeyPair(any(String.class), eq(false));
    // And: A success toast is shown.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("New internal re-encryption key created.");
  }

  @Test
  public void importExternalKey_onClick_launchesQrScanner() {
    // Given: The activity is launched.
    launchActivity();

    // When: The "Import New External Key" button is clicked.
    scenario.onActivity(
        activity -> {
          // Assume camera permission is granted for the test.
          shadowOf(activity).grantPermissions(android.Manifest.permission.CAMERA);

          activity.findViewById(R.id.btn_import_external_re_encrypt_key).performClick();
          shadowOf(Looper.getMainLooper()).idle();

          // Then: An intent to start the QR scanner activity is launched for a result.
          ShadowActivity.IntentForResult startedIntentResult =
              shadowOf(activity).peekNextStartedActivityForResult();
          assertThat(startedIntentResult).isNotNull();

          Intent startedIntent = startedIntentResult.intent;
          assertThat(shadowOf(startedIntent).getIntentClass().getName())
              .isEqualTo(CrumblesQrScannerActivity.class.getName());
        });
  }
}
