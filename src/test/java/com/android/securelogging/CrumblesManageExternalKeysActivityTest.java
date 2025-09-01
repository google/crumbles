/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.Dialog;
import android.content.Context;
import androidx.fragment.app.DialogFragment;
import androidx.appcompat.app.AlertDialog;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ScrollView;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesLogsEncryptor.PrivateKeyBytesConsumer;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.Iterables;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowDialog;
import org.robolectric.shadows.ShadowLooper;
import org.robolectric.shadows.ShadowToast;

/** Unit tests for {@link CrumblesManageExternalKeysActivity}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesManageExternalKeysActivityTest {

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private KeyPair testExternalKeyPair;
  private ActivityScenario<CrumblesManageExternalKeysActivity> scenario;
  private Context appContext;

  private static KeyPair generateTestRsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return kpg.generateKeyPair();
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
    // Using the application's actual theme for the test.
    appContext.setTheme(R.style.Theme_Crumbles);

    testExternalKeyPair = generateTestRsaKeyPair();
    // And: The static accessor for CrumblesLogsEncryptor in CrumblesMain is made to return our
    // mock.
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
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
    // Inject mocks after launch but before the activity is resumed.
    scenario.onActivity(activity -> activity.setPublicKeyManagerForTest(mockPublicKeyManager));
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper(); // Ensure all initial UI tasks complete.
  }

  private void mockSuccessfulKeyGeneration(byte[] keyBytes) throws CrumblesKeysException {
    doAnswer(
        invocation -> {
          invocation.getArgument(0, PrivateKeyBytesConsumer.class).accept(keyBytes);
          return null;
        })
        .when(mockLogsEncryptor)
        .generateAndSetExternalKeyPair(any(PrivateKeyBytesConsumer.class));
    when(mockLogsEncryptor.getExternalEncryptionPublicKey())
        .thenReturn(testExternalKeyPair.getPublic());
  }

  @Test
  public void onGenerateKeystoreKey_clearsExternalAndGeneratesInternal() throws Exception {
    // Given: The activity is launched.
    launchActivity();

    // When: The "Generate Keystore Key Pair" button is clicked.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();

    // Then: The active external key is cleared from the manager and the encryptor.
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    verify(mockLogsEncryptor).setExternalEncryptionPublicKey(isNull(PublicKey.class));

    // And: A new internal key is generated.
    verify(mockLogsEncryptor).generateKeyPair();

    // And: An audit event is logged.
    verify(mockAuditLogger)
        .logEvent("KEY_INTERNAL_GENERATED", "New internal Keystore key pair generated.");

    // And: A success toast is shown.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("New internal Keystore key generated successfully.");

    // And: The activity is finishing.
    // Check isFinishing() instead of lifecycle state for reliability.
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void onClearActiveKey_clearsKeyAndUpdatesUi() {
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

    // Then: The key is cleared from the manager and the encryptor.
    try {
      verify(mockPublicKeyManager).saveActiveExternalPublicKey(isNull());
    } catch (CrumblesKeysException e) {
      throw new AssertionError("Test setup failed.", e);
    }
    verify(mockLogsEncryptor).setExternalEncryptionPublicKey(isNull(PublicKey.class));

    // And: An audit event is logged.
    verify(mockAuditLogger).logEvent("EXTERNAL_KEY_CLEARED", "Active external key was cleared.");

    // And: A success toast is shown.
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(appContext.getString(R.string.toast_external_key_cleared_successfully));
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

  @Test
  public void onChoiceDialog_whenCancelled_clearsTheKey() throws Exception {
    // Given: We have a reference to the key bytes that will be generated.
    final byte[] privateKeyBytes = testExternalKeyPair.getPrivate().getEncoded();
    mockSuccessfulKeyGeneration(privateKeyBytes);
    launchActivity();

    // When: The generate button is clicked to show the choice dialog.
    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_generate_exportable_key).performClick();
          ShadowLooper.idleMainLooper();

          // And: The user cancels the choice dialog.
          AlertDialog choiceDialog = getLatestAppCompatAlertDialog();
          assertThat(choiceDialog).isNotNull();
          choiceDialog.cancel(); // This triggers the OnCancelListener
          ShadowLooper.idleMainLooper();
        });

    // Then: The original byte array is cleared (filled with zeros).
    byte[] expectedClearedBytes = new byte[privateKeyBytes.length];
    assertThat(privateKeyBytes).isEqualTo(expectedClearedBytes);

    // And: Verify the main viewer fragment was never shown.
    scenario.onActivity(
        activity -> {
          DialogFragment dialogFragment =
              (DialogFragment)
                  activity.getSupportFragmentManager().findFragmentByTag("private_key_viewer");
          assertThat(dialogFragment).isNull();
        });
  }
}
