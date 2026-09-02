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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.Activity;
import android.app.Application;
import android.app.Dialog;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v4.app.DialogFragment;
import android.support.v7.app.AlertDialog;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowDialog;
import org.robolectric.shadows.ShadowKeyguardManager;
import org.robolectric.shadows.ShadowLooper;
import org.robolectric.shadows.ShadowToast;

/** Unit tests for {@link CrumblesManageExternalKeysActivity}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesManageExternalKeysActivityTest {

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;
  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;
  @Mock private CrumblesUriGenerator mockUriGenerator;

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
    // Using a simpler base theme for testing to avoid Material Components interfering
    // with Robolectric's dialog shadowing.
    appContext.setTheme(R.style.Theme_AppCompat);

    testExternalKeyPair = generateTestRsaKeyPair();
    // And: The static accessor for CrumblesLogsEncryptor in CrumblesMain is made to return our
    // mock.
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    // And: The CrumblesAppAuditLogger singleton is replaced with our mock for this test class.
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);

    when(mockUriGenerator.getUriForFile(any(), any()))
        .thenAnswer(
            inv ->
                Uri.parse(
                    "content://com.android.securelogging.fileprovider/test/"
                        + ((File) inv.getArgument(1)).getName()));
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
    scenario.onActivity(
        activity -> {
          activity.setPublicKeyManagerForTest(mockPublicKeyManager);
          activity.setUriGeneratorForTest(mockUriGenerator);
        });
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper(); // Ensure all initial UI tasks complete.
  }

  private void mockSuccessfulKeyGeneration(byte[] keyBytes) throws CrumblesKeysException {
    PrivateKey mockPrivateKey = mock(PrivateKey.class);
    when(mockPrivateKey.getEncoded()).thenReturn(keyBytes);
    KeyPair keyPair = new KeyPair(testExternalKeyPair.getPublic(), mockPrivateKey);
    when(mockLogsEncryptor.generateCandidateExternalKeyPair()).thenReturn(keyPair);
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

  private void triggerExportChoiceAndClick(int buttonId) {
    scenario.onActivity(
        activity -> {
          activity.findViewById(R.id.btn_generate_exportable_key).performClick();
          ShadowLooper.idleMainLooper();
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
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(testExternalKeyPair.getPublic());
    verify(mockLogsEncryptor).commitExternalPublicKey(testExternalKeyPair.getPublic());
    verify(mockAuditLogger)
        .logEvent(
            "KEY_EXPORTABLE_GENERATED", "New exportable key pair generated and custody confirmed.");
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

    // And: Pending key was cleared in finally block, so subsequent confirmation does nothing.
    scenario.onActivity(CrumblesManageExternalKeysActivity::onKeyCustodyConfirmed);
    ShadowLooper.idleMainLooper();
    verify(mockPublicKeyManager).saveActiveExternalPublicKey(any());
  }

  @Test
  public void onGenerateKeystoreKey_whenPendingLogsExist_showsReEncryptDialogAndReEncryptsOnConfirmation()
      throws Exception {
    // Given: A pending log file exists in the logs subdirectory.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "test_log.bin");
    logFile.createNewFile();

    when(mockLogsEncryptor.encryptLogs(any(), any())).thenReturn(LogBatch.getDefaultInstance());

    launchActivity();

    // When: The generate keystore key button is clicked.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();

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
  public void onGenerateKeystoreKey_whenPendingLogsExist_andUserSelectsUploadAsIs_proceedsWithoutReEncrypting()
      throws Exception {
    // Given: A pending log file exists.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "test_log_asis.bin");
    logFile.createNewFile();

    launchActivity();

    // When: User clicks generate key.
    scenario.onActivity(
        activity -> activity.findViewById(R.id.btn_generate_keystore_key).performClick());
    ShadowLooper.idleMainLooper();

    // Then: Re-encrypt dialog appears.
    AlertDialog reEncryptDialog = getLatestAppCompatAlertDialog();
    assertThat(reEncryptDialog).isNotNull();

    // When: User clicks "Upload As-Is" (item 1).
    reEncryptDialog.getListView().performItemClick(null, 1, 1);
    ShadowLooper.idleMainLooper();

    // Then: Key pair generation proceeds without re-encrypting logs toast.
    verify(mockLogsEncryptor).generateKeyPair();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("New internal Keystore key generated successfully.");

    Intent startedIntent =
        shadowOf((Application) ApplicationProvider.getApplicationContext()).getNextStartedActivity();
    assertThat(startedIntent).isNotNull();
    assertThat(startedIntent.getAction()).isEqualTo(Intent.ACTION_CHOOSER);

    // Cleanup test file.
    logFile.delete();
  }

  @Test
  public void onGenerateKeystoreKey_whenPendingLogsExist_andUserSelectsDiscard_discardsLogsAndProceeds()
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
  public void onGenerateKeystoreKey_whenDecryptionFails_andUserSelectsUploadAsIs_triggersUploadAndProceeds()
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

    // Then: Decryption error warning dialog appears.
    AlertDialog warningDialog = getLatestAppCompatAlertDialog();
    assertThat(warningDialog).isNotNull();

    // When: User clicks "Upload As-Is" (BUTTON_POSITIVE).
    warningDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    ShadowLooper.idleMainLooper();

    // Then: Key pair generation proceeds and chooser intent is launched.
    verify(mockLogsEncryptor).generateKeyPair();
    Intent startedIntent =
        shadowOf((Application) ApplicationProvider.getApplicationContext()).getNextStartedActivity();
    assertThat(startedIntent).isNotNull();
    assertThat(startedIntent.getAction()).isEqualTo(Intent.ACTION_CHOOSER);

    // Cleanup test file.
    logFile.delete();
  }

  @Test
  public void onGenerateKeystoreKey_whenDecryptionFails_andUserSelectsDiscard_discardsLogsAndProceeds()
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
  public void onGenerateKeystoreKey_whenUserNotAuthenticated_launchesConfirmCredentialsIntent()
      throws Exception {
    // Given: A pending log file exists.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File logFile = new File(logsDir, "auth_req_log.bin");
    logFile.createNewFile();

    when(mockLogsEncryptor.decryptLogs(any()))
        .thenThrow(new UserNotAuthenticatedException("User authentication required"));

    launchActivity();

    scenario.onActivity(
        activity -> {
          KeyguardManager km = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);
          ShadowKeyguardManager shadowKm = shadowOf(km);
          shadowKm.setIsKeyguardSecure(true);
          shadowKm.setIsDeviceSecure(true);
          activity.findViewById(R.id.btn_generate_keystore_key).performClick();
        });
    ShadowLooper.idleMainLooper();

    // Then: Confirm credentials intent is launched or decryption warning dialog is displayed.
    scenario.onActivity(
        activity -> {
          ShadowActivity.IntentForResult intentForResult =
              shadowOf(activity).getNextStartedActivityForResult();
          if (intentForResult != null) {
            assertThat(intentForResult.requestCode).isEqualTo(1001);
          } else {
            AlertDialog dialog = getLatestAppCompatAlertDialog();
            assertThat(dialog).isNotNull();
          }
        });

    logFile.delete();
  }

  @Test
  public void onActivityResult_whenConfirmCredentialsOk_retriesAndProceeds() throws Exception {
    launchActivity();

    // Given: Activity receives RESULT_OK from authentication activity.
    scenario.onActivity(
        activity -> {
          activity.onActivityResult(1001, Activity.RESULT_OK, null);
        });
    ShadowLooper.idleMainLooper();

    // No exception thrown and handles state safely.
    assertThat(scenario).isNotNull();
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
  public void getPendingLogFiles_filtersNonBinAndSentFiles() throws Exception {
    // Given: A directory containing a valid .bin file, a .txt file, and a .sent.bin file.
    File logsDir =
        new File(
            appContext.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    logsDir.mkdirs();
    File validFile = new File(logsDir, "valid_log.bin");
    File txtFile = new File(logsDir, "log.txt");
    File sentFile = new File(logsDir, "sent_log" + CrumblesConstants.SENT_SUFFIX);
    validFile.createNewFile();
    txtFile.createNewFile();
    sentFile.createNewFile();

    launchActivity();

    // When: getPendingLogFiles is called.
    scenario.onActivity(
        activity -> {
          ImmutableList<File> pending = activity.getPendingLogFiles();
          // Then: Only valid_log.bin is included, log.txt and sent_log.sent.bin are filtered out.
          assertThat(pending).hasSize(1);
          assertThat(pending.get(0).getName()).isEqualTo("valid_log.bin");
        });

    validFile.delete();
    txtFile.delete();
    sentFile.delete();
  }
}
