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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.Activity;
import android.app.Application;
import android.app.KeyguardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.Looper;
import android.view.View;
import android.view.WindowManager;
import android.widget.ListView;
import android.widget.TextView;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AlertDialog;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import com.android.securelogging.CrumblesExternalPublicKeyManager.SavedReEncryptKey;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.truth.Expect;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowBiometricPrompt;
import org.robolectric.shadows.ShadowDialog;
import org.robolectric.shadows.ShadowToast;
import org.robolectric.util.ReflectionHelpers;

/** Unit tests for {@link CrumblesReEncryptKeysActivity}. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesReEncryptKeysActivityTest {

  @Rule public final Expect expect = Expect.create();

  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;

  private ActivityScenario<CrumblesReEncryptKeysActivity> scenario;
  private Application app;
  private TimeZone originalTimeZone;

  @Before
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    originalTimeZone = TimeZone.getDefault();
    TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
    ApplicationProvider.getApplicationContext().setTheme(R.style.Theme_AppCompat);
    // Declared in the manifest, so granted at install.
    Application application = ApplicationProvider.getApplicationContext();
    app = application;
    shadowOf(application).grantPermissions(android.Manifest.permission.HIDE_OVERLAY_WINDOWS);
    shadowOf(application.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesReEncryptKeysActivity.publicKeyManagerForTest = mockPublicKeyManager;
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);
  }

  @Test
  public void requireDeviceCredentialAndSave_whenNoSecureLockScreen_logsEventAndShowsToast()
      throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    Context context = ApplicationProvider.getApplicationContext();
    shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(false);

    launchActivity();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_reencrypt_key_requires_screen_lock));
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_IMPORT_REFUSED",
            "Key not saved because no secure lock screen is set up.");
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
  }

  @Test
  public void requireDeviceCredentialAndSave_whenKeyguardServiceUnavailable_logsEventAndShowsToast()
      throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    Application application = ApplicationProvider.getApplicationContext();
    shadowOf(application).removeSystemService(Context.KEYGUARD_SERVICE);

    launchActivity();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(application.getString(R.string.toast_reencrypt_key_requires_screen_lock));
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_IMPORT_REFUSED",
            "Key not saved because no secure lock screen is set up.");
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
  }

  @Test
  public void requireDeviceCredentialAndSave_whenStateSaved_cancelsWithoutLaunchingPrompt()
      throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    Context context = ApplicationProvider.getApplicationContext();
    ActivityController<CrumblesReEncryptKeysActivity> controller =
        Robolectric.buildActivity(CrumblesReEncryptKeysActivity.class).setup();
    CrumblesReEncryptKeysActivity activity = controller.get();
    shadowOf(activity).grantPermissions(android.Manifest.permission.CAMERA);
    activity.findViewById(R.id.btn_import_external_re_encrypt_key).performClick();
    shadowOf(Looper.getMainLooper()).idle();
    Intent scanIntent = shadowOf(activity).peekNextStartedActivityForResult().intent;
    shadowOf(activity)
        .receiveResult(
            scanIntent,
            Activity.RESULT_OK,
            new Intent()
                .putExtra(
                    CrumblesConstants.SCAN_RESULT_EXTRA,
                    CrumblesLogsEncryptor.publicKeyToBase64(scannedKey)));
    shadowOf(Looper.getMainLooper()).idle();
    controller.pause().saveInstanceState(new Bundle());

    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_reencrypt_key_auth_cancelled));
    verify(mockAuditLogger)
        .logEvent("EXTERNAL_KEY_IMPORT_CANCELLED", "Device credential prompt was cancelled.");
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
  }

  @Test
  public void requireDeviceCredentialAndSave_whenPromptCancelled_logsEventAndShowsToast()
      throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    Context context = ApplicationProvider.getApplicationContext();
    shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);

    launchActivity();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getAllowedAuthenticators())
        .isEqualTo(BiometricManager.Authenticators.DEVICE_CREDENTIAL);
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getTitle().toString())
        .isEqualTo(context.getString(R.string.reencrypt_key_auth_title));
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo(context.getString(R.string.reencrypt_key_auth_subtitle));

    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Cancelled");
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(context.getString(R.string.toast_reencrypt_key_auth_cancelled));
    verify(mockAuditLogger)
        .logEvent("EXTERNAL_KEY_IMPORT_CANCELLED", "Device credential prompt was cancelled.");
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
    scenario.onActivity(
        activity ->
            assertThat((Object) ReflectionHelpers.getField(activity, "pendingImportKey")).isNull());

    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void onStop_whenNotAwaitingCredential_finishesActivity() {
    launchActivity();

    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();

    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void importExternalKey_whenStoppedWhileAwaitingQrScan_doesNotFinishUntilScanReturns() {
    launchActivity();
    final Intent[] scanIntent = new Intent[1];
    scenario.onActivity(
        activity -> {
          shadowOf(activity).grantPermissions(android.Manifest.permission.CAMERA);
          activity.findViewById(R.id.btn_import_external_re_encrypt_key).performClick();
          shadowOf(Looper.getMainLooper()).idle();
          scanIntent[0] = shadowOf(activity).peekNextStartedActivityForResult().intent;
        });

    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isFalse());

    scenario.moveToState(Lifecycle.State.RESUMED);
    scenario.onActivity(
        activity ->
            shadowOf(activity)
                .receiveResult(scanIntent[0], Activity.RESULT_CANCELED, /* resultIntent= */ null));
    shadowOf(Looper.getMainLooper()).idle();
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();

    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void importExternalKey_whenQrScannerCannotBeLaunched_resetsAwaitingQrScanAndShowsToast() {
    launchActivity();
    Context context = ApplicationProvider.getApplicationContext();
    shadowOf(RuntimeEnvironment.getApplication()).checkActivities(true);
    shadowOf(context.getPackageManager())
        .removeActivity(new ComponentName(context, CrumblesQrScannerActivity.class));

    scenario.onActivity(
        activity -> {
          shadowOf(activity).grantPermissions(android.Manifest.permission.CAMERA);
          activity.findViewById(R.id.btn_import_external_re_encrypt_key).performClick();
        });
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("QR Scan cancelled or failed.");
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @Test
  public void scannedKey_whenStoppedWhileAwaitingCredential_doesNotFinishActivity()
      throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();

    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isFalse());
  }

  @Test
  public void
      scannedKey_whenRecreatedWhileAwaitingCredential_clearsPendingKeyAndRejectsStaleAuthResult()
          throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    scenario.recreate();
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(
        activity -> {
          assertThat(activity.isFinishing()).isFalse();
          assertThat((Object) ReflectionHelpers.getField(activity, "pendingRemovalKey")).isNull();
        });
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("New external re-encryption key imported.");
    verify(mockPublicKeyManager)
        .saveReEncryptPublicKey(
            argThat(key -> Arrays.equals(key.getEncoded(), scannedKey.getEncoded())));
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  @After
  public void tearDown() {
    shadowOf(RuntimeEnvironment.getApplication()).checkActivities(false);
    if (scenario != null) {
      scenario.close();
    }
    TimeZone.setDefault(originalTimeZone);
    CrumblesReEncryptKeysActivity.publicKeyManagerForTest = null;
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesDecryptedLogsSession.destroyActiveSession();
  }

  private void launchActivity() {
    Context context = ApplicationProvider.getApplicationContext();
    Intent intent = new Intent(context, CrumblesReEncryptKeysActivity.class);
    scenario = ActivityScenario.launch(intent);
    shadowOf(Looper.getMainLooper()).idle();
  }

  /** Starts the QR import flow and returns {@code scannedKey} as the scanner result. */
  private void scanKey(PublicKey scannedKey) {
    scanText(CrumblesLogsEncryptor.publicKeyToBase64(scannedKey));
  }

  /** Starts the QR import flow and returns {@code scannedText} as the scanner result. */
  private void scanText(String scannedText) {
    scenario.onActivity(
        activity -> {
          shadowOf(activity).grantPermissions(android.Manifest.permission.CAMERA);
          activity.findViewById(R.id.btn_import_external_re_encrypt_key).performClick();
          shadowOf(Looper.getMainLooper()).idle();
          Intent scanIntent = shadowOf(activity).peekNextStartedActivityForResult().intent;
          Intent scanResult =
              new Intent().putExtra(CrumblesConstants.SCAN_RESULT_EXTRA, scannedText);
          shadowOf(activity).receiveResult(scanIntent, Activity.RESULT_OK, scanResult);
        });
    shadowOf(Looper.getMainLooper()).idle();
  }

  private static AlertDialog getLatestAlertDialog() {
    return (AlertDialog) Iterables.getLast(ShadowDialog.getShownDialogs());
  }

  @Test
  public void onCreate_setsUpActionBarCorrectly() {
    // Given: The activity is launched.
    launchActivity();

    // When: The activity creates and initializes the UI.
    scenario.onActivity(
        activity -> {
          // Then: The ActionBar is configured correctly.
          ActionBar actionBar = activity.getSupportActionBar();
          assertThat(actionBar).isNotNull();
          assertThat(actionBar.getTitle().toString()).isEqualTo("Select Re-encryption Key");
          int displayOptions = actionBar.getDisplayOptions();
          assertThat((displayOptions & ActionBar.DISPLAY_HOME_AS_UP)).isNotEqualTo(0);
        });
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

  private static String textOf(View row, int viewId) {
    return ((TextView) row.findViewById(viewId)).getText().toString();
  }

  private static SavedReEncryptKey savedKey(PublicKey key, Optional<Instant> importedAt)
      throws CrumblesKeysException {
    String keyId =
        CrumblesLogsEncryptor.getPublicKeyFingerprint(key).replace(":", "").replace("\n", "");
    return new SavedReEncryptKey(keyId, key, importedAt);
  }

  @Test
  public void onResume_keyInfoAdapter_setsCorrectText() throws Exception {
    PublicKey externalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    PublicKey legacyKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getSavedReEncryptPublicKeys())
        .thenReturn(
            ImmutableList.of(
                savedKey(externalKey, Optional.of(Instant.parse("2026-03-15T14:37:00Z"))),
                savedKey(legacyKey, Optional.empty()),
                new SavedReEncryptKey("bad", mock(PublicKey.class), Optional.empty())));
    String externalFingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(externalKey);
    String legacyFingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(legacyKey);

    launchActivity();

    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          assertThat(listView.getCount()).isEqualTo(2);
          View first = listView.getChildAt(0);
          assertThat(textOf(first, R.id.tv_re_encrypt_key_fingerprint)).isEqualTo(externalFingerprint);
          assertThat(textOf(first, R.id.tv_re_encrypt_key_imported_at))
              .containsMatch("(?s)Imported.*Mar.*15.*2026.*37");
          View second = listView.getChildAt(1);
          assertThat(textOf(second, R.id.tv_re_encrypt_key_fingerprint)).isEqualTo(legacyFingerprint);
          assertThat(textOf(second, R.id.tv_re_encrypt_key_imported_at))
              .isEqualTo(activity.getString(R.string.re_encrypt_key_imported_time_unknown));
        });
  }

  @Test
  public void onListItemClick_forExternalKey_setsResultAndFinishes() throws Exception {
    PublicKey externalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getSavedReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(savedKey(externalKey, Optional.empty())));
    String externalFingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(externalKey);

    launchActivity();
    shadowOf(Looper.getMainLooper()).idle();

    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          shadowOf(listView).performItemClick(0);
          assertThat(shadowOf(activity).getResultCode()).isEqualTo(Activity.RESULT_OK);
          Intent resultData = shadowOf(activity).getResultIntent();
          assertThat(resultData.getStringExtra(CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS))
              .isEqualTo(externalFingerprint);
          assertThat(resultData.getBooleanExtra(
                  CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_IS_INTERNAL, true))
              .isFalse();
        });
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
          assertThat(
                  startedIntent.getBooleanExtra(
                      CrumblesQrScannerActivity.EXTRA_END_DECRYPTED_SESSION_ON_STOP, false))
              .isTrue();
        });
    scenario.recreate();
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isFalse());
  }

  @Test
  public void scannedKey_showsFingerprintAndIsNotSavedBeforeConfirmation() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();

    scanKey(scannedKey);

    AlertDialog dialog = getLatestAlertDialog();
    assertThat(dialog.isShowing()).isTrue();
    assertThat(shadowOf(dialog).isCancelable()).isFalse();
    TextView message = dialog.findViewById(android.R.id.message);
    assertThat(message.getText().toString())
        .contains(CrumblesLogsEncryptor.getPublicKeyFingerprint(scannedKey));
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
  }

  @Test
  public void scannedKey_whenFingerprintConfirmed_savesKeyAndRefreshesList() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    String expectedFingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(scannedKey);
    doAnswer(
            invocation -> {
              when(mockPublicKeyManager.getSavedReEncryptPublicKeys())
                  .thenReturn(ImmutableList.of(savedKey(scannedKey, Optional.of(Instant.EPOCH))));
              return null;
            })
        .when(mockPublicKeyManager)
        .saveReEncryptPublicKey(any(PublicKey.class));
    launchActivity();
    scanKey(scannedKey);

    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPublicKeyManager)
        .saveReEncryptPublicKey(
            argThat(key -> Arrays.equals(key.getEncoded(), scannedKey.getEncoded())));
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo("New external re-encryption key imported.");
    scenario.onActivity(
        activity -> {
          assertThat((Object) ReflectionHelpers.getField(activity, "pendingImportKey")).isNull();
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          assertThat(listView.getCount()).isEqualTo(1);
          CrumblesReEncryptKeysActivity.KeyInfo item =
              (CrumblesReEncryptKeysActivity.KeyInfo) listView.getItemAtPosition(0);
          assertThat(item.alias()).isEqualTo(expectedFingerprint);
        });
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(activity -> assertThat(activity.isFinishing()).isTrue());
  }

  private void stubSingleSavedKey() throws Exception {
    PublicKey key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    SavedReEncryptKey entry = savedKey(key, Optional.empty());
    when(mockPublicKeyManager.getSavedReEncryptPublicKeys()).thenReturn(ImmutableList.of(entry));
  }

  private void launchAndClickRemove() {
    launchActivity();
    scenario.onActivity(
        a ->
            ((ListView) a.findViewById(R.id.re_encrypt_key_list))
                .getChildAt(0)
                .findViewById(R.id.btn_remove_re_encrypt_key)
                .performClick());
    shadowOf(Looper.getMainLooper()).idle();
  }

  private static void confirmPrompt() {
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();
  }

  private void assertRemoveRefusedWithoutPrompt() throws Exception {
    launchAndClickRemove();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(app.getString(R.string.toast_remove_re_encrypt_key_requires_screen_lock));
    verify(mockAuditLogger)
        .logEvent(
            "RE_ENCRYPT_KEY_REMOVE_REFUSED",
            "Re-encryption key removal refused because no secure lock screen is set up.");
    verify(mockPublicKeyManager, never()).removeExternalPublicKey(any());
    clearInvocations(mockAuditLogger);
  }

  private void assertCancelledAndNotRemoved(String fingerprint) throws Exception {
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(app.getString(R.string.toast_remove_re_encrypt_key_auth_cancelled));
    verify(mockPublicKeyManager, never()).removeExternalPublicKey(any());
    verify(mockAuditLogger)
        .logEvent(
            "RE_ENCRYPT_KEY_REMOVE_AUTH_FAILED",
            "Kept the re-encryption key with fingerprint "
                + fingerprint
                + " because no device credential was confirmed for removing it.");
  }

  @Test
  public void removeButton_whenAuthenticated_removesKeyLogsAuditAndRefreshesList()
      throws Exception {
    PublicKey key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    SavedReEncryptKey entry = savedKey(key, Optional.empty());
    when(mockPublicKeyManager.getSavedReEncryptPublicKeys()).thenReturn(ImmutableList.of(entry));
    doAnswer(
            invocation -> {
              when(mockPublicKeyManager.getSavedReEncryptPublicKeys())
                  .thenReturn(ImmutableList.of());
              return null;
            })
        .when(mockPublicKeyManager)
        .removeExternalPublicKey(entry.keyId());
    String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(key);

    launchAndClickRemove();

    BiometricPrompt prompt = ShadowBiometricPrompt.getCurrentPrompt();
    assertThat(prompt).isNotNull();
    assertThat(prompt.getAllowedAuthenticators())
        .isEqualTo(BiometricManager.Authenticators.DEVICE_CREDENTIAL);
    assertThat(prompt.getTitle().toString())
        .isEqualTo(app.getString(R.string.remove_re_encrypt_key_auth_title));
    assertThat(prompt.getSubtitle().toString())
        .isEqualTo(app.getString(R.string.remove_re_encrypt_key_auth_subtitle));
    verify(mockPublicKeyManager, never()).removeExternalPublicKey(any());

    scenario.recreate();
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(a -> assertThat(a.isFinishing()).isFalse());
    scenario.moveToState(Lifecycle.State.RESUMED);

    confirmPrompt();

    verify(mockPublicKeyManager).removeExternalPublicKey(entry.keyId());
    verify(mockAuditLogger)
        .logEvent(
            "RE_ENCRYPT_KEY_REMOVED",
            "Removed the re-encryption key with fingerprint " + fingerprint + ".");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(app.getString(R.string.toast_re_encrypt_key_removed));
    scenario.onActivity(
        a -> assertThat(((ListView) a.findViewById(R.id.re_encrypt_key_list)).getCount()).isEqualTo(0));
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(a -> assertThat(a.isFinishing()).isTrue());
  }

  @Test
  public void removeButton_afterAuthenticatedRemoval_doesNotRemoveTheKeyAgain() throws Exception {
    stubSingleSavedKey();
    launchAndClickRemove();
    confirmPrompt();

    // A late or repeated success callback finds no removal pending.
    scenario.onActivity(a -> ReflectionHelpers.callInstanceMethod(a, "onCredentialConfirmed"));

    verify(mockPublicKeyManager).removeExternalPublicKey(any());
  }

  @Test
  public void removeButton_whileImportPromptIsUp_removesTheKeyAndDoesNotImport() throws Exception {
    stubSingleSavedKey();
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(
        a ->
            ((ListView) a.findViewById(R.id.re_encrypt_key_list))
                .getChildAt(0)
                .findViewById(R.id.btn_remove_re_encrypt_key)
                .performClick());
    shadowOf(Looper.getMainLooper()).idle();

    confirmPrompt();

    verify(mockPublicKeyManager).removeExternalPublicKey(any());
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
  }

  @Test
  public void scannedKey_whileRemovalPromptIsUp_cancellingRecordsTheCancelledImport()
      throws Exception {
    stubSingleSavedKey();
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchAndClickRemove();
    scanKey(scannedKey);
    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Cancelled");
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockAuditLogger)
        .logEvent("EXTERNAL_KEY_IMPORT_CANCELLED", "Device credential prompt was cancelled.");
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(app.getString(R.string.toast_reencrypt_key_auth_cancelled));
    verify(mockPublicKeyManager, never()).removeExternalPublicKey(any());
  }

  @Test
  public void removeButton_withoutSecureLockScreen_refusesAndLogsEvent() throws Exception {
    stubSingleSavedKey();
    shadowOf(app.getSystemService(KeyguardManager.class)).setIsDeviceSecure(false);
    assertRemoveRefusedWithoutPrompt();
    scenario.close();
    shadowOf(app).removeSystemService(Context.KEYGUARD_SERVICE);
    assertRemoveRefusedWithoutPrompt();
  }

  @Test
  public void removeButton_whenPromptCancelled_recordsFailureAndKeepsKey() throws Exception {
    PublicKey key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getSavedReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(savedKey(key, Optional.empty())));
    launchAndClickRemove();
    scenario.recreate();
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED, "Cancelled");
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(
        a -> {
          assertThat((Object) ReflectionHelpers.getField(a, "pendingRemovalKey")).isNull();
          ReflectionHelpers.callInstanceMethod(a, "onCredentialCancelled");
          ReflectionHelpers.callInstanceMethod(a, "onCredentialConfirmed");
        });
    assertCancelledAndNotRemoved(CrumblesLogsEncryptor.getPublicKeyFingerprint(key));
    scenario.moveToState(Lifecycle.State.CREATED);
    shadowOf(Looper.getMainLooper()).idle();
    scenario.onActivity(a -> assertThat(a.isFinishing()).isTrue());
  }

  @Test
  public void removeButton_whenStateSaved_cancelsWithoutLaunchingPrompt() throws Exception {
    PublicKey key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getSavedReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(savedKey(key, Optional.empty())));
    ActivityController<CrumblesReEncryptKeysActivity> controller =
        Robolectric.buildActivity(CrumblesReEncryptKeysActivity.class).setup();
    View removeBtn =
        ((ListView) controller.get().findViewById(R.id.re_encrypt_key_list))
            .getChildAt(0)
            .findViewById(R.id.btn_remove_re_encrypt_key);
    controller.pause().saveInstanceState(new Bundle());
    removeBtn.performClick();
    shadowOf(Looper.getMainLooper()).idle();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    assertCancelledAndNotRemoved(CrumblesLogsEncryptor.getPublicKeyFingerprint(key));
  }

  @Test
  public void removeButton_whenPromptCancelledAfterUserLeft_endsSessionAndFinishes()
      throws Exception {
    stubSingleSavedKey();
    long sessionId = startDecryptedSession();
    ActivityController<CrumblesReEncryptKeysActivity> controller = openPickerAndClickRemove();
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.BIOMETRIC_ERROR_CANCELED, "Cancelled");
    // Delivers the error to the prompt, which hands it to the picker only after the user left.
    shadowOf(Looper.getMainLooper()).runOneTask();
    controller.pause().stop();

    shadowOf(Looper.getMainLooper()).idle();

    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    expect.that(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void removeButton_whenPromptConfirmedAfterUserLeft_removesKeyEndsSessionAndFinishes()
      throws Exception {
    stubSingleSavedKey();
    long sessionId = startDecryptedSession();
    ActivityController<CrumblesReEncryptKeysActivity> controller = openPickerAndClickRemove();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    // Delivers the result to the prompt, which hands it to the picker only after the user left.
    shadowOf(Looper.getMainLooper()).runOneTask();
    controller.pause().stop();

    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPublicKeyManager).removeExternalPublicKey(any());
    expect.that(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    expect.that(controller.get().isFinishing()).isTrue();
  }

  /** Starts a decrypted-logs session, as the viewer does before it opens the key picker. */
  private static long startDecryptedSession() {
    return CrumblesDecryptedLogsSession.startSession(
        ImmutableList.of(
            new CrumblesDecryptedLogEntry(
                "log.bin",
                "decrypted log content".getBytes(UTF_8),
                "device-1",
                /* originalBatch= */ null)));
  }

  /** Opens the key picker and taps Remove on its first key, which opens the credential prompt. */
  private static ActivityController<CrumblesReEncryptKeysActivity> openPickerAndClickRemove() {
    ActivityController<CrumblesReEncryptKeysActivity> controller =
        Robolectric.buildActivity(CrumblesReEncryptKeysActivity.class).setup();
    ((ListView) controller.get().findViewById(R.id.re_encrypt_key_list))
        .getChildAt(0)
        .findViewById(R.id.btn_remove_re_encrypt_key)
        .performClick();
    shadowOf(Looper.getMainLooper()).idle();
    return controller;
  }

  @Test
  public void removeButton_whenRemovalThrowsException_showsFailureToast() throws Exception {
    stubSingleSavedKey();
    doThrow(new CrumblesKeysException("Store failure"))
        .when(mockPublicKeyManager)
        .removeExternalPublicKey(any());
    launchAndClickRemove();
    confirmPrompt();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(app.getString(R.string.toast_re_encrypt_key_remove_failed));
    verify(mockAuditLogger, never()).logEvent(any(), any());
  }

  @Test
  public void scannedKey_whenSaveFails_showsErrorToastAndDoesNotRefreshList() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    doThrow(new CrumblesKeysException("Storage failure"))
        .when(mockPublicKeyManager)
        .saveReEncryptPublicKey(any(PublicKey.class));
    launchActivity();
    scanKey(scannedKey);

    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(ShadowToast.getTextOfLatestToast()).isEqualTo("Failed to import key.");
    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          assertThat(listView.getCount()).isEqualTo(0);
        });
  }

  @Test
  public void scannedKey_whenFingerprintConfirmed_recordsTheKeyInTheActivityLog() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();
    scanKey(scannedKey);

    getLatestAlertDialog().getButton(DialogInterface.BUTTON_POSITIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockAuditLogger)
        .logEvent(
            "RE_ENCRYPT_KEY_IMPORTED",
            "Imported the re-encryption key with fingerprint "
                + CrumblesLogsEncryptor.getPublicKeyFingerprint(scannedKey)
                + ".");
  }

  @Test
  public void scannedText_thatIsNotAKey_isRecordedInTheActivityLogAndNotSaved() throws Exception {
    launchActivity();

    scanText("not a key");

    verify(mockAuditLogger)
        .logEvent("EXTERNAL_KEY_IMPORT_FAILED", "Scanned re-encryption key could not be read.");
    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
  }

  @Test
  public void scannedKey_whenFingerprintRejected_doesNotSaveKey() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();
    scanKey(scannedKey);

    getLatestAlertDialog().getButton(DialogInterface.BUTTON_NEGATIVE).performClick();
    shadowOf(Looper.getMainLooper()).idle();

    verify(mockPublicKeyManager, never()).saveReEncryptPublicKey(any(PublicKey.class));
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_IMPORT_REJECTED",
            "User did not confirm the fingerprint of a scanned key.");
  }

  @Test
  public void scannedKey_hidesTheOverlaysOfOtherAppsWhileTheFingerprintIsShown() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();
    scanKey(scannedKey);

    int hideOverlays =
        ReflectionHelpers.getStaticField(
            WindowManager.LayoutParams.class, "SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS");
    int privateFlags =
        ReflectionHelpers.getField(
            getLatestAlertDialog().getWindow().getAttributes(), "privateFlags");
    assertThat(privateFlags & hideOverlays).isEqualTo(hideOverlays);
  }

  @Test
  public void scannedKey_withNoSession_finishesCanceled() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    
    // Start session to get an ID
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "log.bin", new byte[0], "device-1", /* originalBatch= */ null)));
    
    Context context = ApplicationProvider.getApplicationContext();
    Intent intent = new Intent(context, CrumblesReEncryptKeysActivity.class)
        .putExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, sessionId);
    scenario = ActivityScenario.launch(intent);
    shadowOf(Looper.getMainLooper()).idle();

    // Destroy session before scan result
    CrumblesDecryptedLogsSession.destroyActiveSession();

    scanKey(scannedKey);

    scenario.onActivity(activity -> {
      assertThat(shadowOf(activity).getResultCode()).isEqualTo(Activity.RESULT_CANCELED);
      assertThat(activity.isFinishing()).isTrue();
    });
  }

  @Test
  public void scannedKey_setsFlagSecureWhileTheFingerprintIsShown() throws Exception {
    PublicKey scannedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    launchActivity();

    scanKey(scannedKey);

    assertThat(
            getLatestAlertDialog().getWindow().getAttributes().flags
                & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
  }

  @Test
  public void confirmFingerprint_whenKeyEncodingUnavailable_rejectsKeyAndLogsAuditEvent() {
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
    AtomicBoolean verified = new AtomicBoolean(false);
    launchActivity();

    scenario.onActivity(
        activity ->
            CrumblesScannedKeyVerifier.confirmFingerprint(
                activity, unencodableKey, () -> verified.set(true)));
    shadowOf(Looper.getMainLooper()).idle();

    assertThat(verified.get()).isFalse();
    assertThat(ShadowDialog.getShownDialogs()).isEmpty();
    assertThat(ShadowToast.getTextOfLatestToast())
        .isEqualTo(
            ApplicationProvider.getApplicationContext()
                .getString(R.string.toast_key_fingerprint_unavailable));
    verify(mockAuditLogger)
        .logEvent(
            "EXTERNAL_KEY_IMPORT_REJECTED",
            "Scanned key rejected because its fingerprint could not be computed.");
  }

  @Test
  public void onStop_whenScreenLocksOrAppBackgrounds_destroysSessionAndFinishesCanceled() {
    byte[] rawBytes = "decrypted log content".getBytes(UTF_8);
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "log.bin", rawBytes, "device-1", /* originalBatch= */ null)));
    ActivityController<CrumblesReEncryptKeysActivity> controller =
        Robolectric.buildActivity(CrumblesReEncryptKeysActivity.class).setup();

    controller.pause().stop();

    assertThat(rawBytes).isEqualTo(new byte[rawBytes.length]);
    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    assertThat(shadowOf(controller.get()).getResultCode()).isEqualTo(Activity.RESULT_CANCELED);
    assertThat(controller.get().isFinishing()).isTrue();
  }

  @Test
  public void onStop_whileAwaitingQrScanner_keepsSessionAndDoesNotFinish() {
    byte[] expectedBytes = "decrypted log content".getBytes(UTF_8);
    byte[] rawBytes = expectedBytes.clone();
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "log.bin", rawBytes, "device-1", /* originalBatch= */ null)));
    ActivityController<CrumblesReEncryptKeysActivity> controller =
        Robolectric.buildActivity(CrumblesReEncryptKeysActivity.class).setup();
    shadowOf(controller.get()).grantPermissions(android.Manifest.permission.CAMERA);
    controller.get().findViewById(R.id.btn_import_external_re_encrypt_key).performClick();

    controller.pause().stop();

    assertThat(rawBytes).isEqualTo(expectedBytes);
    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isPresent();
    assertThat(controller.get().isFinishing()).isFalse();

    shadowOf(controller.get())
        .receiveResult(
            shadowOf(controller.get()).getNextStartedActivityForResult().intent,
            Activity.RESULT_CANCELED,
            /* resultIntent= */ null);
    controller.restart().pause().stop();

    assertThat(rawBytes).isEqualTo(new byte[expectedBytes.length]);
    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    assertThat(controller.get().isFinishing()).isTrue();
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
