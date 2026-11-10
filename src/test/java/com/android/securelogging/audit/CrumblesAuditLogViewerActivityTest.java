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

package com.android.securelogging.audit;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.os.Bundle;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.biometric.BiometricPrompt;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.WorkManager;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.CrumblesConstants;
import com.android.securelogging.CrumblesDataStoreHolder;
import com.android.securelogging.CrumblesDeviceCredentialGate;
import com.android.securelogging.CrumblesLogsEncryptor;
import com.android.securelogging.CrumblesMain;
import com.android.securelogging.R;
import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesChainVerification;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import java.io.File;
import java.security.Security;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadow.api.Shadow;
import org.robolectric.shadows.ShadowBiometricPrompt;
import org.robolectric.shadows.ShadowContextImpl;
import org.robolectric.shadows.ShadowDialog;
import org.robolectric.shadows.ShadowKeyguardManager;
import org.robolectric.shadows.ShadowLooper;
import org.robolectric.shadows.ShadowToast;
import org.robolectric.util.ReflectionHelpers;

/** Unit tests for {@link CrumblesAuditLogViewerActivity}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesAuditLogViewerActivityTest {

  private static final String SEEDED_EVENT_TYPE = "SEEDED_EVENT";

  @Rule public final Expect expect = Expect.create();

  private CrumblesAppAuditLogger auditLogger;
  private CrumblesAuditLogViewerActivity activity;

  @Before
  public void setUp() throws Exception {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    Context context = ApplicationProvider.getApplicationContext();
    WorkManagerTestInitHelper.initializeTestWorkManager(
        context,
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(new SynchronousExecutor())
            .build());
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(context);
    auditLogger.logEvent(SEEDED_EVENT_TYPE, "Record that must survive an unauthorized clear.");
    // Declared in the manifest, so granted at install.
    shadowOf((Application) context).grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);
    shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    activity = openViewer().get();
    awaitBackgroundTasks();
  }

  @Test
  public void onCreate_hidesOverlayWindows() {
    assertThat(hidesOverlayWindows(activity)).isTrue();
  }

  @Test
  public void onCreate_showsNoLogsBeforeTheUserAuthenticates() {
    CrumblesAuditLogViewerActivity viewer =
        Robolectric.buildActivity(CrumblesAuditLogViewerActivity.class).setup().get();

    RecyclerView recordList = viewer.findViewById(R.id.rv_audit_logs);
    expect.that(recordList.getAdapter().getItemCount()).isEqualTo(0);
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getAllowedAuthenticators())
        .isEqualTo(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
                | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
  }

  @Test
  public void onCreate_whenUserAuthenticates_recordsTheViewingAndShowsLogs() {
    RecyclerView recordList = activity.findViewById(R.id.rv_audit_logs);

    expect.that(persistedEventTypes()).containsExactly(SEEDED_EVENT_TYPE, "AUDIT_LOG_VIEWED");
    expect.that(recordList.getAdapter().getItemCount()).isEqualTo(2);
  }

  @Test
  public void onCreate_whenAuthenticationCancelled_closesWithoutLogsAndRecordsFailure() {
    ActivityController<CrumblesAuditLogViewerActivity> controller =
        Robolectric.buildActivity(CrumblesAuditLogViewerActivity.class).setup();

    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.ERROR_USER_CANCELED, "Cancelled");
    ShadowLooper.idleMainLooper();

    RecyclerView recordList = controller.get().findViewById(R.id.rv_audit_logs);
    expect.that(controller.get().isFinishing()).isTrue();
    expect.that(recordList.getAdapter().getItemCount()).isEqualTo(0);
    expect
        .that(persistedEventTypes())
        .containsExactly(SEEDED_EVENT_TYPE, "AUDIT_LOG_VIEWED", "AUDIT_LOG_VIEW_AUTH_FAILED");
  }

  @Test
  public void onCreate_whenNoSecureLockScreen_closesWithoutLogsAndRecordsRefusal() {
    setDeviceSecure(/* isDeviceSecure= */ false);

    ActivityController<CrumblesAuditLogViewerActivity> controller =
        Robolectric.buildActivity(CrumblesAuditLogViewerActivity.class).setup();

    RecyclerView recordList = controller.get().findViewById(R.id.rv_audit_logs);
    expect.that(controller.get().isFinishing()).isTrue();
    expect.that(recordList.getAdapter().getItemCount()).isEqualTo(0);
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo(activity.getString(R.string.toast_audit_log_view_requires_screen_lock));
    expect
        .that(persistedEventTypes())
        .containsExactly(SEEDED_EVENT_TYPE, "AUDIT_LOG_VIEWED", "AUDIT_LOG_VIEW_REFUSED");
  }

  @Test
  public void onStop_closesTheViewer() {
    ActivityController<CrumblesAuditLogViewerActivity> controller = openViewer();

    controller.pause().stop();

    assertThat(controller.get().isFinishing()).isTrue();
  }

  @After
  public void tearDown() throws Exception {
    awaitBackgroundTasks();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Test
  public void clearLogsConfirmed_whenDeviceSecure_launchesConfirmCredentialWithoutClearing() {
    setDeviceSecure(/* isDeviceSecure= */ true);

    confirmClearLogsDialog();

    expect.that(ShadowBiometricPrompt.getCurrentPrompt()).isNotNull();
    expect
        .that(persistedEventTypes())
        .containsExactly(SEEDED_EVENT_TYPE, "AUDIT_LOG_VIEWED", "AUDIT_LOG_CLEAR_REQUESTED");
  }

  @Test
  public void clearLogsConfirmed_whenNoSecureLockScreen_refusesToClearAndRecordsRefusal() {
    setDeviceSecure(/* isDeviceSecure= */ false);

    confirmClearLogsDialog();

    expect.that(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    expect
        .that(ShadowToast.getTextOfLatestToast())
        .isEqualTo("Please set up a screen lock in your device settings.");
    expect
        .that(persistedEventTypes())
        .containsExactly(
            SEEDED_EVENT_TYPE,
            "AUDIT_LOG_VIEWED",
            "AUDIT_LOG_CLEAR_REQUESTED",
            "AUDIT_LOG_CLEAR_REFUSED");
  }

  @Test
  public void requestDeviceCredentialConfirmation_whenKeyguardManagerUnavailable_recordsRefusal() {
    ShadowContextImpl shadowContext = Shadow.extract(activity.getBaseContext());
    shadowContext.removeSystemService(Context.KEYGUARD_SERVICE);

    activity.requestDeviceCredentialConfirmation();

    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Device does not support Keyguard.");
    expect.that(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
    expect
        .that(persistedEventTypes())
        .containsExactly(SEEDED_EVENT_TYPE, "AUDIT_LOG_VIEWED", "AUDIT_LOG_CLEAR_REFUSED");
  }

  @Test
  public void clearLogsConfirmed_whenCredentialConfirmed_clearsLogs() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // Creating the key preferences store writes its HMAC key. Let that finish first: a seal
    // reading the store meanwhile could find the key without the store and report it deleted.
    CrumblesDataStoreHolder.getInstance(context).updateDataAsync(preferences -> preferences).get();
    CrumblesMain.getLogsEncryptorInstance()
        .generateKeyPair(CrumblesLogsEncryptor.KEY_ALIAS, /* requireUserAuthentication= */ false);
    launchConfirmCredential();
    String clearRequestedTag = auditLogger.getUnshippedExcerpt().getHeadTag().orElseThrow();

    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    awaitBackgroundTasks();

    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    expect.that(logsDir.listFiles((dir, name) -> name.endsWith(".bin"))).hasLength(1);
    expect
        .that(
            context
                .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
                .getString(CrumblesConstants.PREF_AUDIT_SHIPPED_THROUGH_TAG, /* defValue= */ null))
        .isEqualTo(clearRequestedTag);
    expect
        .that(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
                .get())
        .hasSize(1);
    expect.that(persistedEventTypes()).containsExactly("AUDIT_LOG_CLEARED");
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(
            preferences -> preferences.toBuilder().clearInternalKeyFingerprint().build())
        .get();
  }

  @Test
  public void clearLogsConfirmed_whenSealingFailsBeforeClear_clearsAndRecordsUnsealedCount()
      throws Exception {
    launchConfirmCredential();
    int unshippedRecords = auditLogger.getUnshippedExcerpt().size();

    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    awaitBackgroundTasks();

    // No encryption key is set up, so sealing fails and the tombstone counts the records lost.
    assertThat(persistedEventTypes()).containsExactly("AUDIT_LOG_CLEARED");
    expect
        .that(auditLogger.getAllPersistedEventsForDisplay().get(0).getMessage())
        .contains("(" + unshippedRecords + " unshipped records could not be sealed before clear)");
  }

  @Test
  public void clearLogsConfirmed_whenCredentialCancelled_keepsLogsAndRecordsFailure() {
    launchConfirmCredential();

    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.ERROR_USER_CANCELED, "Cancelled");
    ShadowLooper.idleMainLooper();

    expect
        .that(persistedEventTypes())
        .containsExactly(
            SEEDED_EVENT_TYPE,
            "AUDIT_LOG_VIEWED",
            "AUDIT_LOG_CLEAR_REQUESTED",
            "AUDIT_LOG_CLEAR_AUTH_FAILED");
    expect.that(ShadowToast.getTextOfLatestToast()).isEqualTo("Authentication cancelled.");
  }

  @Test
  public void requestDeviceCredentialConfirmation_guardsSavedStateFinishingAndDestroyed() {
    ActivityController<CrumblesAuditLogViewerActivity> savedController = openViewer();
    shadowOf(savedController.get().getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    savedController.pause().saveInstanceState(new Bundle());
    savedController.get().requestDeviceCredentialConfirmation();
    ShadowLooper.idleMainLooper();
    expect.that(persistedEventTypes()).contains(SEEDED_EVENT_TYPE);
    expect.that(persistedEventTypes()).contains("AUDIT_LOG_CLEAR_AUTH_FAILED");

    launchConfirmCredential();
    activity.finish();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();
    expect.that(persistedEventTypes()).contains(SEEDED_EVENT_TYPE);

    ActivityController<CrumblesAuditLogViewerActivity> destroyedController = openViewer();
    shadowOf(destroyedController.get().getSystemService(KeyguardManager.class))
        .setIsDeviceSecure(true);
    destroyedController.get().requestDeviceCredentialConfirmation();
    destroyedController.destroy();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();
    expect.that(persistedEventTypes()).contains(SEEDED_EVENT_TYPE);
  }

  @Test
  public void confirmStrongCredential_enforcesStrongAuthenticatorsAndCallbacks() {
    boolean[] events = new boolean[3];
    setDeviceSecure(/* isDeviceSecure= */ true);
    CrumblesDeviceCredentialGate.confirmStrongCredential(
        activity,
        "Strong Title",
        "Strong Subtitle",
        () -> events[0] = true,
        () -> events[1] = true,
        () -> events[2] = true);
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getAllowedAuthenticators())
        .isEqualTo(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
                | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getTitle().toString())
        .isEqualTo("Strong Title");
    expect
        .that(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("Strong Subtitle");
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();
    expect.that(events[0]).isTrue();

    CrumblesDeviceCredentialGate.confirmStrongCredential(
        activity,
        "Strong Title",
        /* subtitle= */ null,
        () -> {},
        () -> events[1] = true,
        () -> {});
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.ERROR_USER_CANCELED, "Cancelled");
    ShadowLooper.idleMainLooper();
    expect.that(events[1]).isTrue();

    setDeviceSecure(/* isDeviceSecure= */ false);
    CrumblesDeviceCredentialGate.confirmStrongCredential(
        activity,
        "Strong Title",
        /* subtitle= */ null,
        () -> {},
        () -> {},
        () -> events[2] = true);
    expect.that(events[2]).isTrue();
  }

  @Test
  public void showChainVerification_whenEveryRecordVerified_reportsCheckPassed() {
    activity.showNoLogsMessage();

    activity.showChainVerification(
        new CrumblesChainVerification(
            /* totalRecords= */ 2,
            /* verifiedRecords= */ 2,
            /* unverifiableRecords= */ 0,
            /* firstBrokenIndex= */ -1));

    expect.that(chainStatus().getVisibility()).isEqualTo(View.VISIBLE);
    expect
        .that(chainStatus().getText().toString())
        .isEqualTo(activity.getString(R.string.audit_chain_check_passed));
  }

  @Test
  public void showChainVerification_whenOldestRecordsUnverifiable_reportsNewerRecordsPassed() {
    activity.showChainVerification(
        new CrumblesChainVerification(
            /* totalRecords= */ 3,
            /* verifiedRecords= */ 2,
            /* unverifiableRecords= */ 1,
            /* firstBrokenIndex= */ -1));

    expect
        .that(chainStatus().getText().toString())
        .isEqualTo(activity.getString(R.string.audit_chain_check_partly_passed));
  }

  @Test
  public void showChainVerification_whenNoRecordVerifiable_reportsCheckNotPossible() {
    activity.showChainVerification(
        new CrumblesChainVerification(
            /* totalRecords= */ 2,
            /* verifiedRecords= */ 0,
            /* unverifiableRecords= */ 2,
            /* firstBrokenIndex= */ -1));

    expect
        .that(chainStatus().getText().toString())
        .isEqualTo(activity.getString(R.string.audit_chain_check_not_possible));
  }

  @Test
  public void showChainVerification_whenChainBroken_namesFirstBrokenRecordFromOldest() {
    activity.showChainVerification(
        new CrumblesChainVerification(
            /* totalRecords= */ 5,
            /* verifiedRecords= */ 2,
            /* unverifiableRecords= */ 0,
            /* firstBrokenIndex= */ 2));

    expect
        .that(chainStatus().getText().toString())
        .isEqualTo(
            "Activity log check failed at record 3 of 5, counting from the oldest: that record was"
                + " changed or inserted, or records just before it were removed. Records from that"
                + " point on cannot be trusted.");
  }

  @Test
  public void showChainVerificationInProgress_afterEmptyLog_showsCheckRunning() {
    activity.showNoLogsMessage();

    activity.showChainVerificationInProgress();

    expect.that(chainStatus().getVisibility()).isEqualTo(View.VISIBLE);
    expect
        .that(chainStatus().getText().toString())
        .isEqualTo(activity.getString(R.string.audit_chain_check_running));
  }

  @Test
  public void showNoLogsMessage_hidesChainStatus() {
    activity.showChainVerificationInProgress();

    activity.showNoLogsMessage();

    expect.that(chainStatus().getVisibility()).isEqualTo(View.GONE);
  }

  @Test
  public void onCreate_hidesRecordsFromAccessibilityServicesOtherThanTools() {
    ShadowLooper.idleMainLooper();

    ViewGroup recordList = activity.findViewById(R.id.rv_audit_logs);

    assertThat(recordList.getChildCount()).isGreaterThan(0);
    assertThat(recordList.getChildAt(0).isAccessibilityDataSensitive()).isTrue();
  }

  private TextView chainStatus() {
    return activity.findViewById(R.id.tv_audit_chain_status);
  }

  private void setDeviceSecure(boolean isDeviceSecure) {
    ShadowKeyguardManager shadowKeyguardManager =
        shadowOf(activity.getSystemService(KeyguardManager.class));
    shadowKeyguardManager.setIsKeyguardSecure(isDeviceSecure);
    shadowKeyguardManager.setIsDeviceSecure(isDeviceSecure);
  }

  private void confirmClearLogsDialog() {
    activity.findViewById(R.id.btn_clear_audit_logs).performClick();
    ShadowLooper.idleMainLooper();
    ShadowDialog.getLatestDialog().findViewById(android.R.id.button1).performClick();
    ShadowLooper.idleMainLooper();
  }

  private void launchConfirmCredential() {
    setDeviceSecure(/* isDeviceSecure= */ true);
    confirmClearLogsDialog();
  }

  /** Opens the viewer and authenticates at the prompt that it opens with. */
  private static ActivityController<CrumblesAuditLogViewerActivity> openViewer() {
    ActivityController<CrumblesAuditLogViewerActivity> controller =
        Robolectric.buildActivity(CrumblesAuditLogViewerActivity.class).setup();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();
    return controller;
  }

  private ImmutableList<String> persistedEventTypes() {
    return auditLogger.getAllPersistedEventsForDisplay().stream()
        .map(CrumblesAuditEvent::getEventType)
        .collect(toImmutableList());
  }

  private static void awaitBackgroundTasks() throws Exception {
    CrumblesAuditLogViewerActivity.chainCheckExecutor.submit(() -> {}).get(5, SECONDS);
    ShadowLooper.idleMainLooper();
    CrumblesAuditLogViewerActivity.chainCheckExecutor.submit(() -> {}).get(5, SECONDS);
    ShadowLooper.idleMainLooper();
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
