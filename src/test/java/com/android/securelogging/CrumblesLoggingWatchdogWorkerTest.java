/*
 * Copyright 2026 Google LLC
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
import static java.util.stream.Collectors.toCollection;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;
import android.service.notification.StatusBarNotification;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.ListenableWorker.Result;
import androidx.work.testing.TestListenableWorkerBuilder;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Shadows;

/** Unit tests for {@link CrumblesLoggingWatchdogWorker}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesLoggingWatchdogWorkerTest {

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private DevicePolicyManager mockDpm;
  private Context contextWithDpm;

  @BeforeClass
  public static void setUpClass() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
  }

  @AfterClass
  public static void tearDownClass() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Before
  public void setUp() throws Exception {
    context = ApplicationProvider.getApplicationContext();
    // Each test starts with new app files, which the Keystore keys of earlier tests do not match.
    // The key preferences store is a process-wide singleton, so the key of its HMAC stays with it.
    FakeAndroidKeyStoreSpi.keystoreEntries
        .keySet()
        .removeIf(alias -> !alias.equals(CrumblesPreferencesSerializer.MAC_KEY_ALIAS));
    // The first write of the store creates that key, so a worker read must not race with it.
    CrumblesDataStoreHolder.getInstance(context).updateDataAsync(preferences -> preferences).get();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    getNotificationManager().cancelAll();
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit();
    mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    contextWithDpm =
        new ContextWrapper(context) {
          @Override
          public Object getSystemService(String name) {
            return name.equals(Context.DEVICE_POLICY_SERVICE)
                ? mockDpm
                : super.getSystemService(name);
          }
        };
  }

  @After
  public void tearDown() throws Exception {
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesExternalPublicKeyManager.getInstance(context).clearActiveExternalPublicKey();
  }

  @CanIgnoreReturnValue
  private Result runWorkerWithLoggingEnabled(boolean enabled) {
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(enabled);
    return runWorker();
  }

  @CanIgnoreReturnValue
  private Result runWorker() {
    return TestListenableWorkerBuilder.from(contextWithDpm, CrumblesLoggingWatchdogWorker.class)
        .build()
        .doWork();
  }

  /**
   * Makes Crumbles an app that the device owner delegated the given scopes to. Like the device
   * owners that delegated mode relies on, it disallows adding users.
   */
  private void setDelegatedScopes(String... scopes) {
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);
    when(mockDpm.getDelegatedScopes(/* admin= */ null, context.getPackageName()))
        .thenReturn(Arrays.asList(scopes));
    setUserAdditionDisallowed(/* disallowed= */ true);
  }

  private void setUserAdditionDisallowed(boolean disallowed) {
    Shadows.shadowOf(context.getSystemService(UserManager.class))
        .setUserRestriction(Process.myUserHandle(), UserManager.DISALLOW_ADD_USER, disallowed);
  }

  private List<CrumblesAuditEvent> getAuditEvents() {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents();
  }

  private List<String> getAuditEventTypes() {
    return getAuditEvents().stream()
        .map(CrumblesAuditEvent::getEventType)
        .collect(toCollection(ArrayList::new));
  }

  private NotificationManager getNotificationManager() {
    return (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
  }

  private Optional<StatusBarNotification> findDisabledNotification() {
    return Arrays.stream(getNotificationManager().getActiveNotifications())
        .filter(n -> n.getId() == CrumblesConstants.LOGGING_DISABLED_NOTIFICATION_ID)
        .findFirst();
  }

  private Optional<StatusBarNotification> findActionNeededNotification() {
    return Arrays.stream(getNotificationManager().getActiveNotifications())
        .filter(n -> n.getId() == CrumblesConstants.KEY_DELETED_NOTIFICATION_ID)
        .findFirst();
  }

  @Test
  public void doWork_whenDeviceKeyInvalidated_logsAndNotifiesOnceOffTheLockScreen()
      throws Exception {
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesMain.getLogsEncryptorInstance().generateKeyPair();
    FakeAndroidKeyStoreSpi.invalidateKey(CrumblesLogsEncryptor.KEY_ALIAS);

    runWorkerWithLoggingEnabled(true);

    expect
        .that(getAuditEventTypes())
        .contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED);
    Notification notification = findActionNeededNotification().orElseThrow().getNotification();
    expect.that(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    expect
        .that(notification.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        .isEqualTo(context.getString(R.string.notification_title_action_needed));

    getNotificationManager().cancelAll();
    runWorkerWithLoggingEnabled(true);

    expect
        .that(getAuditEventTypes())
        .containsExactly(CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED);
    expect.that(findActionNeededNotification()).isEmpty();
  }

  @Test
  public void saveHeartbeatBatch_whenDeviceKeyInvalidated_skipsBatchAndReportsInvalidation()
      throws Exception {
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesMain.getLogsEncryptorInstance().generateKeyPair();
    FakeAndroidKeyStoreSpi.invalidateKey(CrumblesLogsEncryptor.KEY_ALIAS);
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(true);

    CrumblesDeviceAdminReceiver.saveHeartbeatBatch(contextWithDpm);

    expect
        .that(getAuditEventTypes())
        .contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED);
    expect.that(findActionNeededNotification()).isPresent();
  }

  @Test
  public void doWork_whenExternalKeySelected_doesNotReportInvalidatedDeviceKey() throws Exception {
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesMain.getLogsEncryptorInstance().generateKeyPair();
    FakeAndroidKeyStoreSpi.invalidateKey(CrumblesLogsEncryptor.KEY_ALIAS);
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(
            KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());

    runWorkerWithLoggingEnabled(true);

    expect
        .that(getAuditEventTypes())
        .doesNotContain(CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED);
    expect.that(findActionNeededNotification()).isEmpty();
  }

  @Test
  public void doWork_onFirstRun_recordsBaselineWithoutAuditEvent() {
    Result result = runWorkerWithLoggingEnabled(false);

    assertThat(result).isEqualTo(Result.success());
    assertThat(getAuditEvents()).isEmpty();
    assertThat(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_withoutDevicePolicyManager_skipsCheckWithoutRecordingState() {
    Context contextWithoutDpm =
        new ContextWrapper(context) {
          @Override
          public Object getSystemService(String name) {
            return name.equals(Context.DEVICE_POLICY_SERVICE) ? null : super.getSystemService(name);
          }
        };

    Result result =
        TestListenableWorkerBuilder.from(contextWithoutDpm, CrumblesLoggingWatchdogWorker.class)
            .build()
            .doWork();

    expect.that(result).isEqualTo(Result.success());
    expect
        .that(
            context
                .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
                .getAll())
        .doesNotContainKey(CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED);
    expect.that(getAuditEvents()).isEmpty();
  }

  @Test
  public void doWork_whenStateUnchanged_logsNothing() {
    runWorkerWithLoggingEnabled(true);

    runWorkerWithLoggingEnabled(true);

    assertThat(getAuditEvents()).isEmpty();
    assertThat(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_whenLoggingTurnedOff_logsDisabledAuditEvent() {
    runWorkerWithLoggingEnabled(true);

    runWorkerWithLoggingEnabled(false);

    assertThat(getAuditEventTypes())
        .containsExactly(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_DISABLED);
  }

  @Test
  public void doWork_whenLoggingTurnedOff_notifiesUserOffTheLockScreen() {
    runWorkerWithLoggingEnabled(true);

    runWorkerWithLoggingEnabled(false);

    Notification notification = findDisabledNotification().orElseThrow().getNotification();
    assertThat(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    assertThat(notification.flags & Notification.FLAG_AUTO_CANCEL)
        .isEqualTo(Notification.FLAG_AUTO_CANCEL);
    assertThat(notification.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        .isEqualTo(context.getString(R.string.notification_title_sync_turned_off));
    assertThat(notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        .isEqualTo(context.getString(R.string.notification_text_sync_turned_off));
    NotificationChannel channel =
        getNotificationManager()
            .getNotificationChannel(CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID);
    assertThat(channel.getLockscreenVisibility()).isEqualTo(Notification.VISIBILITY_SECRET);
    assertThat(channel.getDescription())
        .isEqualTo(context.getString(R.string.notification_channel_description_action_needed));
  }

  @Test
  public void doWork_whenLoggingTurnedOff_notificationTapOpensMainScreen() {
    runWorkerWithLoggingEnabled(true);

    runWorkerWithLoggingEnabled(false);

    Notification notification = findDisabledNotification().orElseThrow().getNotification();
    assertThat(notification.contentIntent.isImmutable()).isTrue();
    assertThat(
            Shadows.shadowOf(notification.contentIntent)
                .getSavedIntent()
                .getComponent()
                .getClassName())
        .isEqualTo(CrumblesMain.class.getName());
  }

  @Test
  public void doWork_whenLoggingTurnedBackOn_logsEnabledAuditEvent() {
    runWorkerWithLoggingEnabled(true);
    runWorkerWithLoggingEnabled(false);

    runWorkerWithLoggingEnabled(true);

    assertThat(getAuditEventTypes())
        .containsExactly(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_DISABLED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_ENABLED);
  }

  @Test
  public void doWork_whenLoggingTurnedOn_doesNotNotify() {
    runWorkerWithLoggingEnabled(false);

    runWorkerWithLoggingEnabled(true);

    assertThat(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_asDelegateWhenLoggingTurnedOff_logsDisabledAuditEventAndNotifies() {
    setDelegatedScopes(DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.isSecurityLoggingEnabled(isNull())).thenReturn(true);
    runWorker();
    when(mockDpm.isSecurityLoggingEnabled(isNull())).thenReturn(false);

    runWorker();

    expect
        .that(getAuditEventTypes())
        .containsExactly(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_DISABLED);
    expect.that(findDisabledNotification()).isPresent();
  }

  @Test
  public void doWork_whenDelegationRevokedWhileLoggingOn_logsAccessLostAuditEventAndNotifies() {
    setDelegatedScopes(DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.isSecurityLoggingEnabled(isNull())).thenReturn(true);
    runWorker();
    setDelegatedScopes();

    runWorker();

    expect
        .that(getAuditEventTypes())
        .containsExactly(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_ACCESS_LOST);
    expect.that(findDisabledNotification()).isPresent();
  }

  @Test
  public void doWork_whenAccessLostWhileLoggingOff_logsNothing() {
    runWorkerWithLoggingEnabled(false);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);

    runWorker();

    expect.that(getAuditEvents()).isEmpty();
    expect.that(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_whenStateCheckThrowsSecurityException_logsAccessLostAuditEventAndNotifies() {
    setDelegatedScopes(DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.isSecurityLoggingEnabled(isNull())).thenReturn(true);
    runWorker();
    when(mockDpm.isSecurityLoggingEnabled(isNull()))
        .thenThrow(new SecurityException("Delegation revoked."));

    runWorker();

    expect
        .that(getAuditEventTypes())
        .containsExactly(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_LOGGING_ACCESS_LOST);
    expect.that(findDisabledNotification()).isPresent();
  }

  @Test
  public void doWork_withoutAccessOnFirstRun_recordsNoBaseline() {
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);
    runWorker();
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);

    runWorkerWithLoggingEnabled(true);

    assertThat(getAuditEvents()).isEmpty();
  }

  @Test
  public void doWork_whenNetworkLoggingTurnedOff_logsNetworkDisabledAuditEventAndNotifies() {
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    runWorkerWithLoggingEnabled(true);
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(false);

    runWorkerWithLoggingEnabled(true);

    expect
        .that(getAuditEventTypes())
        .containsExactly(CrumblesLoggingWatchdogWorker.AUDIT_EVENT_NETWORK_LOGGING_DISABLED);
    expect.that(findDisabledNotification()).isPresent();
  }

  @Test
  public void doWork_whenNetworkLoggingToggledWhileSecurityLoggingOff_doesNotLogNetworkDisabled() {
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    runWorkerWithLoggingEnabled(true);

    // Security logging is off, so the worker is not running.
    // The user toggles network logging off then on.
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, false);
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, true);

    runWorkerWithLoggingEnabled(true);

    expect.that(getAuditEventTypes()).isEmpty();
    expect.that(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_whenNetworkLoggingTurnedOn_logsNetworkEnabledAuditEventWithoutNotifying() {
    runWorkerWithLoggingEnabled(true);
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(true);

    runWorkerWithLoggingEnabled(true);

    expect
        .that(getAuditEventTypes())
        .containsExactly(CrumblesLoggingWatchdogWorker.AUDIT_EVENT_NETWORK_LOGGING_ENABLED);
    expect.that(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_whenNetworkDelegationRevokedWhileOn_logsAccessLostAuditEventAndNotifies() {
    setDelegatedScopes(DevicePolicyManager.DELEGATION_NETWORK_LOGGING);
    when(mockDpm.isNetworkLoggingEnabled(isNull())).thenReturn(true);
    runWorker();
    setDelegatedScopes();

    runWorker();

    expect
        .that(getAuditEventTypes())
        .containsExactly(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_NETWORK_LOGGING_ACCESS_LOST);
    expect.that(findDisabledNotification()).isPresent();
  }

  @Test
  public void doWork_asDelegateWhenUsersCanBeAddedThenNot_recordsEachChangeOnce() {
    setDelegatedScopes(DevicePolicyManager.DELEGATION_NETWORK_LOGGING);
    setUserAdditionDisallowed(/* disallowed= */ false);
    runWorker();
    runWorker();
    setUserAdditionDisallowed(/* disallowed= */ true);

    runWorker();

    expect
        .that(getAuditEventTypes())
        .containsExactly(
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_USER_ADDITION_BLOCKED,
            CrumblesLoggingWatchdogWorker.AUDIT_EVENT_USER_ADDITION_ALLOWED)
        .inOrder();
  }

  @Test
  public void doWork_whenNetworkCollectionTurnedOff_ignoresNetworkLoggingTurningOff() {
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    runWorkerWithLoggingEnabled(true);
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(false);

    runWorkerWithLoggingEnabled(true);

    expect.that(getAuditEvents()).isEmpty();
    expect.that(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_whenNetworkCollectionReenabled_doesNotFalselyReportNetworkLoggingDisabled() {
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    runWorkerWithLoggingEnabled(true);

    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(false);
    runWorkerWithLoggingEnabled(true);

    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ true);
    runWorkerWithLoggingEnabled(true);

    expect.that(getAuditEvents()).isEmpty();
    expect.that(findDisabledNotification()).isEmpty();
  }

  @Test
  public void doWork_syncsUserRestrictionAndReconcilesPauseForOwnerAndDelegate() throws Exception {
    String paused = CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_PAUSED;
    String resumed = CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_RESUMED;
    String failed = CrumblesDeviceAdminReceiver.AUDIT_EVENT_PAUSE_BATCH_FAILED;
    when(mockDpm.getSecondaryUsers(any()))
        .thenReturn(Collections.singletonList(UserHandle.getUserHandleForUid(1000000)));
    runWorkerWithLoggingEnabled(true);
    verify(mockDpm).addUserRestriction(any(), eq(UserManager.DISALLOW_ADD_USER));
    runWorkerWithLoggingEnabled(true);
    expect.that(getAuditEventTypes()).containsExactly(failed, paused).inOrder();
    expect.that(hasPausedNotification()).isTrue();

    when(mockDpm.getSecondaryUsers(any())).thenReturn(Collections.emptyList());
    runWorkerWithLoggingEnabled(true);
    expect.that(getAuditEventTypes()).containsExactly(resumed, failed, paused).inOrder();
    expect.that(getAuditEvents().get(0).getMessage()).contains("discarded by the platform");
    expect.that(hasPausedNotification()).isFalse();
    runWorkerWithLoggingEnabled(false);
    verify(mockDpm).clearUserRestriction(any(), eq(UserManager.DISALLOW_ADD_USER));

    CrumblesDeviceAdminReceiver.prefs(context).edit().clear().commit();
    setDelegatedScopes(DevicePolicyManager.DELEGATION_NETWORK_LOGGING);
    when(mockDpm.isNetworkLoggingEnabled(isNull())).thenReturn(true);
    when(mockDpm.retrieveNetworkLogs(isNull(), eq(Long.MIN_VALUE)))
        .thenThrow(new SecurityException("Unaffiliated"));
    runWorker();
    expect.that(hasPausedNotification()).isTrue();
    doReturn(null).when(mockDpm).retrieveNetworkLogs(isNull(), eq(Long.MIN_VALUE));
    runWorker();
    expect.that(hasPausedNotification()).isFalse();
    expect.that(getAuditEventTypes().get(0)).isEqualTo(resumed);

    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    long session = CrumblesDeviceAdminReceiver.currentNetworkLoggingSessionKey(context);
    Files.write(
        new File(context.getNoBackupFilesDir(), CrumblesDeviceAdminReceiver.DEFERRED_TOKENS_FILE)
            .toPath(),
        ByteBuffer.allocate(268).putLong(session).putInt(1).putLong(88L).array());
    // The platform discarded the deferred batch, so draining its token records the loss.
    doReturn(null).when(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(88L));
    runWorkerWithLoggingEnabled(true);
    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(88L));
    expect.that(getAuditEventTypes()).contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST);
  }

  private boolean hasPausedNotification() {
    return Arrays.stream(getNotificationManager().getActiveNotifications())
        .anyMatch(n -> n.getId() == CrumblesConstants.COLLECTION_PAUSED_NOTIFICATION_ID);
  }
}
