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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.app.admin.SecurityLog;
import android.app.admin.SecurityLog.SecurityEvent;
import android.content.BroadcastReceiver;
import android.content.BroadcastReceiver.PendingResult;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowEventLog;

/**
 * Unit tests for {@link CrumblesDelegatedAdminReceiver}.
 *
 * <p>Security events are built through reflection with Robolectric's {@link ShadowEventLog}, since
 * the platform offers no public way to create one with data.
 */
@RunWith(AndroidJUnit4.class)
public final class CrumblesDelegatedAdminReceiverTest {

  private static final long NETWORK_BATCH_TOKEN = 123L;
  private static final Duration BROADCAST_FINISH_TIMEOUT = Duration.ofSeconds(10);
  // The hidden extras that carry the network logs batch token and size.
  private static final String EXTRA_NETWORK_LOGS_TOKEN =
      "android.app.extra.EXTRA_NETWORK_LOGS_TOKEN";
  private static final String EXTRA_NETWORK_LOGS_COUNT =
      "android.app.extra.EXTRA_NETWORK_LOGS_COUNT";

  @Rule public final Expect expect = Expect.create();

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
    Context context = ApplicationProvider.getApplicationContext();
    WorkManagerTestInitHelper.initializeTestWorkManager(
        context, new Configuration.Builder().setExecutor(new SynchronousExecutor()).build());
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(
            KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
  }

  @After
  public void tearDown() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDeviceAdminReceiver.prefs(context).edit().clear().commit();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesExternalPublicKeyManager.getInstance(context).clearActiveExternalPublicKey();
    Shadows.shadowOf(Looper.getMainLooper()).idle();
  }

  @Test
  public void onSecurityLogsAvailable_asDelegate_retrievesPreRebootLogsFirstWithNullAdmin()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm =
        delegateDpm(context, DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.retrievePreRebootSecurityLogs(isNull()))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN)));
    when(mockDpm.retrieveSecurityLogs(isNull()))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_STARTUP)));

    deliverSecurityLogs(createContextWrapper(context, mockDpm));

    InOrder retrievals = inOrder(mockDpm);
    retrievals.verify(mockDpm).retrievePreRebootSecurityLogs(isNull());
    retrievals.verify(mockDpm).retrieveSecurityLogs(isNull());
    assertThat(savedBatches(context)).hasLength(2);
  }

  @Test
  public void onSecurityLogsAvailable_asDelegate_retrievesPreRebootLogsOncePerBoot()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm =
        delegateDpm(context, DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.retrievePreRebootSecurityLogs(isNull()))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN)));
    Context delegateContext = createContextWrapper(context, mockDpm);
    Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 1);

    deliverSecurityLogs(delegateContext);
    deliverSecurityLogs(delegateContext);

    verify(mockDpm).retrievePreRebootSecurityLogs(isNull());
    verify(mockDpm, times(2)).retrieveSecurityLogs(isNull());
  }

  @Test
  public void onSecurityLogsAvailable_whenAnotherUserBlocksTheDelegate_retriesPreRebootLogsLater()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm =
        delegateDpm(context, DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.retrievePreRebootSecurityLogs(isNull()))
        .thenThrow(new SecurityException("Not all users are affiliated"))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN)));
    when(mockDpm.retrieveSecurityLogs(isNull()))
        .thenThrow(new SecurityException("Not all users are affiliated"))
        .thenReturn(ImmutableList.of());
    Context delegateContext = createContextWrapper(context, mockDpm);
    deliverSecurityLogs(delegateContext);

    deliverSecurityLogs(delegateContext);

    verify(mockDpm, times(2)).retrievePreRebootSecurityLogs(isNull());
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEmpty();
  }

  @Test
  public void onNetworkLogsAvailable_asNetworkLoggingDelegate_doesNotRetrievePreRebootLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm =
        delegateDpm(context, DevicePolicyManager.DELEGATION_NETWORK_LOGGING);

    deliverNetworkLogs(createContextWrapper(context, mockDpm));

    verify(mockDpm).retrieveNetworkLogs(isNull(), eq(NETWORK_BATCH_TOKEN));
    verify(mockDpm, never()).retrievePreRebootSecurityLogs(any());
  }

  /**
   * {@link android.app.admin.DelegatedAdminReceiver#onReceive} is final, so this receiver could not
   * handle the boot broadcast: {@link CrumblesDeviceAdminReceiver} handles it for a delegate too.
   */
  @Test
  public void bootCompletedBroadcast_doesNotReachTheDelegatedReceiver() {
    Context context = ApplicationProvider.getApplicationContext();

    List<String> receivers =
        context
            .getPackageManager()
            .queryBroadcastReceivers(
                new Intent(Intent.ACTION_BOOT_COMPLETED).setPackage(context.getPackageName()),
                /* flags= */ 0)
            .stream()
            .map(resolveInfo -> resolveInfo.activityInfo.name)
            .toList();

    expect.that(receivers).contains(CrumblesDeviceAdminReceiver.class.getName());
    expect.that(receivers).doesNotContain(CrumblesDelegatedAdminReceiver.class.getName());
  }

  /** Returns the DevicePolicyManager of an app that the device owner delegated {@code scope} to. */
  private static DevicePolicyManager delegateDpm(Context context, String scope) {
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.getDelegatedScopes(null, context.getPackageName()))
        .thenReturn(ImmutableList.of(scope));
    return mockDpm;
  }

  private static Context createContextWrapper(Context realContext, DevicePolicyManager mockDpm) {
    return new ContextWrapper(realContext) {
      @Override
      public Object getSystemService(String name) {
        if (name.equals(Context.DEVICE_POLICY_SERVICE)) {
          return mockDpm;
        }
        return super.getSystemService(name);
      }
    };
  }

  /** Returns a security event of type {@code tag} with an empty payload. */
  private static SecurityEvent securityEvent(int tag) throws ReflectiveOperationException {
    Constructor<SecurityEvent> constructor =
        SecurityEvent.class.getDeclaredConstructor(long.class, byte[].class);
    constructor.setAccessible(true);
    SecurityEvent securityEvent = constructor.newInstance(0L, new byte[0]);
    Field event = SecurityEvent.class.getDeclaredField("mEvent");
    event.setAccessible(true);
    event.set(securityEvent, new ShadowEventLog.EventBuilder(tag, "").build());
    return securityEvent;
  }

  /** Delivers the security logs broadcast to a new receiver and waits until it is handled. */
  private static void deliverSecurityLogs(Context context) {
    deliver(context, new Intent(DeviceAdminReceiver.ACTION_SECURITY_LOGS_AVAILABLE));
  }

  /**
   * Delivers the broadcast for network logs batch {@link #NETWORK_BATCH_TOKEN} to a new receiver
   * and waits until it is handled.
   */
  private static void deliverNetworkLogs(Context context) {
    deliver(
        context,
        new Intent(DeviceAdminReceiver.ACTION_NETWORK_LOGS_AVAILABLE)
            .putExtra(EXTRA_NETWORK_LOGS_TOKEN, NETWORK_BATCH_TOKEN)
            .putExtra(EXTRA_NETWORK_LOGS_COUNT, 5));
  }

  /**
   * Delivers {@code intent} to a new receiver with a pending result, as the platform does, and
   * waits until the receiver finishes the broadcast.
   */
  private static void deliver(Context context, Intent intent) {
    CrumblesDelegatedAdminReceiver receiver = new CrumblesDelegatedAdminReceiver();
    PendingResult pendingResult = attachPendingResult(receiver);
    receiver.onReceive(context, intent);
    awaitFinish(pendingResult);
  }

  /** Attaches to {@code receiver} the pending result that the platform gives every broadcast. */
  private static PendingResult attachPendingResult(BroadcastReceiver receiver) {
    try {
      Constructor<PendingResult> constructor =
          PendingResult.class.getDeclaredConstructor(
              int.class,
              String.class,
              Bundle.class,
              int.class,
              boolean.class,
              boolean.class,
              IBinder.class,
              int.class,
              int.class);
      constructor.setAccessible(true);
      // An unordered, non-sticky broadcast: resultCode, resultData, resultExtras, type, ordered,
      // sticky, token, userId and flags.
      PendingResult pendingResult =
          constructor.newInstance(0, null, null, 0, false, false, null, 0, 0);
      Method setPendingResult =
          BroadcastReceiver.class.getDeclaredMethod("setPendingResult", PendingResult.class);
      setPendingResult.setAccessible(true);
      setPendingResult.invoke(receiver, pendingResult);
      return pendingResult;
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Unable to attach a pending result to the receiver.", e);
    }
  }

  /** Waits until {@code pendingResult} is finished, failing if that takes too long. */
  private static void awaitFinish(PendingResult pendingResult) {
    try {
      Shadows.shadowOf(pendingResult)
          .getFuture()
          .get(BROADCAST_FINISH_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (ExecutionException | TimeoutException e) {
      throw new AssertionError("The receiver did not finish the broadcast.", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Interrupted while waiting for the receiver.", e);
    }
  }

  /** Returns the encrypted batches saved in the logs directory. */
  private static File[] savedBatches(Context context) {
    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File[] batches = logsDir.listFiles((dir, name) -> name.endsWith(".bin"));
    return batches == null ? new File[0] : batches;
  }

  /** Returns the message of the newest activity log event of type {@code eventType}, or "". */
  private static String newestAuditMessage(Context context, String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .filter(event -> event.getEventType().equals(eventType))
        .map(CrumblesAuditEvent::getMessage)
        .findFirst()
        .orElse("");
  }
}
