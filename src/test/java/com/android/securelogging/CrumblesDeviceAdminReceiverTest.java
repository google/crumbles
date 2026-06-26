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
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.admin.ConnectEvent;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.app.admin.DnsEvent;
import android.app.admin.NetworkEvent;
import android.app.admin.SecurityLog;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.PersistableBundle;
import android.util.Log;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.google.common.collect.ImmutableList;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Unit tests for {@link CrumblesDeviceAdminReceiver}.
 *
 * <p>This version tests the complex private helper methods of getSerializableSecurityLogs directly
 * via reflection, because creating a complete SecurityEvent object in a test environment is not
 * feasible.
 */
@RunWith(AndroidJUnit4.class)
public final class CrumblesDeviceAdminReceiverTest {
  private CrumblesDeviceAdminReceiver receiver;

  @Before
  public void setup() {
    receiver = new CrumblesDeviceAdminReceiver();
    Context context = ApplicationProvider.getApplicationContext();
    Configuration config =
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(new SynchronousExecutor())
            .build();
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config);
  }

  /**
   * Tests that getSerializableNetworkLogs correctly formats a ConnectEvent created via reflection.
   */
  @Test
  public void getSerializableNetworkLogs_withConnectEvent_returnsFormattedString() {
    try {
      // This timestamp (in millis) corresponds to 2023-01-01T00:00:00.000Z
      long timestamp = 1672531200000L;
      String packageName = "com.android.test";
      String ipAddress = "192.168.1.100";
      int port = 443;

      Constructor<ConnectEvent> constructor =
          ConnectEvent.class.getConstructor(String.class, int.class, String.class, long.class);
      ConnectEvent connectEvent = constructor.newInstance(ipAddress, port, packageName, timestamp);

      ImmutableList<NetworkEvent> networkLogs = ImmutableList.of(connectEvent);

      // Verify the timestamp is formatted as a human-readable UTC string.
      String expectedString =
          """
          Network log ID: 0
          Timestamp (UTC): 2023-01-01T00:00:00.000Z
          Package name: com.android.test
          Connect event ID: 0
          Inet address: /192.168.1.100
          Port: 443

          """;

      List<String> serializableNetworkLogs = receiver.getSerializableNetworkLogs(networkLogs);
      assertThat(serializableNetworkLogs).containsExactly(expectedString);
    } catch (ReflectiveOperationException e) {
      fail("Test failed due to reflection error: " + e.getMessage());
    }
  }

  /** Tests that getSerializableNetworkLogs correctly formats a DnsEvent created via reflection. */
  @Test
  public void getSerializableNetworkLogs_withDnsEvent_returnsFormattedString() {
    try {
      // This timestamp (in millis) corresponds to 2023-01-01T00:00:00.000Z
      long timestamp = 1672531200000L;
      String packageName = "com.android.browser";
      String hostname = "example.com";
      String[] ipAddresses = new String[] {"93.184.216.34"};
      int totalCount = 1;

      Constructor<DnsEvent> constructor =
          DnsEvent.class.getConstructor(
              String.class, String[].class, int.class, String.class, long.class);
      DnsEvent dnsEvent =
          constructor.newInstance(hostname, ipAddresses, totalCount, packageName, timestamp);

      ImmutableList<NetworkEvent> networkLogs = ImmutableList.of(dnsEvent);

      // Verify the timestamp is formatted as a human-readable UTC string.
      String expectedString =
          """
          Network log ID: 0
          Timestamp (UTC): 2023-01-01T00:00:00.000Z
          Package name: com.android.browser
          DNS event ID: 0
          Domain name: example.com
          Inet addresses: [/93.184.216.34]
          Total resolved addresses: 1

          """;

      List<String> serializableNetworkLogs = receiver.getSerializableNetworkLogs(networkLogs);
      assertThat(serializableNetworkLogs).containsExactly(expectedString);
    } catch (ReflectiveOperationException e) {
      fail("Test failed due to reflection error: " + e.getMessage());
    }
  }

  /** Tests that getSerializableNetworkLogs returns an empty list for null or empty input. */
  @Test
  public void getSerializableNetworkLogs_withNullOrEmptyList_returnsEmptyList() {
    assertThat(receiver.getSerializableNetworkLogs(null)).isEmpty();
    assertThat(receiver.getSerializableNetworkLogs(new ArrayList<>())).isEmpty();
  }

  /**
   * Tests getSerializableSecurityLogs with null and empty lists, which is the extent of testing
   * possible without being able to construct a SecurityEvent with data.
   */
  @Test
  public void getSerializableSecurityLogs_withNullOrEmptyList_returnsEmptyList() {
    assertThat(receiver.getSerializableSecurityLogs(null)).isEmpty();
    assertThat(receiver.getSerializableSecurityLogs(new ArrayList<>())).isEmpty();
  }

  /** Tests the private getSecurityEventType helper method directly using reflection. */
  @Test
  public void getSecurityEventType_returnsCorrectString() {
    try {
      Method method =
          CrumblesDeviceAdminReceiver.class.getDeclaredMethod("getSecurityEventType", int.class);
      method.setAccessible(true);

      String adbResult = (String) method.invoke(receiver, SecurityLog.TAG_ADB_SHELL_CMD);
      assertThat(adbResult).isEqualTo("ADB shell command: ");

      String processStartResult =
          (String) method.invoke(receiver, SecurityLog.TAG_APP_PROCESS_START);
      assertThat(processStartResult).isEqualTo("App process started: ");

      String wipeFailureResult = (String) method.invoke(receiver, SecurityLog.TAG_WIPE_FAILURE);
      assertThat(wipeFailureResult).isEqualTo("Failure to wipe device or user data: ");

      String userRestrictionRemovedResult =
          (String) method.invoke(receiver, SecurityLog.TAG_USER_RESTRICTION_REMOVED);
      assertThat(userRestrictionRemovedResult).isEqualTo("Admin has removed a user restriction: ");

      String wifiDisconnectionResult =
          (String) method.invoke(receiver, SecurityLog.TAG_WIFI_DISCONNECTION);
      assertThat(wifiDisconnectionResult)
          .isEqualTo("The device disconnects from a managed WiFi network: ");

    } catch (ReflectiveOperationException e) {
      fail("Test failed due to reflection error on getSecurityEventType: " + e.getMessage());
    }
  }

  /** Tests the private getSecurityEventSeverity helper method directly using reflection. */
  @Test
  public void getSecurityEventSeverity_returnsCorrectString() {
    try {
      Method method =
          CrumblesDeviceAdminReceiver.class.getDeclaredMethod(
              "getSecurityEventSeverity", int.class);
      method.setAccessible(true);

      String highResult = (String) method.invoke(receiver, SecurityLog.LEVEL_ERROR);
      assertThat(highResult).isEqualTo("Severity: HIGH");

      String mediumResult = (String) method.invoke(receiver, SecurityLog.LEVEL_WARNING);
      assertThat(mediumResult).isEqualTo("Severity: MEDIUM");

      String lowResult = (String) method.invoke(receiver, SecurityLog.LEVEL_INFO);
      assertThat(lowResult).isEqualTo("Severity: LOW");

      String unknownResult = (String) method.invoke(receiver, 999); // Some other value.
      assertThat(unknownResult).isEqualTo("Severity: UNKNOWN");

    } catch (ReflectiveOperationException e) {
      fail("Test failed due to reflection error on getSecurityEventSeverity: " + e.getMessage());
    }
  }

  @Test
  public void onProfileProvisioningComplete_whenDeviceOwnerAndFlagTrue_enablesSecurityAndNetworkLogging() {
    Context realContext = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(realContext.getPackageName())).thenReturn(true);

    Context contextWrapper = createContextWrapper(realContext, mockDpm);

    Intent intent = new Intent(DeviceAdminReceiver.ACTION_PROFILE_PROVISIONING_COMPLETE);
    PersistableBundle adminExtras = new PersistableBundle();
    adminExtras.putBoolean("enable_logging", true);
    intent.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, adminExtras);

    receiver.onProfileProvisioningComplete(contextWrapper, intent);

    verify(mockDpm).setSecurityLoggingEnabled(any(ComponentName.class), eq(true));
    verify(mockDpm).setNetworkLoggingEnabled(any(ComponentName.class), eq(true));

    try {
      List<WorkInfo> sendWorkInfos =
          WorkManager.getInstance(realContext)
              .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
              .get();
      assertThat(sendWorkInfos).hasSize(1);
    } catch (ExecutionException e) {
      fail("Failed to verify work manager scheduling: " + e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      fail("Interrupted while verifying work manager scheduling: " + e.getMessage());
    }
  }

  @Test
  public void onProfileProvisioningComplete_whenDeviceOwnerAndFlagFalse_doesNotEnableLogging() {
    Context realContext = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(realContext.getPackageName())).thenReturn(true);

    Context contextWrapper = createContextWrapper(realContext, mockDpm);

    Intent intent = new Intent(DeviceAdminReceiver.ACTION_PROFILE_PROVISIONING_COMPLETE);
    PersistableBundle adminExtras = new PersistableBundle();
    adminExtras.putBoolean("enable_logging", false);
    intent.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, adminExtras);

    receiver.onProfileProvisioningComplete(contextWrapper, intent);

    verify(mockDpm, never()).setSecurityLoggingEnabled(any(ComponentName.class), eq(true));
    verify(mockDpm, never()).setNetworkLoggingEnabled(any(ComponentName.class), eq(true));

    try {
      List<WorkInfo> sendWorkInfos =
          WorkManager.getInstance(realContext)
              .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
              .get();
      assertThat(sendWorkInfos).isEmpty();
    } catch (ExecutionException e) {
      fail("Failed to verify work manager scheduling: " + e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      fail("Interrupted while verifying work manager scheduling: " + e.getMessage());
    }
  }

  @Test
  public void onProfileProvisioningComplete_whenDeviceOwnerAndNoFlag_doesNotEnableLogging() {
    Context realContext = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(realContext.getPackageName())).thenReturn(true);

    Context contextWrapper = createContextWrapper(realContext, mockDpm);

    Intent intent = new Intent(DeviceAdminReceiver.ACTION_PROFILE_PROVISIONING_COMPLETE);
    // Intent does not contain EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE

    receiver.onProfileProvisioningComplete(contextWrapper, intent);

    verify(mockDpm, never()).setSecurityLoggingEnabled(any(ComponentName.class), eq(true));
    verify(mockDpm, never()).setNetworkLoggingEnabled(any(ComponentName.class), eq(true));
  }

  @Test
  public void onProfileProvisioningComplete_whenNotDeviceOwner_doesNotEnableLogging() {
    Context realContext = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(realContext.getPackageName())).thenReturn(false);

    Context contextWrapper = createContextWrapper(realContext, mockDpm);

    Intent intent = new Intent(DeviceAdminReceiver.ACTION_PROFILE_PROVISIONING_COMPLETE);
    PersistableBundle adminExtras = new PersistableBundle();
    adminExtras.putBoolean("enable_logging", true);
    intent.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, adminExtras);

    receiver.onProfileProvisioningComplete(contextWrapper, intent);

    verify(mockDpm, never()).setSecurityLoggingEnabled(any(ComponentName.class), eq(true));
    verify(mockDpm, never()).setNetworkLoggingEnabled(any(ComponentName.class), eq(true));
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
}
