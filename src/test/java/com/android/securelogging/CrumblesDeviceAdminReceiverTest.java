package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import android.app.admin.ConnectEvent;
import android.app.admin.DnsEvent;
import android.app.admin.NetworkEvent;
import android.app.admin.SecurityLog;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.common.collect.ImmutableList;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
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
}
