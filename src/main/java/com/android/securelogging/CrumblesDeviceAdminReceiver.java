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

import android.app.admin.ConnectEvent;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.app.admin.DnsEvent;
import android.app.admin.NetworkEvent;
import android.app.admin.SecurityLog;
import android.app.admin.SecurityLog.SecurityEvent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Device admin receiver for Crumbles.
 *
 * <p>Receives security and network logs from Crumbles.
 */
public class CrumblesDeviceAdminReceiver extends DeviceAdminReceiver {
  private static final String TAG = "[CrumblesDeviceAdminReceiver]";
  private DevicePolicyManager dpm;
  private ComponentName adminComponentName;

  @Override
  public void onEnabled(Context context, Intent intent) {
    Log.i(TAG, "onEnabled");
  }

  private void initDpm(Context context) {
    this.dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
    if (this.dpm == null) {
      throw new IllegalStateException("Unable to get DevicePolicyManager");
    }
    this.adminComponentName =
        new ComponentName(context.getApplicationContext(), CrumblesDeviceAdminReceiver.class);
  }

  /**
   * Called each time a new batch of security logs can be retrieved.
   *
   * <p>This callback will be re-triggered if the logs are not retrieved, by a foreground broadcast.
   * If a secondary user or profile is created, this callback won't be received until all users
   * become affiliated again (even if security logging is enabled).
   */
  @Override
  public void onSecurityLogsAvailable(@NonNull Context context, @NonNull Intent intent) {
    Log.i(TAG, "Security logs available.");
    initDpm(context);
    List<SecurityEvent> securityLogs = dpm.retrieveSecurityLogs(adminComponentName);
    if (securityLogs == null) {
      Log.i(TAG, "Security logs are null.");
      return;
    }
    try {
      encryptLogs(context, logsToBytes(getSerializableSecurityLogs(securityLogs)));
    } catch (CrumblesLogsEncryptionException | IOException e) {
      Log.e(TAG, "Failed to encrypt or convert security logs to bytes.", e);
    }
  }

  /**
   * Called each time a new batch of network logs can be retrieved. This callback method will only
   * ever be called when network logging is enabled, by a foreground broadcast, whenever either 1200
   * events are logged or 1.5H timeout is reached, whichever comes first.
   */
  @Override
  public void onNetworkLogsAvailable(
      @NonNull Context context, @NonNull Intent intent, long batchToken, int networkLogsCount) {
    initDpm(context);
    List<NetworkEvent> networkLogs = dpm.retrieveNetworkLogs(adminComponentName, batchToken);
    if (networkLogs == null) {
      Log.i(TAG, "Network logs are null.");
      return;
    }
    try {
      encryptLogs(context, logsToBytes(getSerializableNetworkLogs(networkLogs)));
    } catch (CrumblesLogsEncryptionException | IOException e) {
      Log.e(TAG, "Failed to encrypt or convert network logs to bytes.", e);
    }
  }

  /** Creates and configures a SimpleDateFormat for a standardized UTC format. */
  private SimpleDateFormat getUtcDateFormatter() {
    // Note: SimpleDateFormat is not thread-safe, but it's safe to create a new
    // instance for each use here as these callbacks are not highly concurrent.
    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
    return formatter;
  }

  @VisibleForTesting
  public List<String> getSerializableNetworkLogs(List<NetworkEvent> networkLogs) {
    List<String> serializableNetworkLogs = new ArrayList<>();
    if (networkLogs == null) {
      return serializableNetworkLogs;
    }
    StringBuilder sb;
    SimpleDateFormat formatter = getUtcDateFormatter();
    for (NetworkEvent networkLog : networkLogs) {
      sb = new StringBuilder();
      sb.append("Network log ID: ").append(networkLog.getId()).append("\n");
      // Format the millisecond timestamp into a human-readable UTC string.
      Instant timestampInstant = Instant.ofEpochMilli(networkLog.getTimestamp());
      sb.append("Timestamp (UTC): ")
          .append(formatter.format(Date.from(timestampInstant)))
          .append("\n");
      sb.append("Package name: ").append(networkLog.getPackageName()).append("\n");
      if (networkLog instanceof DnsEvent dnsEvent) {
        sb.append("DNS event ID: ").append(dnsEvent.getId()).append("\n");
        sb.append("Domain name: ").append(dnsEvent.getHostname()).append("\n");
        sb.append("Inet addresses: ").append(dnsEvent.getInetAddresses()).append("\n");
        sb.append("Total resolved addresses: ")
            .append(dnsEvent.getTotalResolvedAddressCount())
            .append("\n");
      } else if (networkLog instanceof ConnectEvent connectEvent) {
        sb.append("Connect event ID: ").append(connectEvent.getId()).append("\n");
        sb.append("Inet address: ").append(connectEvent.getInetAddress()).append("\n");
        sb.append("Port: ").append(connectEvent.getPort()).append("\n");
      }
      serializableNetworkLogs.add(sb.append("\n").toString());
    }
    return serializableNetworkLogs;
  }

  @VisibleForTesting
  public List<String> getSerializableSecurityLogs(List<SecurityEvent> securityLogs) {
    List<String> serializableNetworkLogs = new ArrayList<>();
    if (securityLogs == null) {
      return serializableNetworkLogs;
    }
    StringBuilder sb;
    SimpleDateFormat formatter = getUtcDateFormatter();
    for (SecurityEvent securityEvent : securityLogs) {
      sb = new StringBuilder();
      sb.append("Security log ID: ").append(securityEvent.getId()).append("\n");
      // Format the nanosecond timestamp into a human-readable UTC string by converting to millis.
      long nanos = securityEvent.getTimeNanos();
      Instant timestampInstant = Instant.ofEpochMilli(nanos / 1_000_000L);
      sb.append("Timestamp (UTC): ")
          .append(formatter.format(Date.from(timestampInstant)))
          .append("\n");
      sb.append(getSecurityEventSeverity(securityEvent.getLogLevel())).append("\n");
      sb.append(getSecurityEventType(securityEvent.getTag())).append("\n");
      if (securityEvent.getData() != null) {
        sb.append(securityEvent.getData()).append("\n");
      }
      serializableNetworkLogs.add(sb.append("\n").toString());
    }
    return serializableNetworkLogs;
  }

  private String getSecurityEventSeverity(int logLevel) {
    String severity =
        switch (logLevel) {
          case SecurityLog.LEVEL_ERROR -> "Severity: HIGH";
          case SecurityLog.LEVEL_WARNING -> "Severity: MEDIUM";
          case SecurityLog.LEVEL_INFO -> "Severity: LOW";
          default -> "Severity: UNKNOWN";
        };
    return severity;
  }

  private String getSecurityEventType(int tag) {
    String type =
        switch (tag) {
          case SecurityLog.TAG_ADB_SHELL_CMD -> "ADB shell command: ";
          case SecurityLog.TAG_ADB_SHELL_INTERACTIVE ->
              "ADB interactive shell was opened via \"adb shell\":";
          case SecurityLog.TAG_APP_PROCESS_START -> "App process started: ";
          case SecurityLog.TAG_BACKUP_SERVICE_TOGGLED ->
              "Admin has enabled or disabled backup service: ";
          case SecurityLog.TAG_BLUETOOTH_CONNECTION -> "Attempted to connect to Bluetooth device: ";
          case SecurityLog.TAG_BLUETOOTH_DISCONNECTION ->
              "Attempted to disconnect from Bluetooth device: ";
          case SecurityLog.TAG_CAMERA_POLICY_SET -> "Admin has set policy to disable camera: ";
          case SecurityLog.TAG_CERT_AUTHORITY_INSTALLED ->
              "New root certificate has been installed into system's trusted credential storage: ";
          case SecurityLog.TAG_CERT_AUTHORITY_REMOVED ->
              "New root certificate has been removed from system's trusted credential storage:"
                  + " ";
          case SecurityLog.TAG_CERT_VALIDATION_FAILURE ->
              "Failed to validate X.509v3 certificate: ";
          case SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED ->
              "Cryptographic functionality self test has completed: ";
          case SecurityLog.TAG_KEYGUARD_DISABLED_FEATURES_SET ->
              "Admin has set disabled keyguard features: ";
          case SecurityLog.TAG_KEYGUARD_DISMISSED -> "Keyguard has been dismissed: ";
          case SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT ->
              "Authentication attempt to dismiss the keyguard: ";
          case SecurityLog.TAG_KEYGUARD_SECURED ->
              "The device has been locked, either by the user or by a timeout: ";
          case SecurityLog.TAG_KEY_DESTRUCTION -> "Cryptographic key was destroyed: ";
          case SecurityLog.TAG_KEY_GENERATED -> "Cryptographic key was generated: ";
          case SecurityLog.TAG_KEY_IMPORT -> "Cryptographic key was imported: ";
          case SecurityLog.TAG_KEY_INTEGRITY_VIOLATION ->
              "Failed cryptographic key integrity check: ";
          case SecurityLog.TAG_LOGGING_STARTED -> "Start-up of audit logging: ";
          case SecurityLog.TAG_LOGGING_STOPPED -> "Stop of audit logging: ";
          case SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL ->
              "The audit log buffer has reached 90% of its capacity: ";
          case SecurityLog.TAG_MAX_PASSWORD_ATTEMPTS_SET ->
              "Admin has set a maximum number of failed password attempts before wiping data: ";
          case SecurityLog.TAG_MAX_SCREEN_LOCK_TIMEOUT_SET ->
              "Admin has set a maximum screen lock timeout: ";
          case SecurityLog.TAG_MEDIA_MOUNT -> "Removable media has been mounted on the device: ";
          case SecurityLog.TAG_MEDIA_UNMOUNT ->
              "Removable media has been unmounted from the device: ";
          case SecurityLog.TAG_OS_SHUTDOWN -> "OS shutdown: ";
          case SecurityLog.TAG_OS_STARTUP -> "OS startup: ";
          case SecurityLog.TAG_PACKAGE_INSTALLED -> "Package has been installed: ";
          case SecurityLog.TAG_PACKAGE_UNINSTALLED -> "Package has been uninstalled: ";
          case SecurityLog.TAG_PACKAGE_UPDATED -> "Package has been updated: ";
          case SecurityLog.TAG_PASSWORD_CHANGED ->
              "A user has just changed their lockscreen password: ";
          case SecurityLog.TAG_PASSWORD_COMPLEXITY_REQUIRED ->
              "Admin has set a password complexity requirement, using the platform's pre-defined"
                  + " complexity levels: ";
          case SecurityLog.TAG_PASSWORD_COMPLEXITY_SET ->
              "Admin has set a requirement for password complexity: ";
          case SecurityLog.TAG_PASSWORD_EXPIRATION_SET ->
              "Admin has set a password expiration timeout: ";
          case SecurityLog.TAG_PASSWORD_HISTORY_LENGTH_SET ->
              "Admin has set a password history length: ";
          case SecurityLog.TAG_REMOTE_LOCK -> "Admin remotely locked the device or profile: ";
          case SecurityLog.TAG_SYNC_RECV_FILE ->
              "File was pulled from the device via the adb daemon, for example via adb pull: ";
          case SecurityLog.TAG_SYNC_SEND_FILE ->
              "File was pushed to the device via the adb daemon, for example via adb push: ";
          case SecurityLog.TAG_USER_RESTRICTION_ADDED -> "Admin has set a user restriction: ";
          case SecurityLog.TAG_USER_RESTRICTION_REMOVED -> "Admin has removed a user restriction: ";
          case SecurityLog.TAG_WIFI_CONNECTION ->
              "An event occurred as the device attempted to connect to a managed WiFi network: ";
          case SecurityLog.TAG_WIFI_DISCONNECTION ->
              "The device disconnects from a managed WiFi network: ";
          case SecurityLog.TAG_WIPE_FAILURE -> "Failure to wipe device or user data: ";
          default -> "Unknown security event type";
        };
    return type;
  }

  private byte[] logsToBytes(List<String> logs) throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    new ObjectOutputStream(bos).writeObject(logs);
    return bos.toByteArray();
  }

  private void encryptLogs(Context context, byte[] logsBytes) {
    CrumblesLogsEncryptor logsEncryptor = new CrumblesLogsEncryptor();
    try {
      LogBatch logBatch = logsEncryptor.encryptLogs(logsBytes);
      if (logBatch == null) {
        Log.e(TAG, "Failed to encrypt logs: logBatch is null.");
        return;
      }
      File baseDir =
          new File(
              context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
      if (!baseDir.exists()) {
        baseDir.mkdirs();
      }
      Path encryptedLogFilePath =
          logsEncryptor.serializeBytes(
              logBatch,
              baseDir,
              CrumblesConstants.ENCRYPTED_LOG_FILE_NAME
                  + InstantSource.system().instant().toEpochMilli()
                  + ".bin");
      Log.i(TAG, "Logs encrypted and serialized to file: " + encryptedLogFilePath);
    } catch (CrumblesLogsEncryptionException e) {
      throw new CrumblesLogsEncryptionException(
          "Failed to encrypt or convert network/security logs to bytes.", e);
    }
  }

  @Override
  public void onReceive(Context context, Intent intent) {
    super.onReceive(context, intent);
    Log.i(TAG, "onReceive: " + intent.getAction());
    initDpm(context);
  }
}
