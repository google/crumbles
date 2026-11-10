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

import static com.android.securelogging.CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST;
import static com.android.securelogging.CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED;
import static com.android.securelogging.CrumblesDeviceAdminReceiver.DEFERRED_TOKENS_FILE;
import static com.android.securelogging.CrumblesDeviceAdminReceiver.MIN_NETWORK_USABLE_SPACE_BYTES;
import static com.android.securelogging.CrumblesDeviceAdminReceiver.MIN_SECURITY_USABLE_SPACE_BYTES;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Comparator.comparingLong;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.Application;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.admin.ConnectEvent;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.app.admin.DnsEvent;
import android.app.admin.NetworkEvent;
import android.app.admin.SecurityLog;
import android.app.admin.SecurityLog.SecurityEvent;
import android.content.BroadcastReceiver;
import android.content.BroadcastReceiver.PendingResult;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.service.notification.StatusBarNotification;
import android.util.Log;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.SealedLogs;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.robolectric.Robolectric;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowEventLog;
import org.robolectric.util.ReflectionHelpers;

/**
 * Unit tests for {@link CrumblesDeviceAdminReceiver}.
 *
 * <p>Security events are built through reflection with Robolectric's {@link ShadowEventLog}, since
 * the platform offers no public way to create one with data.
 */
@RunWith(AndroidJUnit4.class)
public final class CrumblesDeviceAdminReceiverTest {

  private static final long NETWORK_BATCH_TOKEN = 123L;
  private static final Duration BROADCAST_FINISH_TIMEOUT = Duration.ofSeconds(10);
  // The hidden DeviceAdminReceiver extras that carry the network logs batch token and size.
  private static final String EXTRA_NETWORK_LOGS_TOKEN =
      "android.app.extra.EXTRA_NETWORK_LOGS_TOKEN";
  private static final String EXTRA_NETWORK_LOGS_COUNT =
      "android.app.extra.EXTRA_NETWORK_LOGS_COUNT";
  private static final Pattern SINCE_RECORD_PATTERN =
      Pattern.compile("--- Crumbles activity log since record (\\S+) ---");
  private static final Pattern CHAIN_HEAD_PATTERN =
      Pattern.compile("--- Crumbles activity log chain head: (\\S+) ---");

  private static FakeAndroidKeyStoreProvider fakeProviderInstance;

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpClass() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    fakeProviderInstance = new FakeAndroidKeyStoreProvider();
    Security.insertProviderAt(fakeProviderInstance, 1);
  }

  @AfterClass
  public static void tearDownClass() {
    CrumblesAppAuditLogger.getInstance(ApplicationProvider.getApplicationContext()).clearAllLogs();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

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

  @After
  public void tearDown() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 1);
    CrumblesDeviceAdminReceiver.prefs(context).edit().clear().commit();
    new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE).delete();
    new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE + ".unreadable").delete();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesMain.getLogsEncryptorInstance().deleteExistingKeyPair();
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesBatchSigningKey.ALIAS);
    CrumblesExternalPublicKeyManager.getInstance(context).clearActiveExternalPublicKey();
    Shadows.shadowOf(Looper.getMainLooper()).idle();
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

      List<String> serializableNetworkLogs =
          CrumblesDeviceAdminReceiver.getSerializableNetworkLogs(networkLogs);
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

      List<String> serializableNetworkLogs =
          CrumblesDeviceAdminReceiver.getSerializableNetworkLogs(networkLogs);
      assertThat(serializableNetworkLogs).containsExactly(expectedString);
    } catch (ReflectiveOperationException e) {
      fail("Test failed due to reflection error: " + e.getMessage());
    }
  }

  /** Tests that getSerializableNetworkLogs returns an empty list for null or empty input. */
  @Test
  public void getSerializableNetworkLogs_withNullOrEmptyList_returnsEmptyList() {
    assertThat(CrumblesDeviceAdminReceiver.getSerializableNetworkLogs(null)).isEmpty();
    assertThat(CrumblesDeviceAdminReceiver.getSerializableNetworkLogs(new ArrayList<>())).isEmpty();
  }

  /** Tests getSerializableSecurityLogs with null and empty lists. */
  @Test
  public void getSerializableSecurityLogs_withNullOrEmptyList_returnsEmptyList() {
    assertThat(CrumblesDeviceAdminReceiver.getSerializableSecurityLogs(null)).isEmpty();
    assertThat(CrumblesDeviceAdminReceiver.getSerializableSecurityLogs(new ArrayList<>()))
        .isEmpty();
  }

  @Test
  public void getSerializableSecurityLogs_writesEveryValueOfThePayload() throws Exception {
    SecurityEvent processStart =
        securityEvent(
            SecurityLog.TAG_APP_PROCESS_START,
            new Object[] {"com.example.implant", 1672531200000L, 10123, 4567, "default", "ab12"});

    assertThat(
            CrumblesDeviceAdminReceiver.getSerializableSecurityLogs(ImmutableList.of(processStart)))
        .containsExactly(
            """
            Security log ID: 7
            Timestamp (UTC): 2023-01-01T00:00:00.000Z
            Severity: LOW
            App process started:\s
            ["com.example.implant", 1672531200000, 10123, 4567, "default", "ab12"]

            """);
  }

  @Test
  public void getSerializableSecurityLogs_keepsAValueThatCouldForgeRecordsOnItsLine()
      throws Exception {
    // Any app can give a Keystore key such an alias.
    SecurityEvent keyGenerated =
        securityEvent(
            SecurityLog.TAG_KEY_GENERATED,
            new Object[] {1, "alias\n\nSecurity log ID: 8\nOS startup: \u202e", 10123});

    assertThat(
            CrumblesDeviceAdminReceiver.getSerializableSecurityLogs(ImmutableList.of(keyGenerated)))
        .containsExactly(
            """
            Security log ID: 7
            Timestamp (UTC): 2023-01-01T00:00:00.000Z
            Severity: LOW
            Cryptographic key was generated:\s
            [1, "alias\\u000a\\u000aSecurity log ID: 8\\u000aOS startup: \\u202e", 10123]

            """);
  }

  @Test
  public void getSerializableNetworkLogs_escapesThePackageAndDomainNames() throws Exception {
    DnsEvent dnsEvent =
        DnsEvent.class
            .getConstructor(String.class, String[].class, int.class, String.class, long.class)
            .newInstance(
                "evil.example\nNetwork log ID: 9",
                new String[0],
                0,
                "com.example\u2028app",
                1672531200000L);

    assertThat(CrumblesDeviceAdminReceiver.getSerializableNetworkLogs(ImmutableList.of(dnsEvent)))
        .containsExactly(
            """
            Network log ID: 0
            Timestamp (UTC): 2023-01-01T00:00:00.000Z
            Package name: com.example\\u2028app
            DNS event ID: 0
            Domain name: evil.example\\u000aNetwork log ID: 9
            Inet addresses: []
            Total resolved addresses: 0

            """);
  }

  @Test
  public void escape_writesEveryCharacterThatCouldBreakOrHideTextAsUnicodeEscapes() {
    expect.that(CrumblesDeviceAdminReceiver.escape("a\r\nb")).isEqualTo("a\\u000d\\u000ab");
    expect
        .that(CrumblesDeviceAdminReceiver.escape("a\u2028b\u2029c"))
        .isEqualTo("a\\u2028b\\u2029c");
    expect.that(CrumblesDeviceAdminReceiver.escape("\u202ecba")).isEqualTo("\\u202ecba");
    // U+E0041, a tag character that is not drawn.
    expect.that(CrumblesDeviceAdminReceiver.escape("a\udb40\udc41b")).isEqualTo("a\\udb40\\udc41b");
    expect.that(CrumblesDeviceAdminReceiver.escape("C:\\ \"x\"")).isEqualTo("C:\\\\ \\\"x\\\"");
    expect
        .that(CrumblesDeviceAdminReceiver.escape("caf\u00e9 \ud83d\ude00"))
        .isEqualTo("caf\u00e9 \ud83d\ude00");
    expect.that(CrumblesDeviceAdminReceiver.escape(null)).isEqualTo("null");
  }

  /** Returns security event 7, logged at 2023-01-01T00:00:00Z with {@code tag} and {@code data}. */
  private static SecurityEvent securityEvent(int tag, Object data) throws Exception {
    return securityEventWithId(7L, tag, data);
  }

  private static SecurityEvent securityEventWithId(long id, int tag, Object data) throws Exception {
    Constructor<SecurityEvent> constructor =
        SecurityEvent.class.getDeclaredConstructor(long.class, byte[].class);
    constructor.setAccessible(true);
    SecurityEvent securityEvent = constructor.newInstance(id, new byte[0]);
    Field event = SecurityEvent.class.getDeclaredField("mEvent");
    event.setAccessible(true);
    event.set(
        securityEvent,
        new ShadowEventLog.EventBuilder(tag, data)
            .setTimeNanos(TimeUnit.MILLISECONDS.toNanos(1672531200000L))
            .build());
    return securityEvent;
  }

  /**
   * Tests that logs are encrypted using the persisted external key after a cold start where the
   * singleton is uninitialized.
   */
  @Test
  public void onSecurityLogsAvailable_usesPersistedExternalKey_notKeystore_afterColdStart()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair ngo = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(ngo.getPublic());

    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);

    CrumblesDeviceAdminReceiver receiver = new CrumblesDeviceAdminReceiver();
    deliverSecurityLogs(receiver, contextWrapper);

    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File[] out = logsDir.listFiles((d, n) -> n.endsWith(".bin"));
    assertThat(out).hasLength(1);
    LogBatch batch =
        LogBatch.parseFrom(
            Files.readAllBytes(out[0].toPath()), ExtensionRegistryLite.getEmptyRegistry());
    Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    OAEPParameterSpec oaepSpec =
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    rsa.init(Cipher.UNWRAP_MODE, ngo.getPrivate(), oaepSpec);
    rsa.unwrap(batch.getKey().getEncryptedSymmetricKey().toByteArray(), "AES", Cipher.SECRET_KEY);
  }

  /** Tests that consecutive batches never share a file name and leave no temporary file behind. */
  @Test
  public void onSecurityLogsAvailable_calledTwice_writesTwoDistinctBatchFiles() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(recipientKey);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    CrumblesDeviceAdminReceiver receiver = new CrumblesDeviceAdminReceiver();

    deliverSecurityLogs(receiver, contextWrapper);
    deliverSecurityLogs(receiver, contextWrapper);

    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsDir.listFiles((d, n) -> n.endsWith(".bin"))).hasLength(2);
    assertThat(logsDir.listFiles((d, n) -> n.endsWith(CrumblesConstants.TEMP_FILE_SUFFIX)))
        .isEmpty();
  }

  /** Tests that a batch file name tells the storage provider neither the app nor the time. */
  @Test
  public void onSecurityLogsAvailable_namesTheBatchFileWithRandomHexOnly() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    PublicKey recipientKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(recipientKey);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());

    deliverSecurityLogs(new CrumblesDeviceAdminReceiver(), createContextWrapper(context, mockDpm));

    String[] batchNames =
        new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY)
            .list((dir, name) -> name.endsWith(".bin"));
    assertThat(batchNames).hasLength(1);
    assertThat(batchNames[0]).matches("[0-9a-f]{32}\\.bin");
  }

  /** Tests that a stored batch ends with the activity records written since the previous one. */
  @Test
  public void onSecurityLogsAvailable_sealsActivityRecordsSincePreviousBatch() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(context);
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(recipientKeyPair.getPublic());
    auditLogger.logEvent("SEALED_EVENT", "Logged before the batch.");
    String unshippedTrailer = new String(auditLogger.getUnshippedExcerpt().toBytes(), UTF_8);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));

    String batch = decryptOnlyBatch(context, recipientKeyPair.getPrivate());
    assertThat(batch).isEqualTo(unshippedTrailer);
    assertThat(batch).contains("\"message\":\"Logged before the batch.\"");
    assertThat(new String(auditLogger.getUnshippedExcerpt().toBytes(), UTF_8))
        .doesNotContain("SEALED_EVENT");
  }

  /** Tests that activity records stay unshipped when their batch cannot be written. */
  @Test
  public void onSecurityLogsAvailable_whenBatchWriteFails_keepsActivityRecordsForNextBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    // A file in place of the logs directory makes writing the batch fail.
    new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY)
        .createNewFile();
    saveNewExternalPublicKey(context);
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent("UNSHIPPED_EVENT", "Logged before a batch that is not written.");
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));

    byte[] nextTrailer =
        CrumblesAppAuditLogger.getInstance(context).getUnshippedExcerpt().toBytes();
    assertThat(new String(nextTrailer, UTF_8)).contains("UNSHIPPED_EVENT");
  }

  /** Decrypts the only stored batch as the recipient holding {@code privateKey} does. */
  private static String decryptOnlyBatch(Context context, PrivateKey privateKey) throws Exception {
    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File[] batches = logsDir.listFiles((dir, name) -> name.endsWith(".bin"));
    assertThat(batches).hasLength(1);
    LogBatch batch =
        LogBatch.parseFrom(
            Files.readAllBytes(batches[0].toPath()), ExtensionRegistryLite.getEmptyRegistry());
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsaCipher.init(
        Cipher.UNWRAP_MODE,
        privateKey,
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    Key aesKey =
        rsaCipher.unwrap(
            batch.getKey().getEncryptedSymmetricKey().toByteArray(), "AES", Cipher.SECRET_KEY);
    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    aesCipher.init(
        Cipher.DECRYPT_MODE,
        aesKey,
        new GCMParameterSpec(/* tLen= */ 128, batch.getKey().getIv().toByteArray()));
    aesCipher.updateAAD(
        CrumblesLogsEncryptor.computeAssociatedData(
            batch.getMetadata(), batch.getKey().getKeyEncryptionType(), publicKeyOf(privateKey)));
    return logsInPaddedPlaintext(aesCipher.doFinal(batch.getData().getLogBlob().toByteArray()));
  }

  /** Tests that consecutive batches are numbered consecutively and signed by this installation. */
  @Test
  public void retrieveAndSaveSecurityLogs_writesNumberedBatchesSignedByThisInstallation()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    Context deviceOwnerContext = deviceOwnerWithoutSecurityLogs(context);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(2);
    assertThat(batches.get(1).getSequenceNumber())
        .isEqualTo(batches.get(0).getSequenceNumber() + 1);
    assertThat(isSignedByThisInstallation(batches.get(0))).isTrue();
    assertThat(isSignedByThisInstallation(batches.get(1))).isTrue();
  }

  /** Tests that a batch that cannot be signed is still written, and that the failure is audited. */
  @Test
  public void retrieveAndSaveSecurityLogs_whenSigningFails_writesUnsignedBatch() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    KeyGenerator secretKeyGenerator =
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256, FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    secretKeyGenerator.init(
        new KeyGenParameterSpec.Builder(CrumblesBatchSigningKey.ALIAS, KeyProperties.PURPOSE_SIGN)
            .build());
    secretKeyGenerator.generateKey();

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(
        deviceOwnerWithoutSecurityLogs(context));

    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(1);
    assertThat(batches.get(0).hasSignature()).isFalse();
    assertThat(batches.get(0).hasSequenceNumber()).isFalse();
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType))
        .contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED);
  }

  /** Tests that a batch refused by the storage cap uses no sequence number until it is drained. */
  @Test
  public void retrieveAndSaveSecurityLogs_whenStorageCapReached_usesNoSequenceNumber()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    Context deviceOwnerContext = deviceOwnerWithoutSecurityLogs(context);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    File filler =
        new File(
            new File(
                context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY),
            "filler.tmp");
    // A sparse file reaches the cap without writing its bytes to disk.
    try (RandomAccessFile file = new RandomAccessFile(filler, "rw")) {
      file.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES);
    }
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    assertThat(filler.delete()).isTrue();

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(3);
    assertThat(batches.get(1).getSequenceNumber())
        .isEqualTo(batches.get(0).getSequenceNumber() + 1);
    assertThat(batches.get(2).getSequenceNumber())
        .isEqualTo(batches.get(0).getSequenceNumber() + 2);
  }

  /** Returns a context whose DevicePolicyManager is a device owner's, with no security logs. */
  private static Context deviceOwnerWithoutSecurityLogs(Context context) {
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    return createContextWrapper(context, mockDpm);
  }

  /** Returns the batches in the logs directory, in sequence number order. */
  private static ImmutableList<LogBatch> writtenBatches(Context context) throws IOException {
    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    ImmutableList.Builder<LogBatch> batches = ImmutableList.builder();
    for (File file : logsDir.listFiles((dir, name) -> name.endsWith(".bin"))) {
      batches.add(
          LogBatch.parseFrom(
              Files.readAllBytes(file.toPath()), ExtensionRegistryLite.getEmptyRegistry()));
    }
    return ImmutableList.sortedCopyOf(comparingLong(LogBatch::getSequenceNumber), batches.build());
  }

  /** Verifies {@code batch} with this installation's signing key, as its recipient does. */
  private static boolean isSignedByThisInstallation(LogBatch batch) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    keyStore.load(/* param= */ null);
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(keyStore.getCertificate(CrumblesBatchSigningKey.ALIAS).getPublicKey());
    verifier.update(batch.toBuilder().clearSignature().build().toByteArray());
    return verifier.verify(batch.getSignature().getSignature().toByteArray());
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
  public void
      onProfileProvisioningComplete_whenDeviceOwnerAndFlagTrue_enablesSecurityAndNetworkLogging() {
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
    verify(mockDpm).addUserRestriction(any(ComponentName.class), eq(UserManager.DISALLOW_ADD_USER));

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

  private static StatusBarNotification findDeferredLogsNotification(Context context) {
    NotificationManager nm =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    return Arrays.stream(nm.getActiveNotifications())
        .filter(n -> n.getId() == CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID)
        .findFirst()
        .orElse(null);
  }

  private static void assertDeferredLogsNotificationPosted(Context context) {
    NotificationManager nm =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    NotificationChannel channel =
        nm.getNotificationChannel(CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID);
    assertThat(channel).isNotNull();
    assertThat(channel.getDescription())
        .isEqualTo(context.getString(R.string.notification_channel_description_action_needed));
    assertThat(channel.getLockscreenVisibility()).isEqualTo(Notification.VISIBILITY_SECRET);
    StatusBarNotification postedNotification = findDeferredLogsNotification(context);
    assertThat(postedNotification).isNotNull();
    Notification notification = postedNotification.getNotification();
    assertThat(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    assertThat(notification.flags & Notification.FLAG_ONGOING_EVENT)
        .isEqualTo(Notification.FLAG_ONGOING_EVENT);
    Intent contentIntent = Shadows.shadowOf(notification.contentIntent).getSavedIntent();
    assertThat(contentIntent.getComponent().getClassName()).isEqualTo(CrumblesMain.class.getName());
    assertThat(
            contentIntent.getFlags()
                & (Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP))
        .isEqualTo(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
  }

  private static void assertDeferredLogsNotificationNotPosted(Context context) {
    NotificationManager nm =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    assertThat(
            Arrays.stream(nm.getActiveNotifications())
                .anyMatch(
                    n -> n.getId() == CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID))
        .isFalse();
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

  private static void saveNewExternalPublicKey(Context context) throws Exception {
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());
  }

  /** Delivers the security logs broadcast to {@code receiver} and waits until it is handled. */
  private static void deliverSecurityLogs(BroadcastReceiver receiver, Context context) {
    deliver(receiver, context, new Intent(DeviceAdminReceiver.ACTION_SECURITY_LOGS_AVAILABLE));
  }

  /**
   * Delivers the broadcast for network logs batch {@link #NETWORK_BATCH_TOKEN} to {@code receiver}
   * and waits until it is handled.
   */
  private static void deliverNetworkLogs(BroadcastReceiver receiver, Context context) {
    deliverNetworkLogs(receiver, context, NETWORK_BATCH_TOKEN);
  }

  private static void deliverNetworkLogs(BroadcastReceiver receiver, Context context, long token) {
    deliver(
        receiver,
        context,
        new Intent(DeviceAdminReceiver.ACTION_NETWORK_LOGS_AVAILABLE)
            .putExtra(EXTRA_NETWORK_LOGS_TOKEN, token)
            .putExtra(EXTRA_NETWORK_LOGS_COUNT, 5));
  }

  /**
   * Delivers {@code intent} to {@code receiver} with a pending result, as the platform does, and
   * waits until the receiver finishes the broadcast.
   */
  private static void deliver(BroadcastReceiver receiver, Context context, Intent intent) {
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

  /**
   * Returns the DevicePolicyManager of a device owner whose network logs batch {@link
   * #NETWORK_BATCH_TOKEN} holds {@code count} connect events.
   */
  private static DevicePolicyManager dpmWithConnectEvents(Context context, int count)
      throws ReflectiveOperationException {
    Constructor<ConnectEvent> constructor =
        ConnectEvent.class.getConstructor(String.class, int.class, String.class, long.class);
    List<NetworkEvent> events = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      // The arguments are the IP address, port, package name and timestamp in milliseconds.
      events.add(constructor.newInstance("192.168.1.100", 443, "com.android.test", 1672531200000L));
    }
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN)))
        .thenReturn(events);
    return mockDpm;
  }

  @Test
  public void onSecurityLogsAvailable_withoutEncryptionKey_stagesTheLogs() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);

    deliverSecurityLogs(receiver, contextWrapper);

    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    expect.that(savedBatches(context)).isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEqualTo("Security log batch of 0 event(s) was staged: no encryption key is available.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void onSecurityLogsAvailable_afterKeyIsSet_savesStagedLogsAndCancelsAlert()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
    deliverSecurityLogs(receiver, contextWrapper);
    assertDeferredLogsNotificationPosted(context);

    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());
    deliverSecurityLogs(receiver, contextWrapper);

    expect.that(savedBatches(context)).hasLength(2);
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(findDeferredLogsNotification(context)).isNull();
  }

  @Test
  public void onSecurityLogsAvailable_whenEncryptionReadyWithExternalKey_retrievesLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    deliverSecurityLogs(receiver, contextWrapper);

    verify(mockDpm).retrieveSecurityLogs(any(ComponentName.class));
  }

  @Test
  public void onSecurityLogsAvailable_retrievesOffTheMainThreadWhileHoldingTheBroadcast()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    PendingResult pendingResult = attachPendingResult(receiver);
    Future<PendingResult> finished = Shadows.shadowOf(pendingResult).getFuture();
    AtomicReference<Thread> retrievalThread = new AtomicReference<>();
    AtomicBoolean finishedDuringRetrieval = new AtomicBoolean(true);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class)))
        .thenAnswer(
            invocation -> {
              retrievalThread.set(Thread.currentThread());
              finishedDuringRetrieval.set(finished.isDone());
              return new ArrayList<>();
            });

    receiver.onReceive(
        createContextWrapper(context, mockDpm),
        new Intent(DeviceAdminReceiver.ACTION_SECURITY_LOGS_AVAILABLE));
    awaitFinish(pendingResult);

    assertThat(retrievalThread.get()).isNotNull();
    expect.that(retrievalThread.get()).isNotSameInstanceAs(Looper.getMainLooper().getThread());
    expect.that(finishedDuringRetrieval.get()).isFalse();
  }

  @Test
  public void onSecurityLogsAvailable_whenDirectoryAlreadyExists_retrievesLogs() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    baseDir.mkdirs();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    deliverSecurityLogs(receiver, contextWrapper);

    verify(mockDpm).retrieveSecurityLogs(any(ComponentName.class));
  }

  @Test
  public void onSecurityLogsAvailable_whenStorageCapReached_doesNotWriteTheBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    baseDir.mkdirs();
    // A sparse file leaves less than the encrypted batch plus signature allowance.
    try (RandomAccessFile pending = new RandomAccessFile(new File(baseDir, "pending.bin"), "rw")) {
      pending.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES - 5000);
    }
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    // Without device owner access the receiver returns before it reaches the storage cap check.
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));

    assertThat(baseDir.list()).asList().containsExactly("pending.bin");
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .contains("LOGS_COLLECTION_STOPPED");
  }

  @Test
  public void onSecurityLogsAvailable_whenStorageDirectoryBlocked_defersLogRetrieval()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    File blockedFile = new File(context.getCacheDir(), "blocked_sec_logs_dir");
    blockedFile.createNewFile();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    Context contextWrapper =
        new ContextWrapper(createContextWrapper(context, mockDpm)) {
          @Override
          public File getFilesDir() {
            return blockedFile;
          }
        };
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    deliverSecurityLogs(receiver, contextWrapper);

    verify(mockDpm, never()).retrieveSecurityLogs(any(ComponentName.class));
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .anyMatch(e -> e.getEventType().equals("LOG_RETRIEVAL_DEFERRED")))
        .isTrue();
  }

  @Test
  public void onSecurityLogsAvailable_asDeviceOwner_retrievesWithDeviceAdminComponent()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    saveNewExternalPublicKey(context);

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));

    verify(mockDpm)
        .retrieveSecurityLogs(new ComponentName(context, CrumblesDeviceAdminReceiver.class));
  }

  @Test
  public void onSecurityLogsAvailable_whenOnlyNetworkLoggingDelegated_doesNotRetrieveLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.getDelegatedScopes(null, context.getPackageName()))
        .thenReturn(ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING));
    saveNewExternalPublicKey(context);

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));

    verify(mockDpm, never()).retrieveSecurityLogs(any());
  }

  @Test
  public void delegatedOnSecurityLogsAvailable_asSecurityLoggingDelegate_retrievesWithNullAdmin()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.getDelegatedScopes(null, context.getPackageName()))
        .thenReturn(ImmutableList.of(DevicePolicyManager.DELEGATION_SECURITY_LOGGING));
    saveNewExternalPublicKey(context);

    deliverSecurityLogs(
        new CrumblesDelegatedAdminReceiver(), createContextWrapper(context, mockDpm));

    verify(mockDpm).retrieveSecurityLogs(isNull());
  }

  @Test
  public void delegatedOnNetworkLogsAvailable_asNetworkLoggingDelegate_retrievesWithNullAdmin()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.getDelegatedScopes(null, context.getPackageName()))
        .thenReturn(ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING));
    saveNewExternalPublicKey(context);

    deliverNetworkLogs(
        new CrumblesDelegatedAdminReceiver(), createContextWrapper(context, mockDpm));

    verify(mockDpm).retrieveNetworkLogs(isNull(), eq(123L));
  }

  @Test
  public void onNetworkLogsAvailable_whenNeitherDeviceOwnerNorDelegate_doesNotRetrieveLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    saveNewExternalPublicKey(context);

    deliverNetworkLogs(receiver, createContextWrapper(context, mockDpm));

    verify(mockDpm, never()).retrieveNetworkLogs(any(), anyLong());
  }

  @Test
  public void onNetworkLogsAvailable_withoutEncryptionKey_stagesTheLogs() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Context contextWrapper = createContextWrapper(context, dpmWithConnectEvents(context, 4));

    deliverNetworkLogs(receiver, contextWrapper);

    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    expect.that(savedBatches(context)).isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEqualTo("Network log batch of 4 event(s) was staged: no encryption key is available.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void onNetworkLogsAvailable_whenEncryptionReadyWithExternalKey_retrievesLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(123L)))
        .thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    deliverNetworkLogs(receiver, contextWrapper);

    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(123L));
  }

  @Test
  public void onNetworkLogsAvailable_whenStorageDirectoryBlocked_defersLogRetrieval()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    File blockedFile = new File(context.getCacheDir(), "blocked_net_logs_dir");
    blockedFile.createNewFile();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    Context contextWrapper =
        new ContextWrapper(createContextWrapper(context, mockDpm)) {
          @Override
          public File getFilesDir() {
            return blockedFile;
          }
        };
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    deliverNetworkLogs(receiver, contextWrapper);
    deliverSecurityLogs(receiver, contextWrapper);

    verify(mockDpm, never()).retrieveNetworkLogs(any(ComponentName.class), eq(123L));
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .anyMatch(e -> e.getEventType().equals("LOG_RETRIEVAL_DEFERRED")))
        .isTrue();

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));
    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(123L));
  }

  private static Context withUsableSpace(
      Context context, DevicePolicyManager mockDpm, LongSupplier usableBytes) {
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    return new ContextWrapper(createContextWrapper(context, mockDpm)) {
      @Override
      public File getFilesDir() {
        return new File(super.getFilesDir().getPath()) {
          @Override
          public long getUsableSpace() {
            return usableBytes.getAsLong();
          }
        };
      }
    };
  }

  @Test
  public void usableSpace_enforcesThresholdsDrainsFifoAndEvictsPastCapacity() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    long lowSecSpace = MIN_SECURITY_USABLE_SPACE_BYTES - 1;
    long lowNetSpace = MIN_NETWORK_USABLE_SPACE_BYTES - 1;
    AtomicLong usableSpace = new AtomicLong(lowSecSpace);
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), anyLong()))
        .thenAnswer(
            inv -> {
              if ((long) inv.getArgument(1) == 10L || (long) inv.getArgument(1) == 12L) {
                usableSpace.set(lowNetSpace);
              }
              return new ArrayList<>();
            });
    deliverSecurityLogs(receiver, ownerContext);
    verify(mockDpm, never()).retrieveSecurityLogs(any());
    expect
        .that(newestAuditMessage(context, "LOG_RETRIEVAL_DEFERRED"))
        .isEqualTo(
            "Security log retrieval deferred: insufficient usable storage ("
                + lowSecSpace
                + " bytes available).");
    assertDeferredLogsNotificationPosted(context);
    usableSpace.set(MIN_SECURITY_USABLE_SPACE_BYTES);
    deliverSecurityLogs(receiver, ownerContext);
    expect.that(savedBatches(context)).hasLength(1);
    assertDeferredLogsNotificationNotPosted(context);
    usableSpace.set(lowNetSpace);
    deliverNetworkLogs(receiver, ownerContext, 10L);
    deliverNetworkLogs(receiver, ownerContext, 10L);
    deliverNetworkLogs(receiver, ownerContext, 11L);
    File tokenFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    ByteBuffer persisted = ByteBuffer.wrap(Files.readAllBytes(tokenFile.toPath()));
    expect.that(persisted.remaining()).isEqualTo(268);
    expect
        .that(persisted.getLong())
        .isEqualTo(CrumblesDeviceAdminReceiver.currentNetworkLoggingSessionKey(context));
    expect.that(persisted.getInt()).isEqualTo(2);
    expect.that(persisted.getLong()).isEqualTo(10L);
    expect.that(persisted.getLong()).isEqualTo(11L);
    expect.that(newestAuditMessage(context, "LOG_RETRIEVAL_DEFERRED")).contains("" + lowNetSpace);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    expect.that(savedBatches(context)).hasLength(2);
    assertDeferredLogsNotificationPosted(context);
    deliverNetworkLogs(receiver, ownerContext, 12L);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    deliverNetworkLogs(receiver, ownerContext, 13L);
    verify(mockDpm, never()).retrieveNetworkLogs(any(), eq(13L));
    assertDeferredLogsNotificationPosted(context);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    deliverNetworkLogs(receiver, ownerContext, 13L);
    InOrder order = inOrder(mockDpm);
    order.verify(mockDpm).retrieveSecurityLogs(any(ComponentName.class));
    order.verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(10L));
    order.verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(11L));
    order.verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(12L));
    order.verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(13L));
    order.verifyNoMoreInteractions();
    expect.that(savedBatches(context)).hasLength(5);
    assertDeferredLogsNotificationNotPosted(context);
    CrumblesDeviceAdminReceiver.bumpLoggingEnableEpoch(context);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    DevicePolicyManager evictDpm = mock(DevicePolicyManager.class);
    when(evictDpm.retrieveNetworkLogs(any(ComponentName.class), anyLong()))
        .thenAnswer(i -> (long) i.getArgument(1) % 32 == 2L ? null : ImmutableList.of());
    Context evictCtx = withUsableSpace(context, evictDpm, usableSpace::get);
    usableSpace.set(lowNetSpace);
    for (long token = 1L; token <= 33L; token++) {
      deliverNetworkLogs(receiver, evictCtx, token);
    }
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    deliverNetworkLogs(receiver, evictCtx, 34L);
    verify(evictDpm, never()).retrieveNetworkLogs(any(), eq(1L));
    verify(evictDpm).retrieveNetworkLogs(any(ComponentName.class), eq(2L));
    verify(evictDpm).retrieveNetworkLogs(any(ComponentName.class), eq(34L));
    expect.that(savedBatches(context)).hasLength(36);
    expect
        .that(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .filter(e -> e.getEventType().equals(AUDIT_EVENT_LOGS_LOST))
                .map(CrumblesAuditEvent::getMessage)
                .toList())
        .containsExactly(
            "Deferred network log batch (token 2) was lost: discarded by platform before"
                + " retrieval.",
            "Deferred network log batch (token 1) was lost: deferred queue full.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void drainDeferredNetworkLogs_viaSecurityLogsAt50MiBFallbackDiskSessionAndPause()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    ConnectEvent connectEvent =
        ConnectEvent.class
            .getConstructor(String.class, int.class, String.class, long.class)
            .newInstance("192.0.2.9", 443, "com.android.test", 1672531200000L);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    AtomicLong usableSpace = new AtomicLong(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), anyLong()))
        .thenAnswer(
            inv -> {
              if ((long) inv.getArgument(1) == 50L) {
                usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
              }
              return ImmutableList.of(connectEvent, connectEvent);
            });
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    File tokenFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    blockDeferredTokenWrites(context);
    deliverNetworkLogs(receiver, ownerContext, 50L);
    deliverNetworkLogs(receiver, ownerContext, 51L);
    assertThat(tokenFile.delete()).isTrue();
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    usableSpace.set(50L * 1024 * 1024);
    deliverSecurityLogs(receiver, ownerContext);
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ true);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    verify(mockDpm, never()).retrieveNetworkLogs(any(), eq(50L));
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    deliverSecurityLogs(receiver, ownerContext);
    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(50L));
    verify(mockDpm, never()).retrieveNetworkLogs(any(), eq(51L));
    verify(mockDpm, never()).retrieveSecurityLogs(any());
    expect.that(newestAuditMessage(context, AUDIT_EVENT_LOGS_STAGED)).contains("2 event(s)");
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());
    usableSpace.set(50L * 1024 * 1024);
    long session = CrumblesDeviceAdminReceiver.currentNetworkLoggingSessionKey(context);
    Files.write(tokenFile.toPath(), ByteBuffer.allocate(267).putLong(session).putInt(1).array());
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    Files.write(tokenFile.toPath(), ByteBuffer.allocate(268).putLong(session).putInt(99).array());
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    Files.write(
        tokenFile.toPath(),
        ByteBuffer.allocate(268).putLong(session ^ 1L).putInt(1).putLong(55L).array());
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    verify(mockDpm, never()).retrieveNetworkLogs(any(), eq(55L));
    expect
        .that(newestAuditMessage(context, AUDIT_EVENT_LOGS_LOST))
        .contains("token 55) was lost: logging session restarted");
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(60L)))
        .thenThrow(new SecurityException("Paused"))
        .thenReturn(ImmutableList.of(connectEvent));
    Files.write(
        tokenFile.toPath(),
        ByteBuffer.allocate(268).putLong(session).putInt(1).putLong(60L).array());
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    expect.that(findPausedNotification(context)).isNotNull();
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    verify(mockDpm, times(2)).retrieveNetworkLogs(any(ComponentName.class), eq(60L));
    ImmutableList<LogBatch> batches = writtenBatches(context);
    expect.that(batches).hasSize(3);
    expect.that(decryptWithPrivateKey(batches.get(0), externalKeyPair.getPrivate()))
        .contains("192.0.2.9");
    ByteBuffer after = ByteBuffer.wrap(Files.readAllBytes(tokenFile.toPath()));
    expect.that(after.getLong()).isEqualTo(session);
    expect.that(after.getInt()).isEqualTo(0);
  }

  @Test
  public void onNetworkLogsAvailable_drainingItsDeferredBatchLowersSpace_doesNotQueueItAgain()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    AtomicLong usableSpace = new AtomicLong(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN)))
        .thenAnswer(
            inv -> {
              usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
              return ImmutableList.of();
            });
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    deliverNetworkLogs(receiver, ownerContext);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);

    deliverNetworkLogs(receiver, ownerContext);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);

    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN));
    expect.that(auditMessages(context, AUDIT_EVENT_LOGS_LOST)).isEmpty();
    expect.that(savedBatches(context)).hasLength(1);
  }

  @Test
  public void onNetworkLogsAvailable_whenRetrievalIsRejected_queuesTheBatchForTheNextDrain()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN)))
        .thenThrow(new SecurityException("Paused"))
        .thenReturn(ImmutableList.of());
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN + 1)))
        .thenReturn(null);
    Context ownerContext = createContextWrapper(context, mockDpm);

    deliverNetworkLogs(receiver, ownerContext);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    deliverNetworkLogs(receiver, ownerContext, NETWORK_BATCH_TOKEN + 1);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);

    verify(mockDpm, times(2))
        .retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN));
    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN + 1));
    expect.that(findPausedNotification(context)).isNull();
  }

  @Test
  public void drainDeferredNetworkLogs_whenTheTokenFileIsUnreadable_keepsItAndReportsTheLossOnce()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Context ownerContext = createContextWrapper(context, mock(DevicePolicyManager.class));
    File tokenFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    File keptFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE + ".unreadable");
    assertThat(tokenFile.mkdir()).isTrue();
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    expect.that(keptFile.isDirectory()).isTrue();
    byte[] malformed = ByteBuffer.allocate(268).putInt(Long.BYTES, 99).array();
    Files.write(tokenFile.toPath(), malformed);

    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);

    expect.that(tokenFile.exists()).isFalse();
    expect.that(Files.readAllBytes(keptFile.toPath())).isEqualTo(malformed);
    expect.that(auditMessages(context, AUDIT_EVENT_LOGS_LOST)).hasSize(2);
    expect
        .that(newestAuditMessage(context, AUDIT_EVENT_LOGS_LOST))
        .contains("their token file could not be read");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void deferredTokens_whenAnUnreadableFileCannotBeMovedAside_leaveItAloneUntilItCan()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), anyLong()))
        .thenReturn(ImmutableList.of());
    AtomicLong usableSpace = new AtomicLong(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    File tokenFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    File keptFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE + ".unreadable");
    // A directory that is not empty where the file would go makes moving it aside fail.
    File blocker = new File(keptFile, "blocker");
    assertThat(blocker.mkdirs()).isTrue();
    byte[] malformed = new byte[3];
    Files.write(tokenFile.toPath(), malformed);

    deliverNetworkLogs(receiver, ownerContext, 7L);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);

    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(7L));
    expect.that(Files.readAllBytes(tokenFile.toPath())).isEqualTo(malformed);
    assertThat(blocker.delete() && keptFile.delete()).isTrue();
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    deliverNetworkLogs(receiver, ownerContext, 8L);
    expect.that(Files.readAllBytes(keptFile.toPath())).isEqualTo(malformed);
    ByteBuffer queue = ByteBuffer.wrap(Files.readAllBytes(tokenFile.toPath()));
    expect.that(queue.getInt(Long.BYTES)).isEqualTo(1);
    expect.that(queue.getLong(Long.BYTES + Integer.BYTES)).isEqualTo(8L);
    expect.that(auditMessages(context, AUDIT_EVENT_LOGS_LOST)).hasSize(1);
  }

  @Test
  public void drainDeferredNetworkLogs_afterSavingAnEmptyQueueFails_stillReadsTheFile()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), anyLong()))
        .thenReturn(ImmutableList.of());
    AtomicLong usableSpace = new AtomicLong(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    File tokenFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    blockDeferredTokenWrites(context);
    deliverNetworkLogs(receiver, ownerContext, 7L);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    expect.that(Files.isSymbolicLink(tokenFile.toPath())).isFalse();
    long session = CrumblesDeviceAdminReceiver.currentNetworkLoggingSessionKey(context);
    byte[] queue = ByteBuffer.allocate(268).putLong(session).putInt(1).putLong(8L).array();
    Files.write(tokenFile.toPath(), queue);

    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);

    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(7L));
    verify(mockDpm).retrieveNetworkLogs(any(ComponentName.class), eq(8L));
  }

  @Test
  public void drainDeferredNetworkLogs_whenSavingTheEmptyQueueFails_retrievesTheTokenOnce()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    AtomicLong usableSpace = new AtomicLong(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    List<Long> retrievals = new ArrayList<>();
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), anyLong()))
        .thenAnswer(
            inv -> {
              long token = inv.getArgument(1);
              if (retrievals.contains(token)) {
                // Only a stale token file retrieves a batch twice: end the drain there.
                usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
              }
              retrievals.add(token);
              return token == 7L ? ImmutableList.of() : null;
            });
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    File dir = context.getNoBackupFilesDir();
    File tokenFile = new File(dir, DEFERRED_TOKENS_FILE);
    // The token file can be read but not written, and then it cannot be deleted either.
    deliverNetworkLogs(receiver, ownerContext, 7L);
    assertThat(tokenFile.setReadOnly()).isTrue();
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    expect.that(savedBatches(context)).hasLength(1);
    expect.that(tokenFile.exists()).isFalse();
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    deliverNetworkLogs(receiver, ownerContext, 8L);
    assertThat(tokenFile.setReadOnly() && dir.setWritable(false)).isTrue();
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);
    assertThat(dir.setWritable(true)).isTrue();
    expect.that(tokenFile.exists()).isTrue();
    usableSpace.set(MIN_SECURITY_USABLE_SPACE_BYTES);

    deliverSecurityLogs(receiver, ownerContext);

    expect.that(retrievals).containsExactly(7L, 8L).inOrder();
    expect.that(auditMessages(context, AUDIT_EVENT_LOGS_LOST)).hasSize(1);
    expect.that(tokenFile.exists()).isFalse();
  }

  @Test
  public void drainDeferredNetworkLogs_whenSavingThrows_keepsTheTokenQueued() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    NetworkEvent unsavable = mock(NetworkEvent.class);
    when(unsavable.getPackageName()).thenThrow(new IllegalStateException("Crash while saving."));
    when(mockDpm.retrieveNetworkLogs(any(ComponentName.class), eq(7L)))
        .thenReturn(ImmutableList.of(unsavable))
        .thenReturn(ImmutableList.of());
    AtomicLong usableSpace = new AtomicLong(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    deliverNetworkLogs(receiver, ownerContext, 7L);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES);
    assertThrows(
        IllegalStateException.class,
        () -> CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext));

    CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(ownerContext);

    verify(mockDpm, times(2)).retrieveNetworkLogs(any(ComponentName.class), eq(7L));
    expect.that(savedBatches(context)).hasLength(1);
    assertDeferredLogsNotificationNotPosted(context);
  }

  @Test
  public void sealActivityLogBeforeClear_whileAStagingDrainWrites_doesNotDeadlock()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    PublicKey key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(key);
    CrumblesLogStaging staging = new CrumblesLogStaging(context);
    assertThat(staging.stage(/* isNetworkBatch= */ false, "staged\n".getBytes(UTF_8))).isTrue();
    CrumblesAppAuditLogger.getInstance(context).logEvent("UNSHIPPED", "An unshipped record.");
    Thread sealer =
        new Thread(() -> CrumblesDeviceAdminReceiver.sealActivityLogBeforeClear(context));
    // The drain lets the clear start while it holds the staged batch, then saves that batch.
    CrumblesLogStaging.BatchWriter writer =
        (isNetworkBatch, logs) -> {
          sealer.start();
          while (sealer.isAlive() && sealer.getState() != Thread.State.BLOCKED) {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
          }
          try {
            return CrumblesDeviceAdminReceiver.encryptAndSaveLogs(
                        context, isNetworkBatch, logs, key)
                    .isPresent()
                ? CrumblesLogStaging.WriteResult.STORED
                : CrumblesLogStaging.WriteResult.FAILED;
          } catch (QuotaRefusedException e) {
            return CrumblesLogStaging.WriteResult.FAILED;
          }
        };
    Thread drainer = new Thread(() -> expect.that(staging.drain(writer)).isEqualTo(1));
    sealer.setDaemon(true);
    drainer.setDaemon(true);

    drainer.start();
    drainer.join(10_000);
    sealer.join(10_000);

    expect.that(drainer.isAlive()).isFalse();
    expect.that(sealer.isAlive()).isFalse();
  }

  @Test
  public void prepareLogRetrieval_writesTheTokenFileOnlyForTokensKeptInMemory() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    AtomicLong usableSpace = new AtomicLong(MIN_SECURITY_USABLE_SPACE_BYTES);
    Context ownerContext = withUsableSpace(context, mockDpm, usableSpace::get);
    File tokenFile = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    deliverSecurityLogs(receiver, ownerContext);
    expect.that(tokenFile.exists()).isFalse();
    blockDeferredTokenWrites(context);
    usableSpace.set(MIN_NETWORK_USABLE_SPACE_BYTES - 1);
    deliverNetworkLogs(receiver, ownerContext, 7L);
    assertThat(tokenFile.delete()).isTrue();
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    usableSpace.set(MIN_SECURITY_USABLE_SPACE_BYTES);

    deliverSecurityLogs(receiver, ownerContext);

    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ true);
    ByteBuffer queue = ByteBuffer.wrap(Files.readAllBytes(tokenFile.toPath()));
    expect.that(queue.getInt(Long.BYTES)).isEqualTo(1);
    expect.that(queue.getLong(Long.BYTES + Integer.BYTES)).isEqualTo(7L);
  }

  /** Makes saving deferred tokens fail: a link into a missing directory reads as no file. */
  private static void blockDeferredTokenWrites(Context context) throws IOException {
    Files.createSymbolicLink(
        new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE).toPath(),
        new File(context.getCacheDir(), "missing/" + DEFERRED_TOKENS_FILE).toPath());
  }

  /** Returns the messages of the activity log events of type {@code eventType}, newest first. */
  private static List<String> auditMessages(Context context, String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .filter(event -> event.getEventType().equals(eventType))
        .map(CrumblesAuditEvent::getMessage)
        .toList();
  }

  @Test
  public void onNetworkLogsAvailable_whenBatchCannotBeWritten_stagesIt() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // A file in place of the logs directory makes writing the batch fail.
    assertThat(
            new File(
                    context.getFilesDir(),
                    CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY)
                .createNewFile())
        .isTrue();
    saveNewExternalPublicKey(context);

    deliverNetworkLogs(receiver, createContextWrapper(context, dpmWithConnectEvents(context, 3)));

    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEqualTo("Network log batch of 3 event(s) was staged: encrypting or saving it failed.");
    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    expect.that(findDeferredLogsNotification(context)).isNotNull();
  }

  @Test
  public void onNetworkLogsAvailable_whenStorageCapReached_dropsTheBatch() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(baseDir.mkdirs()).isTrue();
    // A sparse file leaves less than the encrypted batch plus signature allowance.
    try (RandomAccessFile pending = new RandomAccessFile(new File(baseDir, "pending.bin"), "rw")) {
      pending.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES - 5000);
    }
    saveNewExternalPublicKey(context);

    deliverNetworkLogs(receiver, createContextWrapper(context, dpmWithConnectEvents(context, 2)));

    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEqualTo("Network log batch of 2 event(s) was lost: storage quota reached.");
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(findDeferredLogsNotification(context)).isNotNull();
  }

  @Test
  public void onNetworkLogsAvailable_whenStagedNetworkBatchHitsCapDuringDrain_reportsLostAndDrops()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    deliverNetworkLogs(receiver, createContextWrapper(context, dpmWithConnectEvents(context, 3)));
    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(baseDir.mkdirs() || baseDir.exists()).isTrue();
    try (RandomAccessFile fill = new RandomAccessFile(new File(baseDir, "fill.dat"), "rw")) {
      fill.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES - 5000);
    }
    saveNewExternalPublicKey(context);
    CrumblesDeviceAdminReceiver.bumpNetworkLoggingEnableEpoch(context);

    deliverNetworkLogs(receiver, createContextWrapper(context, dpmWithConnectEvents(context, 2)));

    ImmutableList<String> lostMessages =
        CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
            .filter(e -> e.getEventType().equals(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
            .map(CrumblesAuditEvent::getMessage)
            .collect(toImmutableList());
    expect
        .that(lostMessages)
        .containsExactly(
            "Network log batch of 2 event(s) was lost: storage quota reached.",
            "Network log batch of 3 event(s) was lost: storage quota reached.")
        .inOrder();
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
  }

  @Test
  public void onSecurityLogsAvailable_whenStagedSecurityBatchHitsCapDuringDrain_keepsStaged()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
    deliverSecurityLogs(receiver, contextWrapper);

    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(baseDir.mkdirs() || baseDir.exists()).isTrue();
    try (RandomAccessFile pending = new RandomAccessFile(new File(baseDir, "pending.bin"), "rw")) {
      pending.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES - 5000);
    }
    saveNewExternalPublicKey(context);
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();

    deliverSecurityLogs(receiver, contextWrapper);

    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEqualTo(
            "Security log batch of 0 event(s) was staged: older staged batches are waiting.");
    expect.that(baseDir.list()).asList().containsExactly("pending.bin");
  }

  @Test
  public void onSecurityLogsAvailable_whenNearStorageCapButBatchFits_writesTheBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(baseDir.mkdirs() || baseDir.exists()).isTrue();
    try (RandomAccessFile pending = new RandomAccessFile(new File(baseDir, "pending.bin"), "rw")) {
      pending.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES - 20_000);
    }
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    saveNewExternalPublicKey(context);

    deliverSecurityLogs(receiver, createContextWrapper(context, mockDpm));

    assertThat(baseDir.list()).hasLength(2);
  }

  @Test
  public void onNetworkLogsAvailable_whileOlderLogsAreStaged_stagesTheNewBatchAfterThem()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Context contextWrapper = createContextWrapper(context, dpmWithConnectEvents(context, 8));
    deliverNetworkLogs(receiver, contextWrapper);
    saveNewExternalPublicKey(context);
    File logsDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    // A file in place of the logs directory makes saving the staged batch fail.
    assertThat(logsDir.delete() && logsDir.createNewFile()).isTrue();

    deliverNetworkLogs(receiver, contextWrapper);

    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEqualTo("Network log batch of 8 event(s) was staged: older staged batches are waiting.");
    expect.that(findDeferredLogsNotification(context)).isNotNull();
  }

  @Test
  public void onNetworkLogsAvailable_whenStagingIsFull_reportsLostEvents() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // A batch that fills the staging area on its own.
    int fullBatchBytes =
        Math.toIntExact(CrumblesLogStaging.CAP_BYTES - CrumblesLogStagingSealer.OVERHEAD_BYTES);
    assertThat(new CrumblesLogStaging(context).stage(false, new byte[fullBatchBytes])).isTrue();

    deliverNetworkLogs(receiver, createContextWrapper(context, dpmWithConnectEvents(context, 5)));

    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEqualTo("Network log batch of 5 event(s) was lost: the staging area is full.");
    expect.that(findDeferredLogsNotification(context)).isNotNull();
  }

  @Test
  public void onNetworkLogsAvailable_whenStagingFails_reportsLostEvents() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // A file in place of the staging directory makes staging the batch fail.
    assertThat(new File(context.getNoBackupFilesDir(), "staged_logs").createNewFile()).isTrue();

    deliverNetworkLogs(receiver, createContextWrapper(context, dpmWithConnectEvents(context, 7)));

    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEqualTo("Network log batch of 7 event(s) was lost: staging it failed.");
    expect.that(findDeferredLogsNotification(context)).isNotNull();
  }

  @Test
  public void onNetworkLogsAvailable_whenNetworkCollectionOff_skipsRetrievalWithoutDeferring() {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    Context contextWrapper = createContextWrapper(context, mockDpm);

    deliverNetworkLogs(receiver, contextWrapper);

    verify(mockDpm, never()).retrieveNetworkLogs(any(ComponentName.class), eq(123L));
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .anyMatch(e -> e.getEventType().equals("NETWORK_COLLECTION_OFF")))
        .isTrue();
    assertDeferredLogsNotificationNotPosted(context);
  }

  @Test
  public void onProfileProvisioningComplete_whenNetworkCollectionOff_enablesSecurityLoggingOnly() {
    Context realContext = ApplicationProvider.getApplicationContext();
    CrumblesCollectionScope.setNetworkCollectionEnabled(realContext, /* enabled= */ false);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(realContext.getPackageName())).thenReturn(true);
    Context contextWrapper = createContextWrapper(realContext, mockDpm);
    Intent intent = new Intent(DeviceAdminReceiver.ACTION_PROFILE_PROVISIONING_COMPLETE);
    PersistableBundle adminExtras = new PersistableBundle();
    adminExtras.putBoolean("enable_logging", true);
    intent.putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, adminExtras);

    receiver.onProfileProvisioningComplete(contextWrapper, intent);

    verify(mockDpm).setSecurityLoggingEnabled(any(ComponentName.class), eq(true));
    verify(mockDpm).setNetworkLoggingEnabled(any(ComponentName.class), eq(false));
  }

  @Test
  public void onSecurityLogsAvailable_whenSelectedExternalKeyUnreadable_failsClosed()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(new ArrayList<>());
    Context contextWrapper = createContextWrapper(context, mockDpm);
    selectUnreadableExternalKeyWithInternalKeyAvailable(context);

    deliverSecurityLogs(receiver, contextWrapper);

    expect.that(savedBatches(context)).isEmpty();
    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_EXTERNAL_KEY_UNAVAILABLE);
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void onNetworkLogsAvailable_whenSelectedExternalKeyUnreadable_failsClosed()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Context contextWrapper = createContextWrapper(context, dpmWithConnectEvents(context, 6));
    selectUnreadableExternalKeyWithInternalKeyAvailable(context);

    deliverNetworkLogs(receiver, contextWrapper);

    expect.that(savedBatches(context)).isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_STAGED))
        .isEqualTo("Network log batch of 6 event(s) was staged: no encryption key is available.");
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_EXTERNAL_KEY_UNAVAILABLE);
    assertDeferredLogsNotificationPosted(context);
  }

  /**
   * Selects an external key and then makes it unreadable, while an internal key that a silent
   * fallback could use exists.
   */
  private static void selectUnreadableExternalKeyWithInternalKeyAvailable(Context context)
      throws Exception {
    CrumblesMain.getLogsEncryptorInstance()
        .generateKeyPair(CrumblesLogsEncryptor.KEY_ALIAS, /* requireUserAuthentication= */ false);
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(
            KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    // Losing the key that seals stored entries leaves the selected external key unreadable.
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS);
  }

  @Test
  public void retrieveAndSaveSecurityLogs_whenKeystoreKeyInvalidatedAndReplaced_stagesThenDrains()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    Context deviceOwnerContext = deviceOwnerWithoutSecurityLogs(context);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesLogsEncryptor encryptor = new CrumblesLogsEncryptor(context);
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    try {
      KeyPair firstKeyPair = encryptor.generateKeyPair();
      CrumblesDeviceAdminReceiver.recordActivatedInternalKey(context, firstKeyPair.getPublic());
      FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
      CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
      expect.that(savedBatches(context)).hasLength(1);
      expect
          .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .isEmpty();

      FakeAndroidKeyStoreSpi.invalidateKey(CrumblesLogsEncryptor.KEY_ALIAS);
      CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

      expect.that(savedBatches(context)).hasLength(1);
      expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
      expect
          .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .contains(
              "Fingerprint: "
                  + CrumblesLogsEncryptor.getPublicKeyFingerprint(firstKeyPair.getPublic())
                      .replace('\n', ':'));
      assertDeferredLogsNotificationPosted(context);
      expect
          .that(
              Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();

      KeyPair replacementKeyPair = encryptor.generateKeyPair();
      expect
          .that(
              Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();
      CrumblesDeviceAdminReceiver.recordActivatedInternalKey(
          context, replacementKeyPair.getPublic());
      expect
          .that(
              Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNull();
      CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

      expect.that(savedBatches(context)).hasLength(3);
      expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    } finally {
      encryptor.deleteExistingKeyPair();
      CrumblesMain.setLogsEncryptorInstanceForTest(null);
    }
  }

  @Test
  public void reportIfDeviceKeyInvalidated_handlesDeletedKeyPlannedDeletionAndMainResume()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesLogsEncryptor encryptor = new CrumblesLogsEncryptor(context);
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    try {
      KeyPair firstKeyPair = encryptor.generateKeyPair();
      CrumblesDeviceAdminReceiver.recordActivatedInternalKey(context, firstKeyPair.getPublic());
      expect.that(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();
      FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogsEncryptor.KEY_ALIAS);

      expect.that(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isTrue();
      expect
          .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .contains(
              "Fingerprint: "
                  + CrumblesLogsEncryptor.getPublicKeyFingerprint(firstKeyPair.getPublic())
                      .replace('\n', ':'));

      KeyPair secondKeyPair = encryptor.generateKeyPair();
      CrumblesDeviceAdminReceiver.recordActivatedInternalKey(context, secondKeyPair.getPublic());
      encryptor.deleteExistingKeyPair();
      CrumblesDeviceAdminReceiver.clearActivatedInternalKey(context);
      CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
      expect.that(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isTrue();
      expect
          .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .isEmpty();

      KeyPair thirdKeyPair = encryptor.generateKeyPair();
      CrumblesDeviceAdminReceiver.recordActivatedInternalKey(context, thirdKeyPair.getPublic());
      FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogsEncryptor.KEY_ALIAS);
      CrumblesSetupActivity.markAcknowledged(context);
      Shadows.shadowOf((Application) context)
          .grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS");
      CrumblesMain mainActivity =
          Robolectric.buildActivity(CrumblesMain.class).create().start().resume().get();
      ExecutorService probeExecutor = ReflectionHelpers.getField(mainActivity, "keyProbeExecutor");
      probeExecutor.shutdown();
      assertThat(probeExecutor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
      Shadows.shadowOf(Looper.getMainLooper()).idle();
      expect
          .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .contains(
              "Fingerprint: "
                  + CrumblesLogsEncryptor.getPublicKeyFingerprint(thirdKeyPair.getPublic())
                      .replace('\n', ':'));
    } finally {
      encryptor.deleteExistingKeyPair();
      CrumblesMain.setLogsEncryptorInstanceForTest(null);
    }
  }

  @Test
  public void sealFinalBatch_withExternalKey_writesLoggingOffBatchAndRequestsUpload()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    boolean sealed = CrumblesDeviceAdminReceiver.sealFinalBatch(context);

    assertThat(sealed).isTrue();
    ImmutableList<File> batches = listBatchFiles(context);
    assertThat(batches).hasSize(1);
    LogBatch batch =
        LogBatch.parseFrom(
            Files.readAllBytes(batches.get(0).toPath()), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(decryptWithPrivateKey(batch, externalKeyPair.getPrivate()))
        .containsMatch(
            "Crumbles: logging was turned off at \\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\\. No"
                + " more batches until it is turned back on\\.");
    assertThat(getSendNowWorkInfos(context)).hasSize(1);
  }

  @Test
  public void sealFinalBatch_whenSelectedExternalKeyUnreadable_writesNothingAndLogsFailure()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    selectUnreadableExternalKeyWithInternalKeyAvailable(context);

    boolean sealed = CrumblesDeviceAdminReceiver.sealFinalBatch(context);

    assertThat(sealed).isFalse();
    assertThat(listBatchFiles(context)).isEmpty();
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .contains(CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED);
    assertThat(getSendNowWorkInfos(context)).isEmpty();
  }

  @Test
  public void sealFinalBatch_whenDrainingFailsButNoticeWritten_logsPendingBatches()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // Stage an unreadable batch (a directory with a .sealed name causes Files.readAllBytes to throw
    // IOException) so drain fails while saveLoggingOffBatch still succeeds.
    File badBatch =
        new File(context.getNoBackupFilesDir(), "staged_logs/0000000000000000001-S.sealed");
    assertThat(badBatch.mkdirs()).isTrue();

    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());

    boolean sealed = CrumblesDeviceAdminReceiver.sealFinalBatch(context);

    assertThat(sealed).isTrue();
    CrumblesAuditEvent event =
        CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
            .filter(e -> e.getEventType().equals("FINAL_BATCH_SEALED"))
            .findFirst()
            .orElse(null);
    assertThat(event).isNotNull();
    assertThat(event.getMessage()).isEqualTo("Notice sealed, 1 staged batch(es) still pending.");
    expect
        .that(
            decryptWithPrivateKey(
                LogBatch.parseFrom(
                    Files.readAllBytes(listBatchFiles(context).get(0).toPath()),
                    ExtensionRegistryLite.getEmptyRegistry()),
                externalKeyPair.getPrivate()))
        .containsMatch(
            "Crumbles: logging was turned off at \\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\\. No"
                + " more batches until it is turned back on\\. 1 staged batch\\(es\\) are still"
                + " pending and will follow\\.\n");
    assertThat(getSendNowWorkInfos(context)).isNotEmpty();
  }

  @Test
  public void drainStagedBatches_cancelsDeferredNotificationOnlyWhenDrainedAndEmpty()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    PublicKey activeKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    CrumblesLogStaging staging = new CrumblesLogStaging(context);

    // 1. Nothing staged (saved == 0, empty == true): notification from an earlier error stays up.
    deliverSecurityLogs(receiver, deviceOwnerWithoutSecurityLogs(context));
    assertDeferredLogsNotificationPosted(context);
    assertThat(staging.wipeAllBatches()).isEqualTo(1);
    // Batches are encrypted to the active key, which encryptAndSaveLogs reads again.
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(activeKey);
    expect.that(CrumblesDeviceAdminReceiver.drainStagedBatches(context, activeKey)).isTrue();
    expect.that(findDeferredLogsNotification(context)).isNotNull();

    // 2. One batch drained, one unreadable left (saved == 1, empty == false): notification stays.
    assertThat(staging.stage(/* isNetworkBatch= */ false, "first\n".getBytes(UTF_8))).isTrue();
    File unreadable =
        new File(context.getNoBackupFilesDir(), "staged_logs/0000000000000000002-S.sealed");
    assertThat(unreadable.mkdirs()).isTrue();
    expect.that(CrumblesDeviceAdminReceiver.drainStagedBatches(context, activeKey)).isFalse();
    expect.that(findDeferredLogsNotification(context)).isNotNull();
    assertThat(unreadable.delete()).isTrue();

    // 3. Last staged batch drained (saved == 1, empty == true): notification is cancelled.
    assertThat(staging.stage(/* isNetworkBatch= */ false, "last\n".getBytes(UTF_8))).isTrue();
    expect.that(CrumblesDeviceAdminReceiver.drainStagedBatches(context, activeKey)).isTrue();
    expect.that(findDeferredLogsNotification(context)).isNull();
  }

  @Test
  public void drainStagedBatches_whenQuotaReached_dropsNetworkOnlyIfNoUnuploadedFiles()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesLogStaging staging = new CrumblesLogStaging(context);
    PublicKey activeKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(activeKey);
    File baseDir =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(baseDir.mkdirs()).isTrue();

    // 1. With un-uploaded pending.bin: network batch is kept for retry.
    assertThat(staging.stage(/* isNetworkBatch= */ true, "network\n".getBytes(UTF_8))).isTrue();
    File pending = new File(baseDir, "pending.bin");
    try (RandomAccessFile raf = new RandomAccessFile(pending, "rw")) {
      raf.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES);
    }
    expect.that(CrumblesDeviceAdminReceiver.drainStagedBatches(context, activeKey)).isFalse();
    expect.that(staging.countBatches()).isEqualTo(1);
    expect
        .that(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .filter(
                    e -> e.getEventType().equals(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
                .toList())
        .isEmpty();

    // 2. Without un-uploaded files (only sent files filling quota): network batch is dropped.
    assertThat(pending.delete()).isTrue();
    try (RandomAccessFile fill =
        new RandomAccessFile(new File(baseDir, "fill.dat"), "rw")) {
      fill.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES);
    }
    assertThat(staging.stage(/* isNetworkBatch= */ false, "security\n".getBytes(UTF_8))).isTrue();
    expect.that(CrumblesDeviceAdminReceiver.drainStagedBatches(context, activeKey)).isFalse();
    expect.that(staging.countBatches()).isEqualTo(1);
    expect
        .that(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .filter(
                    e -> e.getEventType().equals(CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
                .map(CrumblesAuditEvent::getMessage)
                .toList())
        .containsExactly("Network log batch of 0 event(s) was lost: storage quota reached.");
  }

  @Test
  public void saveHeartbeatBatch_respectsStagedBatches() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    Context contextWrapper = createContextWrapper(context, mockDpm);

    File unreadable =
        new File(context.getNoBackupFilesDir(), "staged_logs/0000000000000000001-S.sealed");
    assertThat(unreadable.mkdirs()).isTrue();
    CrumblesDeviceAdminReceiver.saveHeartbeatBatch(contextWrapper);
    expect.that(listBatchFiles(context)).isEmpty();
    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    assertThat(unreadable.delete()).isTrue();

    assertThat(
            new CrumblesLogStaging(context)
                .stage(/* isNetworkBatch= */ false, "staged earlier\n".getBytes(UTF_8)))
        .isTrue();
    CrumblesDeviceAdminReceiver.saveHeartbeatBatch(contextWrapper);
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(listBatchFiles(context)).hasSize(2);
  }

  @Test
  public void sealFinalBatch_whenEncryptionFails_writesNothingAndLogsFailure() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(
            KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    File logsPath =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    // Making the logs directory path a regular file causes serializeBytes to fail with
    // CrumblesLogsEncryptionException.
    assertThat(logsPath.createNewFile()).isTrue();

    boolean sealed = CrumblesDeviceAdminReceiver.sealFinalBatch(context);

    assertThat(sealed).isFalse();
    CrumblesAuditEvent event =
        CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().get(0);
    assertThat(event.getEventType())
        .isEqualTo(CrumblesDeviceAdminReceiver.AUDIT_EVENT_FINAL_BATCH_FAILED);
    assertThat(event.getMessage()).contains("the batch could not be encrypted or saved");
    assertThat(getSendNowWorkInfos(context)).isEmpty();
  }

  @Test
  public void onReceive_disableRequested_returnsTheDeactivationWarning() {
    Context context = ApplicationProvider.getApplicationContext();
    PendingResult pendingResult = attachPendingResult(receiver);

    receiver.onReceive(
        context, new Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED));

    assertThat(
            pendingResult
                .getResultExtras(/* makeMap= */ false)
                .getCharSequence(DeviceAdminReceiver.EXTRA_DISABLE_WARNING)
                .toString())
        .isEqualTo(context.getString(R.string.device_admin_disable_warning));
  }

  @Test
  public void onDisabled_recordsTheEventSealsItIntoABatchAndRequestsUpload() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    assertThat(new CrumblesLogStaging(context).stage(false, "older\n".getBytes(UTF_8))).isTrue();
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(recipientKeyPair.getPublic());

    deliver(receiver, context, new Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_DISABLED));

    CrumblesAuditEvent disabledEvent =
        CrumblesAppAuditLogger.getInstance(context).getAllPersistedEventsForDisplay().stream()
            .filter(
                event ->
                    event
                        .getEventType()
                        .equals(CrumblesDeviceAdminReceiver.AUDIT_EVENT_DEVICE_ADMIN_DISABLED))
            .findFirst()
            .orElseThrow();
    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(2);
    expect
        .that(decryptWithPrivateKey(batches.get(0), recipientKeyPair.getPrivate()))
        .contains("older\n");
    expect
        .that(decryptWithPrivateKey(batches.get(0), recipientKeyPair.getPrivate()))
        .contains(disabledEvent.getTag());
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(getSendNowWorkInfos(context)).hasSize(1);
  }

  @Test
  public void onDisabled_withoutEncryptionKey_recordsTheEventAndStillRequestsUpload()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);

    deliver(receiver, context, new Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_DISABLED));

    expect
        .that(
            newestAuditMessage(
                context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_DEVICE_ADMIN_DISABLED))
        .isEqualTo(
            "Deactivated as a device admin: clearing storage, force stopping and uninstalling are"
                + " no longer blocked.");
    expect.that(listBatchFiles(context)).isEmpty();
    expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
    expect.that(getSendNowWorkInfos(context)).hasSize(1);
  }

  @Test
  public void onDisabled_whenStorageCapReached_stillSealsEventIntoBatchAndRequestsUpload()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(recipientKeyPair.getPublic());
    File logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsDirectory.mkdirs()).isTrue();
    File pendingFile = new File(logsDirectory, "pending.bin");
    try (RandomAccessFile sparseFile = new RandomAccessFile(pendingFile, "rw")) {
      sparseFile.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES);
    }

    deliver(receiver, context, new Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_DISABLED));

    CrumblesAuditEvent disabledEvent =
        CrumblesAppAuditLogger.getInstance(context).getAllPersistedEventsForDisplay().stream()
            .filter(
                event ->
                    event
                        .getEventType()
                        .equals(CrumblesDeviceAdminReceiver.AUDIT_EVENT_DEVICE_ADMIN_DISABLED))
            .findFirst()
            .orElseThrow();
    File sealedFile =
        listBatchFiles(context).stream()
            .filter(file -> !file.equals(pendingFile))
            .findFirst()
            .orElseThrow();
    LogBatch sealedBatch =
        LogBatch.parseFrom(
            Files.readAllBytes(sealedFile.toPath()), ExtensionRegistryLite.getEmptyRegistry());
    expect
        .that(decryptWithPrivateKey(sealedBatch, recipientKeyPair.getPrivate()))
        .contains(disabledEvent.getTag());
    expect.that(getSendNowWorkInfos(context)).hasSize(1);
  }

  @Test
  public void onDisabled_whenBatchCannotBeWritten_stillRecordsEventAndRequestsUpload()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(
            KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    File logsPath =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsPath.createNewFile()).isTrue();

    deliver(receiver, context, new Intent(DeviceAdminReceiver.ACTION_DEVICE_ADMIN_DISABLED));

    expect
        .that(
            newestAuditMessage(
                context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_DEVICE_ADMIN_DISABLED))
        .isEqualTo(
            "Deactivated as a device admin: clearing storage, force stopping and uninstalling are"
                + " no longer blocked.");
    expect.that(getSendNowWorkInfos(context)).hasSize(1);
  }

  private static ImmutableList<File> listBatchFiles(Context context) {
    File logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File[] batches = logsDirectory.listFiles((dir, name) -> name.endsWith(".bin"));
    return batches == null ? ImmutableList.of() : ImmutableList.copyOf(batches);
  }

  private static List<WorkInfo> getSendNowWorkInfos(Context context) throws Exception {
    Shadows.shadowOf(Looper.getMainLooper()).idle();
    return WorkManager.getInstance(context)
        .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
        .get();
  }

  /** Decrypts {@code batch} the way the holder of the RSA-OAEP {@code privateKey} does. */
  private static String decryptWithPrivateKey(LogBatch batch, PrivateKey privateKey)
      throws Exception {
    return sealedLogsOf(batch, privateKey).getLogs().toStringUtf8();
  }

  /** Returns what {@code batch} seals, decrypted with the RSA-OAEP {@code privateKey}. */
  private static SealedLogs sealedLogsOf(LogBatch batch, PrivateKey privateKey) throws Exception {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsaCipher.init(
        Cipher.UNWRAP_MODE,
        privateKey,
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    Key aesKey =
        rsaCipher.unwrap(
            batch.getKey().getEncryptedSymmetricKey().toByteArray(), "AES", Cipher.SECRET_KEY);
    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    aesCipher.init(
        Cipher.DECRYPT_MODE,
        aesKey,
        new GCMParameterSpec(
            CrumblesLogsEncryptor.GCM_TAG_LEN_BITS, batch.getKey().getIv().toByteArray()));
    aesCipher.updateAAD(
        CrumblesLogsEncryptor.computeAssociatedData(
            batch.getMetadata(), batch.getKey().getKeyEncryptionType(), publicKeyOf(privateKey)));
    return sealedLogsInPaddedPlaintext(
        aesCipher.doFinal(batch.getData().getLogBlob().toByteArray()));
  }

  /** Returns the public key of the RSA {@code privateKey}, which batches for it are bound to. */
  private static PublicKey publicKeyOf(PrivateKey privateKey) throws Exception {
    RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
    return KeyFactory.getInstance("RSA")
        .generatePublic(
            new RSAPublicKeySpec(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent()));
  }

  /** Reads the logs out of a padded version 2 batch plaintext, laid out as logs.proto describes. */
  private static String logsInPaddedPlaintext(byte[] paddedPlaintext) throws Exception {
    return sealedLogsInPaddedPlaintext(paddedPlaintext).getLogs().toStringUtf8();
  }

  /** Reads the {@link SealedLogs} out of a padded version 2 batch plaintext. */
  private static SealedLogs sealedLogsInPaddedPlaintext(byte[] paddedPlaintext) throws Exception {
    ByteBuffer paddedLogs = ByteBuffer.wrap(paddedPlaintext);
    byte[] sealedLogs = new byte[paddedLogs.getInt()];
    paddedLogs.get(sealedLogs);
    return SealedLogs.parseFrom(sealedLogs, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Test
  public void onSecurityLogsAvailable_whenAccessLost_logsLostAndNotifies() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager dpm = mock(DevicePolicyManager.class);
    when(dpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true, false);
    when(dpm.retrieveSecurityLogs(any(ComponentName.class)))
        .thenThrow(new SecurityException("Test Exception"));
    Context deviceOwnerContext = createContextWrapper(context, dpm);

    deliverSecurityLogs(receiver, deviceOwnerContext);

    expect.that(savedBatches(context)).isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEqualTo("Security logs lost due to SecurityException.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void onNetworkLogsAvailable_whenAccessLost_logsLostCountAndNotifies() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager dpm = mock(DevicePolicyManager.class);
    when(dpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true, false);
    when(dpm.retrieveNetworkLogs(any(ComponentName.class), eq(NETWORK_BATCH_TOKEN)))
        .thenThrow(new SecurityException("Test Exception"));
    Context deviceOwnerContext = createContextWrapper(context, dpm);
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, true);

    deliverNetworkLogs(receiver, deviceOwnerContext);

    expect.that(savedBatches(context)).isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEqualTo("Network log batch of 5 event(s) was lost: retrieval threw SecurityException.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void delegatedOnNetworkLogsAvailable_whenAccessLost_logsLostCountAndNotifies()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager dpm = mock(DevicePolicyManager.class);
    when(dpm.getDelegatedScopes(null, context.getPackageName()))
        .thenReturn(
            ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING), ImmutableList.of());
    when(dpm.retrieveNetworkLogs(isNull(), eq(NETWORK_BATCH_TOKEN)))
        .thenThrow(new SecurityException("Test Exception"));
    Context delegateContext = createContextWrapper(context, dpm);
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, true);

    deliverNetworkLogs(new CrumblesDelegatedAdminReceiver(), delegateContext);

    expect.that(savedBatches(context)).isEmpty();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEqualTo("Network log batch of 5 event(s) was lost: retrieval threw SecurityException.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void saveHeartbeatBatch_whenSecurityExceptionCheckingStatus_logsAuditEventAndSkipsBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager dpm = mock(DevicePolicyManager.class);
    when(dpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(dpm.isSecurityLoggingEnabled(any())).thenThrow(new SecurityException("Test Exception"));
    when(dpm.isNetworkLoggingEnabled(any())).thenThrow(new SecurityException("Test Exception"));
    Context deviceOwnerContext = createContextWrapper(context, dpm);
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, true);

    CrumblesDeviceAdminReceiver.saveHeartbeatBatch(deviceOwnerContext);

    expect.that(savedBatches(context)).isEmpty();
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType))
        .containsAtLeast("SECURITY_LOGGING_ACCESS_LOST", "NETWORK_LOGGING_ACCESS_LOST");
  }

  @Test
  public void saveHeartbeatBatch_whenSecurityStatusThrowsButNetworkLoggingOn_writesBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager dpm = mock(DevicePolicyManager.class);
    when(dpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(dpm.isSecurityLoggingEnabled(any())).thenThrow(new SecurityException("Test Exception"));
    when(dpm.isNetworkLoggingEnabled(any())).thenReturn(true);
    Context deviceOwnerContext = createContextWrapper(context, dpm);

    CrumblesDeviceAdminReceiver.saveHeartbeatBatch(deviceOwnerContext);

    expect.that(savedBatches(context)).hasLength(1);
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType))
        .contains("SECURITY_LOGGING_ACCESS_LOST");
  }

  @Test
  public void encryptAndSaveLogs_calledConcurrently_givesConsecutiveExcerpts() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());
    PublicKey activeKey = externalKeyPair.getPublic();
    CrumblesAppAuditLogger logger = CrumblesAppAuditLogger.getInstance(context);
    logger.logEvent("INIT", "Init message");
    CrumblesDeviceAdminReceiver.encryptAndSaveLogs(
        context, /* isNetworkBatch= */ false, new byte[0], activeKey);

    int numThreads = 10;
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(numThreads);
    AtomicReference<Exception> failure = new AtomicReference<>();

    for (int i = 0; i < numThreads; i++) {
      final int index = i;
      new Thread(
              () -> {
                try {
                  startLatch.await();
                  logger.logEvent("CONCURRENT_" + index, "Message");
                  CrumblesDeviceAdminReceiver.encryptAndSaveLogs(
                      context, /* isNetworkBatch= */ false, new byte[0], activeKey);
                } catch (InterruptedException e) {
                  Thread.currentThread().interrupt();
                  failure.compareAndSet(null, e);
                } catch (QuotaRefusedException | RuntimeException e) {
                  failure.compareAndSet(null, e);
                } finally {
                  doneLatch.countDown();
                }
              })
          .start();
    }
    startLatch.countDown();
    doneLatch.await();
    if (failure.get() != null) {
      throw failure.get();
    }

    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(numThreads + 1);

    String previousHeadTag = null;
    for (LogBatch batch : batches) {
      String decrypted = decryptWithPrivateKey(batch, externalKeyPair.getPrivate());
      Matcher mSince = SINCE_RECORD_PATTERN.matcher(decrypted);
      Matcher mHead = CHAIN_HEAD_PATTERN.matcher(decrypted);

      assertThat(mSince.find()).isTrue();
      assertThat(mHead.find()).isTrue();

      String sinceTag = mSince.group(1);
      String headTag = mHead.group(1);

      if (previousHeadTag == null) {
        assertThat(sinceTag).isEqualTo("none");
      } else {
        assertThat(sinceTag).isEqualTo(previousHeadTag);
      }
      previousHeadTag = headTag;
    }
  }

  @Test
  public void encryptAndSaveLogs_reResolvesActiveKeyUnderUploadLock() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair oldKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    KeyPair newKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    var keyManager = CrumblesExternalPublicKeyManager.getInstance(context);
    keyManager.saveActiveExternalPublicKey(oldKey.getPublic());
    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(1);
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      new Thread(
              () -> {
                started.countDown();
                try {
                  CrumblesDeviceAdminReceiver.encryptAndSaveLogs(
                      context, false, "payload".getBytes(UTF_8), oldKey.getPublic());
                  done.countDown();
                } catch (QuotaRefusedException e) {
                  throw new AssertionError(e);
                }
              })
          .start();
      assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
      keyManager.saveActiveExternalPublicKey(newKey.getPublic());
    }
    assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
    assertThat(decryptOnlyBatch(context, newKey.getPrivate())).startsWith("payload");
  }


  @Test
  public void retrieveAndSaveSecurityLogs_whenKeystoreKeyDeleted_stagesAndReportsInvalidation()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    Context deviceOwnerContext = deviceOwnerWithoutSecurityLogs(context);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesLogsEncryptor encryptor = new CrumblesLogsEncryptor(context);
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    try {
      KeyPair keyPair = encryptor.generateKeyPair();
      CrumblesDeviceAdminReceiver.recordActivatedInternalKey(context, keyPair.getPublic());
      FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogsEncryptor.KEY_ALIAS);

      CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

      expect.that(savedBatches(context)).isEmpty();
      expect.that(new CrumblesLogStaging(context).isEmpty()).isFalse();
      expect
          .that(
              newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .contains(
              "Fingerprint: "
                  + CrumblesLogsEncryptor.getPublicKeyFingerprint(keyPair.getPublic())
                      .replace('\n', ':'));
      Notification notification =
          Shadows.shadowOf(context.getSystemService(NotificationManager.class))
              .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID);
      assertThat(notification).isNotNull();
      expect
          .that(notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
          .isEqualTo("screen lock removed; built-in key and its batches are lost");
    } finally {
      encryptor.deleteExistingKeyPair();
      CrumblesMain.setLogsEncryptorInstanceForTest(null);
    }
  }

  @Test
  public void reportIfDeviceKeyInvalidated_readsTheRecordedFingerprintOncePerKey()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesLogsEncryptor encryptor = new CrumblesLogsEncryptor(context);
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    try {
      encryptor.generateKeyPair();
      // The first check records the key, and the second finds it recorded.
      assertThat(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();
      assertThat(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();
      setRecordedInternalKeyFingerprint(context, "changed elsewhere");

      assertThat(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();

      expect.that(recordedInternalKeyFingerprint(context)).isEqualTo("changed elsewhere");
    } finally {
      encryptor.deleteExistingKeyPair();
      CrumblesMain.setLogsEncryptorInstanceForTest(null);
    }
  }

  @Test
  public void reportIfDeviceKeyInvalidated_afterInternalKeyCleared_recordsTheKeyAgain()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    CrumblesLogsEncryptor encryptor = new CrumblesLogsEncryptor(context);
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    try {
      KeyPair keyPair = encryptor.generateKeyPair();
      assertThat(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();
      assertThat(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();
      CrumblesDeviceAdminReceiver.clearActivatedInternalKey(context);

      assertThat(CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context)).isFalse();

      expect
          .that(recordedInternalKeyFingerprint(context))
          .isEqualTo(CrumblesLogsEncryptor.getPublicKeyFingerprint(keyPair.getPublic()));
    } finally {
      encryptor.deleteExistingKeyPair();
      CrumblesMain.setLogsEncryptorInstanceForTest(null);
    }
  }

  private static String recordedInternalKeyFingerprint(Context context) throws Exception {
    return CrumblesDataStoreHolder.getInstance(context)
        .getDataAsync()
        .get()
        .getInternalKeyFingerprint();
  }

  private static void setRecordedInternalKeyFingerprint(Context context, String fingerprint)
      throws Exception {
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(prefs -> prefs.toBuilder().setInternalKeyFingerprint(fingerprint).build())
        .get();
  }

  @Test
  public void retrieveAndSaveSecurityLogs_whenUnrecordedKeyIsDeleted_reportsInvalidation()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    Shadows.shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    Context deviceOwnerContext = deviceOwnerWithoutSecurityLogs(context);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesLogsEncryptor encryptor = new CrumblesLogsEncryptor(context);
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    try {
      // A key generated before fingerprints were recorded has none.
      KeyPair keyPair = encryptor.generateKeyPair();
      CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
      FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogsEncryptor.KEY_ALIAS);

      CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

      expect
          .that(
              newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
          .contains(
              "Fingerprint: "
                  + CrumblesLogsEncryptor.getPublicKeyFingerprint(keyPair.getPublic())
                      .replace('\n', ':'));
      expect
          .that(
              Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                  .getNotification(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID))
          .isNotNull();
    } finally {
      encryptor.deleteExistingKeyPair();
      CrumblesMain.setLogsEncryptorInstanceForTest(null);
    }
  }

  @Test
  public void reportInvalidatedKey_formatsMultilineFingerprintAndDeduplicatesAndSkipsEmpty() {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesDeviceAdminReceiver.reportInvalidatedKey(context, "");
    assertThat(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
        .isEmpty();

    String fingerprint = "AA:BB:CC:DD\nEE:FF:00:11";
    CrumblesDeviceAdminReceiver.reportInvalidatedKey(context, fingerprint);
    assertThat(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
        .contains("Fingerprint: AA:BB:CC:DD:EE:FF:00:11");

    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDeviceAdminReceiver.reportInvalidatedKey(context, fingerprint);
    assertThat(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_KEY_INVALIDATED))
        .isEmpty();
  }

  @Test
  public void sealActivityLogBeforeClear_whenNoUnshippedRecords_writesNothingAndRequestsNoUpload()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    CrumblesAppAuditLogger logger = CrumblesAppAuditLogger.getInstance(context);
    logger.logEvent("ALREADY_SHIPPED", "Included in an earlier batch.");
    logger.markShipped(logger.getUnshippedExcerpt());
    expect.that(CrumblesDeviceAdminReceiver.sealActivityLogBeforeClear(context)).isEqualTo(0);
    expect.that(listBatchFiles(context)).isEmpty();
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(getSendNowWorkInfos(context)).isEmpty();
  }

  @Test
  public void
      sealActivityLogBeforeClear_withActiveKey_drainsStagingWritesSignedBatchAndMarksShipped()
          throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    assertThat(new CrumblesLogStaging(context).stage(false, "older\n".getBytes(UTF_8))).isTrue();
    KeyPair externalKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(externalKeyPair.getPublic());
    File logsDir = new File(context.getFilesDir(), "logs");
    assertThat(logsDir.mkdirs()).isTrue();
    try (RandomAccessFile pending =
        new RandomAccessFile(new File(logsDir, "pending_security.keep"), "rw")) {
      pending.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES * 85 / 100);
    }
    CrumblesAppAuditLogger logger = CrumblesAppAuditLogger.getInstance(context);
    logger.logEvent("COERCED_SHARE", "Shared decrypted logs before clearing.");
    String coercedShareTag = logger.getUnshippedExcerpt().getHeadTag().orElseThrow();
    expect.that(CrumblesDeviceAdminReceiver.sealActivityLogBeforeClear(context)).isEqualTo(0);
    expect.that(logger.getUnshippedExcerpt().isEmpty()).isTrue();
    logger.clearAllLogs();
    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(2);
    String drained = decryptWithPrivateKey(batches.get(0), externalKeyPair.getPrivate());
    expect.that(drained).contains("older\n");
    expect.that(drained).contains("COERCED_SHARE");
    expect.that(drained).contains(coercedShareTag);
    expect.that(drained).doesNotContain("\"sealed\"");
    expect.that(batches.get(1).hasSignature()).isTrue();
    expect
        .that(decryptWithPrivateKey(batches.get(1), externalKeyPair.getPrivate()))
        .containsMatch(
            "Crumbles: activity log was cleared at \\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z;"
                + " sealing unshipped activity records before clearing\\.");
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(getSendNowWorkInfos(context)).hasSize(1);
  }

  @Test
  public void sealActivityLogBeforeClear_whenKeyMissingOrSaveFails_refusesClearAndLogsFailure()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // Else a device key fingerprint left by an earlier test is reported as invalidated here.
    CrumblesDeviceAdminReceiver.clearActivatedInternalKey(context);
    CrumblesAppAuditLogger logger = CrumblesAppAuditLogger.getInstance(context);
    logger.logEvent("COERCED_DEST_CHANGE", "Changed destination before clearing.");
    int unshipped = logger.getUnshippedExcerpt().size();
    expect.that(CrumblesDeviceAdminReceiver.sealActivityLogBeforeClear(context))
        .isEqualTo(unshipped);
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();

    saveNewExternalPublicKey(context);
    assertThat(new File(context.getFilesDir(), "logs").createNewFile()).isTrue();
    int afterFirstFailure = logger.getUnshippedExcerpt().size();
    expect.that(afterFirstFailure).isGreaterThan(unshipped);
    expect.that(CrumblesDeviceAdminReceiver.sealActivityLogBeforeClear(context))
        .isEqualTo(afterFirstFailure);
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_CLEAR_SEAL_FAILED))
        .contains("Unshipped activity records could not be sealed");
    // Each attempt asks for an upload; the second one is appended to the first.
    expect.that(getSendNowWorkInfos(context)).hasSize(2);
  }

  @Test
  public void syncDisallowAddUserRestriction_handlesNullsDelegatesPreExistingAndExceptions() {
    Context context = ApplicationProvider.getApplicationContext();
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    Context nullDpm = createContextWrapper(context, null);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(nullDpm, /* enabled= */ true);
    expect.that(CrumblesDeviceAdminReceiver.hasSecondaryUsers(nullDpm)).isFalse();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.getSecondaryUsers(any()))
        .thenReturn(ImmutableList.of(UserHandle.getUserHandleForUid(1000000)));
    Context dpmCtx = createContextWrapper(context, mockDpm);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ true);
    expect.that(CrumblesDeviceAdminReceiver.hasSecondaryUsers(dpmCtx)).isFalse();

    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    UserManager um = context.getSystemService(UserManager.class);
    Shadows.shadowOf(um)
        .setUserRestriction(android.os.Process.myUserHandle(), UserManager.DISALLOW_ADD_USER, true);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ true);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ false);
    verify(mockDpm, never()).addUserRestriction(any(), any());
    Shadows.shadowOf(um)
        .setUserRestriction(
            android.os.Process.myUserHandle(), UserManager.DISALLOW_ADD_USER, false);

    doThrow(new SecurityException()).when(mockDpm).addUserRestriction(any(), any());
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ true);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ false);
    verify(mockDpm, never()).clearUserRestriction(any(), any());

    doNothing().when(mockDpm).addUserRestriction(admin, UserManager.DISALLOW_ADD_USER);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ true);
    doThrow(new SecurityException()).when(mockDpm).clearUserRestriction(any(), any());
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ false);
    doNothing().when(mockDpm).clearUserRestriction(admin, UserManager.DISALLOW_ADD_USER);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ false);
    CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(dpmCtx, /* enabled= */ false);
    verify(mockDpm, times(2)).clearUserRestriction(admin, UserManager.DISALLOW_ADD_USER);
  }

  @Test
  public void onUserAddedAndRemoved_tracksSecondaryUsersNotifiesAndSealsPauseBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    UserHandle user10 = UserHandle.getUserHandleForUid(1000000);
    UserHandle user11 = UserHandle.getUserHandleForUid(1100000);
    when(mockDpm.getSecondaryUsers(any())).thenReturn(ImmutableList.of(user10, user11));
    Context dpmCtx = createContextWrapper(context, mockDpm);
    Intent added = new Intent("android.app.action.USER_ADDED").putExtra(Intent.EXTRA_USER, user10);

    deliver(receiver, dpmCtx, added);
    expect.that(findPausedNotification(context)).isNull();
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    deliver(receiver, dpmCtx, added);
    expect.that(findPausedNotification(context)).isNotNull();
    expect
        .that(
            newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_PAUSE_BATCH_FAILED))
        .contains("no usable encryption key");
    CrumblesDeviceAdminReceiver.prefs(context).edit().clear().commit();

    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(keyPair.getPublic());
    deliver(receiver, dpmCtx, added);

    Notification n = findPausedNotification(context);
    assertThat(n).isNotNull();
    expect.that(n.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    expect
        .that(n.flags & Notification.FLAG_ONGOING_EVENT)
        .isEqualTo(Notification.FLAG_ONGOING_EVENT);
    expect
        .that(n.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        .isEqualTo(context.getString(R.string.notification_title_sync_paused_other_user));
    expect
        .that(n.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        .isEqualTo(context.getString(R.string.notification_text_sync_paused_other_user));
    String decrypted =
        decryptWithPrivateKey(writtenBatches(context).get(0), keyPair.getPrivate());
    expect.that(decrypted).contains("Collection paused: secondary or guest user present");
    expect.that(decrypted).contains("discarded by the platform");
    expect.that(decrypted).contains("COLLECTION_PAUSED_SECONDARY_USER");
    String resumedType = CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_RESUMED;
    expect
        .that(
            newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_PAUSED))
        .contains("secondary or guest user");
    expect.that(getSendNowWorkInfos(context)).hasSize(1);

    when(mockDpm.getSecondaryUsers(any())).thenReturn(ImmutableList.of(user11));
    Intent removed =
        new Intent("android.app.action.USER_REMOVED").putExtra(Intent.EXTRA_USER, user10);
    deliver(receiver, dpmCtx, removed);
    expect.that(findPausedNotification(context)).isNotNull();
    expect.that(newestAuditMessage(context, resumedType)).isEmpty();

    when(mockDpm.getSecondaryUsers(any())).thenReturn(null);
    deliver(receiver, dpmCtx, removed);
    deliver(receiver, dpmCtx, removed);
    expect.that(findPausedNotification(context)).isNull();
    expect.that(newestAuditMessage(context, resumedType)).contains("discarded by the platform");
    expect
        .that(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .filter(e -> e.getEventType().equals(resumedType))
                .count())
        .isEqualTo(1);
  }

  @Test
  public void retrieveLogs_asDelegate_pausesOnUnaffiliatedUserIgnoresRevocationAndResumes() {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    Context dpmCtx = createContextWrapper(context, mockDpm);
    String pkg = context.getPackageName();
    ImmutableList<String> sec = ImmutableList.of(DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    ImmutableList<String> net = ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING);

    when(mockDpm.getDelegatedScopes(null, pkg)).thenReturn(sec, ImmutableList.of(), sec);
    when(mockDpm.retrieveSecurityLogs(isNull())).thenThrow(new SecurityException("Blocked"));
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect.that(findPausedNotification(context)).isNull();
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect.that(findPausedNotification(context)).isNotNull();
    doReturn(null).when(mockDpm).retrieveSecurityLogs(isNull());
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect.that(findPausedNotification(context)).isNull();
    expect
        .that(
            newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_RESUMED))
        .contains("discarded by the platform");

    when(mockDpm.getDelegatedScopes(null, pkg)).thenReturn(net, ImmutableList.of(), net);
    when(mockDpm.retrieveNetworkLogs(isNull(), eq(7L))).thenThrow(new SecurityException("Blocked"));
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 7L, /* networkLogsCount= */ 1);
    expect.that(findPausedNotification(context)).isNull();
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 7L, /* networkLogsCount= */ 1);
    expect.that(findPausedNotification(context)).isNotNull();
    doReturn(null).when(mockDpm).retrieveNetworkLogs(isNull(), eq(7L));
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 7L, /* networkLogsCount= */ 1);
    expect.that(findPausedNotification(context)).isNull();
  }

  @Test
  public void retrieveLogs_detectsForwardSequenceGapsWithinSameSessionAndResetsOnNewSession()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    Context dpmCtx = createContextWrapper(context, mockDpm);

    when(mockDpm.retrieveSecurityLogs(any()))
        .thenReturn(
            ImmutableList.of(securityEventWithId(1L, SecurityLog.TAG_OS_STARTUP, "boot")),
            ImmutableList.of(securityEventWithId(4L, SecurityLog.TAG_OS_STARTUP, "after-gap")),
            ImmutableList.of(securityEventWithId(2L, SecurityLog.TAG_OS_STARTUP, "reset")),
            ImmutableList.of(securityEventWithId(1L, SecurityLog.TAG_OS_STARTUP, "re-enabled")));
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEmpty();

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .contains("Security log event ID gap detected (2..3 missing)");
    assertDeferredLogsNotificationPosted(context);

    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDeviceAdminReceiver.bumpNetworkLoggingEnableEpoch(context);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .contains("Security log event IDs reset (2 after 4)");

    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDeviceAdminReceiver.bumpSecurityLoggingEnableEpoch(context);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(dpmCtx);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEmpty();

    when(mockDpm.retrieveNetworkLogs(any(), anyLong())).thenReturn(ImmutableList.of());
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 10L, /* networkLogsCount= */ 1);
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 11L, /* networkLogsCount= */ 1);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEmpty();
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 14L, /* networkLogsCount= */ 1);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .contains("Network log batch token gap detected (12..13 missing)");
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 0L, /* networkLogsCount= */ 1);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .contains("Network log batch token reset (0 after 14)");
    Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 2);
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
        dpmCtx, /* batchToken= */ 1L, /* networkLogsCount= */ 1);
    expect
        .that(newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST))
        .isEmpty();
  }

  @Test
  public void bootCompletedBroadcast_reachesTheDeviceAdminReceiver() {
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

    assertThat(receivers).contains(CrumblesDeviceAdminReceiver.class.getName());
  }

  @Test
  public void onReceive_bootCompleted_savesPreRebootSecurityLogsInABatchOfTheirOwn()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(recipientKeyPair.getPublic());
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(
            new ComponentName(context, CrumblesDeviceAdminReceiver.class)))
        .thenReturn(
            ImmutableList.of(securityEvent(SecurityLog.TAG_ADB_SHELL_CMD, "pm clear com.example")));
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(null);

    deliverBootCompleted(receiver, createContextWrapper(context, mockDpm));

    String batch = decryptOnlyBatch(context, recipientKeyPair.getPrivate());
    expect
        .that(batch)
        .startsWith(
            "Crumbles: security logs that the platform kept from before the device restarted.");
    expect.that(batch).contains("ADB shell command: \n\"pm clear com.example\"\n");
  }

  @Test
  public void onReceive_bootCompleted_whenNoLogsWereKeptBeforeTheRestart_reportsNoLoss()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(any(ComponentName.class))).thenReturn(null);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(null);

    deliverBootCompleted(receiver, createContextWrapper(context, mockDpm));

    expect.that(savedBatches(context)).isEmpty();
    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(newestAuditMessage(context, AUDIT_EVENT_LOGS_LOST)).isEmpty();
  }

  @Test
  public void onReceive_bootCompleted_whenRetrievalIsRefused_retriesWithTheNextSecurityLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(admin)).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenThrow(new SecurityException("Not all users are affiliated"))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN, "")));
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(null, ImmutableList.of());
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);
    deliverBootCompleted(receiver, deviceOwnerContext);

    deliverSecurityLogs(receiver, deviceOwnerContext);

    verify(mockDpm, times(2)).retrievePreRebootSecurityLogs(admin);
    expect.that(savedBatches(context)).hasLength(2);
    expect.that(newestAuditMessage(context, AUDIT_EVENT_LOGS_LOST)).isEmpty();
  }

  @Test
  public void onReceive_bootCompleted_whenStorageIsLow_defersTheRetrieval() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isSecurityLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    long lowSpace = MIN_SECURITY_USABLE_SPACE_BYTES - 1;

    deliverBootCompleted(receiver, withUsableSpace(context, mockDpm, () -> lowSpace));

    verify(mockDpm, never()).retrievePreRebootSecurityLogs(any());
    verify(mockDpm, never()).retrieveSecurityLogs(any());
    expect
        .that(newestAuditMessage(context, "LOG_RETRIEVAL_DEFERRED"))
        .isEqualTo(
            "Security log retrieval deferred: insufficient usable storage ("
                + lowSpace
                + " bytes available).");
  }

  @Test
  public void onReceive_bootCompleted_retrievesTheSecurityLogsAnnouncedBeforeTheUnlock()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(admin)).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin)).thenReturn(null);
    when(mockDpm.retrieveSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_STARTUP, "boot")));

    deliverBootCompleted(receiver, createContextWrapper(context, mockDpm));

    verify(mockDpm).retrieveSecurityLogs(admin);
    expect.that(savedBatches(context)).hasLength(1);
  }

  @Test
  public void onReceive_bootCompleted_asSecurityLoggingDelegate_retrievesWithNullAdmin()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.getDelegatedScopes(null, context.getPackageName()))
        .thenReturn(ImmutableList.of(DevicePolicyManager.DELEGATION_SECURITY_LOGGING));
    when(mockDpm.isSecurityLoggingEnabled(isNull())).thenReturn(true);

    deliverBootCompleted(receiver, createContextWrapper(context, mockDpm));

    verify(mockDpm).retrievePreRebootSecurityLogs(isNull());
  }

  @Test
  public void onReceive_bootCompleted_asDeviceOwner_schedulesThePeriodicWork() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);

    deliverBootCompleted(receiver, createContextWrapper(context, mockDpm));

    assertThat(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
                .get())
        .hasSize(1);
  }

  @Test
  public void onReceive_bootCompleted_withoutLoggingAccess_neitherSchedulesWorkNorRetrievesLogs()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);

    deliverBootCompleted(receiver, createContextWrapper(context, mockDpm));

    verify(mockDpm, never()).retrievePreRebootSecurityLogs(any());
    assertThat(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
                .get())
        .isEmpty();
  }

  @Test
  public void onReceive_bootCompleted_whenOnlyNetworkLoggingIsOn_keepsTheSecondaryUserPause() {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesDeviceAdminReceiver.prefs(context)
        .edit()
        .putBoolean(CrumblesDeviceAdminReceiver.PREF_PAUSED_BY_SECONDARY_USER, true)
        .commit();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isNetworkLoggingEnabled(any(ComponentName.class))).thenReturn(true);
    when(mockDpm.getSecondaryUsers(any(ComponentName.class)))
        .thenReturn(ImmutableList.of(UserHandle.getUserHandleForUid(1000000)));
    // While security logging is off, the platform returns no logs instead of refusing.
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(null);
    // The periodic work that the boot schedules reads the device policy of the app itself.
    Shadows.shadowOf((Application) context)
        .setSystemService(Context.DEVICE_POLICY_SERVICE, mockDpm);

    deliverBootCompleted(receiver, context);

    expect
        .that(
            CrumblesDeviceAdminReceiver.prefs(context)
                .getBoolean(
                    CrumblesDeviceAdminReceiver.PREF_PAUSED_BY_SECONDARY_USER,
                    /* defValue= */ false))
        .isTrue();
    expect
        .that(
            newestAuditMessage(context, CrumblesDeviceAdminReceiver.AUDIT_EVENT_COLLECTION_RESUMED))
        .isEmpty();
  }

  @Test
  public void onReceive_bootCompleted_whenSecurityLoggingIsOff_neitherRetrievesNorDefersLogs() {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);

    deliverBootCompleted(
        receiver, withUsableSpace(context, mockDpm, () -> MIN_SECURITY_USABLE_SPACE_BYTES - 1));

    verify(mockDpm, never()).retrievePreRebootSecurityLogs(any());
    verify(mockDpm, never()).retrieveSecurityLogs(any());
    expect.that(newestAuditMessage(context, "LOG_RETRIEVAL_DEFERRED")).isEmpty();
    assertDeferredLogsNotificationNotPosted(context);
  }

  @Test
  public void onReceive_bootCompleted_savesTheLogsStagedBeforeTheRestart() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrieveSecurityLogs(any(ComponentName.class))).thenReturn(ImmutableList.of());
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
    deliverSecurityLogs(receiver, deviceOwnerContext);
    assertThat(new CrumblesLogStaging(context).isEmpty()).isFalse();
    saveNewExternalPublicKey(context);

    deliverBootCompleted(receiver, deviceOwnerContext);

    expect.that(new CrumblesLogStaging(context).isEmpty()).isTrue();
    expect.that(savedBatches(context)).hasLength(1);
  }

  @Test
  public void retrieveAndSaveSecurityLogs_savesPreRebootLogsAheadOfNewerLogs() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(recipientKeyPair.getPublic());
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(
            ImmutableList.of(securityEvent(SecurityLog.TAG_ADB_SHELL_CMD, "before the restart")));
    when(mockDpm.retrieveSecurityLogs(admin))
        .thenReturn(
            ImmutableList.of(securityEvent(SecurityLog.TAG_ADB_SHELL_CMD, "after the restart")));

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(createContextWrapper(context, mockDpm));

    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(2);
    expect
        .that(decryptWithPrivateKey(batches.get(0), recipientKeyPair.getPrivate()))
        .contains("\"before the restart\"");
    expect
        .that(decryptWithPrivateKey(batches.get(1), recipientKeyPair.getPrivate()))
        .contains("\"after the restart\"");
  }

  /**
   * Tests that the batch of logs kept from before the restart is bound to its recipient and seals
   * the attestation chain of this installation's batch-signing key, as every signed batch does.
   */
  @Test
  public void retrieveAndSaveSecurityLogs_sealsTheAttestationChainInThePreRebootBatch()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair recipientKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(recipientKeyPair.getPublic());
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(
            ImmutableList.of(securityEvent(SecurityLog.TAG_ADB_SHELL_CMD, "before the restart")));
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(null);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(createContextWrapper(context, mockDpm));

    ImmutableList<LogBatch> batches = writtenBatches(context);
    assertThat(batches).hasSize(1);
    LogBatch preRebootBatch = batches.get(0);
    // Like a recipient, sealedLogsOf binds the recipient's public key in the associated data.
    SealedLogs sealedLogs = sealedLogsOf(preRebootBatch, recipientKeyPair.getPrivate());
    expect.that(sealedLogs.getLogs().toStringUtf8()).contains("\"before the restart\"");
    expect.that(sealedLogs.getAttestationChainList()).isNotEmpty();
    expect
        .that(sealedLogs.getAttestationChainList())
        .containsExactlyElementsIn(new CrumblesBatchSigningKey(context).attestationChain())
        .inOrder();
    expect.that(preRebootBatch.getSignature().getAttestationChainList()).isEmpty();
    expect.that(isSignedByThisInstallation(preRebootBatch)).isTrue();
  }

  @Test
  public void retrieveAndSaveSecurityLogs_savesPreRebootLogsOncePerBoot() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN, "")));
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(new ArrayList<>());
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    verify(mockDpm).retrievePreRebootSecurityLogs(admin);
    expect.that(savedBatches(context)).hasLength(3);
  }

  @Test
  public void retrieveAndSaveSecurityLogs_afterAnotherRestart_savesThePreRebootLogsAgain()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN, "")));
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(new ArrayList<>());
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);
    Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 1);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 2);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    verify(mockDpm, times(2)).retrievePreRebootSecurityLogs(admin);
  }

  @Test
  public void retrieveAndSaveSecurityLogs_doesNotCheckPreRebootEventIdsForGaps() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    // Events kept from before the restart carry the IDs of the logging session before it.
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEventWithId(41L, SecurityLog.TAG_OS_SHUTDOWN, "")));
    when(mockDpm.retrieveSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEventWithId(0L, SecurityLog.TAG_OS_STARTUP, "boot")));

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(createContextWrapper(context, mockDpm));

    expect.that(savedBatches(context)).hasLength(2);
    expect.that(newestAuditMessage(context, AUDIT_EVENT_LOGS_LOST)).isEmpty();
  }

  @Test
  public void retrieveAndSaveSecurityLogs_whenTheDeviceKeepsNoLogsAcrossRestarts_asksOncePerBoot()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin)).thenReturn(null);
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(null);
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    verify(mockDpm).retrievePreRebootSecurityLogs(admin);
  }

  @Test
  public void retrieveAndSaveSecurityLogs_whenNoLogsWereKeptBeforeTheRestart_asksOncePerBoot()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    saveNewExternalPublicKey(context);
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin)).thenReturn(ImmutableList.of());
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(null);
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    verify(mockDpm).retrievePreRebootSecurityLogs(admin);
    expect.that(savedBatches(context)).isEmpty();
  }

  @Test
  public void retrieveAndSaveSecurityLogs_whenPreRebootLogsCannotBeKept_defersThemWithoutLoss()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    // Without an encryption key the logs are staged, and a file in place of the staging area makes
    // staging fail.
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
    assertThat(new File(context.getNoBackupFilesDir(), "staged_logs").createNewFile()).isTrue();
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN, "")));
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(null);

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(createContextWrapper(context, mockDpm));

    expect.that(newestAuditMessage(context, AUDIT_EVENT_LOGS_LOST)).isEmpty();
    expect
        .that(newestAuditMessage(context, "LOG_RETRIEVAL_DEFERRED"))
        .isEqualTo(
            "Pre-reboot security log batch of 1 event(s) was deferred: staging it failed. The"
                + " platform keeps it until the device restarts.");
    assertDeferredLogsNotificationPosted(context);
  }

  @Test
  public void retrieveAndSaveSecurityLogs_afterPreRebootLogsCouldNotBeKept_retriesThem()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(null);
    CrumblesMain.getLogsEncryptorInstance().setExternalEncryptionPublicKey(null);
    File blockedStagingArea = new File(context.getNoBackupFilesDir(), "staged_logs");
    assertThat(blockedStagingArea.createNewFile()).isTrue();
    ComponentName admin = new ComponentName(context, CrumblesDeviceAdminReceiver.class);
    DevicePolicyManager mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(admin))
        .thenReturn(ImmutableList.of(securityEvent(SecurityLog.TAG_OS_SHUTDOWN, "")));
    when(mockDpm.retrieveSecurityLogs(admin)).thenReturn(null);
    Context deviceOwnerContext = createContextWrapper(context, mockDpm);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);
    assertThat(blockedStagingArea.delete()).isTrue();

    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(deviceOwnerContext);

    verify(mockDpm, times(2)).retrievePreRebootSecurityLogs(admin);
    expect.that(new CrumblesLogStaging(context).countBatches()).isEqualTo(1);
  }

  /** Delivers the boot completed broadcast to {@code receiver} and waits until it is handled. */
  private static void deliverBootCompleted(BroadcastReceiver receiver, Context context) {
    deliver(receiver, context, new Intent(Intent.ACTION_BOOT_COMPLETED));
  }

  private static Notification findPausedNotification(Context context) {
    return Arrays.stream(
            context.getSystemService(NotificationManager.class).getActiveNotifications())
        .filter(n -> n.getId() == CrumblesConstants.COLLECTION_PAUSED_NOTIFICATION_ID)
        .map(StatusBarNotification::getNotification)
        .findFirst()
        .orElse(null);
  }
}
