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

import static com.android.securelogging.CrumblesSendAndMarkProcessingWorker.uploadSingleFile;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.robolectric.util.ReflectionHelpers.callInstanceMethod;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import androidx.annotation.Nullable;
import androidx.datastore.guava.GuavaDataStore;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.ListenableWorker.Result;
import androidx.work.testing.TestListenableWorkerBuilder;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.google.common.truth.Expect;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.ToIntFunction;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowNotificationManager;
import org.robolectric.shadows.ShadowSystemClock;
import org.robolectric.util.ReflectionHelpers.ClassParameter;

/** Unit tests for {@link CrumblesSendAndMarkProcessingWorker}. */
@RunWith(RobolectricTestRunner.class)
public class CrumblesSendAndMarkProcessingWorkerTest {
  private static final String DRIVE_AUTHORITY = "com.google.android.apps.docs.storage";
  private static final Uri VALID_DRIVE_URI =
      Uri.parse("content://" + DRIVE_AUTHORITY + "/tree/valid_drive");
  private static final EncryptedPayload ENCRYPTED_WEBDAV_SERVER_URL =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("enc_url")).build();
  private static final EncryptedPayload ENCRYPTED_WEBDAV_USERNAME =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("enc_user")).build();
  private static final EncryptedPayload ENCRYPTED_WEBDAV_PASSWORD =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("enc_pass")).build();
  private static final EncryptedPayload ENCRYPTED_WEBDAV_SERVER_KEY_SHA256 =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("enc_key")).build();

  private static final HeldCertificate testRootCertificate =
      new HeldCertificate.Builder().certificateAuthority(/* maxIntermediateCas= */ 0).build();
  private static final HeldCertificate serverCertificate =
      new HeldCertificate.Builder()
          .addSubjectAlternativeName("localhost")
          .signedBy(testRootCertificate)
          .build();

  /** Authorization header for the "user" and "pass" credentials that the tests store. */
  private static final String WEBDAV_AUTHORIZATION =
      "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes(UTF_8));

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private GuavaDataStore<UserKeyPreferences> testDataStore;
  private File testDirectory;
  private FakeGoogleDriveContentProvider fakeDriveProvider;

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;
  @Mock private PublicKey mockPublicKey;
  @Mock private PublicKey mockReplacementKey;

  /** Fake ContentProvider simulating Google Drive storage via Storage Access Framework. */
  public static class FakeGoogleDriveContentProvider extends ContentProvider {
    private File tempDriveDir;
    private boolean shouldFailStreaming;
    private boolean shouldCrashStreaming;
    private boolean isInvalidDirectory;
    @Nullable Runnable onOpenFile;

    /** Makes queries wait until {@link #release} opens, like a provider that never answers. */
    boolean holdsQueries;

    final CountDownLatch release = new CountDownLatch(1);

    public void setShouldFailStreaming(boolean fail) {
      this.shouldFailStreaming = fail;
    }

    /** Makes opening a document throw an unchecked exception, like a provider with a bug. */
    public void setShouldCrashStreaming(boolean crash) {
      this.shouldCrashStreaming = crash;
    }

    public void setIsInvalidDirectory(boolean invalid) {
      this.isInvalidDirectory = invalid;
    }

    @Override
    public boolean onCreate() {
      tempDriveDir = new File(getContext().getFilesDir(), "fake_remote_drive");
      tempDriveDir.mkdirs();
      return true;
    }

    @Override
    public Cursor query(
        Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
      if (holdsQueries) {
        try {
          release.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      if (isInvalidDirectory) {
        return null;
      }
      String[] columns =
          projection != null
              ? projection
              : new String[] {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_FLAGS,
              };
      MatrixCursor cursor = new MatrixCursor(columns);
      Object[] row = new Object[columns.length];
      for (int i = 0; i < columns.length; i++) {
        String col = columns[i];
        if (Objects.equals(col, DocumentsContract.Document.COLUMN_DOCUMENT_ID)) {
          row[i] = "valid_drive";
        } else if (Objects.equals(col, DocumentsContract.Document.COLUMN_MIME_TYPE)) {
          row[i] = DocumentsContract.Document.MIME_TYPE_DIR;
        } else if (Objects.equals(col, DocumentsContract.Document.COLUMN_FLAGS)) {
          row[i] =
              DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
                  | DocumentsContract.Document.FLAG_SUPPORTS_WRITE;
        }
      }
      cursor.addRow(row);
      return cursor;
    }

    @Override
    public Bundle call(String method, @Nullable String arg, @Nullable Bundle extras) {
      if (Objects.equals(method, "android:createDocument")) {
        String name =
            extras != null
                ? extras.getString(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    extras.getString(Intent.EXTRA_TITLE, "log.bin"))
                : "log.bin";
        File created = new File(tempDriveDir, name);
        try {
          created.createNewFile();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        Bundle res = new Bundle();
        res.putParcelable("uri", Uri.parse("content://" + DRIVE_AUTHORITY + "/document/" + name));
        return res;
      }
      if (Objects.equals(method, "android:isChildDocument")) {
        Bundle res = new Bundle();
        res.putBoolean("result", true);
        return res;
      }
      return null;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      if (onOpenFile != null) {
        onOpenFile.run();
      }
      if (shouldFailStreaming) {
        throw new FileNotFoundException("Simulated upload streaming failure");
      }
      if (shouldCrashStreaming) {
        throw new IllegalStateException("Simulated provider crash");
      }
      return ParcelFileDescriptor.open(
          new File(tempDriveDir, uri.getLastPathSegment()), ParcelFileDescriptor.MODE_READ_WRITE);
    }

    @Override
    public String getType(Uri uri) {
      return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
      return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
      return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
      return 0;
    }
  }

  private void deleteRecursive(File fileOrDirectory) {
    if (fileOrDirectory.isDirectory()) {
      File[] children = fileOrDirectory.listFiles();
      if (children != null) {
        for (File child : children) {
          deleteRecursive(child);
        }
      }
    }
    fileOrDirectory.delete();
  }

  @CanIgnoreReturnValue
  private File createFile(String namePrefix, long timestamp, String suffix, String content)
      throws IOException {
    String fileName = namePrefix + timestamp + suffix;
    File file = new File(testDirectory, fileName);
    Files.write(file.toPath(), content.getBytes(UTF_8));
    assertTrue("File should exist after creation: " + file.getAbsolutePath(), file.exists());
    return file;
  }

  @CanIgnoreReturnValue
  private Result runWorker() throws ExecutionException, InterruptedException {
    return runWorkerOnAttempt(/* runAttemptCount= */ 0);
  }

  private Result runWorkerOnAttempt(int runAttemptCount)
      throws ExecutionException, InterruptedException {
    return TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
        .setRunAttemptCount(runAttemptCount)
        .build()
        .startWork()
        .get();
  }

  /** Moves the clock past the transfer deadlines until {@code run} ends, and returns its result. */
  private static Result awaitPastDeadline(Future<Result> run) throws Exception {
    for (int attempt = 0; attempt < 100 && !run.isDone(); attempt++) {
      ShadowSystemClock.advanceBy(Duration.ofHours(1));
      Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
    }
    return run.get(/* timeout= */ 1, SECONDS);
  }

  private void configureDestination(Uri uri, boolean grantPermission) {
    if (grantPermission) {
      context.grantUriPermission(
          context.getPackageName(),
          uri,
          Intent.FLAG_GRANT_READ_URI_PERMISSION
              | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
              | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
      context
          .getContentResolver()
          .takePersistableUriPermission(
              uri, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    }
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, uri.toString())
        .commit();
  }

  /**
   * Stores a WebDAV destination whose server URL and username decrypt successfully. Each test
   * decides how the password decrypts.
   */
  private void configureWebDav(String serverUrl)
      throws CrumblesKeysException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_SERVER_URL, CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID))
        .thenReturn(serverUrl.getBytes(UTF_8));
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_USERNAME, CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
        .thenReturn("user".getBytes(UTF_8));
    testDataStore
        .updateDataAsync(
            preferences ->
                preferences.toBuilder()
                    .setRemoteStorageConfig(
                        RemoteStorageConfig.newBuilder()
                            .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
                            .setWebdavServerUrl(ENCRYPTED_WEBDAV_SERVER_URL)
                            .setWebdavCredentials(
                                WebDavCredentials.newBuilder()
                                    .setUsername(ENCRYPTED_WEBDAV_USERNAME)
                                    .setPassword(ENCRYPTED_WEBDAV_PASSWORD)))
                    .build())
        .get();
  }

  /**
   * Starts a localhost WebDAV server that answers each request carrying the stored credentials with
   * the status for its path, and any other request with 401.
   */
  private static HttpServer startWebDavServer(ToIntFunction<String> statusCodeForPath)
      throws IOException {
    HttpServer server =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.createContext(
        "/webdav",
        exchange -> {
          boolean isAuthorized =
              Objects.equals(
                  exchange.getRequestHeaders().getFirst("Authorization"), WEBDAV_AUTHORIZATION);
          exchange.sendResponseHeaders(
              isAuthorized
                  ? statusCodeForPath.applyAsInt(exchange.getRequestURI().getPath())
                  : HttpURLConnection.HTTP_UNAUTHORIZED,
              /* responseLength= */ -1);
          exchange.close();
        });
    server.start();
    return server;
  }

  /**
   * Starts a WebDAV server on this device whose uploads {@code handler} answers, each on a thread
   * of its own, so that a held upload does not hold the next.
   */
  private static HttpServer startWebDavServer(HttpHandler handler) throws IOException {
    HttpServer server =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.createContext("/webdav", handler);
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    return server;
  }

  /**
   * Stores a WebDAV destination at {@code serverUrl} whose pinned server key decrypts to {@code
   * pinnedKeySha256}, with credentials that decrypt successfully.
   */
  private void configurePinnedWebDav(String serverUrl, byte[] pinnedKeySha256) throws Exception {
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_SERVER_KEY_SHA256,
            CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID))
        .thenReturn(pinnedKeySha256);
    configureWebDav(serverUrl);
    testDataStore
        .updateDataAsync(
            preferences ->
                preferences.toBuilder()
                    .setRemoteStorageConfig(
                        preferences.getRemoteStorageConfig().toBuilder()
                            .setWebdavServerKeySha256(ENCRYPTED_WEBDAV_SERVER_KEY_SHA256))
                    .build())
        .get();
  }

  private static byte[] sha256(PublicKey key) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
  }

  /**
   * Starts a localhost WebDAV server over TLS that presents {@link #serverCertificate}, answers
   * every request with 201 and records whether any request reached it in {@code requestReceived}.
   */
  static HttpsServer startHttpsWebDavServer(AtomicBoolean requestReceived) throws IOException {
    return startHttpsWebDavServer(requestReceived, new AtomicInteger());
  }

  private static HttpsServer startHttpsWebDavServer(
      AtomicBoolean requestReceived, AtomicInteger handshakesAttempted) throws IOException {
    HttpsServer server =
        HttpsServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.setHttpsConfigurator(
        new HttpsConfigurator(
            new HandshakeCertificates.Builder()
                .heldCertificate(serverCertificate)
                .build()
                .sslContext()) {
          @Override
          public void configure(HttpsParameters params) {
            handshakesAttempted.incrementAndGet();
          }
        });
    server.createContext(
        "/webdav",
        exchange -> {
          requestReceived.set(true);
          exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, /* responseLength= */ -1);
          exchange.close();
        });
    server.start();
    return server;
  }

  /**
   * Security provider whose default {@link TrustManagerFactory} trusts {@link #testRootCertificate}
   * alone, so that it stands in for the platform's CA store.
   */
  static final class TestRootTrustProvider extends Provider {
    static final String NAME = "CrumblesTestRootTrust";

    @SuppressWarnings("deprecation") // Android lacks Provider(String, String, String).
    TestRootTrustProvider() {
      super(NAME, 1.0, "Trusts only the test root CA");
      TrustManager testRootTrustManager =
          new HandshakeCertificates.Builder()
              .addTrustedCertificate(testRootCertificate.certificate())
              .build()
              .trustManager();
      putService(
          new Service(
              this,
              "TrustManagerFactory",
              TrustManagerFactory.getDefaultAlgorithm(),
              FixedTrustManagerFactorySpi.class.getName(),
              /* aliases= */ null,
              /* attributes= */ null) {
            @Override
            public Object newInstance(Object constructorParameter) {
              return new FixedTrustManagerFactorySpi(testRootTrustManager);
            }
          });
    }
  }

  private static final class FixedTrustManagerFactorySpi extends TrustManagerFactorySpi {
    private final TrustManager trustManager;
    private boolean initialized;

    FixedTrustManagerFactorySpi(TrustManager trustManager) {
      this.trustManager = trustManager;
    }

    @Override
    protected void engineInit(KeyStore keyStore) {
      initialized = true;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters parameters) {}

    @Override
    protected TrustManager[] engineGetTrustManagers() {
      return initialized ? new TrustManager[] {trustManager} : new TrustManager[0];
    }
  }

  /** Returns whether an upload time is recorded for {@code sentFile}, so that it expires by age. */
  private boolean hasRecordedUploadTime(File sentFile) {
    return context
        .getSharedPreferences(CrumblesDeleteSentFilesWorker.RETENTION_PREFS, Context.MODE_PRIVATE)
        .contains(sentFile.getName());
  }

  private void assertNotificationPosted() {
    NotificationManager nm =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    ShadowNotificationManager snm = Shadows.shadowOf(nm);
    assertThat(snm.size()).isGreaterThan(0);

    NotificationChannel channel =
        nm.getNotificationChannel(CrumblesConstants.NOTIFICATION_CHANNEL_ID);
    assertThat(channel).isNotNull();
    assertThat(channel.getDescription()).isEqualTo("Status updates for background sync tasks.");
    assertThat(channel.getLockscreenVisibility()).isEqualTo(Notification.VISIBILITY_SECRET);

    Notification notification =
        snm.getNotification(CrumblesConstants.UPLOAD_NOTIFICATION_ID);
    assertThat(notification).isNotNull();
    assertThat(notification.flags & Notification.FLAG_ONGOING_EVENT)
        .isEqualTo(Notification.FLAG_ONGOING_EVENT);
    assertThat(notification.flags & Notification.FLAG_ONLY_ALERT_ONCE)
        .isEqualTo(Notification.FLAG_ONLY_ALERT_ONCE);
    assertThat(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);

    assertThat(notification.contentIntent).isNotNull();
    Intent savedIntent = Shadows.shadowOf(notification.contentIntent).getSavedIntent();
    assertThat(savedIntent).isNotNull();
    assertThat(
            savedIntent.getFlags()
                & (Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP))
        .isEqualTo(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    assertThat(savedIntent.getComponent().getClassName()).isEqualTo(CrumblesMain.class.getName());

    assertThat(notification.icon).isEqualTo(android.R.drawable.stat_notify_error);
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    context = ApplicationProvider.getApplicationContext();
    ShadowLog.stream = System.out;

    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    when(mockLogsEncryptor.getPublicKey()).thenReturn(mockPublicKey);
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);
    // The key preferences store is authenticated with a Keystore key.
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    testDataStore = CrumblesDataStoreHolder.getInstance(context);
    testDataStore.updateDataAsync(preferences -> UserKeyPreferences.getDefaultInstance()).get();
    fakeDriveProvider =
        Robolectric.setupContentProvider(FakeGoogleDriveContentProvider.class, DRIVE_AUTHORITY);

    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit();

    File baseDir = context.getFilesDir();
    testDirectory = new File(baseDir, CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (testDirectory.exists()) {
      deleteRecursive(testDirectory);
    }
    assertTrue("Test directory should be created", testDirectory.mkdirs());
  }

  @After
  public void tearDown() {
    if (testDirectory != null && testDirectory.exists()) {
      deleteRecursive(testDirectory);
    }
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    Security.removeProvider(TestRootTrustProvider.NAME);
  }

  @Test
  public void doWork_whenNoKeyAvailable_preservesLogsAndReturnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(
        "Encrypted log file must be preserved when key is unavailable", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_DEFERRED_NO_KEY"),
            eq(
                "Upload deferred because active encryption key is unavailable; logs preserved on"
                    + " disk."));
    assertNotificationPosted();
    Notification notification =
        Shadows.shadowOf(context.getSystemService(NotificationManager.class))
            .getNotification(CrumblesConstants.UPLOAD_NOTIFICATION_ID);
    expect
        .that(Shadows.shadowOf(notification).getContentTitle().toString())
        .isEqualTo(context.getString(R.string.notification_title_action_needed));
    expect
        .that(Shadows.shadowOf(notification).getContentText().toString())
        .isEqualTo(context.getString(R.string.notification_text_action_needed));
  }

  @Test
  public void doWork_whenStillDeferredOnLastAttempt_waitsForNextPeriodAndKeepsLogs()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorkerOnAttempt(CrumblesSendAndMarkProcessingWorker.MAX_RUN_ATTEMPTS - 1);

    expect.that(result).isEqualTo(Result.failure());
    expect.that(fileToProcess.exists()).isTrue();
  }

  @Test
  public void doWork_whenDeferredBeforeLastAttempt_retries()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorkerOnAttempt(CrumblesSendAndMarkProcessingWorker.MAX_RUN_ATTEMPTS - 2);

    assertThat(result).isEqualTo(Result.retry());
  }

  @Test
  public void doWork_whenUploadSucceedsOnLastAttempt_succeeds()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorkerOnAttempt(CrumblesSendAndMarkProcessingWorker.MAX_RUN_ATTEMPTS - 1);

    assertThat(result).isEqualTo(Result.success());
  }

  @Test
  public void doWork_whenSameDeferralRepeats_logsItOnceAndPostsItAgain()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    runWorker();
    NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
    notificationManager.cancelAll();

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(Shadows.shadowOf(notificationManager).getAllNotifications()).hasSize(1);
    verify(mockAuditLogger).logEvent(eq("LOGS_UPLOAD_DEFERRED_NO_KEY"), anyString());
  }

  @Test
  public void doWork_whenWebDavPasswordDecryptionKeepsFailing_logsItOnceAndPostsItAgain()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenThrow(new CrumblesKeysException("Simulated decryption failure"));
    configureWebDav("https://webdav.example.com/");
    createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    runWorker();
    NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
    notificationManager.cancelAll();

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(Shadows.shadowOf(notificationManager).getAllNotifications()).hasSize(1);
    verify(mockAuditLogger).logEvent(eq("UPLOAD_CREDENTIALS_DECRYPTION_FAILED"), anyString());
  }

  @Test
  public void doWork_whenDeferralReasonChanges_reportsNewReason()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    runWorker();
    context.getSystemService(NotificationManager.class).cancelAll();
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_NOT_CONFIGURED"),
            eq("Upload deferred: destination folder is not configured."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenDeferralRecursAfterSuccessfulUpload_reportsItAgain()
      throws IOException, ExecutionException, InterruptedException {
    long timestamp = InstantSource.system().instant().toEpochMilli();
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    createFile("log1_", timestamp, ".bin", "c1");
    runWorker();
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    assertEquals(Result.success(), runWorker());
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    createFile("log2_", timestamp + 10, ".bin", "c2");
    context.getSystemService(NotificationManager.class).cancelAll();

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    verify(mockAuditLogger, times(2)).logEvent(eq("LOGS_UPLOAD_DEFERRED_NO_KEY"), anyString());
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenSingleStaleProcessingFileExists_recoversFileToBin()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File staleFile =
        createFile(
            "log_",
            InstantSource.system().instant().toEpochMilli(),
            CrumblesConstants.PROCESSING_SUFFIX,
            "content");

    runWorker();

    assertFalse(staleFile.exists());
    File recoveredFile =
        new File(
            testDirectory,
            staleFile.getName().replace(CrumblesConstants.PROCESSING_SUFFIX, ".bin"));
    assertTrue("Stale processing file must be recovered to .bin", recoveredFile.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_RECOVERED_PROCESSING"),
            eq("Recovered 1 stale processing log file(s) for upload retry."));
  }

  @Test
  public void doWork_whenMultipleStaleProcessingFilesExist_recoversAllFilesToBin()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File file1 =
        createFile(
            "log1_",
            InstantSource.system().instant().toEpochMilli(),
            CrumblesConstants.PROCESSING_SUFFIX,
            "c1");
    File file2 =
        createFile(
            "log2_",
            InstantSource.system().instant().plusMillis(10).toEpochMilli(),
            CrumblesConstants.PROCESSING_SUFFIX,
            "c2");

    runWorker();

    assertFalse(file1.exists());
    assertFalse(file2.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_RECOVERED_PROCESSING"),
            eq("Recovered 2 stale processing log file(s) for upload retry."));
  }

  @Test
  public void doWork_whenStaleRecoveryRenameFails_doesNotLogAuditEvent()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    createFile(
        "log_",
        InstantSource.system().instant().toEpochMilli(),
        CrumblesConstants.PROCESSING_SUFFIX,
        "content");

    testDirectory.setWritable(false);
    try {
      runWorker();
      verify(mockAuditLogger, never())
          .logEvent(eq("LOGS_UPLOAD_RECOVERED_PROCESSING"), anyString());
    } finally {
      testDirectory.setWritable(true);
    }
  }

  @Test
  public void doWork_whenDestinationNotConfigured_returnsRetryAndPreservesLogFiles()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue("Original log file must be preserved without data loss", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_NOT_CONFIGURED"),
            eq("Upload deferred: destination folder is not configured."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenDestinationPermissionMissing_returnsRetryAndPreservesLogFiles()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ false);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(
        "Original log file must be preserved on permission check failure", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_PERMISSION_REVOKED"),
            eq("Upload failed because persistable write permission was missing or revoked."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenDestinationPermissionGrantedButDirectoryInvalid_returnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    fakeDriveProvider.setIsInvalidDirectory(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue("Original file must be preserved", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_INVALID"),
            eq("Upload deferred: destination folder is inaccessible or unwritable."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenFolderProviderNeverAnswers_reportsTheFolderInaccessibleAtTheDeadline()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    String heldAuthority = "com.android.securelogging.test.held";
    FakeGoogleDriveContentProvider heldProvider =
        Robolectric.setupContentProvider(FakeGoogleDriveContentProvider.class, heldAuthority);
    heldProvider.holdsQueries = true;
    configureDestination(
        Uri.parse("content://" + heldAuthority + "/tree/valid_drive"), /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    ExecutorService workerThread = Executors.newSingleThreadExecutor();
    try {
      Future<Result> run = workerThread.submit(this::runWorker);

      Result result = awaitPastDeadline(run);

      expect.that(result).isEqualTo(Result.retry());
      expect.that(fileToProcess.exists()).isTrue();
      verify(mockAuditLogger)
          .logEvent(
              eq("UPLOAD_DESTINATION_INVALID"),
              eq("Upload deferred: destination folder is inaccessible or unwritable."));
    } finally {
      heldProvider.release.countDown();
      workerThread.shutdownNow();
    }
  }

  @Test
  public void doWork_whenUploadSucceeds_streamsFileAndMarksSentWithoutNotifying()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.success(), result);
    assertFalse(fileToProcess.exists());
    File sentFile =
        new File(
            testDirectory, fileToProcess.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX));
    assertTrue("Uploaded file must be marked as sent", sentFile.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_SUCCESS"),
            eq("Successfully automatically uploaded 1 log file(s) to the upload folder."));
    expect
        .that(
            Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                .getAllNotifications())
        .isEmpty();
  }

  @Test
  public void doWork_whenUploadSucceedsAfterReportedIssue_withdrawsIssueNotification()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    runWorker();
    assertNotificationPosted();
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.success());
    expect
        .that(
            Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                .getAllNotifications())
        .isEmpty();
  }

  @Test
  public void doWork_whenUploadSucceeds_keepsTheTimeTheBatchWasWritten()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    Instant writtenAt = Instant.parse("2026-01-02T03:04:05Z");
    assertTrue(fileToProcess.setLastModified(writtenAt.toEpochMilli()));

    runWorker();

    File sentFile =
        new File(
            testDirectory, fileToProcess.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX));
    assertThat(Instant.ofEpochMilli(sentFile.lastModified())).isEqualTo(writtenAt);
    // SAF copies never expire by age, so their upload time is not recorded.
    assertThat(hasRecordedUploadTime(sentFile)).isFalse();
  }

  @Test
  public void doWork_whenStreamingFails_rollsBackFileAndNotifiesUser()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    fakeDriveProvider.setShouldFailStreaming(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue("File must be rolled back to original .bin for retry", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_FAILED"),
            eq("One or more log files failed to upload; preserved safely on device for retry."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenProviderThrowsUncheckedException_keepsBatchPendingAndReportsFailure()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    fakeDriveProvider.setShouldCrashStreaming(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(fileToProcess.exists()).isTrue();
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_FAILED"),
            eq("One or more log files failed to upload; preserved safely on device for retry."));
    assertNotificationPosted();
  }

  @Test
  public void uploadSingleFile_whenUploaderThrows_restoresBatchForRetry() throws Exception {
    RemoteStorageUploader uploader = mock(RemoteStorageUploader.class);
    when(uploader.uploadFile(any(), any(), any()))
        .thenThrow(new IllegalStateException("Simulated uploader crash"));
    File batch =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    assertThrows(
        IllegalStateException.class,
        () ->
            CrumblesSendAndMarkProcessingWorker.uploadSingleFile(
                context, uploader, batch, testDirectory));

    // The batch is pending again under its own name, and is never marked as sent.
    expect.that(testDirectory.list()).asList().containsExactly(batch.getName());
  }

  @Test
  public void doWork_whenFileCannotBeRenamedToProcessing_returnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    testDirectory.setWritable(false);
    try {
      Result result = runWorker();
      assertEquals(Result.retry(), result);
      assertTrue("Original log file must be preserved on rename failure", fileToProcess.exists());
    } finally {
      testDirectory.setWritable(true);
    }
  }

  @Test
  public void doWork_noUnprocessedFiles_returnsSuccess()
      throws ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    Result result = runWorker();
    assertEquals(Result.success(), result);
  }

  @Test
  public void doWork_whenStagedBatchRemainsAfterUpload_returnsRetry() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    // Reading a directory fails as an I/O error would, so the drain keeps this staged batch.
    assertTrue(
        new File(context.getNoBackupFilesDir(), "staged_logs/0000000000000000001-S.sealed")
            .mkdirs());

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(fileToProcess.exists()).isFalse();
  }

  @Test
  public void doWork_whenKeyChangesDuringUpload_drainsStagedBatchToTheNewKey() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    AtomicReference<PublicKey> activeKey = new AtomicReference<>(mockPublicKey);
    when(mockLogsEncryptor.getPublicKey()).thenAnswer(invocation -> activeKey.get());
    CrumblesLogStaging staging = new CrumblesLogStaging(context);
    assertTrue(staging.stage(/* isNetworkBatch= */ false, "staged".getBytes(UTF_8)));
    // The user replaces the key while the pending batch uploads.
    HttpServer server =
        startWebDavServer(
            path -> {
              activeKey.set(mockReplacementKey);
              return 201;
            });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
      // The drain reads the activity log for the batch, which the mock logger cannot provide.
      CrumblesAppAuditLogger.setInstanceForTest(null);

      runWorker();

      verify(mockLogsEncryptor).encryptLogs(any(), any(), eq(mockReplacementKey), any(), any());
      verify(mockLogsEncryptor, never()).encryptLogs(any(), any(), eq(mockPublicKey), any(), any());
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenOnlyTempFileExists_doesNotUploadIt()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File tempFile =
        createFile(
            "log_",
            InstantSource.system().instant().toEpochMilli(),
            ".bin.partial" + CrumblesConstants.TEMP_FILE_SUFFIX,
            "partially written batch");

    Result result = runWorker();

    assertEquals(Result.success(), result);
    assertTrue("Temp file must be left for its writer", tempFile.exists());
    verify(mockAuditLogger, never()).logEvent(eq("LOGS_UPLOAD_SUCCESS"), anyString());
  }

  @Test
  public void doWork_whenWebDavConfigured_uploadsSuccessfullyAndMarksSent() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    HttpServer server = startWebDavServer(path -> 201);
    try {
      String serverUrl = "http://localhost:" + server.getAddress().getPort() + "/webdav";
      configureWebDav(serverUrl);
      File fileToProcess =
          createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

      Result result = runWorker();

      assertEquals(Result.success(), result);
      assertFalse(fileToProcess.exists());
      File sentFile =
          new File(
              testDirectory,
              fileToProcess.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX));
      assertTrue("Uploaded file must be marked as sent", sentFile.exists());
      expect.that(hasRecordedUploadTime(sentFile)).isTrue();
      verify(mockAuditLogger)
          .logEvent(
              eq("LOGS_UPLOAD_SUCCESS"),
              eq("Successfully automatically uploaded 1 log file(s) to WebDAV server."));
      expect
          .that(
              Shadows.shadowOf(context.getSystemService(NotificationManager.class))
                  .getAllNotifications())
          .isEmpty();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenWebDavCredentialsMissing_returnsRetryAndNotifiesUser() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    testDataStore
        .updateDataAsync(
            preferences ->
                preferences.toBuilder()
                    .setRemoteStorageConfig(
                        RemoteStorageConfig.newBuilder()
                            .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
                            .setWebdavServerUrl(ENCRYPTED_WEBDAV_SERVER_URL))
                    .build())
        .get();

    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_NOT_CONFIGURED"),
            eq("Upload deferred: WebDAV server URL or credentials not configured."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenWebDavPasswordCannotBeDecrypted_returnsRetryAndNotifiesUser()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenThrow(new CrumblesKeysException("Simulated decryption failure"));
    configureWebDav("https://webdav.example.com/");
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_CREDENTIALS_DECRYPTION_FAILED"),
            eq("Upload deferred: the saved WebDAV credentials could not be decrypted."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenWebDavServerUrlCannotBeDecrypted_returnsRetryAndNotifiesUser()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    configureWebDav("https://webdav.example.com/");
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_SERVER_URL, CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID))
        .thenThrow(new CrumblesKeysException("Simulated decryption failure"));
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_CREDENTIALS_DECRYPTION_FAILED"),
            eq("Upload deferred: the saved WebDAV credentials could not be decrypted."));
    assertNotificationPosted();
  }

  @Test
  public void doWork_whenSomeWebDavUploadsFail_postsNeutralFailureNotification() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    long timestamp = InstantSource.system().instant().toEpochMilli();
    createFile("log_", timestamp, ".bin", "uploaded");
    File failingFile = createFile("log_", timestamp + 1, ".bin", "failing");
    HttpServer server = startWebDavServer(path -> path.endsWith(failingFile.getName()) ? 500 : 201);
    try {
      String serverUrl = "http://localhost:" + server.getAddress().getPort() + "/webdav";
      configureWebDav(serverUrl);

      Result result = runWorker();

      assertEquals(Result.retry(), result);
      assertNotificationPosted();
      Notification notification =
          Shadows.shadowOf(context.getSystemService(NotificationManager.class))
              .getNotification(CrumblesConstants.UPLOAD_NOTIFICATION_ID);
      expect
          .that(Shadows.shadowOf(notification).getContentTitle().toString())
          .isEqualTo(context.getString(R.string.notification_title_upload_interrupted));
      expect
          .that(Shadows.shadowOf(notification).getContentText().toString())
          .isEqualTo(context.getString(R.string.notification_text_upload_failed));
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenWebDavUploadFails_triesItOnlyOnceInTheRun() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    List<String> uploadedPaths = new ArrayList<>();
    HttpServer server =
        startWebDavServer(
            path -> {
              uploadedPaths.add(path);
              return HttpURLConnection.HTTP_INTERNAL_ERROR;
            });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      File failingFile =
          createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.retry());
      // The failed batch waits for the backoff rather than being uploaded again in this run.
      expect.that(uploadedPaths).hasSize(1);
      expect.that(failingFile.exists()).isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenWebDavServerDropsTheConnection_stopsTheRunAfterTheFirstBatch()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    AtomicInteger requestCount = new AtomicInteger();
    HttpServer server =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.createContext(
        "/webdav",
        exchange -> {
          requestCount.incrementAndGet();
          // Closing the exchange before any response closes the connection.
          exchange.close();
        });
    server.start();
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      long timestamp = InstantSource.system().instant().toEpochMilli();
      File firstFile = createFile("log_", timestamp, ".bin", "first");
      File secondFile = createFile("log_", timestamp + 1, ".bin", "second");

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.retry());
      expect.that(requestCount.get()).isEqualTo(1);
      expect.that(firstFile.exists()).isTrue();
      expect.that(secondFile.exists()).isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenWebDavServerHoldsPinnedKey_uploadsAndMarksSent() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    HttpsServer server = startHttpsWebDavServer(new AtomicBoolean());
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      configurePinnedWebDav(
          "https://localhost:" + server.getAddress().getPort() + "/webdav",
          sha256(serverCertificate.keyPair().getPublic()));
      File fileToProcess =
          createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.success());
      expect
          .that(
              new File(
                      testDirectory,
                      fileToProcess.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX))
                  .exists())
          .isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenWebDavServerPresentsAnotherKey_keepsBatchAndReportsKeyChange()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    AtomicBoolean requestReceived = new AtomicBoolean();
    AtomicInteger handshakesAttempted = new AtomicInteger();
    HttpsServer server = startHttpsWebDavServer(requestReceived, handshakesAttempted);
    Security.insertProviderAt(new TestRootTrustProvider(), 1);
    try {
      configurePinnedWebDav(
          "https://localhost:" + server.getAddress().getPort() + "/webdav",
          sha256(KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic()));
      long timestamp = InstantSource.system().instant().toEpochMilli();
      File fileToProcess = createFile("log_", timestamp, ".bin", "content");
      File secondFile = createFile("log_", timestamp + 1, ".bin", "content2");

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.retry());
      expect.that(fileToProcess.exists()).isTrue();
      expect.that(secondFile.exists()).isTrue();
      // Stops after the first rejected handshake rather than reconnecting for remaining batches.
      expect.that(handshakesAttempted.get()).isEqualTo(1);
      // Requests carry the credentials, so none may reach a server that lacks the pinned key.
      expect.that(requestReceived.get()).isFalse();
      verify(mockAuditLogger)
          .logEvent(
              eq("UPLOAD_SERVER_KEY_REJECTED"),
              eq(
                  "Upload refused: the WebDAV server presented a public key other than the pinned"
                      + " one; logs preserved on disk."));
      Notification notification =
          Shadows.shadowOf(context.getSystemService(NotificationManager.class))
              .getNotification(CrumblesConstants.UPLOAD_NOTIFICATION_ID);
      expect
          .that(Shadows.shadowOf(notification).getContentText().toString())
          .isEqualTo(context.getString(R.string.notification_text_upload_server_key_changed));
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenPinnedWebDavServerKeyIsNotADigest_reportsUnreadableSettings()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configurePinnedWebDav("https://webdav.example.com/", new byte[31]);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(fileToProcess.exists()).isTrue();
    verify(mockAuditLogger).logEvent(eq("UPLOAD_CREDENTIALS_DECRYPTION_FAILED"), anyString());
  }

  @Test
  public void doWork_whenHttpsWebDavServerKeyWasNeverConfirmed_keepsBatchAndAsksToConfirmIt()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    // Like settings saved before servers were pinned, these hold no pinned key.
    configureWebDav("https://webdav.example.com/");
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(fileToProcess.exists()).isTrue();
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_SERVER_KEY_NOT_CONFIRMED"),
            eq(
                "Upload refused: no confirmed key for the HTTPS WebDAV server; logs preserved on"
                    + " disk."));
    Notification notification =
        Shadows.shadowOf(context.getSystemService(NotificationManager.class))
            .getNotification(CrumblesConstants.UPLOAD_NOTIFICATION_ID);
    expect
        .that(Shadows.shadowOf(notification).getContentText().toString())
        .isEqualTo(context.getString(R.string.notification_text_upload_server_key_not_confirmed));
  }

  @Test
  public void resolveStorageUploader_whenWebDavConfigured_returnsWebDavUploader() throws Exception {
    configurePinnedWebDav("https://webdav.example.com/", new byte[32]);

    RemoteStorageUploader uploader =
        CrumblesSendAndMarkProcessingWorker.resolveStorageUploader(context);

    assertThat(uploader).isNotNull();
    assertThat(uploader.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
  }

  @Test
  public void doWork_whenWebDavConfigured_wipesDecryptedCredentialsAndStillAuthenticates()
      throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    byte[] decryptedUsername = "user".getBytes(UTF_8);
    byte[] decryptedPassword = "pass".getBytes(UTF_8);
    HttpServer server = startWebDavServer(path -> 201);
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      when(mockLogsEncryptor.decryptDataStoreEntry(
              ENCRYPTED_WEBDAV_USERNAME, CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
          .thenReturn(decryptedUsername);
      when(mockLogsEncryptor.decryptDataStoreEntry(
              ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
          .thenReturn(decryptedPassword);
      createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.success());
      expect.that(decryptedUsername).isEqualTo(new byte[decryptedUsername.length]);
      expect.that(decryptedPassword).isEqualTo(new byte[decryptedPassword.length]);
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void resolveStorageUploader_whenPasswordCannotBeDecrypted_wipesDecryptedUsername()
      throws Exception {
    byte[] decryptedUsername = "user".getBytes(UTF_8);
    configureWebDav("https://webdav.example.com/");
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_USERNAME, CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
        .thenReturn(decryptedUsername);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenThrow(new CrumblesKeysException("Simulated decryption failure"));

    RemoteStorageUploader uploader =
        CrumblesSendAndMarkProcessingWorker.resolveStorageUploader(context);

    expect.that(uploader).isNull();
    expect.that(decryptedUsername).isEqualTo(new byte[decryptedUsername.length]);
  }

  @Test
  public void doWork_uploadsOldestFirst_whenNamesSortDifferently() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));

    List<String> uploadedPaths = new ArrayList<>();
    HttpServer server =
        startWebDavServer(
            path -> {
              uploadedPaths.add(path);
              return 201;
            });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");

      long now = InstantSource.system().instant().toEpochMilli();
      // file C is oldest, file A is middle, file B is newest
      File fileC = createFile("file_C_", now - 2000, ".bin", "c1");
      fileC.setLastModified(now - 2000);
      File fileA = createFile("file_A_", now - 1000, ".bin", "c2");
      fileA.setLastModified(now - 1000);
      File fileB = createFile("file_B_", now, ".bin", "c3");
      fileB.setLastModified(now);

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.success());
      expect.that(uploadedPaths).hasSize(3);
      expect.that(uploadedPaths.get(0)).endsWith("file_C_" + (now - 2000) + ".bin");
      expect.that(uploadedPaths.get(1)).endsWith("file_A_" + (now - 1000) + ".bin");
      expect.that(uploadedPaths.get(2)).endsWith("file_B_" + now + ".bin");
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenABatchFailsInTransit_uploadsTheNewerBatchOnTheNextRun() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
    long now = InstantSource.system().instant().toEpochMilli();
    File failingFile = createFile("log_", now - 2000, ".bin", "dropped");
    assertTrue(failingFile.setLastModified(now - 2000));
    File newerFile = createFile("log_", now - 1000, ".bin", "newer");
    assertTrue(newerFile.setLastModified(now - 1000));
    HttpServer server =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.createContext(
        "/webdav",
        exchange -> {
          if (!exchange.getRequestURI().getPath().endsWith(failingFile.getName())) {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, /* responseLength= */ -1);
          }
          // Closing the exchange before any response closes the connection.
          exchange.close();
        });
    server.start();
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      runWorker();

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.retry());
      expect.that(failingFile.exists()).isTrue();
      expect
          .that(
              new File(
                      testDirectory,
                      newerFile.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX))
                  .exists())
          .isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenTheClockWasSetBack_stillRetriesTheFailedBatchAfterTheOthers()
      throws Exception {
    givenWebDavPassword();
    long now = InstantSource.system().instant().toEpochMilli();
    File failingFile = createFile("log_", now - 2000, ".bin", "dropped");
    assertTrue(failingFile.setLastModified(now - 2000));
    // Written a day ahead of the clock, as when the clock was set back since.
    File newerFile = createFile("log_", now - 1000, ".bin", "newer");
    assertTrue(newerFile.setLastModified(now + Duration.ofDays(1).toMillis()));
    HttpServer server =
        startWebDavServer(exchange -> {
          if (!exchange.getRequestURI().getPath().endsWith(failingFile.getName())) {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, -1);
          }
          // Closing the exchange before any response closes the connection.
          exchange.close();
        });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      runWorker();

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.retry());
      expect.that(failingFile.exists()).isTrue();
      expect.that(sentCopyOf(newerFile).exists()).isTrue();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenARunWasKilledMidUpload_retriesItsBatchAfterTheNewerOnes()
      throws Exception {
    givenWebDavPassword();
    long now = InstantSource.system().instant().toEpochMilli();
    // The upload of a batch too large for the link can be what killed the run.
    File interruptedFile =
        createFile("log_", now - 2000, CrumblesConstants.PROCESSING_SUFFIX, "interrupted");
    assertTrue(interruptedFile.setLastModified(now - 2000));
    File newerFile = createFile("log_", now - 1000, ".bin", "newer");
    assertTrue(newerFile.setLastModified(now - 1000));
    List<String> uploadedNames = Collections.synchronizedList(new ArrayList<>());
    HttpServer server =
        startWebDavServer(exchange -> {
          String path = exchange.getRequestURI().getPath();
          uploadedNames.add(path.substring(path.lastIndexOf('/') + 1));
          exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, -1);
          exchange.close();
        });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.success());
      expect
          .that(uploadedNames)
          .containsExactly(newerFile.getName(), "log_" + (now - 2000) + ".bin")
          .inOrder();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenALargeBatchIsCutOffMidBody_stillUploadsTheSmallerBatchBehindIt()
      throws Exception {
    givenWebDavPassword();
    long now = InstantSource.system().instant().toEpochMilli();
    // More than the socket buffers hold, so that the upload blocks once the server stops reading.
    File largeFile = createFile("log_", now - 2000, ".bin", "");
    Files.write(largeFile.toPath(), new byte[32 << 20]);
    assertTrue(largeFile.setLastModified(now - 2000));
    File smallFile = createFile("log_", now - 1000, ".bin", "small");
    assertTrue(smallFile.setLastModified(now - 1000));
    CountDownLatch largeUploadStarted = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    HttpServer server =
        startWebDavServer(exchange -> {
          if (exchange.getRequestURI().getPath().endsWith(largeFile.getName())) {
            // Reads none of the body, like a link too slow for it.
            largeUploadStarted.countDown();
            try {
              release.await(10, SECONDS);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          } else {
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, -1);
          }
          exchange.close();
        });
    ExecutorService workerThread = Executors.newSingleThreadExecutor();
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      Future<Result> run = workerThread.submit(this::runWorker);
      assertThat(largeUploadStarted.await(10, SECONDS)).isTrue();
      // Lets the upload fill the socket buffers before the clock moves past its last progress.
      Uninterruptibles.sleepUninterruptibly(500, MILLISECONDS);

      ShadowSystemClock.advanceBy(Duration.ofSeconds(61));
      Result result = run.get(/* timeout= */ 10, SECONDS);

      expect.that(result).isEqualTo(Result.retry());
      expect.that(largeFile.exists()).isTrue();
      expect.that(sentCopyOf(smallFile).exists()).isTrue();
    } finally {
      release.countDown();
      workerThread.shutdownNow();
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenAFailedBatchUploads_forgetsItsFailures() throws Exception {
    givenWebDavPassword();
    AtomicBoolean refuses = new AtomicBoolean(true);
    HttpServer server =
        startWebDavServer(exchange -> {
          exchange.sendResponseHeaders(
              refuses.get()
                  ? HttpURLConnection.HTTP_INTERNAL_ERROR
                  : HttpURLConnection.HTTP_CREATED,
              -1);
          exchange.close();
        });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      File file =
          createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
      runWorker();
      assertThat(failedUploads().getInt(file.getName(), 0)).isEqualTo(1);
      refuses.set(false);

      runWorker();

      assertThat(failedUploads().contains(file.getName())).isFalse();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_forgetsTheFailedUploadsOfBatchesThatAreGone() throws Exception {
    givenWebDavPassword();
    HttpServer server =
        startWebDavServer(exchange -> {
          exchange.sendResponseHeaders(HttpURLConnection.HTTP_INTERNAL_ERROR, -1);
          exchange.close();
        });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      File file =
          createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
      runWorker();
      assertThat(failedUploads().getInt(file.getName(), 0)).isEqualTo(1);
      assertTrue(file.delete());

      runWorker();

      assertThat(failedUploads().contains(file.getName())).isFalse();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void doWork_whenBatchesFailMultipleTimes_uploadsTheLeastFailedOneFirst() throws Exception {
    givenWebDavPassword();
    long now = InstantSource.system().instant().toEpochMilli();
    File olderFailedTwice = createFile("log_", now - 2000, ".bin", "older");
    assertTrue(olderFailedTwice.setLastModified(now - 2000));
    AtomicBoolean refuseAll = new AtomicBoolean(true);
    List<String> uploadedNames = Collections.synchronizedList(new ArrayList<>());
    HttpServer server =
        startWebDavServer(exchange -> {
          if (refuseAll.get()) {
            exchange.sendResponseHeaders(
                HttpURLConnection.HTTP_INTERNAL_ERROR, /* responseLength= */ -1);
          } else {
            String path = exchange.getRequestURI().getPath();
            uploadedNames.add(path.substring(path.lastIndexOf('/') + 1));
            exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, /* responseLength= */ -1);
          }
          exchange.close();
        });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");
      runWorker();
      File newerFailedOnce = createFile("log_", now - 1000, ".bin", "newer");
      assertTrue(newerFailedOnce.setLastModified(now - 1000));
      runWorker();
      refuseAll.set(false);

      Result result = runWorker();

      expect.that(result).isEqualTo(Result.success());
      expect
          .that(uploadedNames)
          .containsExactly(newerFailedOnce.getName(), olderFailedTwice.getName())
          .inOrder();
    } finally {
      server.stop(0);
    }
  }

  @Test
  public void uploadPendingBatches_onceTheStopCheckIsTrue_uploadsNoFurtherBatch() throws Exception {
    givenWebDavPassword();
    long now = InstantSource.system().instant().toEpochMilli();
    createFile("log_", now - 2000, ".bin", "first");
    createFile("log_", now - 1000, ".bin", "second");
    List<String> uploadedNames = Collections.synchronizedList(new ArrayList<>());
    HttpServer server =
        startWebDavServer(exchange -> {
          uploadedNames.add(exchange.getRequestURI().getPath());
          exchange.sendResponseHeaders(HttpURLConnection.HTTP_CREATED, -1);
          exchange.close();
        });
    try {
      configureWebDav("http://localhost:" + server.getAddress().getPort() + "/webdav");

      Result stopped =
          CrumblesSendAndMarkProcessingWorker.uploadPendingBatches(
              context, () -> !uploadedNames.isEmpty());
      int uploadedBeforeStop = uploadedNames.size();
      Result resumed = CrumblesSendAndMarkProcessingWorker.uploadPendingBatches(context);

      expect.that(stopped).isEqualTo(Result.retry());
      expect.that(uploadedBeforeStop).isEqualTo(1);
      expect.that(resumed).isEqualTo(Result.success());
      expect.that(uploadedNames).hasSize(2);
    } finally {
      server.stop(0);
    }
  }

  /** Makes the stored WebDAV password decrypt, as {@link #configureWebDav} does the rest. */
  private void givenWebDavPassword() throws CrumblesKeysException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    when(mockLogsEncryptor.decryptDataStoreEntry(
            ENCRYPTED_WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("pass".getBytes(UTF_8));
  }

  private File sentCopyOf(File pendingFile) {
    return new File(
        testDirectory, pendingFile.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX));
  }

  private SharedPreferences failedUploads() {
    return context.getSharedPreferences(
        CrumblesSendAndMarkProcessingWorker.FAILED_UPLOADS_PREFS, Context.MODE_PRIVATE);
  }

  @Test
  public void doWork_whenDeferralRecursAfterQueueEmpties_reportsItAgain()
      throws IOException, ExecutionException, InterruptedException {
    long timestamp = InstantSource.system().instant().toEpochMilli();
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File log1 = createFile("log1_", timestamp, ".bin", "c1");
    runWorker();
    assertTrue(log1.delete());
    assertEquals(Result.success(), runWorker());
    createFile("log2_", timestamp + 10, ".bin", "c2");
    context.getSystemService(NotificationManager.class).cancelAll();

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    verify(mockAuditLogger, times(2))
        .logEvent(eq("UPLOAD_DESTINATION_NOT_CONFIGURED"), anyString());
    assertNotificationPosted();
  }

  @Test
  public void uploadAndStop_handlesCancellationConcurrencyAndInFlightRollback() throws Exception {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File dir = testDirectory;
    File log1 = createFile("log1_", 1L, ".bin", "c1");
    File log2 = createFile("log2_", 2L, ".bin", "c2");
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    fakeDriveProvider.onOpenFile =
        () -> callInstanceMethod(worker, "stop", ClassParameter.from(int.class, 1));
    assertEquals(Result.retry(), worker.doWork());
    assertThat(dir.list((d, n) -> n.endsWith(CrumblesConstants.SENT_SUFFIX))).hasLength(1);
    verify(mockAuditLogger).logEvent(eq("LOGS_UPLOAD_SUCCESS"), anyString());
    verify(mockAuditLogger, never()).logEvent(eq("LOGS_UPLOAD_FAILED"), anyString());
    fakeDriveProvider.onOpenFile = null;
    assertTrue((log1.exists() ? log1 : log2).delete());
    RemoteStorageUploader up = mock(RemoteStorageUploader.class);
    assertFalse(uploadSingleFile(context, up, log2, dir));
    File f1 = createFile("f1_", 1L, ".bin", "c1");
    createFile("f2_", 2L, ".bin", "c2");
    when(up.uploadFile(any(), any(), anyString()))
        .thenAnswer(
            i -> {
              File p = i.getArgument(1);
              String n = i.getArgument(2);
              if (!n.equals("f1_1.bin")) {
                return p.delete() && n.equals("d1_1.bin");
              }
              assertFalse(Thread.holdsLock(CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK));
              assertEquals(Result.success(), runWorker());
              assertTrue(p.exists() && new File(dir, "f2_2_sent.bin").exists());
              return false;
            });
    assertTrue(!uploadSingleFile(context, up, f1, dir) && f1.exists());
    assertTrue(f1.renameTo(new File(dir, "f1_1_processing.bin")));
    assertTrue(runWorker().equals(Result.success()) && new File(dir, "f1_1_sent.bin").exists());
    assertFalse(uploadSingleFile(context, up, createFile("d1_", 1L, ".bin", "c"), dir));
    assertFalse(uploadSingleFile(context, up, createFile("d2_", 2L, ".bin", "c"), dir));
  }
}
