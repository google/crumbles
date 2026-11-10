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

import static com.android.securelogging.CrumblesKeyHandover.handOver;
import static com.android.securelogging.CrumblesLogsEncryptor.KEY_ALIAS;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.robolectric.Shadows.shadowOf;

import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import androidx.annotation.Nullable;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesKeyHandover.Outcome;
import com.android.securelogging.CrumblesSendAndMarkProcessingWorkerTest.FakeGoogleDriveContentProvider;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;

/** Unit tests for {@link CrumblesKeyHandover}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesKeyHandoverTest {
  private static final String DRIVE_AUTHORITY = "com.google.android.apps.docs.storage";
  private static final Uri DRIVE_TREE_URI =
      Uri.parse("content://" + DRIVE_AUTHORITY + "/tree/valid_drive");
  private static final String CHANGE_DESCRIPTION = "Changing to a test key";
  private static final String WEBDAV_USERNAME = "user";
  private static final String WEBDAV_PASSWORD = "password";

  /** Authorization header for the WebDAV credentials that the tests store. */
  private static final String WEBDAV_AUTHORIZATION =
      "Basic "
          + Base64.getEncoder()
              .encodeToString((WEBDAV_USERNAME + ":" + WEBDAV_PASSWORD).getBytes(UTF_8));

  private final Context context = ApplicationProvider.getApplicationContext();
  private final CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
  private final File logsDirectory =
      new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);

  /** Bodies of the uploads that the WebDAV server accepted, by file name. */
  private final Map<String, byte[]> webDavUploads = new ConcurrentHashMap<>();

  private FakeGoogleDriveContentProvider driveProvider;
  private PublicKey outgoingKey;
  @Nullable private HttpServer webDavServer;

  @Before
  public void setUp() throws Exception {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    driveProvider =
        Robolectric.setupContentProvider(FakeGoogleDriveContentProvider.class, DRIVE_AUTHORITY);
    // The device key is the outgoing key, so that the tests can decrypt the handover record.
    outgoingKey =
        encryptor.generateKeyPair(KEY_ALIAS, /* requireUserAuthentication= */ false).getPublic();
    CrumblesExternalPublicKeyManager.getInstance(context).saveActiveExternalPublicKey(outgoingKey);
    // The key preferences outlive a test, so a destination saved by an earlier test is dropped.
    saveRemoteStorageConfig(RemoteStorageConfig.getDefaultInstance());
    logsDirectory.mkdirs();
  }

  @After
  public void tearDown() {
    if (webDavServer != null) {
      webDavServer.stop(/* delay= */ 0);
    }
  }

  @Test
  public void handOver_withoutExternalKey_writesNothing() throws Exception {
    CrumblesExternalPublicKeyManager.getInstance(context).clearActiveExternalPublicKey();
    assertThat(handOver(context, CHANGE_DESCRIPTION)).isEqualTo(Outcome.NOT_NEEDED);
    assertThat(logsDirectory.list()).isEmpty();
    assertThat(latestAuditEventType()).isEqualTo("KEY_HANDOVER_NOT_NEEDED");
  }

  @Test
  public void handOver_withoutDestination_keepsRecordOnDevice() throws Exception {
    assertThat(handOver(context, CHANGE_DESCRIPTION)).isEqualTo(Outcome.KEPT_ON_DEVICE);
    String handoverRecord =
        new String(encryptor.decryptLogs(encryptor.deserializeFile(onlyBatch().toPath())), UTF_8);
    assertThat(handoverRecord).contains(CHANGE_DESCRIPTION);
    assertThat(handoverRecord)
        .contains(CrumblesLogsEncryptor.getPublicKeyFingerprint(outgoingKey).replace('\n', ':'));
    assertThat(latestAuditEventType()).isEqualTo("KEY_HANDOVER_KEPT_ON_DEVICE");
  }

  @Test
  public void handOver_withDriveDestination_uploadsRecordAndMarksItSent() {
    selectDriveDestination();
    assertThat(handOver(context, CHANGE_DESCRIPTION)).isEqualTo(Outcome.UPLOADED);
    assertThat(onlyBatch().getName()).endsWith(CrumblesConstants.SENT_SUFFIX);
    assertThat(onlyBatch().getName()).doesNotContain(".bin.");
    assertThat(latestAuditEventType()).isEqualTo("KEY_HANDOVER_UPLOADED");
  }

  @Test
  public void handOver_withWebDavDestination_uploadsRecordAndMarksItSent() throws Exception {
    saveRemoteStorageConfig(webDavConfig(startWebDavServer()));

    Outcome outcome = handOver(context, CHANGE_DESCRIPTION);

    File sentBatch = onlyBatch();
    String uploadedName = sentBatch.getName().replace(CrumblesConstants.SENT_SUFFIX, ".bin");
    assertThat(outcome).isEqualTo(Outcome.UPLOADED);
    assertThat(sentBatch.getName()).endsWith(CrumblesConstants.SENT_SUFFIX);
    assertThat(webDavUploads.keySet()).containsExactly(uploadedName);
    assertThat(webDavUploads.get(uploadedName)).isEqualTo(Files.readAllBytes(sentBatch.toPath()));
    assertThat(latestAuditEventType()).isEqualTo("KEY_HANDOVER_UPLOADED");
  }

  @Test
  public void handOver_whenWebDavPasswordIsMissing_keepsRecordOnDeviceWithoutNotifying()
      throws Exception {
    RemoteStorageConfig webDavConfig = webDavConfig("https://webdav.example.com/");
    saveRemoteStorageConfig(
        webDavConfig.toBuilder()
            .setWebdavCredentials(webDavConfig.getWebdavCredentials().toBuilder().clearPassword())
            .build());

    Outcome outcome = handOver(context, CHANGE_DESCRIPTION);

    assertThat(outcome).isEqualTo(Outcome.KEPT_ON_DEVICE);
    assertThat(shadowOf(context.getSystemService(NotificationManager.class)).getAllNotifications())
        .isEmpty();
  }

  @Test
  public void handOver_whenOutgoingKeyUnreadable_writesNoRecord() throws Exception {
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(prefs -> prefs.toBuilder().clearExternalPublicKeys().build())
        .get();
    assertHandoverNotSealed();
    assertThat(logsDirectory.list()).isEmpty();
  }

  @Test
  public void handOver_whenEncryptionFails_writesNoRecord() throws Exception {
    logsDirectory.delete();
    logsDirectory.createNewFile();
    assertHandoverNotSealed();
  }

  @Test
  public void handOver_whenDestinationPermissionMissing_keepsRecordPending() {
    setUploadDestinationUri();
    assertHandoverUploadFailed();
  }

  @Test
  public void handOver_whenUploadFails_keepsRecordPending() {
    selectDriveDestination();
    driveProvider.setShouldFailStreaming(true);
    assertHandoverUploadFailed();
  }

  @Test
  public void handOver_whenNetworkStorageCapReached_stillSealsRecordInSecurityReserve()
      throws Exception {
    File networkFullBatch = new File(logsDirectory, "pending.bin");
    long networkEffectiveCap =
        CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES
            - (CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES
                * CrumblesConstants.LOGS_DIRECTORY_RESERVED_PERCENT
                / 100);
    try (RandomAccessFile pending = new RandomAccessFile(networkFullBatch, "rw")) {
      pending.setLength(networkEffectiveCap);
    }
    assertThat(handOver(context, CHANGE_DESCRIPTION)).isEqualTo(Outcome.KEPT_ON_DEVICE);
    assertThat(logsDirectory.listFiles()).hasLength(2);
  }

  @Test
  public void handOver_whenStorageCapReached_writesNoRecord() throws Exception {
    File fullBatch = new File(logsDirectory, "pending.bin");
    try (RandomAccessFile pending = new RandomAccessFile(fullBatch, "rw")) {
      pending.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES);
    }
    assertHandoverNotSealed();
    assertThat(onlyBatch()).isEqualTo(fullBatch);
  }

  private void selectDriveDestination() {
    context.grantUriPermission(
        context.getPackageName(),
        DRIVE_TREE_URI,
        Intent.FLAG_GRANT_READ_URI_PERMISSION
            | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
    context
        .getContentResolver()
        .takePersistableUriPermission(DRIVE_TREE_URI, Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    setUploadDestinationUri();
  }

  private void setUploadDestinationUri() {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, DRIVE_TREE_URI.toString())
        .commit();
  }

  /** Returns WebDAV settings for {@code serverUrl}, sealed like the app seals them. */
  private RemoteStorageConfig webDavConfig(String serverUrl) throws CrumblesKeysException {
    return RemoteStorageConfig.newBuilder()
        .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
        .setWebdavServerUrl(seal(serverUrl, CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID))
        .setWebdavCredentials(
            WebDavCredentials.newBuilder()
                .setUsername(seal(WEBDAV_USERNAME, CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
                .setPassword(seal(WEBDAV_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID)))
        .build();
  }

  private EncryptedPayload seal(String value, String entryId) throws CrumblesKeysException {
    return encryptor.encryptDataStoreEntry(value.getBytes(UTF_8), entryId);
  }

  private void saveRemoteStorageConfig(RemoteStorageConfig config) throws Exception {
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(
            preferences -> preferences.toBuilder().setRemoteStorageConfig(config).build())
        .get();
  }

  /**
   * Starts a localhost WebDAV server that keeps each upload carrying the stored credentials and
   * refuses any other, and returns its URL.
   */
  private String startWebDavServer() throws IOException {
    webDavServer =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    webDavServer.createContext(
        "/webdav",
        exchange -> {
          boolean isAuthorized =
              Objects.equals(
                  exchange.getRequestHeaders().getFirst("Authorization"), WEBDAV_AUTHORIZATION);
          if (isAuthorized) {
            String path = exchange.getRequestURI().getPath();
            webDavUploads.put(
                path.substring(path.lastIndexOf('/') + 1),
                exchange.getRequestBody().readAllBytes());
          }
          exchange.sendResponseHeaders(
              isAuthorized ? HttpURLConnection.HTTP_CREATED : HttpURLConnection.HTTP_UNAUTHORIZED,
              /* responseLength= */ -1);
          exchange.close();
        });
    webDavServer.start();
    return "http://localhost:" + webDavServer.getAddress().getPort() + "/webdav";
  }

  private void assertHandoverNotSealed() {
    assertThat(handOver(context, CHANGE_DESCRIPTION)).isEqualTo(Outcome.NOT_SEALED);
    assertThat(latestAuditEventType()).isEqualTo("KEY_HANDOVER_NOT_SEALED");
  }

  private void assertHandoverUploadFailed() {
    assertThat(handOver(context, CHANGE_DESCRIPTION)).isEqualTo(Outcome.UPLOAD_FAILED);
    assertThat(onlyBatch().getName()).doesNotContain(CrumblesConstants.PROCESSING_SUFFIX);
    assertThat(onlyBatch().getName()).doesNotContain(CrumblesConstants.SENT_SUFFIX);
    assertThat(latestAuditEventType()).isEqualTo("KEY_HANDOVER_UPLOAD_FAILED");
  }

  private File onlyBatch() {
    File[] batches = logsDirectory.listFiles();
    assertThat(batches).hasLength(1);
    return batches[0];
  }

  private String latestAuditEventType() {
    return CrumblesAppAuditLogger.getInstance(context)
        .getMemoryCachedEvents()
        .get(0)
        .getEventType();
  }
}
