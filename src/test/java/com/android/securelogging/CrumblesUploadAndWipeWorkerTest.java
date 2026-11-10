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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import androidx.annotation.Nullable;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.ListenableWorker.Result;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.testing.TestListenableWorkerBuilder;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.google.common.collect.ImmutableList;
import com.google.common.time.Sleeper;
import com.google.common.truth.Expect;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.Security;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.shadows.ShadowNetworkCapabilities;

/** Unit tests for {@link CrumblesUploadAndWipeWorker}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesUploadAndWipeWorkerTest {

  private static final String SAF_AUTHORITY = "com.google.android.apps.docs.storage";
  private static final Uri SAF_TREE_URI =
      Uri.parse("content://" + SAF_AUTHORITY + "/tree/valid_drive");
  private static final EncryptedPayload SEALED_URL =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("sealed_url")).build();
  private static final EncryptedPayload SEALED_USERNAME =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("sealed_user")).build();
  private static final EncryptedPayload SEALED_PASSWORD =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("sealed")).build();

  /** Runs on the WebDAV server or SAF provider for each upload, before completing it. */
  @SuppressWarnings("NonFinalStaticField")
  private static volatile Runnable duringUpload = () -> {};

  @Rule public final Expect expect = Expect.create();

  private final Context context = ApplicationProvider.getApplicationContext();
  private final ConnectivityManager connectivityManager =
      context.getSystemService(ConnectivityManager.class);
  private final List<String> uploadedNames = Collections.synchronizedList(new ArrayList<>());
  private File logsDirectory;
  private HttpServer webDavServer;
  private CrumblesLogsEncryptor encryptor;

  /** Fake SAF ContentProvider for testing Google Drive uploads in Robolectric. */
  public static final class FakeSafContentProvider extends ContentProvider {
    private File tempSafDir;

    @Override
    public boolean onCreate() {
      tempSafDir = new File(getContext().getFilesDir(), "fake_saf_drive");
      tempSafDir.mkdirs();
      return true;
    }

    @Override
    public Cursor query(
        Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
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
    @Nullable
    public Bundle call(String method, @Nullable String arg, @Nullable Bundle extras) {
      if (Objects.equals(method, "android:createDocument")) {
        String name =
            extras != null
                ? extras.getString(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    extras.getString(Intent.EXTRA_TITLE, "log.bin"))
                : "log.bin";
        File created = new File(tempSafDir, name);
        try {
          created.createNewFile();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        Bundle res = new Bundle();
        res.putParcelable("uri", Uri.parse("content://" + SAF_AUTHORITY + "/document/" + name));
        return res;
      }
      return null;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      duringUpload.run();
      return ParcelFileDescriptor.open(
          new File(tempSafDir, uri.getLastPathSegment()), ParcelFileDescriptor.MODE_READ_WRITE);
    }

    @Override
    @Nullable
    public String getType(Uri uri) {
      return null;
    }

    @Override
    @Nullable
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

  @Before
  public void setUp() throws Exception {
    duringUpload = () -> {};
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    NetworkCapabilities validated = ShadowNetworkCapabilities.newInstance();
    shadowOf(validated).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
    shadowOf(connectivityManager)
        .setNetworkCapabilities(connectivityManager.getActiveNetwork(), validated);
    encryptor = mock(CrumblesLogsEncryptor.class);
    when(encryptor.doesPrivateKeyExist()).thenReturn(true);
    when(encryptor.getPublicKey()).thenReturn(mock(PublicKey.class));
    when(encryptor.encryptLogs(any(), any(), any())).thenReturn(LogBatch.getDefaultInstance());
    when(encryptor.serializeBytes(any(), any(), any()))
        .thenAnswer(
            inv -> {
              File dir = inv.getArgument(1);
              String name = inv.getArgument(2);
              File f = new File(dir, name);
              f.createNewFile();
              return f.toPath();
            });
    webDavServer = startWebDavServerFailingNamesContaining("failing");
    String serverUrl = "http://localhost:" + webDavServer.getAddress().getPort() + "/webdav";
    when(encryptor.decryptDataStoreEntry(SEALED_URL, CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID))
        .thenReturn(serverUrl.getBytes(UTF_8));
    when(encryptor.decryptDataStoreEntry(
            SEALED_USERNAME, CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID))
        .thenReturn("user".getBytes(UTF_8));
    when(encryptor.decryptDataStoreEntry(
            SEALED_PASSWORD, CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID))
        .thenReturn("password".getBytes(UTF_8));
    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(
            preferences ->
                UserKeyPreferences.newBuilder()
                    .setRemoteStorageConfig(
                        RemoteStorageConfig.newBuilder()
                            .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
                            .setWebdavServerUrl(SEALED_URL)
                            .setWebdavCredentials(
                                WebDavCredentials.newBuilder()
                                    .setUsername(SEALED_USERNAME)
                                    .setPassword(SEALED_PASSWORD)))
                    .build())
        .get();
    logsDirectory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    assertThat(logsDirectory.mkdirs()).isTrue();
  }

  @After
  public void tearDown() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    webDavServer.stop(/* delay= */ 0);
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
  }

  @Test
  public void doWork_uploadsEveryPendingBatchThenDeletesIt() throws Exception {
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
    File first = createBatch("crumbles_logs_encrypted_1.bin");
    File second = createBatch("crumbles_logs_encrypted_2.bin");

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.success());
    expect.that(uploadedNames).containsExactly(first.getName(), second.getName());
    expect.that(logsDirectory.list()).isEmpty();
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_FINISHED"))
        .containsExactly(
            "Deleted 2 uploaded batch(es). 0 batch(es) could not be uploaded and are still on this"
                + " device.");
    expect.that(auditMessages("UPLOAD_AND_WIPE_SENT_KEPT")).isEmpty();
  }

  @Test
  public void doWork_whenLogsDirectoryDoesNotExist_succeedsWithZeroBatchesLeft() {
    assertThat(logsDirectory.delete()).isTrue();

    expect.that(runWorker()).isEqualTo(Result.success());
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
  }

  @Test
  public void doWork_drainsStagedBatchesOnlyWhenActiveKeyAvailable() throws Exception {
    CrumblesLogsEncryptor noKeyEncryptor = mock(CrumblesLogsEncryptor.class);
    when(noKeyEncryptor.doesPrivateKeyExist()).thenReturn(false);
    CrumblesMain.setLogsEncryptorInstanceForTest(noKeyEncryptor);

    File staged = createStagedBatch("0000000000000000001-S.sealed");
    expect.that(runWorker()).isEqualTo(Result.success());
    expect.that(staged.exists()).isTrue();
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(1);

    CrumblesMain.setLogsEncryptorInstanceForTest(encryptor);
    expect.that(runWorker()).isEqualTo(Result.success());
    expect.that(staged.exists()).isFalse();
    expect.that(uploadedNames).hasSize(1);
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
  }

  @Test
  public void doWork_whenSomeUploadsFail_keepsAndCountsTheBatchesLeft() throws Exception {
    File uploaded = createBatch("crumbles_logs_encrypted_1.bin");
    File failing = createBatch("crumbles_logs_encrypted_failing.bin");

    runWorker();

    expect.that(uploaded.exists()).isFalse();
    expect.that(failing.exists()).isTrue();
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(1);
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_FINISHED"))
        .containsExactly(
            "Deleted 1 uploaded batch(es). 1 batch(es) could not be uploaded and are still on this"
                + " device.");
  }

  @Test
  public void doWork_deletesBatchesThatAnEarlierUploadMarkedAsSent() throws Exception {
    File sentEarlier = createBatch("crumbles_logs_encrypted_0" + CrumblesConstants.SENT_SUFFIX);
    CrumblesDeleteSentFilesWorker.recordSentFile(context, sentEarlier.getName());

    runWorker();

    expect.that(sentEarlier.exists()).isFalse();
    expect.that(uploadedNames).isEmpty();
  }

  @Test
  public void doWork_withoutNetwork_webDav_deletesUploadedBatches() throws Exception {
    
    shadowOf(connectivityManager).setDefaultNetworkActive(false);
    createBatch("crumbles_logs_encrypted_1.bin");
    File failing = createBatch("crumbles_logs_encrypted_failing.bin");

    runWorker();

    expect
        .that(logsDirectory.list())
        .asList()
        .containsExactly(failing.getName());
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(1);
    expect.that(auditMessages("UPLOAD_AND_WIPE_SENT_KEPT")).isEmpty();
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_FINISHED"))
        .containsExactly(
            "Deleted 1 uploaded batch(es). 1 batch(es) could not be uploaded and are still on this"
                + " device.");
  }

  @Test
  public void doWork_whenValidatedNetworkIsLostDuringUpload_webDav_deletesUploadedBatches()
      throws Exception {
    duringUpload = () -> shadowOf(connectivityManager).setDefaultNetworkActive(false);
    File batch = createBatch("crumbles_logs_encrypted_1.bin");

    runWorker();

    expect.that(uploadedNames).containsExactly(batch.getName());
    expect.that(logsDirectory.list()).asList().isEmpty();
  }

  @Test
  public void doWork_saf_keepsAllUploadedBatches() throws Exception {
    configureSafDestination();
    File preExistingSent = createBatch("crumbles_logs_encrypted_0" + CrumblesConstants.SENT_SUFFIX);
    createBatch("crumbles_logs_encrypted_1.bin");

    runWorker();

    expect.that(logsDirectory.list()).asList().containsExactly(
        preExistingSent.getName(), "crumbles_logs_encrypted_1" + CrumblesConstants.SENT_SUFFIX);
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
    expect.that(CrumblesUploadAndWipeWorker.countKeptSafBatches(context)).isEqualTo(2);
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_SENT_KEPT"))
        .containsExactly(
            "Kept 2 uploaded batch(es) on this device because Drive may still be syncing.");
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_FINISHED"))
        .containsExactly(
            "Deleted 0 uploaded batch(es). 0 batch(es) could not be uploaded and are still on this"
                + " device.");
  }

  @Test
  public void doWork_webDavConfigured_keepsUnrecordedSafCopies() throws Exception {
    File safCopy = createBatch("crumbles_logs_encrypted_0" + CrumblesConstants.SENT_SUFFIX);
    File webDavCopy = createBatch("crumbles_logs_encrypted_1" + CrumblesConstants.SENT_SUFFIX);
    CrumblesDeleteSentFilesWorker.recordSentFile(context, webDavCopy.getName());

    runWorker();

    expect.that(safCopy.exists()).isTrue();
    expect.that(webDavCopy.exists()).isFalse();
    expect.that(CrumblesUploadAndWipeWorker.countKeptSafBatches(context)).isEqualTo(1);
  }

  @Test
  public void wipeAllBatches_deletesEveryBatchExceptOnesBeingWritten() throws Exception {
    createBatch("crumbles_logs_encrypted_failing.bin");
    runWorker();
    File staged = createStagedBatch("0000000000000000001-S.sealed");
    createBatch("crumbles_logs_encrypted_2" + CrumblesConstants.PROCESSING_SUFFIX);
    createBatch("crumbles_logs_encrypted_3" + CrumblesConstants.SENT_SUFFIX);
    File beingWritten =
        createBatch("crumbles_logs_encrypted_4.bin.1a2b" + CrumblesConstants.TEMP_FILE_SUFFIX);
    NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
    notificationManager.createNotificationChannel(
        new NotificationChannel(
            CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID,
            "Action needed",
            NotificationManager.IMPORTANCE_HIGH));
    notificationManager.notify(
        CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID,
        new Notification.Builder(context, CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .build());
    assertThat(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID))
        .isNotNull();

    int deletedCount = CrumblesUploadAndWipeWorker.wipeAllBatches(context);

    expect.that(deletedCount).isEqualTo(4);
    expect.that(staged.exists()).isFalse();
    expect.that(logsDirectory.list()).asList().containsExactly(beingWritten.getName());
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
    expect
        .that(
            shadowOf(notificationManager)
                .getNotification(CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID))
        .isNull();
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_FORCED"))
        .containsExactly(
            "Deleted 4 batch(es), including any that were not uploaded, after the user confirmed"
                + " the device credential.");
  }

  @Test
  public void wipeAllBatches_whenStagedBatchCannotBeDeleted_countsOnlyDeletedOnes()
      throws Exception {
    File deletable = createStagedBatch("0000000000000000001-S.sealed");
    File undeletable =
        new File(context.getNoBackupFilesDir(), "staged_logs/0000000000000000002-S.sealed");
    assertThat(undeletable.mkdirs()).isTrue();
    assertThat(new File(undeletable, "child").createNewFile()).isTrue();
    expect.that(new CrumblesLogStaging(context).countBatches()).isEqualTo(2);

    int deletedCount = CrumblesUploadAndWipeWorker.wipeAllBatches(context);

    expect.that(deletedCount).isEqualTo(1);
    expect.that(deletable.exists()).isFalse();
    expect.that(undeletable.exists()).isTrue();
    expect.that(new CrumblesLogStaging(context).countBatches()).isEqualTo(1);
  }

  @Test
  public void doWork_waitsForAnUploadInProgressElsewhereThenDeletesItsBatch() throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(2);
    CountDownLatch release = new CountDownLatch(1);
    try {
      Future<Boolean> upload =
          startHeldUpload(executor, createBatch("crumbles_logs_encrypted_1.bin"), release);

      Future<Result> wipe = executor.submit(this::runWorker);

      // The wipe neither takes the batch over from the upload nor goes on without it.
      assertThrows(TimeoutException.class, () -> wipe.get(500, MILLISECONDS));
      release.countDown();
      expect.that(upload.get(10, SECONDS)).isTrue();
      expect.that(wipe.get(10, SECONDS)).isEqualTo(Result.success());
    } finally {
      executor.shutdownNow();
    }
    expect.that(uploadedNames).isEmpty();
    expect.that(logsDirectory.list()).isEmpty();
    expect.that(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(0);
  }

  @Test
  public void wipeAllBatches_waitsBoundedForAnUploadInProgressThenDeletesItsBatch()
      throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    CountDownLatch release = new CountDownLatch(1);
    try {
      Future<Boolean> upload =
          startHeldUpload(executor, createBatch("crumbles_logs_encrypted_1.bin"), release);
      long start = System.nanoTime();

      expect.that(CrumblesUploadAndWipeWorker.wipeAllBatches(context)).isEqualTo(1);

      expect
          .that(System.nanoTime() - start)
          .isAtLeast(CrumblesUploadAndWipeWorker.WIPE_ALL_UPLOAD_WAIT.toNanos());
      release.countDown();
      // The upload can mark the deleted batch neither as sent nor as pending again.
      expect.that(upload.get(10, SECONDS)).isFalse();
    } finally {
      executor.shutdownNow();
    }
    expect.that(logsDirectory.list()).isEmpty();
  }

  @Test
  public void wipeAllBatches_duringAnUpload_leavesNoUploadFailureBehind() throws Exception {
    createBatch("crumbles_logs_encrypted_1.bin");
    createBatch("crumbles_logs_encrypted_2.bin");
    AtomicInteger wipedCount = new AtomicInteger();
    duringUpload =
        () -> {
          duringUpload = () -> {};
          wipedCount.set(CrumblesUploadAndWipeWorker.wipeAllBatches(context));
        };

    Result result =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build()
            .doWork();

    expect.that(result).isEqualTo(Result.retry());
    expect.that(wipedCount.get()).isEqualTo(2);
    expect.that(auditMessages("LOGS_UPLOAD_FAILED")).isEmpty();
    expect
        .that(shadowOf(context.getSystemService(NotificationManager.class)).getAllNotifications())
        .isEmpty();
  }

  @Test
  public void wipeAllBatches_waitsForADrainInProgressThenDeletesWhatItMoved() throws Exception {
    createStagedBatch("0000000000000000001-S.sealed");
    createStagedBatch("0000000000000000002-S.sealed");
    CrumblesLogStaging staging = new CrumblesLogStaging(context);
    CountDownLatch firstWritten = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    Thread wipe =
        new Thread(
            () -> {
              var _ = CrumblesUploadAndWipeWorker.wipeAllBatches(context);
            });
    try {
      Future<Integer> drain =
          executor.submit(
              () ->
                  staging.drain(
                      (isNetworkBatch, logs) -> {
                        try {
                          File batch = File.createTempFile("drained", ".bin", logsDirectory);
                          Files.write(batch.toPath(), logs);
                          firstWritten.countDown();
                          return release.await(10, SECONDS)
                              ? CrumblesLogStaging.WriteResult.STORED
                              : CrumblesLogStaging.WriteResult.FAILED;
                        } catch (IOException | InterruptedException e) {
                          return CrumblesLogStaging.WriteResult.FAILED;
                        }
                      }));
      assertThat(firstWritten.await(10, SECONDS)).isTrue();

      wipe.start();
      long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
      while (wipe.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
        Sleeper.defaultSleeper().sleep(Duration.ofMillis(10));
      }
      release.countDown();
      expect.that(drain.get(10, SECONDS)).isEqualTo(2);
      wipe.join(Duration.ofSeconds(10).toMillis());
    } finally {
      executor.shutdownNow();
    }
    expect.that(logsDirectory.list()).isEmpty();
    expect.that(staging.isEmpty()).isTrue();
  }

  @Test
  public void start_uploadsAndWipesInTheBackground() throws Exception {
    WorkManagerTestInitHelper.initializeTestWorkManager(context);
    File batch = createBatch("crumbles_logs_encrypted_1.bin");

    CrumblesUploadAndWipeWorker.start(context);

    List<WorkInfo> workInfos =
        WorkManager.getInstance(context)
            .getWorkInfosForUniqueWork(CrumblesUploadAndWipeWorker.UNIQUE_WORK_NAME)
            .get();
    expect
        .that(workInfos.stream().map(WorkInfo::getState).collect(toImmutableList()))
        .containsExactly(WorkInfo.State.SUCCEEDED);
    expect.that(batch.exists()).isFalse();
    expect.that(uploadedNames).containsExactly(batch.getName());
    expect
        .that(auditMessages("UPLOAD_AND_WIPE_REQUESTED"))
        .containsExactly("Upload and wipe of every pending batch requested.");
  }

  private void configureSafDestination() throws Exception {
    var _ = Robolectric.setupContentProvider(FakeSafContentProvider.class, SAF_AUTHORITY);
    context.grantUriPermission(
        context.getPackageName(),
        SAF_TREE_URI,
        Intent.FLAG_GRANT_READ_URI_PERMISSION
            | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
    context
        .getContentResolver()
        .takePersistableUriPermission(
            SAF_TREE_URI,
            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(
            prefs ->
                prefs.toBuilder()
                    .setRemoteStorageConfig(
                        prefs.getRemoteStorageConfig().toBuilder()
                            .setStorageType(StorageType.STORAGE_TYPE_GOOGLE_DRIVE)
                            .setUploadDestinationUri(SAF_TREE_URI.toString())
                            .build())
                    .build())
        .get();
  }

  private HttpServer startWebDavServerFailingNamesContaining(String failingPart)
      throws IOException {
    HttpServer server =
        HttpServer.create(new InetSocketAddress("localhost", /* port= */ 0), /* backlog= */ 0);
    server.createContext(
        "/webdav",
        exchange -> {
          String path = exchange.getRequestURI().getPath();
          String name = path.substring(path.lastIndexOf('/') + 1);
          boolean fails = name.contains(failingPart);
          if (!fails) {
            uploadedNames.add(name);
          }
          duringUpload.run();
          exchange.sendResponseHeaders(fails ? 500 : 201, /* responseLength= */ -1);
          exchange.close();
        });
    server.start();
    return server;
  }

  @CanIgnoreReturnValue
  private File createBatch(String name) throws IOException {
    File batch = new File(logsDirectory, name);
    Files.writeString(batch.toPath(), "encrypted batch");
    return batch;
  }

  /**
   * Starts uploading {@code batch} on {@code executor} through an uploader that holds the upload
   * until {@code release}, and returns once the upload is in progress.
   */
  private Future<Boolean> startHeldUpload(
      ExecutorService executor, File batch, CountDownLatch release) throws Exception {
    CountDownLatch uploading = new CountDownLatch(1);
    RemoteStorageUploader uploader = mock(RemoteStorageUploader.class);
    when(uploader.getStorageType()).thenReturn(StorageType.STORAGE_TYPE_WEBDAV);
    when(uploader.uploadFile(any(), any(), any()))
        .thenAnswer(
            invocation -> {
              uploading.countDown();
              return release.await(10, SECONDS);
            });
    Future<Boolean> upload =
        executor.submit(
            () ->
                CrumblesSendAndMarkProcessingWorker.uploadSingleFile(
                    context, uploader, batch, logsDirectory));
    assertThat(uploading.await(10, SECONDS)).isTrue();
    return upload;
  }

  @CanIgnoreReturnValue
  private File createStagedBatch(String name) throws Exception {
    File stagedDir = new File(context.getNoBackupFilesDir(), "staged_logs");
    stagedDir.mkdirs();
    File batch = new File(stagedDir, name);
    byte[] sealed = CrumblesLogStagingSealer.seal("sealed batch".getBytes(UTF_8), name);
    Files.write(batch.toPath(), sealed);
    return batch;
  }

  @CanIgnoreReturnValue
  private Result runWorker() {
    return TestListenableWorkerBuilder.from(context, CrumblesUploadAndWipeWorker.class)
        .build()
        .doWork();
  }

  private ImmutableList<String> auditMessages(String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .filter(event -> event.getEventType().equals(eventType))
        .map(CrumblesAuditEvent::getMessage)
        .collect(toImmutableList());
  }
}
