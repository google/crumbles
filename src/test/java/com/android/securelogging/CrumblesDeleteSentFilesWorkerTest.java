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

import static com.android.securelogging.CrumblesConstants.PREFS_NAME;
import static com.android.securelogging.CrumblesConstants.PREF_UPLOAD_DESTINATION_URI;
import static com.android.securelogging.CrumblesDeleteSentFilesWorker.RETENTION_PREFS;
import static com.android.securelogging.CrumblesDeleteSentFilesWorker.SENT_KEY_PREFS;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import android.provider.Settings;
import android.util.Log;
import androidx.documentfile.provider.DocumentFile;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.Configuration;
import androidx.work.ListenableWorker;
import androidx.work.WorkManager;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.TestListenableWorkerBuilder;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.GoogleDriveStorageUploaderTest.TestDriveContentProvider;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.google.common.truth.Expect;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowPausedSystemClock;
import org.robolectric.shadows.ShadowSystemClock;

/** Tests the {@link CrumblesDeleteSentFilesWorker} class. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesDeleteSentFilesWorkerTest {

  private static final Uri SAF_URI = DocumentsContract.buildTreeDocumentUri("s", "root_folder");
  private static final EncryptedPayload SEC =
      EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("x")).build();
  private static final RemoteStorageConfig SAF_CONFIG =
      RemoteStorageConfig.newBuilder()
          .setStorageType(StorageType.STORAGE_TYPE_GOOGLE_DRIVE)
          .setUploadDestinationUri(SAF_URI.toString())
          .build();
  private static final String LISTING_FAILED =
      "Could not list the upload folder; kept every uploaded copy unverified.";
  private Context context;
  private File logDirectory;
  private TreeProvider safProvider;
  private SharedPreferences ret;

  @Rule public final Expect expect = Expect.create();

  /**
   * A strict provider, which lists children in name order with only the columns it knows, and
   * counts queries and the documents that it opens.
   */
  public static final class TreeProvider extends TestDriveContentProvider {
    /** Prefix of a document that has the display name of another one, as in a duplicate. */
    private static final Pattern DUPLICATE_PREFIX = Pattern.compile("^dup\\d+_");

    int queryCount;

    /** Documents named like no batch, which the folder lists after its files. */
    int otherDocumentCount;

    final List<String> openedDocuments = new ArrayList<>();

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sortOrder) {
      queryCount++;
      holdIf("query");
      if (queryFault != 0 || !uri.getPath().endsWith("/children")) {
        return super.query(uri, proj, sel, selArgs, sortOrder);
      }
      MatrixCursor cursor = new MatrixCursor(proj);
      Stream<String> ids =
          Stream.concat(
              Arrays.stream(tempDriveDir.list()).sorted(),
              IntStream.range(0, otherDocumentCount).mapToObj(index -> "other" + index));
      ids.forEach(
          id -> cursor.addRow(Arrays.stream(proj).map(column -> columnOf(id, column)).toArray()));
      return cursor;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      openedDocuments.add(uri.getLastPathSegment());
      return super.openFile(uri, mode);
    }

    /** Returns {@code column} of document {@code id}, and throws for a column it does not know. */
    private static String columnOf(String id, String column) {
      // Switching on a null column throws too, as a provider that validates projections does.
      return switch (column) {
        case Document.COLUMN_DOCUMENT_ID -> id;
        case Document.COLUMN_DISPLAY_NAME -> DUPLICATE_PREFIX.matcher(id).replaceFirst("");
        default -> throw new IllegalArgumentException("Unknown column " + column);
      };
    }
  }

  @Before
  public void setUp() throws Exception {
    context = ApplicationProvider.getApplicationContext();
    shadowOf(context.getSystemService(KeyguardManager.class)).setIsDeviceSecure(true);
    ret = context.getSharedPreferences(RETENTION_PREFS, 0);
    ShadowSystemClock.advanceBy(Duration.ofDays(40));

    Configuration config =
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(new SynchronousExecutor())
            .build();
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    safProvider = Robolectric.buildContentProvider(TreeProvider.class).create("s").get();
    WebDavCredentials creds = WebDavCredentials.newBuilder().setUsername(SEC).setPassword(SEC).build();
    configureStorage(
        RemoteStorageConfig.newBuilder()
            .setStorageType(StorageType.STORAGE_TYPE_WEBDAV)
            .setWebdavServerUrl(SEC)
            .setWebdavCredentials(creds)
            .build());

    File baseDir = context.getFilesDir();
    logDirectory = new File(baseDir, CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (logDirectory.exists()) {
      deleteRecursive(logDirectory);
    }
    assertTrue("Test log directory could not be created", logDirectory.mkdirs());
  }

  @After
  public void tearDown() throws Exception {
    safProvider.release.countDown();
    GoogleDriveStorageUploaderTest.awaitProviderAnswers(SAF_URI);
    CrumblesMain.getLogsEncryptorInstance().deleteExistingKeyPair();
    if (logDirectory != null && logDirectory.exists()) {
      deleteRecursive(logDirectory);
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

  private void configureStorage(RemoteStorageConfig cfg) throws Exception {
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(prefs -> prefs.toBuilder().setRemoteStorageConfig(cfg).build())
        .get();
  }

  private boolean runWorker() {
    return TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class)
        .build()
        .doWork()
        .equals(ListenableWorker.Result.success());
  }

  private File createFile(String name) throws IOException {
    File file = new File(logDirectory, name);
    assertTrue("Could not create test file: " + name, file.createNewFile());
    return file;
  }

  /** Creates a batch that was marked sent {@code age} ago. */
  private File createSentFile(String baseName, Duration age) throws IOException {
    File file = createFile(baseName + CrumblesConstants.SENT_SUFFIX);
    assertTrue(file.setLastModified(Instant.now().minus(age).toEpochMilli()));
    long sentAt = SystemClock.elapsedRealtime() - age.toMillis();
    ret.edit().putInt("_boot_count", -1).putLong(file.getName(), sentAt).commit();
    return file;
  }

  /** Creates a copy sent to a SAF folder, which has no upload time. */
  private File sent(String baseName, String content) throws IOException {
    File file = createFile(baseName + CrumblesConstants.SENT_SUFFIX);
    Files.write(file.toPath(), content.getBytes(UTF_8));
    assertThat(file.setLastModified(1_000L)).isTrue();
    return file;
  }

  private File createRemote(String name, String content) throws IOException {
    return Files.write(new File(safProvider.tempDriveDir, name).toPath(), content.getBytes(UTF_8))
        .toFile();
  }

  private List<String> events(String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .filter(e -> e.getEventType().equals(eventType))
        .map(e -> e.getMessage())
        .toList();
  }

  @Test
  public void doWork_safKeepsPresentAndResendsMissingOrCorrupted() throws Exception {
    CrumblesLogsEncryptor enc = CrumblesMain.getLogsEncryptorInstance();
    enc.generateKeyPair();
    assertThat(enc.serializeBytes(enc.encryptLogs(new byte[1], null), logDirectory, "del_sent.bin"))
        .isNotNull();
    enc.deleteExistingKeyPair();
    File matched = sent("log1", "encrypted payload");
    File missing = sent("log4", "missing payload");
    for (StorageType t : EnumSet.complementOf(EnumSet.of(StorageType.UNRECOGNIZED))) {
      configureStorage(RemoteStorageConfig.newBuilder().setStorageType(t).build());
      assertTrue(runWorker());
    }
    File dup = createRemote("dup1_log1.bin", "truncated");
    File valid = createRemote("dup2_log1.bin", "encrypted payload");
    File delCopy = createRemote("dup1_del.bin", "truncated");
    configureStorage(RemoteStorageConfig.getDefaultInstance());
    context.getSharedPreferences(PREFS_NAME, 0).edit().putString(PREF_UPLOAD_DESTINATION_URI, SAF_URI.toString()).commit();
    File resent = new File(logDirectory, "log4.bin");
    assertTrue(runWorker() && !missing.exists() && !new File(logDirectory, "del.bin").exists());
    // A corrupted copy goes even when the key of the batch is gone and it cannot be resent.
    assertTrue(!delCopy.exists() && new File(logDirectory, "del_sent.bin").exists());
    assertTrue(matched.exists() && !dup.exists() && valid.exists() && resent.lastModified() == 1000L);
    assertThat(WorkManager.getInstance(context).getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME).get()).isNotEmpty();
    assertThat(events("KEPT_COPY_RESENT")).containsExactly("Resent 1 missing uploaded copy(ies).");
    assertTrue(
        matched.delete()
            && valid.delete()
            && resent.delete()
            && events("KEPT_COPIES_DELETED").isEmpty());
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    File mismatch = sent("log2", "encrypted payload");
    File bad1 = createRemote("dup1_log2.bin", "truncated");
    File bad2 = createRemote("dup2_log2.bin", "encrypted payload!");
    configureStorage(SAF_CONFIG);
    for (int fault : new int[] {1, 2}) {
      safProvider.queryFault = fault;
      assertTrue(runWorker() && mismatch.exists() && bad1.exists() && bad2.exists());
    }
    safProvider.queryFault = 0;
    safProvider.setShouldWithholdReadBack(true);
    DocumentFile doc = DocumentFile.fromSingleUri(context, Uri.parse("content://s/doc/x"));
    assertThrows(IOException.class, () -> GoogleDriveStorageUploader.readBackDigest(context, doc, 10));
    safProvider.setShouldWithholdReadBack(false);
    File blockedSent = sent("blocked", "older");
    Files.write(createFile("blocked.bin").toPath(), "newer".getBytes(UTF_8));
    assertTrue(runWorker() && new File(logDirectory, "log2.bin").exists());
    assertTrue(!bad1.exists() && !bad2.exists() && !mismatch.exists() && blockedSent.exists());
    assertThat(new String(Files.readAllBytes(new File(logDirectory, "blocked.bin").toPath()), UTF_8))
        .isEqualTo("newer");
    assertThat(events("KEPT_COPY_RESENT")).containsExactly("Resent 1 missing uploaded copy(ies).");
  }

  @Test
  public void doWork_whenTheFolderProviderNeverAnswersTheListing_keepsCopiesAtTheDeadline()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File kept = sent("log1", "payload");
    safProvider.heldCall = "query";

    boolean succeeded = runWorkerPastDeadline();

    expect.that(succeeded).isTrue();
    expect.that(kept.exists()).isTrue();
  }

  @Test
  public void doWork_whenTheProviderNeverDeletesACorruptedCopy_resendsTheBatchAtTheDeadline()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File kept = sent("log1", "payload");
    File corrupted = createRemote("log1.bin", "other bytes");
    safProvider.heldCall = "android:deleteDocument";

    boolean succeeded = runWorkerPastDeadline();

    expect.that(succeeded).isTrue();
    expect.that(kept.exists()).isFalse();
    expect.that(new File(logDirectory, "log1.bin").exists()).isTrue();
    expect.that(corrupted.exists()).isTrue();
  }

  /** Runs the worker on another thread, and moves the clock on until the run ends. */
  private boolean runWorkerPastDeadline() throws Exception {
    ExecutorService workerThread = Executors.newSingleThreadExecutor();
    try {
      return GoogleDriveStorageUploaderTest.awaitPastDeadline(workerThread.submit(this::runWorker));
    } finally {
      workerThread.shutdownNow();
    }
  }

  @Test
  public void doWork_safWithManyCopies_listsFolderOnceAndResendsMissingCopy() throws Exception {
    configureStorage(SAF_CONFIG);
    List<File> remoteCopies = new ArrayList<>();
    for (int i = 0; i < 500; i++) {
      remoteCopies.add(createRemote("log" + i + ".bin", "payload " + i));
    }
    List<File> keptCopies = new ArrayList<>();
    for (int i = 0; i < 50; i++) {
      keptCopies.add(sent("log" + i, "payload " + i));
    }
    File missing = sent("missing", "missing payload");

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(safProvider.queryCount).isEqualTo(1);
    expect.that(missing.exists()).isFalse();
    expect.that(new File(logDirectory, "missing.bin").exists()).isTrue();
    expect.that(keptCopies.stream().filter(File::exists).count()).isEqualTo(50L);
    expect.that(remoteCopies.stream().filter(File::exists).count()).isEqualTo(500L);
  }

  @Test
  public void doWork_safFolderReturnsNoCursor_keepsCopyAndRecordsFailure() throws Exception {
    configureStorage(SAF_CONFIG);
    File sentFile = sent("log", "payload");
    safProvider.queryFault = 1;

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(sentFile.exists()).isTrue();
    expect.that(events("KEPT_COPY_RECONCILE_FAILED")).containsExactly(LISTING_FAILED);
  }

  @Test
  public void doWork_safFolderQueryThrows_keepsCopyAndRecordsFailure() throws Exception {
    configureStorage(SAF_CONFIG);
    File sentFile = sent("log", "payload");
    safProvider.queryFault = 2;

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(sentFile.exists()).isTrue();
    expect.that(events("KEPT_COPY_RECONCILE_FAILED")).containsExactly(LISTING_FAILED);
  }

  @Test
  public void doWork_safFolderWithMoreThanTenThousandOtherDocuments_resendsMissingCopy()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File missing = sent("missing", "payload");
    safProvider.otherDocumentCount = 10_001;

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(missing.exists()).isFalse();
    expect.that(events("KEPT_COPY_RESENT")).containsExactly("Resent 1 missing uploaded copy(ies).");
    expect.that(events("KEPT_COPY_RECONCILE_FAILED")).isEmpty();
  }

  @Test
  public void doWork_safCopyWithThreeNamesakes_readsBackOnlyTwo() throws Exception {
    configureStorage(SAF_CONFIG);
    File sentFile = sent("log", "payload");
    File first = createRemote("dup1_log.bin", "other payload 1");
    File second = createRemote("dup2_log.bin", "other payload 2");
    File third = createRemote("dup3_log.bin", "other payload 3");

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(safProvider.openedDocuments).containsExactly("dup1_log.bin", "dup2_log.bin");
    expect.that(first.exists()).isFalse();
    expect.that(second.exists()).isFalse();
    expect.that(third.exists()).isTrue();
    expect.that(sentFile.exists()).isFalse();
  }

  @Test
  public void doWork_safCopyWhoseOnlyNamesakeCannotBeOpened_isResentAndNamesakeKept()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File sentFile = sent("log", "payload");
    File namesake = createRemote("log.bin", "payload");
    safProvider.setShouldCrash(true);

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(sentFile.exists()).isFalse();
    expect.that(new File(logDirectory, "log.bin").exists()).isTrue();
    expect.that(namesake.exists()).isTrue();
    expect.that(events("KEPT_COPY_RESENT")).containsExactly("Resent 1 missing uploaded copy(ies).");
  }

  @Test
  public void doWork_safCopyWithUnreadableNamesakeBeforeItsCopy_checksBothAndStaysKept()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File sentFile = sent("log", "payload");
    File directory = new File(safProvider.tempDriveDir, "dup1_log.bin");
    assertThat(directory.mkdir()).isTrue();
    File copy = createRemote("dup2_log.bin", "payload");

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(safProvider.openedDocuments).containsExactly("dup1_log.bin", "dup2_log.bin");
    expect.that(sentFile.exists()).isTrue();
    expect.that(directory.exists()).isTrue();
    expect.that(copy.exists()).isTrue();
  }

  @Test
  public void doWork_safCopyThatCannotBeRead_staysKeptAndOpensNoNamesake() throws Exception {
    configureStorage(SAF_CONFIG);
    File unreadable = new File(logDirectory, "log" + CrumblesConstants.SENT_SUFFIX);
    assertThat(unreadable.mkdir()).isTrue();
    File namesake = createRemote("log.bin", "payload");

    boolean succeeded = runWorker();

    expect.that(succeeded).isTrue();
    expect.that(unreadable.exists()).isTrue();
    expect.that(namesake.exists()).isTrue();
    expect.that(safProvider.openedDocuments).isEmpty();
  }

  @Test
  public void doWork_safReadBacksPastTheirDeadline_checksEveryCopyAndRecordsFailure()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File firstSentFile = sent("log1", "payload 1");
    File secondSentFile = sent("log2", "payload 2");
    File firstCopy = createRemote("log1.bin", "payload 1");
    File secondCopy = createRemote("log2.bin", "payload 2");
    File pipe = new File(context.getCacheDir(), "stalled_pipe");
    assertThat(new ProcessBuilder("mkfifo", pipe.getPath()).start().waitFor()).isEqualTo(0);
    ExecutorService workerThread = Executors.newSingleThreadExecutor();
    // Holding the pipe open for writing, but writing nothing, leaves every read of it blocked.
    try (RandomAccessFile idleWriter = new RandomAccessFile(pipe, "rw")) {
      safProvider.stalledReadBack = pipe;
      Future<Boolean> run = workerThread.submit(this::runWorker);

      boolean succeeded = awaitPastDeadline(run);

      expect.that(succeeded).isTrue();
      expect.that(safProvider.openedDocuments).hasSize(2);
      expect.that(firstSentFile.exists()).isTrue();
      expect.that(secondSentFile.exists()).isTrue();
      expect.that(firstCopy.exists()).isTrue();
      expect.that(secondCopy.exists()).isTrue();
      expect
          .that(events("KEPT_COPY_RECONCILE_FAILED"))
          .containsExactly(
              "The upload folder did not return 2 copy(ies) in time; kept them unverified.");
    } finally {
      workerThread.shutdownNow();
    }
  }

  @Test
  public void storageQuota_reclaimingSafCopyThatNoRecheckFound_recordsLogsLost() throws Exception {
    File safCopy = sent("saf", "x".repeat(300));
    File webDavCopy = createSentFile("webdav", Duration.ofDays(1));
    Files.write(webDavCopy.toPath(), "x".repeat(300).getBytes(UTF_8));

    boolean admitted =
        CrumblesLogStorageQuota.admitNewBatch(
            context,
            logDirectory,
            /* capBytes= */ 1000,
            /* isNetworkBatch= */ false,
            /* incomingBytes= */ 700L);

    expect.that(admitted).isTrue();
    expect.that(safCopy.exists()).isFalse();
    expect.that(webDavCopy.exists()).isFalse();
    expect
        .that(events("LOGS_LOST"))
        .containsExactly(
            "Reclaimed 1 uploaded copy(ies) that no re-check found at the destination: "
                + "saf_sent.bin.");
  }

  @Test
  public void storageQuota_afterAFailedListing_recordsReclaimingAVerifiedCopyAsLost()
      throws Exception {
    configureStorage(SAF_CONFIG);
    File sentFile = sent("log", "x".repeat(300));
    assertTrue(createRemote("log.bin", "x".repeat(300)).exists() && runWorker());
    safProvider.queryFault = 1;
    assertTrue(runWorker());

    boolean admitted =
        CrumblesLogStorageQuota.admitNewBatch(
            context,
            logDirectory,
            /* capBytes= */ 1000,
            /* isNetworkBatch= */ false,
            /* incomingBytes= */ 800L);

    expect.that(admitted).isTrue();
    expect.that(sentFile.exists()).isFalse();
    expect
        .that(events("LOGS_LOST"))
        .containsExactly(
            "Reclaimed 1 uploaded copy(ies) that no re-check found at the destination: "
                + "log_sent.bin.");
  }

  /**
   * Moves the clock past the transfer deadline, repeatedly until {@code run} ends, as the worker
   * sets its deadline only once it reads a document back, and returns whether it succeeded.
   */
  private static boolean awaitPastDeadline(Future<Boolean> run) throws Exception {
    for (int attempt = 0; attempt < 100 && !run.isDone(); attempt++) {
      ShadowSystemClock.advanceBy(Duration.ofHours(1));
      Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
    }
    return run.get(/* timeout= */ 1, SECONDS);
  }

  @Test
  public void doWork_safResendsMissingCopiesOnlyWhileTheirKeyMayExist() throws Exception {
    configureStorage(SAF_CONFIG);
    CrumblesLogsEncryptor enc = CrumblesMain.getLogsEncryptorInstance();
    enc.generateKeyPair();
    LogBatch wrapped = enc.encryptLogs(new byte[1], null);
    assertTrue(restores(wrapped, "wrapped"));
    KeyStore keyStore = KeyStore.getInstance(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    keyStore.load(null);
    keyStore.deleteEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    assertTrue(!restores(wrapped, "no_rsa_key"));
    enc.generateKeyPair();
    assertTrue(!restores(wrapped, "rotated"));
    CrumblesBatchKeyStore.deleteKeys();
    assertTrue(!restores(wrapped, "no_batch_keys"));
    // Batches that earlier versions wrote for the internal key without batch-wrap keys name no key,
    // as batches for an external key.
    LogBatch written = enc.encryptLogs(new byte[1], null);
    LogBatch rsaOnly =
        written.toBuilder().setKey(written.getKey().toBuilder().clearBatchWrapKeyId()).build();
    LogBatch unfit =
        rsaOnly.toBuilder()
            .setKey(
                rsaOnly.getKey().toBuilder()
                    .setEncryptedSymmetricKey(ByteString.copyFrom(new byte[128])))
            .build();
    assertTrue(restores(rsaOnly, "fits") && !restores(unfit, "unfit"));
    updateKeyPrefs(prefs -> prefs.setActiveKeyId("unreadable"));
    assertTrue(restores(unfit, "selected"));
    CrumblesExternalPublicKeyManager keys = CrumblesExternalPublicKeyManager.getInstance(context);
    keys.saveActiveExternalPublicKey(
        KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    keys.clearActiveExternalPublicKey();
    assertTrue(restores(unfit, "cleared"));
    updateKeyPrefs(UserKeyPreferences.Builder::clearExternalPublicKeys);
    enc.deleteExistingKeyPair();
    assertTrue(!restores(rsaOnly, "deleted"));
  }

  @Test
  public void doWork_safResendsMissingCopyForInternalKeyWithoutBatchWrapKeysWhileThatKeyExists()
      throws Exception {
    configureStorage(SAF_CONFIG);
    CrumblesLogsEncryptor enc = CrumblesMain.getLogsEncryptorInstance();
    enc.generateKeyPair();
    CrumblesBatchKeyStore.deleteKeys();
    LogBatch rsaOnly = enc.encryptLogs(new byte[1], null);
    // An external key was selected since then, so a batch that names no key may be for it.
    updateKeyPrefs(prefs -> prefs.setActiveKeyId("unreadable"));

    boolean restoredWithInternalKey = restores(rsaOnly, "with_key");
    enc.deleteExistingKeyPair();
    boolean restoredWithoutInternalKey = restores(rsaOnly, "without_key");
    updateKeyPrefs(UserKeyPreferences.Builder::clearActiveKeyId);

    assertThat(restoredWithInternalKey).isTrue();
    assertThat(restoredWithoutInternalKey).isFalse();
  }

  @Test
  public void rsaOnlyCopy_internalKeyReplacedBySameSizeKey_notRestored() throws Exception {
    File batch = uploadRsaOnlyCopyToSaf(/* replaceKeyDuringUpload= */ false);
    // The new key has the size of the old one, so the RSA-wrapped key alone cannot tell them apart.
    CrumblesMain.getLogsEncryptorInstance().generateKeyPair();

    assertTrue(runWorker());

    assertTrue(new File(logDirectory, "old_sent.bin").exists() && !batch.exists());
  }

  @Test
  public void rsaOnlyCopy_keyReplacedDuringUpload_notRestored() throws Exception {
    File batch = uploadRsaOnlyCopyToSaf(/* replaceKeyDuringUpload= */ true);

    assertTrue(runWorker());

    assertTrue(new File(logDirectory, "old_sent.bin").exists() && !batch.exists());
  }

  /** Uploads an RSA-only batch for the internal key to a SAF folder, and returns the batch file. */
  private File uploadRsaOnlyCopyToSaf(boolean replaceKeyDuringUpload) throws Exception {
    configureStorage(SAF_CONFIG);
    updateKeyPrefs(prefs -> prefs.clearActiveKeyId().clearExternalPublicKeys());
    CrumblesLogsEncryptor enc = CrumblesMain.getLogsEncryptorInstance();
    enc.generateKeyPair();
    CrumblesBatchKeyStore.deleteKeys();
    File batch = new File(logDirectory, "old.bin");
    LogBatch rsaOnly = enc.encryptLogs(new byte[1], null);
    assertThat(enc.serializeBytes(rsaOnly, logDirectory, batch.getName())).isNotNull();
    ret.edit().putLong("old_sent.bin", 1L).commit();
    RemoteStorageUploader saf = mock(RemoteStorageUploader.class);
    when(saf.uploadFile(any(), any(), any()))
        .thenAnswer(
            invocation -> {
              if (replaceKeyDuringUpload) {
                enc.generateKeyPair();
              }
              return true;
            });
    when(saf.getStorageType()).thenReturn(StorageType.STORAGE_TYPE_GOOGLE_DRIVE);
    assertTrue(
        CrumblesSendAndMarkProcessingWorker.uploadSingleFile(context, saf, batch, logDirectory));
    assertTrue(!ret.contains("old_sent.bin"));
    return batch;
  }

  @Test
  public void doWork_webDav_unrecordedCopyNotAgedOut() throws Exception {
    File safCopy = createFile("saf" + CrumblesConstants.SENT_SUFFIX);
    assertTrue(runWorker());
    ShadowSystemClock.advanceBy(Duration.ofDays(8));
    assertTrue(runWorker() && safCopy.exists() && !ret.contains(safCopy.getName()));
    // An upload time marks a WebDAV copy, which expires whatever the destination is now.
    assertTrue(safCopy.delete());
    File webDavCopy = createSentFile("webdav", Duration.ofDays(8));
    configureStorage(SAF_CONFIG);
    assertTrue(runWorker() && !webDavCopy.exists());
    assertTrue(!new File(logDirectory, "webdav.bin").exists());
  }

  @Test
  public void doWork_forgetsRecordedKeysOfCopiesNoLongerOnDisk() throws Exception {
    File kept = createFile("kept" + CrumblesConstants.SENT_SUFFIX);
    CrumblesDeleteSentFilesWorker.recordSafCopy(context, kept.getName(), "kept key");
    CrumblesDeleteSentFilesWorker.recordSafCopy(context, "gone_sent.bin", "gone key");

    assertTrue(runWorker());

    assertThat(context.getSharedPreferences(SENT_KEY_PREFS, 0).getAll())
        .containsExactly(kept.getName(), "kept key");
  }

  @Test
  public void internalKeyFingerprint_withoutInternalKey_isNullAndLogsNoFailure() {
    assertThat(CrumblesMain.getLogsEncryptorInstance().getPublicKey()).isNull();

    assertThat(CrumblesDeleteSentFilesWorker.internalKeyFingerprint()).isNull();
    // Having no internal key, as with an external key alone, is no failure to read it.
    assertThat(ShadowLog.getLogsForTag("CrumblesDeleteSentFilesWorker")).isEmpty();
  }

  /** Saves {@code batch} as an uploaded copy that the folder lacks; returns whether it is sent. */
  private boolean restores(LogBatch batch, String name) throws Exception {
    assertThat(
            CrumblesMain.getLogsEncryptorInstance()
                .serializeBytes(batch, logDirectory, name + CrumblesConstants.SENT_SUFFIX))
        .isNotNull();
    assertTrue(runWorker());
    return new File(logDirectory, name + ".bin").exists();
  }

  private void updateKeyPrefs(UnaryOperator<UserKeyPreferences.Builder> update) throws Exception {
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(prefs -> update.apply(prefs.toBuilder()).build())
        .get();
  }

  private void assertUploaded(RemoteStorageUploader uploader, String name) throws Exception {
    assertTrue(CrumblesSendAndMarkProcessingWorker.uploadSingleFile(context, uploader, createFile(name), logDirectory));
  }

  @Test
  public void doWork_webDavExpiresMonotonicallyAcrossWallClockShiftAndReboot() throws Exception {
    RemoteStorageUploader ok = mock(RemoteStorageUploader.class);
    when(ok.uploadFile(any(), any(), any())).thenReturn(true);
    when(ok.getStorageType()).thenReturn(StorageType.STORAGE_TYPE_WEBDAV);
    assertUploaded(ok, "up.bin");
    ShadowSystemClock.advanceBy(Duration.ofDays(1));
    assertUploaded(ok, "up2.bin");
    File uploaded = new File(logDirectory, "up_sent.bin");
    ret.edit().putLong("wiped_sent.bin", 1L).commit();
    ShadowSystemClock.advanceBy(Duration.ofDays(6).minusMillis(1));
    assertTrue(uploaded.setLastModified(1_000L) && runWorker() && uploaded.exists());
    File untracked = createFile("untracked_sent.bin");
    ShadowSystemClock.advanceBy(Duration.ofMillis(1));
    assertTrue(untracked.setLastModified(1_000L) && runWorker() && !uploaded.exists());
    assertTrue(untracked.exists() && !ret.contains("untracked_sent.bin"));
    assertTrue(new File(logDirectory, "up2_sent.bin").exists() && ret.contains("_boot_count"));
    assertTrue(!ret.contains("up_sent.bin") && !ret.contains("wiped_sent.bin"));
    assertThat(events("KEPT_COPIES_DELETED"))
        .containsExactly("Deleted 1 expired uploaded copy(ies).");
    assertUploaded(ok, "boot.bin");
    ShadowSystemClock.advanceBy(Duration.ofDays(3));
    assertUploaded(ok, "late.bin");
    File late = new File(logDirectory, "late_sent.bin");
    for (int boot : new int[] {1, 2}) {
      // Uptime restarts at each reboot, but the copies keep the age that they had reached.
      ShadowPausedSystemClock.reset();
      Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, boot);
      ShadowSystemClock.advanceBy(Duration.ofDays(2));
      assertTrue(runWorker() && late.exists());
    }
    assertTrue(untracked.exists() && !new File(logDirectory, "boot_sent.bin").exists());
    ShadowSystemClock.advanceBy(Duration.ofDays(3));
    assertTrue(runWorker() && !late.exists());
  }

  @Test
  public void recordSentFile_firstReading_isTheUptimeOfThisBoot() {
    CrumblesDeleteSentFilesWorker.recordSentFile(context, "first_sent.bin");

    // No earlier boot has been counted yet, so nothing is added to the uptime of this one.
    assertThat(ret.getLong("first_sent.bin", -1)).isEqualTo(SystemClock.elapsedRealtime());
  }

  @Test
  public void safRetainedCopiesAtCap_securityBatchReclaimsAndSavesCleanly() throws Exception {
    configureStorage(SAF_CONFIG);
    File reserved = sent("reserved", "oldest");
    File reclaimable = sent("reclaimable", "newer");
    assertTrue(
        createRemote("reserved.bin", "oldest").exists()
            && createRemote("reclaimable.bin", "newer").exists()
            && runWorker());
    try (RandomAccessFile f1 = new RandomAccessFile(reserved, "rw");
        RandomAccessFile f2 = new RandomAccessFile(reclaimable, "rw")) {
      f1.setLength(50_000_000L);
      f2.setLength(CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES - 50_000_000L - 100L);
    }
    assertTrue(reserved.exists() && reclaimable.exists() && reclaimable.setLastModified(2_000L));
    CrumblesMain.getLogsEncryptorInstance().generateKeyPair();
    DevicePolicyManager dpm = mock(DevicePolicyManager.class);
    when(dpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(
        new ContextWrapper(context) {
          @Override
          public Object getSystemService(String n) {
            return n.equals(Context.DEVICE_POLICY_SERVICE) ? dpm : super.getSystemService(n);
          }
        });
    assertTrue(reserved.exists() && !reclaimable.exists() && logDirectory.list().length == 2);
    assertTrue(new CrumblesLogStaging(context).isEmpty() && events("LOGS_LOST").isEmpty());
    assertTrue(events("LOGS_STAGED").isEmpty() && events("LOGS_COLLECTION_STOPPED").isEmpty());
    assertThat(events("LOGS_STORAGE_CAP_REACHED"))
        .containsExactly("Reclaimed 1 uploaded copy(ies) (218435356 bytes): reclaimable_sent.bin.");
  }

  @Test
  public void doWork_keepsSentFilesUploadedWithinTheRetentionPeriod() throws IOException {
    File recentlySentFile = createSentFile("log1", Duration.ofDays(6));
    File oldSentFile = createSentFile("log2", Duration.ofDays(8));
    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    ListenableWorker.Result result = worker.doWork();

    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(recentlySentFile.exists()).isTrue();
    assertThat(oldSentFile.exists()).isFalse();
  }

  @Test
  public void doWork_noSentFiles_returnsSuccess() {
    // GIVEN: The log directory exists but contains no _sent.bin files.
    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success and no files should have been present to delete.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(logDirectory.listFiles()).isEmpty();
  }

  @Test
  public void doWork_deletesSentFiles_returnsSuccess() throws IOException {
    // GIVEN: Multiple _sent.bin files and other files exist in the log directory.
    File sentFile1 = createSentFile("log1", Duration.ofDays(8));
    File sentFile2 = createSentFile("log2", Duration.ofDays(30));
    File processingFile = createFile("log3" + CrumblesConstants.PROCESSING_SUFFIX);
    File otherFile = createFile("other_log.txt");

    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success, _sent.bin files should be deleted and other files
    // should remain.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());

    assertThat(sentFile1.exists()).isFalse();
    assertThat(sentFile2.exists()).isFalse();

    assertThat(processingFile.exists()).isTrue();
    assertThat(otherFile.exists()).isTrue();
  }

  @Test
  public void doWork_logDirectoryMissing_returnsFailure() {
    // GIVEN: The log directory does not exist.
    assertTrue(logDirectory.exists());
    deleteRecursive(logDirectory);
    assertThat(logDirectory.exists()).isFalse();

    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return failure.
    assertThat(result).isEqualTo(ListenableWorker.Result.failure());
  }

  @Test
  public void doWork_emptyDirectory_returnsSuccess() {
    // GIVEN: The log directory exists and is empty (as per setup).
    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(logDirectory.listFiles()).isEmpty(); // Directory should remain empty.
  }

  @Test
  public void doWork_fileWithoutCorrectSuffix_isNotDeleted() throws IOException {
    // GIVEN: Files exist that do not strictly end with _sent.bin.
    File notSentFile = createFile("some_file.txt");
    File sentFileWithExtraStuff = createFile("abc" + CrumblesConstants.SENT_SUFFIX + ".tmp");
    File exactSentFile = createSentFile("exact", Duration.ofDays(8));

    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success, and only the exact _sent.bin file should be deleted.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(notSentFile.exists()).isTrue();
    assertThat(sentFileWithExtraStuff.exists()).isTrue();
    assertThat(exactSentFile.exists()).isFalse();
  }
}
