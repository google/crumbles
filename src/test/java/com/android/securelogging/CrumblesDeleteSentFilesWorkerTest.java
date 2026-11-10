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
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
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
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
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
  private Context context;
  private File logDirectory;
  private TreeProvider safProvider;
  private SharedPreferences ret;

  @Rule public final Expect expect = Expect.create();

  /** A strict provider, which lists children with only the columns it knows, and counts queries. */
  public static final class TreeProvider extends TestDriveContentProvider {
    /** Prefix of a document that has the display name of another one, as in a duplicate. */
    private static final Pattern DUPLICATE_PREFIX = Pattern.compile("^dup\\d+_");

    int queryCount;

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sortOrder) {
      queryCount++;
      if (queryFault != 0 || !uri.getPath().endsWith("/children")) {
        return super.query(uri, proj, sel, selArgs, sortOrder);
      }
      MatrixCursor cursor = new MatrixCursor(proj);
      for (File file : tempDriveDir.listFiles()) {
        cursor.addRow(
            Arrays.stream(proj).map(column -> columnOf(file.getName(), column)).toArray());
      }
      return cursor;
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
  public void tearDown() {
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
    assertTrue(Files.writeString(file.toPath(), content).toFile().setLastModified(1_000L));
    return file;
  }

  private File createRemote(String name, String content) throws IOException {
    return Files.writeString(new File(safProvider.tempDriveDir, name).toPath(), content).toFile();
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
    for (int f : new int[] {1, 2, 3, 4}) {
      safProvider.queryFault = f <= 2 ? f : 0;
      safProvider.setShouldCrash(f == 3);
      safProvider.setShouldWithholdReadBack(f == 4);
      assertTrue(runWorker() && mismatch.exists() && bad1.exists() && bad2.exists());
    }
    DocumentFile doc = DocumentFile.fromSingleUri(context, Uri.parse("content://s/doc/x"));
    assertThrows(IOException.class, () -> GoogleDriveStorageUploader.readBackDigest(context, doc, 10));
    safProvider.setShouldWithholdReadBack(false);
    File blockedSent = sent("blocked", "older");
    Files.writeString(createFile("blocked.bin").toPath(), "newer");
    assertTrue(runWorker() && new File(logDirectory, "log2.bin").exists());
    assertTrue(!bad1.exists() && !bad2.exists() && !mismatch.exists() && blockedSent.exists());
    assertThat(Files.readString(new File(logDirectory, "blocked.bin").toPath())).isEqualTo("newer");
    assertThat(events("KEPT_COPY_RESENT")).containsExactly("Resent 1 missing uploaded copy(ies).");
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
    // Without batch-wrap keys, batches for the internal key are RSA-only, as for an external key.
    LogBatch rsaOnly = enc.encryptLogs(new byte[1], null);
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
