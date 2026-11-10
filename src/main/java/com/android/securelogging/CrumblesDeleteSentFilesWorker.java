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

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.SystemClock;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import android.provider.Settings;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.documentfile.provider.DocumentFile;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.io.ByteStreams;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link Worker} that deletes files with the "_sent.bin" suffix from the app's private directory
 * once they have been uploaded for {@link #SENT_FILE_RETENTION}.
 */
public class CrumblesDeleteSentFilesWorker extends Worker {

  private static final String TAG = "CrumblesDeleteSentFilesWorker";
  static final String RETENTION_PREFS = "CrumblesSentRetention";

  /** Fingerprints of the internal key current at the upload of each copy sent to a SAF folder. */
  static final String SENT_KEY_PREFS = "CrumblesSentKeys";

  /** Prefix of the keys that hold no upload time, which batch names never start with. */
  private static final String STATE_KEY_PREFIX = "_";

  /** The boot that {@link #KEY_EARLIER_UPTIME} is for. */
  private static final String KEY_BOOT_COUNT = STATE_KEY_PREFIX + "boot_count";

  /** Uptime that the boots before {@link #KEY_BOOT_COUNT} added up to. */
  private static final String KEY_EARLIER_UPTIME = STATE_KEY_PREFIX + "earlier_uptime";

  /** The last reading of {@link #uptimeAcrossBoots}, from which the next boot counts on. */
  private static final String KEY_LAST_UPTIME = STATE_KEY_PREFIX + "last_uptime";

  /**
   * How long an uploaded batch stays on the device, counted from its upload, so that a copy lost at
   * the destination can still be sent again.
   */
  static final Duration SENT_FILE_RETENTION = Duration.ofDays(7);

  public CrumblesDeleteSentFilesWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  /** Records the upload time of {@code sentFileName}, in uptime across boots, for WebDAV expiry. */
  static void recordSentFile(Context ctx, String sentFileName) {
    SharedPreferences prefs = ctx.getSharedPreferences(RETENTION_PREFS, Context.MODE_PRIVATE);
    SharedPreferences.Editor ed = prefs.edit();
    ed.putLong(sentFileName, uptimeAcrossBoots(ctx, prefs, ed)).apply();
  }

  /**
   * Records that {@code sentFileName} went to a Storage Access Framework folder, so that it never
   * expires by age, and {@code keyFingerprint}, the internal key it is encrypted to, if known.
   */
  static void recordSafCopy(Context ctx, String sentFileName, @Nullable String keyFingerprint) {
    ctx.getSharedPreferences(RETENTION_PREFS, Context.MODE_PRIVATE)
        .edit()
        .remove(sentFileName)
        .apply();
    SharedPreferences.Editor keys =
        ctx.getSharedPreferences(SENT_KEY_PREFS, Context.MODE_PRIVATE).edit().remove(sentFileName);
    if (keyFingerprint != null) {
      keys.putString(sentFileName, keyFingerprint);
    }
    keys.apply();
  }

  /** Returns the fingerprint of the internal key, or null if there is none or it is unreadable. */
  @Nullable
  static String internalKeyFingerprint() {
    try {
      PublicKey key = CrumblesMain.getLogsEncryptorInstance().getPublicKey();
      return key == null ? null : CrumblesLogsEncryptor.getPublicKeyFingerprint(key);
    } catch (CrumblesKeysException | RuntimeException e) {
      Log.w(TAG, "Failed to read the internal key.", e);
      return null;
    }
  }

  /**
   * Returns the device uptime summed over boots, and adds its new state to {@code ed}. Unlike the
   * wall clock, nobody can set it, and unlike {@link SystemClock#elapsedRealtime}, it does not
   * restart at a reboot, so uploaded copies keep their age. Uptime after the last reading of a boot
   * is not counted, which only keeps copies longer.
   */
  private static long uptimeAcrossBoots(
      Context ctx, SharedPreferences prefs, SharedPreferences.Editor ed) {
    int boot = Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.BOOT_COUNT, -1);
    boolean sameBoot = prefs.getInt(KEY_BOOT_COUNT, boot) == boot;
    long earlier = prefs.getLong(sameBoot ? KEY_EARLIER_UPTIME : KEY_LAST_UPTIME, 0);
    long uptime = earlier + SystemClock.elapsedRealtime();
    ed.putInt(KEY_BOOT_COUNT, boot)
        .putLong(KEY_EARLIER_UPTIME, earlier)
        .putLong(KEY_LAST_UPTIME, uptime);
    return uptime;
  }

  @NonNull
  @Override
  public Result doWork() {
    Log.d(TAG, "CrumblesDeleteSentFilesWorker doWork() started");
    Context context = getApplicationContext();

    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return Result.failure();
    }

    // Find files ending ONLY in _sent.bin.
    File[] sentBinFiles =
        directory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.SENT_SUFFIX));

    if (sentBinFiles == null || sentBinFiles.length == 0) {
      Log.d(TAG, "No _sent.bin files found for deletion.");
      return Result.success();
    }

    Log.d(TAG, "Found " + sentBinFiles.length + " _sent.bin files.");
    RemoteStorageConfig cfg =
        CrumblesSendAndMarkProcessingWorker.readUserPreferences(context).getRemoteStorageConfig();
    SharedPreferences retention =
        context.getSharedPreferences(RETENTION_PREFS, Context.MODE_PRIVATE);
    // A copy with an upload time went to WebDAV, and expires whatever the destination is now. The
    // others went to a SAF folder, which may not have synced them yet.
    File[] safCopies =
        Arrays.stream(sentBinFiles)
            .filter(file -> !retention.contains(file.getName()))
            .toArray(File[]::new);
    int deletedCount = deleteExpiredWebDavFiles(context, directory, sentBinFiles);
    if (!cfg.getStorageType().equals(StorageType.STORAGE_TYPE_WEBDAV)) {
      reconcileSafFiles(context, directory, safCopies, cfg);
    }
    pruneMissingCopies(
        context.getSharedPreferences(SENT_KEY_PREFS, Context.MODE_PRIVATE), directory);

    Log.d(
        TAG,
        "Deletion task finished. Successfully deleted "
            + deletedCount
            + " files with _sent suffix.");
    return Result.success();
  }

  private static int deleteExpiredWebDavFiles(Context ctx, File dir, File[] sentBinFiles) {
    SharedPreferences prefs = ctx.getSharedPreferences(RETENTION_PREFS, Context.MODE_PRIVATE);
    Map<String, ?> entries = prefs.getAll();
    SharedPreferences.Editor ed = prefs.edit();
    long now = uptimeAcrossBoots(ctx, prefs, ed);
    int deletedCount = 0;
    for (File file : sentBinFiles) {
      Object recorded = entries.get(file.getName());
      if (recorded instanceof Long recordedTime
          && now - recordedTime >= SENT_FILE_RETENTION.toMillis()) {
        if (file.delete()) {
          Log.d(TAG, "Deleted: " + file.getName());
          deletedCount++;
        } else {
          // Failure to delete one file shouldn't stop the worker.
          Log.e(TAG, "Failed to delete: " + file.getName());
        }
      }
    }
    ed.apply();
    pruneMissingCopies(prefs, dir);
    if (deletedCount > 0) {
      String msg = "Deleted " + deletedCount + " expired uploaded copy(ies).";
      CrumblesAppAuditLogger.getInstance(ctx).logEvent("KEPT_COPIES_DELETED", msg);
    }
    return deletedCount;
  }

  /** Removes the entries of {@code prefs} for copies that are no longer in {@code dir}. */
  private static void pruneMissingCopies(SharedPreferences prefs, File dir) {
    SharedPreferences.Editor ed = prefs.edit();
    for (String key : prefs.getAll().keySet()) {
      if (!key.startsWith(STATE_KEY_PREFIX) && !new File(dir, key).exists()) {
        ed.remove(key);
      }
    }
    ed.apply();
  }

  private static void reconcileSafFiles(
      Context ctx, File dir, File[] sentBinFiles, RemoteStorageConfig cfg) {
    String uri =
        !cfg.getUploadDestinationUri().isEmpty()
            ? cfg.getUploadDestinationUri()
            : ctx.getSharedPreferences(CrumblesConstants.PREFS_NAME, 0)
                .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, "");
    if (uri.isEmpty()) {
      return;
    }
    Optional<ListMultimap<String, DocumentFile>> remoteFiles;
    try {
      remoteFiles = listRemoteFilesByName(ctx, Uri.parse(uri));
    } catch (RuntimeException e) {
      Log.e(TAG, "Failed to list folder, keeping everything.", e);
      return;
    }
    if (remoteFiles.isEmpty()) {
      return;
    }
    int resent = 0;
    for (File file : sentBinFiles) {
      resent += reconcileSafSentFile(ctx, dir, file, remoteFiles.get()) ? 1 : 0;
    }
    if (resent > 0) {
      CrumblesAppAuditLogger.getInstance(ctx)
          .logEvent("KEPT_COPY_RESENT", "Resent " + resent + " missing uploaded copy(ies).");
      CrumblesWorkScheduler.requestImmediateUpload(WorkManager.getInstance(ctx));
    }
  }

  /**
   * Returns the documents in the folder of {@code treeUri} by display name, which one query lists,
   * rather than one query per document, or empty if the provider returns no cursor.
   */
  private static Optional<ListMultimap<String, DocumentFile>> listRemoteFilesByName(
      Context ctx, Uri treeUri) {
    Uri childrenUri =
        DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri, DocumentsContract.getTreeDocumentId(treeUri));
    String[] projection = {Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME};
    try (Cursor cursor =
        ctx.getContentResolver()
            .query(
                childrenUri,
                projection,
                /* selection= */ null,
                /* selectionArgs= */ null,
                /* sortOrder= */ null)) {
      if (cursor == null) {
        return Optional.empty();
      }
      ImmutableListMultimap.Builder<String, DocumentFile> files = ImmutableListMultimap.builder();
      while (cursor.moveToNext()) {
        Uri document = DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(0));
        files.put(
            Strings.nullToEmpty(cursor.getString(1)), DocumentFile.fromSingleUri(ctx, document));
      }
      return Optional.of(files.build());
    }
  }

  private static boolean reconcileSafSentFile(
      Context context,
      File directory,
      File sentFile,
      ListMultimap<String, DocumentFile> remoteFiles) {
    String name = sentFile.getName();
    String originalName =
        name.substring(0, name.length() - CrumblesConstants.SENT_SUFFIX.length()) + ".bin";
    List<DocumentFile> corrupted = new ArrayList<>();
    byte[] local = null;
    boolean foundValid = false;
    for (DocumentFile remoteFile : remoteFiles.get(originalName)) {
      try {
        if (local == null) {
          local = sha256(sentFile);
        }
        byte[] remote =
            GoogleDriveStorageUploader.readBackDigest(context, remoteFile, sentFile.length() + 1);
        if (MessageDigest.isEqual(local, remote)) {
          foundValid = true;
        } else {
          corrupted.add(remoteFile);
        }
      } catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
        Log.e(TAG, "Digest match failed", e);
        return false;
      }
    }
    corrupted.forEach(DocumentFile::delete);
    if (foundValid || hasDeletedKey(context, sentFile)) {
      return false;
    }
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      try {
        Files.move(sentFile.toPath(), new File(directory, originalName).toPath());
        return true;
      } catch (IOException e) {
        Log.e(TAG, "Failed to restore missing batch for retry: " + name, e);
        return false;
      }
    }
  }

  private static byte[] sha256(File file) throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream in = new DigestInputStream(Files.newInputStream(file.toPath()), digest)) {
      ByteStreams.exhaust(in);
    }
    return digest.digest();
  }

  /**
   * Returns whether no key on this device can decrypt {@code sentFile} any more, because the
   * internal key that it is encrypted to is gone.
   *
   * <p>A batch-wrapped key names its batch-wrap key, which is replaced together with the internal
   * key. An RSA-only batch names no key: it is for an internal key if no external key was ever set,
   * and that key is gone if no internal key exists, or if the current one differs from the key
   * recorded at upload, or else does not have the size of the RSA-wrapped key.
   */
  private static boolean hasDeletedKey(Context context, File sentFile) {
    try {
      CrumblesLogsEncryptor enc = CrumblesMain.getLogsEncryptorInstance();
      var k = enc.deserializeFile(sentFile.toPath()).getKey();
      if (k.hasBatchWrapKeyId()) {
        return !enc.doesPrivateKeyExist()
            || !CrumblesBatchKeyStore.hasKeys()
            || !CrumblesBatchKeyStore.keyId().equals(k.getBatchWrapKeyId());
      }
      if (mayHaveExternalKeyBatches(context)) {
        return false;
      }
      PublicKey internalKey = enc.getPublicKey();
      if (internalKey == null) {
        return true;
      }
      String uploadKey =
          context
              .getSharedPreferences(SENT_KEY_PREFS, Context.MODE_PRIVATE)
              .getString(sentFile.getName(), null);
      return uploadKey != null
          ? !uploadKey.equals(CrumblesLogsEncryptor.getPublicKeyFingerprint(internalKey))
          : k.getEncryptedSymmetricKey().size()
              != ((RSAPublicKey) internalKey).getModulus().bitLength() / Byte.SIZE;
    } catch (CrumblesKeysException | RuntimeException e) {
      return false;
    }
  }

  /** Returns whether batches may be encrypted to an external key, as one is or was set. */
  private static boolean mayHaveExternalKeyBatches(Context context) {
    return CrumblesExternalPublicKeyManager.getInstance(context).isExternalKeySelected()
        || !CrumblesSendAndMarkProcessingWorker.readUserPreferences(context)
            .getExternalPublicKeysMap()
            .isEmpty();
  }
}
