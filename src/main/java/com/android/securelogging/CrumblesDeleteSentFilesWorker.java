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

import static com.google.common.collect.ImmutableSet.toImmutableSet;

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
import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multiset;
import com.google.common.io.ByteStreams;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.ClosedChannelException;
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
import java.util.Set;

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

  /**
   * Names of the copies sent to a SAF folder that the daily re-check has found there since their
   * upload. The storage quota records deleting any other one as a loss.
   */
  private static final String VERIFIED_PREFS = "CrumblesSentVerified";

  /**
   * Most documents named like a kept copy that the re-check reads back, each within its own
   * transfer deadline, so that duplicates cannot hold the worker past its time limit.
   */
  private static final int MAX_DOCUMENTS_PER_NAME = 2;

  /** How the re-check of one kept copy ended. */
  private enum CheckOutcome {
    /** The folder has a copy with the same bytes. */
    VERIFIED,
    /** The folder lacks the copy, which is back in the upload queue. */
    RESENT,
    /**
     * The copy stays unverified: the folder cannot be listed, the copy cannot be read, or the
     * folder lacks it and it is not resent.
     */
    UNVERIFIED,
    /** Reading back a document hit the transfer deadline, so the copy stays unverified. */
    STALLED
  }

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
    Uri treeUri = Uri.parse(uri);
    ImmutableSet<String> originalNames =
        Arrays.stream(sentBinFiles)
            .map(CrumblesDeleteSentFilesWorker::originalName)
            .collect(toImmutableSet());
    Optional<ListMultimap<String, DocumentFile>> remoteFiles;
    try {
      // The cursor reads from the provider too, so the whole listing gets the deadline of a call.
      remoteFiles =
          CrumblesTransferDeadline.callProvider(
              treeUri, () -> listRemoteFilesByName(ctx, treeUri, originalNames));
    } catch (IOException | RuntimeException e) {
      // Binder passes on what the provider throws, such as SecurityException once access ends.
      Log.e(TAG, "Failed to list folder, keeping everything.", e);
      remoteFiles = Optional.empty();
    }
    if (remoteFiles.isEmpty()) {
      reportReconcileFailure(
          ctx, "Could not list the upload folder; kept every uploaded copy unverified.");
    }
    // Only the copies that this check finds in the folder stay verified.
    SharedPreferences.Editor verified =
        ctx.getSharedPreferences(VERIFIED_PREFS, Context.MODE_PRIVATE).edit().clear();
    int resent = 0;
    int stalled = 0;
    for (File file : sentBinFiles) {
      CheckOutcome outcome =
          remoteFiles.isPresent()
              ? reconcileSafSentFile(ctx, dir, file, remoteFiles.get())
              : CheckOutcome.UNVERIFIED;
      if (outcome.equals(CheckOutcome.VERIFIED)) {
        verified.putBoolean(file.getName(), true);
      }
      resent += outcome.equals(CheckOutcome.RESENT) ? 1 : 0;
      stalled += outcome.equals(CheckOutcome.STALLED) ? 1 : 0;
    }
    verified.apply();
    if (stalled > 0) {
      reportReconcileFailure(
          ctx,
          "The upload folder did not return "
              + stalled
              + " copy(ies) in time; kept them unverified.");
    }
    if (resent > 0) {
      CrumblesAppAuditLogger.getInstance(ctx)
          .logEvent("KEPT_COPY_RESENT", "Resent " + resent + " missing uploaded copy(ies).");
      CrumblesWorkScheduler.requestImmediateUpload(WorkManager.getInstance(ctx));
    }
  }

  /**
   * Returns the documents in the folder of {@code treeUri} whose display name is one of {@code
   * names}, at most {@link #MAX_DOCUMENTS_PER_NAME} per name, by name. One query lists them all,
   * rather than one query per document. It is empty if the provider returns no cursor.
   */
  private static Optional<ListMultimap<String, DocumentFile>> listRemoteFilesByName(
      Context ctx, Uri treeUri, Set<String> names) {
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
      // A document is wanted if it has the name of a kept copy and that name has a place left, so
      // that other documents, however many, take no memory.
      Multiset<String> wanted = HashMultiset.create();
      names.forEach(name -> wanted.add(name, MAX_DOCUMENTS_PER_NAME));
      ImmutableListMultimap.Builder<String, DocumentFile> files = ImmutableListMultimap.builder();
      while (cursor.moveToNext()) {
        String name = cursor.getString(1);
        if (wanted.remove(name)) {
          Uri document = DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(0));
          files.put(name, DocumentFile.fromSingleUri(ctx, document));
        }
      }
      return Optional.of(files.build());
    }
  }

  private static CheckOutcome reconcileSafSentFile(
      Context context,
      File directory,
      File sentFile,
      ListMultimap<String, DocumentFile> remoteFiles) {
    String name = sentFile.getName();
    String originalName = originalName(sentFile);
    List<DocumentFile> corrupted = new ArrayList<>();
    byte[] local = null;
    boolean foundValid = false;
    for (DocumentFile remoteFile : remoteFiles.get(originalName)) {
      if (local == null) {
        try {
          local = sha256(sentFile);
        } catch (IOException | NoSuchAlgorithmException e) {
          Log.e(TAG, "Failed to read " + name + ", keeping it.", e);
          return CheckOutcome.UNVERIFIED;
        }
      }
      byte[] remote;
      try {
        remote =
            GoogleDriveStorageUploader.readBackDigest(context, remoteFile, sentFile.length() + 1);
      } catch (ClosedChannelException e) {
        // Only the transfer deadline closes the channel early.
        Log.e(TAG, "The folder did not return " + originalName + " in time.", e);
        return CheckOutcome.STALLED;
      } catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
        // Whoever shares the folder can give the name of a batch to a directory or to a document of
        // their own, and binder passes on what the provider throws. Such a document is no copy of
        // the batch, but it is not ours to delete.
        Log.w(TAG, "Skipped a document named " + originalName + " that cannot be read.", e);
        continue;
      }
      if (MessageDigest.isEqual(local, remote)) {
        foundValid = true;
      } else {
        corrupted.add(remoteFile);
      }
    }
    corrupted.forEach(CrumblesDeleteSentFilesWorker::deleteCorruptedCopy);
    if (foundValid) {
      return CheckOutcome.VERIFIED;
    }
    if (hasDeletedKey(context, sentFile)) {
      return CheckOutcome.UNVERIFIED;
    }
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      try {
        Files.move(sentFile.toPath(), new File(directory, originalName).toPath());
        return CheckOutcome.RESENT;
      } catch (IOException e) {
        Log.e(TAG, "Failed to restore missing batch for retry: " + name, e);
        return CheckOutcome.UNVERIFIED;
      }
    }
  }

  /** Deletes {@code copy}, unless its provider does not answer in time; the next check retries. */
  private static void deleteCorruptedCopy(DocumentFile copy) {
    try {
      @SuppressWarnings("unused")
      var unusedDeleted = CrumblesTransferDeadline.callProvider(copy.getUri(), copy::delete);
    } catch (IOException e) {
      Log.w(TAG, "The provider did not delete a corrupted copy in time", e);
    }
  }

  /**
   * Returns whether {@code sentFileName} is a copy sent to a SAF folder that the daily re-check has
   * not found there since its upload, so that deleting it may lose its logs.
   */
  static boolean isUnverifiedSafCopy(Context context, String sentFileName) {
    // Copies with an upload time went to WebDAV, which nothing re-checks.
    return !context
            .getSharedPreferences(RETENTION_PREFS, Context.MODE_PRIVATE)
            .contains(sentFileName)
        && !context
            .getSharedPreferences(VERIFIED_PREFS, Context.MODE_PRIVATE)
            .contains(sentFileName);
  }

  /** Returns the name that {@code sentFile} had before its upload, which its copy has too. */
  private static String originalName(File sentFile) {
    String name = sentFile.getName();
    return name.substring(0, name.length() - CrumblesConstants.SENT_SUFFIX.length()) + ".bin";
  }

  /** Records that the re-check could not verify some kept copies, which stay on the device. */
  private static void reportReconcileFailure(Context context, String message) {
    CrumblesAppAuditLogger.getInstance(context).logEvent("KEPT_COPY_RECONCILE_FAILED", message);
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
   * key. Any other batch for the internal key has an empty batch-wrap key id, unless an earlier
   * version wrote it: such a batch names no key, and is for an internal key if no external key was
   * ever set. The key of either batch is gone if no internal key exists, if the current one differs
   * from the key recorded at upload, or else if it does not have the size of the RSA-wrapped key.
   */
  private static boolean hasDeletedKey(Context context, File sentFile) {
    try {
      CrumblesLogsEncryptor enc = CrumblesMain.getLogsEncryptorInstance();
      var k = enc.deserializeFile(sentFile.toPath()).getKey();
      if (!k.getBatchWrapKeyId().isEmpty()) {
        return !enc.doesPrivateKeyExist()
            || !CrumblesBatchKeyStore.hasKeys()
            || !CrumblesBatchKeyStore.keyId().equals(k.getBatchWrapKeyId());
      }
      if (!k.hasBatchWrapKeyId() && mayHaveExternalKeyBatches(context)) {
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
