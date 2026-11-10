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

import static java.nio.charset.StandardCharsets.UTF_8;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.UriPermission;
import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.documentfile.provider.DocumentFile;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.base.Enums;
import com.google.errorprone.annotations.concurrent.GuardedBy;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLSocketFactory;

/**
 * A WorkManager worker class that handles automated streaming of encrypted log files to the
 * user-selected upload destination while guaranteeing zero log batch loss, transactional status
 * tracking, and full audit traceability.
 */
public class CrumblesSendAndMarkProcessingWorker extends Worker {

  private static final String TAG = "CrumblesSendAndMarkProcessingWorker";

  static final Object UPLOAD_LOCK = new Object();

  /**
   * Processing files that uploads in this process hold. They are not stale, so recovery leaves them
   * alone, and the wipes wait until they are marked sent or pending again.
   */
  @GuardedBy("UPLOAD_LOCK")
  private static final Set<String> inFlightProcessingNames = new HashSet<>();

  private static final ThreadLocal<BooleanSupplier> STOP_CHECK =
      ThreadLocal.withInitial(() -> () -> false);

  /** Attempts of one periodic run, retries included, before it waits for the next period. */
  static final int MAX_RUN_ATTEMPTS = 5;

  /** Preferences key holding the {@link UploadIssue} that was last reported to the user. */
  private static final String PREF_LAST_REPORTED_UPLOAD_ISSUE = "lastReportedUploadIssue";

  /**
   * Problems that defer or interrupt uploads. Each problem is logged once until it changes or an
   * upload succeeds, so that retries do not flood the audit log, while its notification stays up.
   * Notification texts stay neutral: anyone who sees the phone can read them.
   */
  private enum UploadIssue {
    NO_KEY(
        "LOGS_UPLOAD_DEFERRED_NO_KEY",
        "Upload deferred because active encryption key is unavailable; logs preserved on disk.",
        R.string.notification_title_action_needed,
        R.string.notification_text_action_needed),
    WEBDAV_NOT_CONFIGURED(
        "UPLOAD_DESTINATION_NOT_CONFIGURED",
        "Upload deferred: WebDAV server URL or credentials not configured.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_webdav_not_configured),
    CREDENTIALS_DECRYPTION_FAILED(
        "UPLOAD_CREDENTIALS_DECRYPTION_FAILED",
        "Upload deferred: the saved WebDAV credentials could not be decrypted.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_credentials_decryption_failed),
    DESTINATION_NOT_CONFIGURED(
        "UPLOAD_DESTINATION_NOT_CONFIGURED",
        "Upload deferred: destination folder is not configured.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_dest_not_configured),
    DESTINATION_PERMISSION_REVOKED(
        "UPLOAD_DESTINATION_PERMISSION_REVOKED",
        "Upload failed because persistable write permission was missing or revoked.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_permission_revoked),
    DESTINATION_INACCESSIBLE(
        "UPLOAD_DESTINATION_INVALID",
        "Upload deferred: destination folder is inaccessible or unwritable.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_dest_inaccessible),
    UPLOAD_FAILED(
        "LOGS_UPLOAD_FAILED",
        "One or more log files failed to upload; preserved safely on device for retry.",
        R.string.notification_title_upload_interrupted,
        R.string.notification_text_upload_failed),
    SERVER_KEY_NOT_CONFIRMED(
        "UPLOAD_SERVER_KEY_NOT_CONFIRMED",
        "Upload refused: no confirmed key for the HTTPS WebDAV server; logs preserved on disk.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_server_key_not_confirmed),
    SERVER_KEY_CHANGED(
        "UPLOAD_SERVER_KEY_REJECTED",
        "Upload refused: the WebDAV server presented a public key other than the pinned one; logs"
            + " preserved on disk.",
        R.string.notification_title_action_needed,
        R.string.notification_text_upload_server_key_changed);

    private final String auditEvent;
    private final String auditMessage;
    @StringRes private final int notificationTitleResId;
    @StringRes private final int notificationContentResId;

    UploadIssue(
        String auditEvent,
        String auditMessage,
        @StringRes int notificationTitleResId,
        @StringRes int notificationContentResId) {
      this.auditEvent = auditEvent;
      this.auditMessage = auditMessage;
      this.notificationTitleResId = notificationTitleResId;
      this.notificationContentResId = notificationContentResId;
    }
  }

  public CrumblesSendAndMarkProcessingWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  @NonNull
  @Override
  public Result doWork() {
    STOP_CHECK.set(this::isStopped);
    Result result;
    try {
      result = uploadPendingBatches(getApplicationContext());
    } finally {
      STOP_CHECK.remove();
    }
    // A problem that outlasts a few backed-off retries, such as a missing key, waits for the next
    // period instead of waking the device again.
    if (result.equals(Result.retry()) && getRunAttemptCount() + 1 >= MAX_RUN_ATTEMPTS) {
      Log.w(TAG, "Upload still deferred after " + MAX_RUN_ATTEMPTS + " attempts.");
      return Result.failure();
    }
    return result;
  }

  /**
   * Uploads every pending batch to the configured destination and marks each uploaded batch as
   * sent. Batches that fail to upload stay pending.
   *
   * @return success when no batch is left to upload, retry when some are, or failure when the log
   *     directory does not exist
   */
  static Result uploadPendingBatches(Context context) {
    Log.d(TAG, "Uploading pending batches");

    Optional<PublicKey> activeKey = CrumblesDeviceAdminReceiver.resolveActiveEncryptionKey(context);
    boolean keyIsAvailable = activeKey.isPresent();

    if (!keyIsAvailable) {
      Log.w(
          TAG,
          "No encryption key (internal or external) is available. Deferring upload to preserve"
              + " logs.");
      reportUploadIssue(context, UploadIssue.NO_KEY);
      return Result.retry();
    }

    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return Result.failure();
    }

    File[] unprocessedBinFiles;
    synchronized (UPLOAD_LOCK) {
      // Recover any stale processing files from interrupted runs to prevent log loss
      recoverStaleProcessingFiles(context, directory);
      unprocessedBinFiles = getUnprocessedBinFiles(directory);
    }

    if (unprocessedBinFiles.length == 0) {
      CrumblesDeviceAdminReceiver.drainStagedBatches(context, activeKey.get());
      synchronized (UPLOAD_LOCK) {
        unprocessedBinFiles = getUnprocessedBinFiles(directory);
      }
      if (unprocessedBinFiles.length == 0) {
        Log.d(TAG, "No unprocessed .bin files found.");
        clearReportedUploadIssue(context);
        return new CrumblesLogStaging(context).isEmpty() ? Result.success() : Result.retry();
      }
    }

    Result result = processAndUploadFiles(context, unprocessedBinFiles, directory);
    // Staged batches that the drain could not encrypt yet need another run.
    return new CrumblesLogStaging(context).isEmpty() ? result : Result.retry();
  }

  private static File[] getUnprocessedBinFiles(File directory) {
    File[] unprocessedBinFiles =
        directory.listFiles(
            (dir, name) ->
                name.endsWith(".bin")
                    && !name.endsWith(CrumblesConstants.PROCESSING_SUFFIX)
                    && !name.endsWith(CrumblesConstants.SENT_SUFFIX));
    if (unprocessedBinFiles == null) {
      return new File[0];
    }
    Arrays.sort(
        unprocessedBinFiles,
        Comparator.comparingLong(File::lastModified).thenComparing(File::getName));
    return unprocessedBinFiles;
  }

  @GuardedBy("UPLOAD_LOCK")
  private static void recoverStaleProcessingFiles(Context context, File directory) {
    File[] staleProcessingFiles =
        directory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.PROCESSING_SUFFIX));
    if (staleProcessingFiles == null) {
      return;
    }
    int recoveredCount = 0;
    for (File processingFile : staleProcessingFiles) {
      String processingName = processingFile.getName();
      if (inFlightProcessingNames.contains(processingName)) {
        continue;
      }
      String baseName =
          processingName.substring(
              0, processingName.length() - CrumblesConstants.PROCESSING_SUFFIX.length());
      File restoredFile = new File(directory, baseName + ".bin");
      if (processingFile.renameTo(restoredFile)) {
        recoveredCount++;
      } else {
        Log.e(TAG, "Failed to recover stale processing file: " + processingName);
      }
    }
    if (recoveredCount > 0) {
      Log.i(TAG, "Recovered " + recoveredCount + " stale processing file(s) for upload retry.");
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_UPLOAD_RECOVERED_PROCESSING",
              "Recovered " + recoveredCount + " stale processing log file(s) for upload retry.");
    }
  }

  private static Result processAndUploadFiles(
      Context context, File[] unprocessedBinFiles, File directory) {
    // Closing the uploader wipes any credentials it holds once this run no longer needs them.
    try (RemoteStorageUploader uploader = resolveStorageUploader(context)) {
      if (uploader == null) {
        return Result.retry();
      }
      Result result = uploadFiles(context, uploader, unprocessedBinFiles, directory);
      // Failed batches, and every batch after a rejected server key, wait for the backoff.
      if (!result.equals(Result.success())) {
        return result;
      }
      // The key can change while the batches upload, so the drain resolves it again.
      CrumblesDeviceAdminReceiver.drainStagedBatchesToCurrentKey(context);
      File[] newlyDrainedFiles = getUnprocessedBinFiles(directory);
      if (newlyDrainedFiles.length > 0) {
        result = uploadFiles(context, uploader, newlyDrainedFiles, directory);
      }
      return result;
    }
  }

  private static Result uploadFiles(
      Context context, RemoteStorageUploader uploader, File[] unprocessedBinFiles, File directory) {
    int uploadedCount = 0;
    boolean hasFailures = false;
    // Batches that a wipe deletes meanwhile fail to upload, but are gone, not kept for a retry.
    int wipeGeneration = CrumblesUploadAndWipeWorker.currentWipeGeneration();

    for (File file : unprocessedBinFiles) {
      if (STOP_CHECK.get().getAsBoolean()) {
        break;
      }
      if (uploadSingleFile(context, uploader, file, directory)) {
        uploadedCount++;
      } else {
        hasFailures = true;
        // The next batches would fail the same way, after a failure in transit only once their
        // deadline passed.
        if (uploader.rejectedServerKey() || uploader.transportFailed()) {
          break;
        }
      }
    }

    // Any Storage Access Framework provider can back the selected folder, so do not name one.
    String destination =
        uploader.getStorageType().equals(StorageType.STORAGE_TYPE_GOOGLE_DRIVE)
            ? "the upload folder"
            : uploader.getDestinationDescription();
    if (uploadedCount > 0) {
      clearReportedUploadIssue(context);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_UPLOAD_SUCCESS",
              "Successfully automatically uploaded "
                  + uploadedCount
                  + " log file(s) to "
                  + destination
                  + ".");
    }

    if (uploader.rejectedServerKey()) {
      // Uploads resume on their own if the server presents the pinned key again. Until then, the
      // user has to check the server, so this is not reported as a failure that a retry will fix.
      reportUploadIssue(context, UploadIssue.SERVER_KEY_CHANGED);
      return Result.retry();
    }
    if (hasFailures && wipeGeneration == CrumblesUploadAndWipeWorker.currentWipeGeneration()) {
      reportUploadIssue(context, UploadIssue.UPLOAD_FAILED);
      return Result.retry();
    }
    if (uploadedCount != unprocessedBinFiles.length) {
      return Result.retry();
    }

    // No success notification: it would tell whoever sees the phone what the app does.
    return Result.success();
  }

  static UserKeyPreferences readUserPreferences(Context context) {
    try {
      return CrumblesDataStoreHolder.getInstance(context).getDataAsync().get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      Log.e(TAG, "Interrupted while reading UserKeyPreferences from DataStore", e);
    } catch (ExecutionException e) {
      Log.e(TAG, "Failed to read UserKeyPreferences from DataStore", e);
    }
    return UserKeyPreferences.getDefaultInstance();
  }

  @Nullable
  static RemoteStorageUploader resolveStorageUploader(Context context) {
    UserKeyPreferences userPrefs = readUserPreferences(context);
    RemoteStorageConfig storageConfig = userPrefs.getRemoteStorageConfig();
    if (storageConfig.getStorageType().equals(StorageType.STORAGE_TYPE_WEBDAV)) {
      EncryptedPayload encryptedServerUrl = storageConfig.getWebdavServerUrl();
      WebDavCredentials credentials = storageConfig.getWebdavCredentials();
      if (!isWebDavConfigComplete(storageConfig)) {
        Log.w(TAG, "WebDAV destination or credentials not fully configured.");
        reportUploadIssue(context, UploadIssue.WEBDAV_NOT_CONFIGURED);
        return null;
      }
      byte[] username = null;
      byte[] password = null;
      try {
        String serverUrl =
            new String(
                unsealWebDavSetting(
                    encryptedServerUrl, CrumblesConstants.WEBDAV_SERVER_URL_ENTRY_ID),
                UTF_8);
        username =
            unsealWebDavSetting(
                credentials.getUsername(), CrumblesConstants.WEBDAV_USERNAME_ENTRY_ID);
        password =
            unsealWebDavSetting(
                credentials.getPassword(), CrumblesConstants.WEBDAV_PASSWORD_ENTRY_ID);
        Optional<SSLSocketFactory> pinnedSocketFactory =
            pinnedSocketFactory(storageConfig.getWebdavServerKeySha256());
        if (pinnedSocketFactory.isEmpty()
            && Objects.equals(Uri.parse(serverUrl).normalizeScheme().getScheme(), "https")) {
          // Settings saved before servers were pinned hold no key that the user has confirmed.
          reportUploadIssue(context, UploadIssue.SERVER_KEY_NOT_CONFIRMED);
          return null;
        }
        return new WebDavStorageUploader(
            serverUrl, username, password, pinnedSocketFactory.orElse(null));
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to decrypt the WebDAV server URL or credentials", e);
        reportUploadIssue(context, UploadIssue.CREDENTIALS_DECRYPTION_FAILED);
        return null;
      } finally {
        // The uploader keeps its own copies, which it wipes when the run closes it.
        wipe(username);
        wipe(password);
      }
    }
    DocumentFile targetDir = resolveDriveDestination(context, userPrefs);
    if (targetDir == null) {
      return null;
    }
    return new GoogleDriveStorageUploader(targetDir);
  }

  /** Decrypts a WebDAV setting that the key preferences hold sealed for {@code entryId}. */
  private static byte[] unsealWebDavSetting(EncryptedPayload payload, String entryId)
      throws CrumblesKeysException {
    return CrumblesMain.getLogsEncryptorInstance().decryptDataStoreEntry(payload, entryId);
  }

  /** Overwrites a decrypted credential with zeroes, if it was decrypted at all. */
  private static void wipe(@Nullable byte[] credential) {
    if (credential != null) {
      Arrays.fill(credential, (byte) 0);
    }
  }

  /**
   * Returns a socket factory that requires the WebDAV server key the user confirmed, or empty if
   * {@code sealedServerKeySha256} pins no key.
   *
   * @throws CrumblesKeysException if the pinned key digest cannot be decrypted or used
   */
  private static Optional<SSLSocketFactory> pinnedSocketFactory(
      EncryptedPayload sealedServerKeySha256) throws CrumblesKeysException {
    if (sealedServerKeySha256.getCiphertext().isEmpty()) {
      return Optional.empty();
    }
    byte[] serverKeySha256 =
        CrumblesMain.getLogsEncryptorInstance()
            .decryptDataStoreEntry(
                sealedServerKeySha256, CrumblesConstants.WEBDAV_SERVER_KEY_SHA256_ENTRY_ID);
    try {
      return Optional.of(
          WebDavServerKeyPin.ofSha256(serverKeySha256)
              .newSocketFactory(WebDavServerKeyPin.platformTrustManager()));
    } catch (IllegalArgumentException | GeneralSecurityException e) {
      throw new CrumblesKeysException("The pinned WebDAV server key cannot be used.", e);
    }
  }

  /**
   * Returns whether an upload destination is set: a Google Drive folder, or a WebDAV server URL
   * with both credentials. Unlike {@link #resolveStorageUploader}, it decrypts nothing and reports
   * nothing to the user.
   */
  static boolean isUploadDestinationConfigured(Context context) {
    RemoteStorageConfig storageConfig = readUserPreferences(context).getRemoteStorageConfig();
    if (storageConfig.getStorageType().equals(StorageType.STORAGE_TYPE_WEBDAV)) {
      return isWebDavConfigComplete(storageConfig);
    }
    return !storageConfig.getUploadDestinationUri().isEmpty()
        || context
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .contains(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI);
  }

  /**
   * Returns whether {@code storageConfig} holds a sealed WebDAV server URL and both credentials.
   */
  static boolean isWebDavConfigComplete(RemoteStorageConfig storageConfig) {
    WebDavCredentials credentials = storageConfig.getWebdavCredentials();
    return !storageConfig.getWebdavServerUrl().getCiphertext().isEmpty()
        && !credentials.getUsername().getCiphertext().isEmpty()
        && !credentials.getPassword().getCiphertext().isEmpty();
  }

  @Nullable
  private static DocumentFile resolveDriveDestination(
      Context context, UserKeyPreferences userPrefs) {
    String uriString = userPrefs.getRemoteStorageConfig().getUploadDestinationUri();
    if (uriString.isEmpty()) {
      SharedPreferences legacyPrefs =
          context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
      uriString = legacyPrefs.getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, null);
    }
    if (uriString == null) {
      Log.w(TAG, "Upload destination URI not configured. Logs will remain safely on device.");
      reportUploadIssue(context, UploadIssue.DESTINATION_NOT_CONFIGURED);
      return null;
    }

    Uri treeUri = Uri.parse(uriString);
    boolean hasValidPersistedGrant = false;
    for (UriPermission perm : context.getContentResolver().getPersistedUriPermissions()) {
      if (perm.getUri().equals(treeUri) && perm.isWritePermission()) {
        hasValidPersistedGrant = true;
        break;
      }
    }

    if (!hasValidPersistedGrant) {
      Log.e(TAG, "Persisted write permission missing or revoked for: " + uriString);
      reportUploadIssue(context, UploadIssue.DESTINATION_PERMISSION_REVOKED);
      return null;
    }

    DocumentFile targetDir = DocumentFile.fromTreeUri(context, treeUri);
    if (targetDir == null || !targetDir.isDirectory() || !targetDir.canWrite()) {
      Log.e(TAG, "Target directory is invalid or not writable: " + uriString);
      reportUploadIssue(context, UploadIssue.DESTINATION_INACCESSIBLE);
      return null;
    }
    return targetDir;
  }

  static boolean uploadSingleFile(
      Context context, RemoteStorageUploader uploader, File file, File directory) {
    String originalName = file.getName();
    String baseName =
        originalName.endsWith(".bin")
            ? originalName.substring(0, originalName.length() - ".bin".length())
            : originalName;
    String newProcessingName = baseName + CrumblesConstants.PROCESSING_SUFFIX;
    File processingFile = new File(directory, newProcessingName);
    String keyFingerprint;
    synchronized (UPLOAD_LOCK) {
      if (!file.renameTo(processingFile)) {
        Log.e(TAG, "Could not rename to processing: " + originalName);
        return false;
      }
      inFlightProcessingNames.add(newProcessingName);
      // Read before the upload, which a key change can overlap: the batch is for this key.
      keyFingerprint = CrumblesDeleteSentFilesWorker.internalKeyFingerprint();
    }

    boolean uploadSuccess = false;
    try {
      uploadSuccess = uploader.uploadFile(context, processingFile, originalName);
    } finally {
      synchronized (UPLOAD_LOCK) {
        inFlightProcessingNames.remove(newProcessingName);
        UPLOAD_LOCK.notifyAll();
        uploadSuccess =
            markUploaded(
                context,
                uploader,
                processingFile,
                baseName,
                originalName,
                uploadSuccess,
                keyFingerprint);
      }
    }
    return uploadSuccess;
  }

  /**
   * Renames {@code processingFile} to the sent name of {@code baseName} if {@code uploadSuccess},
   * or back to {@code originalName} otherwise, and returns whether it is now marked as sent.
   */
  @GuardedBy("UPLOAD_LOCK")
  private static boolean markUploaded(
      Context context,
      RemoteStorageUploader uploader,
      File processingFile,
      String baseName,
      String originalName,
      boolean uploadSuccess,
      @Nullable String keyFingerprint) {
    File directory = processingFile.getParentFile();
    if (uploadSuccess) {
      File sentFile = new File(directory, baseName + CrumblesConstants.SENT_SUFFIX);
      if (processingFile.renameTo(sentFile)) {
        // CrumblesDeleteSentFilesWorker keeps the batch for a while, counted from this time. If
        // this fails, the batch keeps its write time, as before.
        sentFile.setLastModified(Instant.now().toEpochMilli());
        // Only WebDAV copies expire by age; SAF copies stay until the storage quota reclaims them.
        if (uploader.getStorageType() == StorageType.STORAGE_TYPE_WEBDAV) {
          CrumblesDeleteSentFilesWorker.recordSentFile(context, sentFile.getName());
        } else {
          CrumblesDeleteSentFilesWorker.recordSafCopy(context, sentFile.getName(), keyFingerprint);
        }
        Log.d(TAG, "Successfully uploaded and marked as sent: " + sentFile.getName());
        return true;
      }
      Log.e(TAG, "Failed to rename to sent: " + processingFile.getName());
    }

    // Safe rollback to guarantee zero log batch data loss
    File originalFile = new File(directory, originalName);
    if (processingFile.renameTo(originalFile)) {
      Log.w(TAG, "Reverted processing file back to original for retry: " + originalName);
    } else {
      Log.e(TAG, "Failed to revert processing file to original: " + processingFile.getName());
    }
    return false;
  }

  /**
   * Waits until no upload in this process holds a processing file, for at most {@code timeout}.
   * Callers hold {@link #UPLOAD_LOCK}, which this releases only while waiting, so that no upload
   * starts after it returns until they release the lock.
   */
  static void awaitNoUploadInFlight(Duration timeout) {
    Duration deadline = Duration.ofNanos(System.nanoTime()).plus(timeout);
    synchronized (UPLOAD_LOCK) {
      while (!inFlightProcessingNames.isEmpty()) {
        long left = deadline.minusNanos(System.nanoTime()).toNanos();
        if (left <= 0) {
          Log.w(TAG, "Uploads still in progress after " + timeout + "; going on without them.");
          return;
        }
        try {
          TimeUnit.NANOSECONDS.timedWait(UPLOAD_LOCK, left);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
  }

  /**
   * Notifies the user of {@code issue}, again on every run that it lasts so that dismissing the
   * notification does not hide it, and logs it unless it is the issue that was reported last, so
   * that retries hitting the same problem do not flood the activity log.
   */
  private static void reportUploadIssue(Context context, UploadIssue issue) {
    SharedPreferences preferences =
        context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    String lastReportedIssue =
        preferences.getString(PREF_LAST_REPORTED_UPLOAD_ISSUE, /* defValue= */ null);
    if (!Objects.equals(lastReportedIssue, issue.name())) {
      preferences.edit().putString(PREF_LAST_REPORTED_UPLOAD_ISSUE, issue.name()).apply();
      CrumblesAppAuditLogger.getInstance(context).logEvent(issue.auditEvent, issue.auditMessage);
    }
    notifyUploadIssue(context, issue);
  }

  /**
   * Returns the notification text of the upload issue that was reported last, unless an upload
   * succeeded or nothing was left to upload since.
   */
  static Optional<String> describeReportedUploadIssue(Context context) {
    String issue =
        context
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(PREF_LAST_REPORTED_UPLOAD_ISSUE, /* defValue= */ "");
    return Enums.getIfPresent(UploadIssue.class, issue)
        .toJavaUtil()
        .map(reported -> context.getString(reported.notificationContentResId));
  }

  /**
   * Forgets the last reported upload issue so that any later problem is reported again, and
   * withdraws its notification, as the problem no longer applies.
   */
  private static void clearReportedUploadIssue(Context context) {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .remove(PREF_LAST_REPORTED_UPLOAD_ISSUE)
        .apply();
    NotificationManagerCompat.from(context).cancel(CrumblesConstants.UPLOAD_NOTIFICATION_ID);
  }

  private static void createNotificationChannel(Context context) {
    NotificationChannel channel =
        new NotificationChannel(
            CrumblesConstants.NOTIFICATION_CHANNEL_ID,
            "Background sync",
            NotificationManager.IMPORTANCE_DEFAULT);
    channel.setDescription("Status updates for background sync tasks.");
    // Keep the content off the lock screen: revealing that the device collects and exports
    // security logs endangers at-risk users.
    channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);

    NotificationManagerCompat.from(context).createNotificationChannel(channel);
  }

  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private static void notifyUploadIssue(Context context, UploadIssue issue) {
    createNotificationChannel(context);

    Intent openIntent = new Intent(context, CrumblesMain.class);
    openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    PendingIntent pendingIntent =
        PendingIntent.getActivity(
            context,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

    NotificationCompat.Builder builder =
        new NotificationCompat.Builder(context, CrumblesConstants.NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(context.getString(issue.notificationTitleResId))
            .setContentText(context.getString(issue.notificationContentResId))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(pendingIntent)
            .setOnlyAlertOnce(true)
            // Stays up while uploads fail: dismissing it would hide that logs stay on the phone.
            .setOngoing(true);

    try {
      NotificationManagerCompat.from(context)
          .notify(CrumblesConstants.UPLOAD_NOTIFICATION_ID, builder.build());
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted, skipping notification", e);
    }
  }
}
