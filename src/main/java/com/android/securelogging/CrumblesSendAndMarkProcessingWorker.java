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

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.UriPermission;
import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.documentfile.provider.DocumentFile;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.android.libraries.security.content.SafeContentResolver;
import com.google.android.libraries.security.content.SafeContentResolver.SourcePolicy;
import com.google.common.io.ByteStreams;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;

/**
 * A WorkManager worker class that handles automated streaming of encrypted log files to Google
 * Drive while guaranteeing zero log batch loss, transactional status tracking, and full audit
 * traceability.
 */
public class CrumblesSendAndMarkProcessingWorker extends Worker {

  private static final String TAG = "CrumblesSendAndMarkProcessingWorker";
  static final int UPLOAD_NOTIFICATION_ID = 2001;

  public CrumblesSendAndMarkProcessingWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  @NonNull
  @Override
  public Result doWork() {
    Log.d(TAG, "CrumblesSendAndMarkProcessingWorker doWork() started");
    Context context = getApplicationContext();

    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    CrumblesExternalPublicKeyManager publicKeyManager =
        CrumblesExternalPublicKeyManager.getInstance(context);
    boolean isInternalPrivateKey = encryptor.doesPrivateKeyExist();
    PublicKey externalPublicKey = publicKeyManager.getActiveExternalPublicKey();
    boolean keyIsAvailable = isInternalPrivateKey || (externalPublicKey != null);

    if (!keyIsAvailable) {
      Log.w(
          TAG,
          "No encryption key (internal or external) is available. Deferring upload to preserve"
              + " logs.");
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_UPLOAD_DEFERRED_NO_KEY",
              "Upload deferred because active encryption key is unavailable; logs preserved on"
                  + " disk.");
      notifyUploadStatus(
          context,
          "Log Upload Deferred",
          "Encryption key is unavailable. Encrypted logs remain securely preserved on device.",
          /* isError= */ true);
      return Result.retry();
    }

    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return Result.failure();
    }

    // Recover any stale processing files from interrupted runs to prevent log loss
    recoverStaleProcessingFiles(context, directory);

    File[] unprocessedBinFiles =
        directory.listFiles(
            (dir, name) ->
                name.endsWith(".bin")
                    && !name.endsWith(CrumblesConstants.PROCESSING_SUFFIX)
                    && !name.endsWith(CrumblesConstants.SENT_SUFFIX));

    if (unprocessedBinFiles == null || unprocessedBinFiles.length == 0) {
      Log.d(TAG, "No unprocessed .bin files found.");
      return Result.success();
    }

    return processAndUploadFiles(context, unprocessedBinFiles, directory);
  }

  private static void recoverStaleProcessingFiles(Context context, File directory) {
    File[] staleProcessingFiles =
        directory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.PROCESSING_SUFFIX));
    if (staleProcessingFiles == null) {
      return;
    }
    int recoveredCount = 0;
    for (File processingFile : staleProcessingFiles) {
      String processingName = processingFile.getName();
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

  private Result processAndUploadFiles(
      Context context, File[] unprocessedBinFiles, File directory) {
    DocumentFile targetDir = resolveUploadDestination(context);
    if (targetDir == null) {
      return Result.retry();
    }

    int uploadedCount = 0;
    boolean hasFailures = false;

    for (File file : unprocessedBinFiles) {
      if (uploadSingleFile(context, targetDir, file, directory)) {
        uploadedCount++;
      } else {
        hasFailures = true;
      }
    }

    if (uploadedCount > 0) {
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_UPLOAD_SUCCESS",
              "Successfully automatically uploaded "
                  + uploadedCount
                  + " log file(s) to Google Drive destination.");
      notifyUploadStatus(
          context,
          "Log Upload Successful",
          "Successfully uploaded " + uploadedCount + " log file(s) to Google Drive.",
          /* isError= */ false);
    }

    if (hasFailures) {
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_UPLOAD_FAILED",
              "One or more log files failed to upload; preserved safely on device for retry.");
      notifyUploadStatus(
          context,
          "Log Upload Interrupted",
          "Some log files could not be uploaded. Files remain safely saved on device for retry.",
          /* isError= */ true);
      return Result.retry();
    }

    return Result.success();
  }

  @Nullable
  private static DocumentFile resolveUploadDestination(Context context) {
    String uriString =
        context
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, null);

    if (uriString == null) {
      Log.w(TAG, "Upload destination URI not configured. Logs will remain safely on device.");
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "UPLOAD_DESTINATION_NOT_CONFIGURED",
              "Upload deferred: Google Drive destination folder is not configured.");
      notifyUploadStatus(
          context,
          "Upload Destination Not Configured",
          "Please select a Google Drive destination folder in Crumbles to enable log uploads.",
          /* isError= */ true);
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
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "UPLOAD_DESTINATION_PERMISSION_REVOKED",
              "Upload failed because persistable write permission was missing or revoked.");
      notifyUploadStatus(
          context,
          "Upload Permission Revoked",
          "Google Drive write permission was revoked. Please re-select the destination folder.",
          /* isError= */ true);
      return null;
    }

    DocumentFile targetDir = DocumentFile.fromTreeUri(context, treeUri);
    if (targetDir == null || !targetDir.isDirectory() || !targetDir.canWrite()) {
      Log.e(TAG, "Target directory is invalid or not writable: " + uriString);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "UPLOAD_DESTINATION_INVALID",
              "Upload deferred: destination folder is inaccessible or unwritable.");
      notifyUploadStatus(
          context,
          "Upload Destination Inaccessible",
          "The selected destination folder is not accessible. Please check storage access.",
          /* isError= */ true);
      return null;
    }
    return targetDir;
  }

  private static boolean uploadSingleFile(
      Context context, DocumentFile targetDir, File file, File directory) {
    String originalName = file.getName();
    String baseName = originalName.substring(0, originalName.length() - ".bin".length());
    String newProcessingName = baseName + CrumblesConstants.PROCESSING_SUFFIX;
    File processingFile = new File(directory, newProcessingName);
    if (!file.renameTo(processingFile)) {
      Log.e(TAG, "Could not rename to processing: " + originalName);
      return false;
    }

    boolean uploadSuccess =
        streamFileToDestination(context, targetDir, processingFile, originalName);

    if (uploadSuccess) {
      File sentFile = new File(directory, baseName + CrumblesConstants.SENT_SUFFIX);
      if (processingFile.renameTo(sentFile)) {
        Log.d(TAG, "Successfully uploaded and marked as sent: " + sentFile.getName());
        return true;
      }
      Log.e(TAG, "Failed to rename to sent: " + processingFile.getName());
    }

    // Safe rollback to guarantee zero log batch data loss
    File originalFile = new File(directory, originalName);
    if (!processingFile.renameTo(originalFile)) {
      Log.e(TAG, "Failed to revert processing file to original: " + processingFile.getName());
    }
    Log.w(TAG, "Reverted processing file back to original for retry: " + originalName);
    return false;
  }

  private static boolean streamFileToDestination(
      Context context, DocumentFile targetDir, File processingFile, String originalName) {
    try {
      DocumentFile targetDocFile = targetDir.createFile("application/octet-stream", originalName);
      if (targetDocFile != null) {
        try (InputStream in = new FileInputStream(processingFile);
            OutputStream out =
                SafeContentResolver.openOutputStream(
                    context, targetDocFile.getUri(), SourcePolicy.EXTERNAL_ONLY)) {
          if (out != null) {
            ByteStreams.copy(in, out);
            out.flush();
            return true;
          }
        }
      }
    } catch (IOException | SecurityException e) {
      // DocumentFile or ContentResolver may throw on I/O issues, network disconnects, or permission
      // expiration
      Log.e(TAG, "Failed to upload file " + originalName + " to destination", e);
    }
    return false;
  }

  private static void createNotificationChannel(Context context) {
    NotificationChannel channel =
        new NotificationChannel(
            CrumblesConstants.NOTIFICATION_CHANNEL_ID,
            "Log Upload Notifications",
            NotificationManager.IMPORTANCE_DEFAULT);
    channel.setDescription("Status notifications for encrypted log uploads.");

    NotificationManagerCompat.from(context).createNotificationChannel(channel);
  }

  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private static void notifyUploadStatus(
      Context context, String title, String content, boolean isError) {
    createNotificationChannel(context);

    Intent openIntent = new Intent(context, CrumblesMain.class);
    openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    PendingIntent pendingIntent =
        PendingIntent.getActivity(
            context,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

    int icon =
        isError ? android.R.drawable.stat_notify_error : android.R.drawable.stat_sys_upload_done;
    NotificationCompat.Builder builder =
        new NotificationCompat.Builder(context, CrumblesConstants.NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(content)
            .setPriority(
                isError ? NotificationCompat.PRIORITY_HIGH : NotificationCompat.PRIORITY_DEFAULT)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true);

    try {
      NotificationManagerCompat.from(context).notify(UPLOAD_NOTIFICATION_ID, builder.build());
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted, skipping notification", e);
    }
  }
}
