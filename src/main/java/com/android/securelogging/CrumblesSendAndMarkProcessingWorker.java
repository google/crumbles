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
import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.app.NotificationCompat;
import androidx.core.content.FileProvider;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import java.io.File;
import java.security.PublicKey;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;

/**
 * A WorkManager worker class that handles the processing and sending of encrypted log files.
 *
 * <p>This worker performs the following tasks:
 *
 * <ul>
 *   <li>Checks for encryption key availability. If no key, deletes existing logs.
 *   <li>Finds unprocessed crumble log files (.bin files) in the designated directory.
 *   <li>Marks the filtered files as "processing" by renaming them.
 *   <li>Creates a notification with an intent to allow the user to upload the files using the
 *       preferred upload method (e.g., email, drive, etc.).
 *   <li>Handles cases where no uploading client is available.
 *   <li>Includes retry logic if the uploading fails.
 * </ul>
 */
public class CrumblesSendAndMarkProcessingWorker extends Worker {

  private static final String TAG = "CrumblesSendAndMarkProcessingWorker";
  private final CrumblesUriGenerator uriGenerator;

  @SuppressWarnings("NonFinalStaticField")
  @VisibleForTesting
  static CrumblesUriGenerator testUriGeneratorInstance = null;

  /**
   * Constructor for the CrumblesSendAndMarkProcessingWorker.
   *
   * @param context The application context.
   * @param workerParams The worker parameters.
   */
  public CrumblesSendAndMarkProcessingWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
    // Use the test instance if it's been set, otherwise use the real one.
    if (testUriGeneratorInstance != null) {
      this.uriGenerator = testUriGeneratorInstance;
    } else {
      this.uriGenerator = new CrumblesUriGenerator();
    }
  }

  private static int createNotificationId() {
    return (int) InstantSource.system().instant().toEpochMilli();
  }

  /*
   * This method is called by the WorkManager to perform the processing of the encrypted log files.
   * It identifies unprocessed files, renames them by adding the "processing" suffix, and then
   * creates a notification intent for the user to upload the files.
   */
  @NonNull
  @Override
  public Result doWork() {
    Log.d(TAG, "CrumblesSendAndMarkProcessingWorker doWork() started");
    Context context = getApplicationContext();

    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    // Create a manager instance here to read the current key state.
    CrumblesExternalPublicKeyManager publicKeyManager =
        CrumblesExternalPublicKeyManager.getInstance(context);
    boolean isInternalPrivateKey = encryptor.doesPrivateKeyExist();
    PublicKey externalPublicKey = publicKeyManager.getActiveExternalPublicKey();
    boolean keyIsAvailable = isInternalPrivateKey || (externalPublicKey != null);

    if (!keyIsAvailable) {
      Log.w(
          TAG,
          "No encryption key (internal or external) is available. Deleting existing encrypted log"
              + " files.");
      deleteAllLogFiles(context);
      return Result.success();
    }

    createNotificationChannel(context);
    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return Result.failure();
    }

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

    List<Uri> filesToSendUris = markFilesAsProcessing(context, unprocessedBinFiles, directory);
    if (filesToSendUris.isEmpty()) {
      Log.d(TAG, "No files were marked for processing (e.g., due to URI generation errors).");
      return Result.success();
    }
    return triggerUploading(context, filesToSendUris);
  }

  /**
   * Deletes all relevant Crumbles log files (.bin, _processing.bin, _sent.bin) from the log
   * directory. This is typically called when no encryption key is available.
   *
   * @param context The application context.
   */
  private void deleteAllLogFiles(Context context) {
    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists() || !directory.isDirectory()) {
      Log.d(
          TAG,
          "Log directory " + directory.getAbsolutePath() + " does not exist, nothing to delete.");
      return;
    }

    File[] filesToDelete =
        directory.listFiles(
            (dir, name) ->
                name.endsWith(".bin")
                    || name.endsWith(CrumblesConstants.PROCESSING_SUFFIX)
                    || name.endsWith(CrumblesConstants.SENT_SUFFIX));

    if (filesToDelete == null || filesToDelete.length == 0) {
      Log.d(TAG, "No log files found in directory " + directory.getAbsolutePath() + " to delete.");
      return;
    }

    int deleteCount = 0;
    for (File file : filesToDelete) {
      if (file.delete()) {
        Log.i(TAG, "Deleted orphaned log file (no key available): " + file.getName());
        deleteCount++;
      } else {
        Log.e(TAG, "Failed to delete orphaned log file: " + file.getName());
      }
    }
    Log.i(
        TAG,
        "Orphaned log file deletion complete. Deleted "
            + deleteCount
            + " files from "
            + directory.getAbsolutePath());
  }

  /**
   * Triggers the upload of the files by showing a notification with an intent to launch the
   * uploading client chooser. The notification is shown to the user, and when the user taps it, the
   * intent is launched.
   *
   * @param context The application context.
   * @param filesToSendUris The list of URIs to send.
   * @return The result of the upload operation.
   */
  @SuppressWarnings("PendingIntentMutability")
  private Result triggerUploading(Context context, List<Uri> filesToSendUris) {
    // Create the email intent - this will be launched by the notification.
    Intent emailIntent = new Intent(Intent.ACTION_SEND_MULTIPLE);
    emailIntent.setType("application/octet-stream");
    emailIntent.putParcelableArrayListExtra(Intent.EXTRA_STREAM, (ArrayList<Uri>) filesToSendUris);
    emailIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

    // Verify if there's any uploading client to handle the intent (before showing notification).
    if (emailIntent.resolveActivity(context.getPackageManager()) == null) {
      Log.w(TAG, "No uploading client found. Cannot show notification to upload logs.");
      // If no uploading client, then the work can't proceed.
      // Return retry - maybe an email client will be installed later.
      return Result.retry();
    }

    // Create a PendingIntent to launch the uploading client chooser.
    // Request code should be unique, here using a fixed ID.
    // FLAG_UPDATE_CURRENT will update the PendingIntent if a new one is created for the same ID.
    int notificationId = createNotificationId();
    // The use of PendingIntent in the current implementation is already secure and changing it to
    // SaferPendingIntent would be non-trivial as well as restricting the supported Android versions
    // while Crumbles is meant to support older versions instead.
    PendingIntent pendingIntent =
        PendingIntent.getActivity(
            context,
            notificationId, // Use a unique request code.
            Intent.createChooser(emailIntent, "Upload Filtered Log Files..."),
            PendingIntent.FLAG_UPDATE_CURRENT
                | PendingIntent.FLAG_IMMUTABLE // FLAG_IMMUTABLE is required for API 23+.
            );

    // Build the notification.
    NotificationCompat.Builder builder =
        new NotificationCompat.Builder(context, CrumblesConstants.NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle("New Encrypted Log Files Ready to Upload")
            .setContentText("Tap to upload " + filesToSendUris.size() + " encrypted log file(s).")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true);

    NotificationManager notificationManager =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    if (notificationManager != null) {
      notificationManager.notify(notificationId, builder.build());
      Log.d(TAG, "Notification shown to upload.");
      return Result.success(); // Task succeeded by showing notification.
    } else {
      Log.e(TAG, "NotificationManager is null. Cannot show notification.");
      return Result.failure(); // Critical failure to get NotificationManager.
    }
  }

  @Nullable
  protected Uri getUriForFileInternal(
      @NonNull Context context, @NonNull String authority, @NonNull File file) {
    try {
      return FileProvider.getUriForFile(context, authority, file);
    } catch (IllegalArgumentException e) {
      Log.e(TAG, "Error getting URI for file " + file.getName() + ": " + e.getMessage());
      return null; // Return null on failure so markFilesAsProcessing can handle it.
    }
  }

  private List<Uri> markFilesAsProcessing(
      Context context, File[] unprocessedBinFiles, File directory) {
    List<Uri> filesToSendUris = new ArrayList<>();
    for (File file : unprocessedBinFiles) {
      String fileName = file.getName();
      String newProcessingName = insertSuffixBeforeExtension(fileName, "_processing");
      if (newProcessingName == null) {
        Log.e(TAG, "Failed to create new processing name for: " + fileName);
        continue;
      }
      File newProcessingFile = new File(directory, newProcessingName);

      if (file.renameTo(newProcessingFile)) {
        Log.d(TAG, "Renamed " + fileName + " to " + newProcessingName);

        Uri fileUri = this.uriGenerator.getUriForFile(context, newProcessingFile);

        if (fileUri != null) {
          filesToSendUris.add(fileUri);
          Log.d(TAG, "Added file URI (matches filter): " + fileUri);
        } else {
          Log.w(
              TAG, "URI for " + newProcessingName + " was null. File will not be sent this cycle.");
          // If URI generation fails, the file remains _processing. It will be retried next time.
          // No explicit retry here, as we'll rely on WorkManager's retry for the whole worker if
          // notification fails.
        }
      } else {
        Log.e(TAG, "Failed to rename file to _processing: " + fileName);
      }
    }
    return filesToSendUris;
  }

  /**
   * Creates the notification channel for the encrypted log files.
   *
   * @param context The application context.
   */
  private void createNotificationChannel(Context context) {
    String name = "Upload Log Notifications";
    String description = "Notifications for uploading encrypted log files.";
    int importance = NotificationManager.IMPORTANCE_HIGH;
    NotificationChannel channel =
        new NotificationChannel(CrumblesConstants.NOTIFICATION_CHANNEL_ID, name, importance);
    channel.setDescription(description);

    NotificationManager notificationManager = context.getSystemService(NotificationManager.class);
    if (notificationManager != null) {
      notificationManager.createNotificationChannel(channel);
    }
  }

  /**
   * Inserts a suffix before the extension of a filename.
   *
   * @param filename The filename to modify.
   * @param suffix The suffix to insert.
   * @return The modified filename with the suffix inserted.
   */
  private String insertSuffixBeforeExtension(String filename, String suffix) {
    int dotIndex = filename.lastIndexOf('.');
    if (dotIndex != -1) {
      return filename.substring(0, dotIndex) + suffix + filename.substring(dotIndex);
    }
    return filename + suffix;
  }
}
