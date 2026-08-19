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
import android.content.UriPermission;
import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
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
 * A WorkManager worker class that handles the automated upload of encrypted log files.
 *
 * <p>This worker performs the following tasks:
 *
 * <ul>
 *   <li>Checks for encryption key availability. If no key, deletes existing logs.
 *   <li>Finds unprocessed crumble log files (.bin files) in the designated directory.
 *   <li>Verifies the configured Google Drive destination folder and its persistable write permissions.
 *   <li>Streams encrypted log files directly to the destination folder using DocumentFile.
 *   <li>Transitions files to _sent.bin only on verified write completion.
 *   <li>Safely reverts files to .bin on any failure for automatic retry, preventing data loss.
 * </ul>
 */
public class CrumblesSendAndMarkProcessingWorker extends Worker {

  private static final String TAG = "CrumblesSendAndMarkProcessingWorker";

  /**
   * Constructor for the CrumblesSendAndMarkProcessingWorker.
   *
   * @param context The application context.
   * @param workerParams The worker parameters.
   */
  public CrumblesSendAndMarkProcessingWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
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

    return processAndUploadFiles(context, unprocessedBinFiles, directory);
  }

  /**
   * Processes unprocessed .bin files, streams them to the configured Google Drive destination,
   * and transitions files to _sent.bin only on verified stream write completion. On any error,
   * files are safely restored to .bin for automated retry.
   */
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
    }

    return hasFailures ? Result.retry() : Result.success();
  }

  @Nullable
  private static DocumentFile resolveUploadDestination(Context context) {
    String uriString =
        context
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, null);

    if (uriString == null) {
      Log.w(TAG, "Upload destination URI not configured. Logs will remain safely on device.");
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
      return null;
    }

    DocumentFile targetDir = DocumentFile.fromTreeUri(context, treeUri);
    if (targetDir == null || !targetDir.isDirectory() || !targetDir.canWrite()) {
      Log.e(TAG, "Target directory is invalid or not writable: " + uriString);
      return null;
    }
    return targetDir;
  }

  private static boolean uploadSingleFile(
      Context context, DocumentFile targetDir, File file, File directory) {
    String originalName = file.getName();
    if (!originalName.endsWith(".bin")) {
      Log.e(TAG, "Unexpected non-bin file in unprocessed list: " + originalName);
      return false;
    }

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

    // Safe rollback to ensure no logs are lost
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
      Log.e(TAG, "Failed to upload file " + originalName + " to destination", e);
    }
    return false;
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


}
