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

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.work.ExistingWorkPolicy;
import androidx.work.OneTimeWorkRequest;
import androidx.work.OutOfQuotaPolicy;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import java.io.File;
import java.io.FilenameFilter;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Uploads every pending batch now, then deletes from this device every batch that a WebDAV server
 * confirmed, so that the user can clear the device quickly.
 *
 * <p>Batches that could not be uploaded stay on the device, and their number is kept until a later
 * run uploads them or {@link #wipeAllBatches} deletes them.
 *
 * <p>Batches uploaded to a Storage Access Framework folder stay too. Offline, its provider can
 * accept a batch into its local cache and report it uploaded, and clearing the provider's storage
 * would then lose it. So these copies stay until the storage quota reclaims them or {@link
 * #wipeAllBatches} deletes them.
 */
public final class CrumblesUploadAndWipeWorker extends Worker {

  private static final String TAG = "CrumblesUploadAndWipe";

  static final String UNIQUE_WORK_NAME = "upload_and_wipe_work";

  /** Preferences key holding how many batches the last run left on the device. */
  private static final String PREF_BATCHES_LEFT = "uploadAndWipeBatchesLeft";

  /** How long an upload and wipe waits for uploads in progress elsewhere to mark their batches. */
  private static final Duration UPLOAD_WAIT = Duration.ofMinutes(1);

  /** How long {@link #wipeAllBatches}, which runs on the main thread, waits for them. */
  static final Duration WIPE_ALL_UPLOAD_WAIT = Duration.ofSeconds(2);

  /** How many times {@link #wipeAllBatches} has run in this process. */
  private static final AtomicInteger wipeGeneration = new AtomicInteger();

  public CrumblesUploadAndWipeWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  /** Starts an upload and wipe as soon as possible, unless one is already queued or running. */
  public static void start(Context context) {
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent("UPLOAD_AND_WIPE_REQUESTED", "Upload and wipe of every pending batch requested.");
    WorkManager.getInstance(context)
        .enqueueUniqueWork(
            UNIQUE_WORK_NAME,
            ExistingWorkPolicy.KEEP,
            new OneTimeWorkRequest.Builder(CrumblesUploadAndWipeWorker.class)
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .build());
  }

  /**
   * Returns how many uploaded batches stay on this device because a Storage Access Framework
   * provider may still be syncing them.
   */
  public static int countKeptSafBatches(Context context) {
    return listBatches(context, (dir, name) -> isSafCopy(context, name)).length;
  }

  /**
   * Returns how many batches on this device were never uploaded: pending, being uploaded, or staged
   * until an encryption key is available.
   */
  public static int countPendingBatches(Context context) {
    File[] notUploaded =
        listBatches(
            context,
            (dir, name) -> name.endsWith(".bin") && !name.endsWith(CrumblesConstants.SENT_SUFFIX));
    return notUploaded.length + new CrumblesLogStaging(context).countBatches();
  }

  /**
   * Returns whether {@code name} is an uploaded copy without an upload time, so one that went to a
   * Storage Access Framework folder rather than to WebDAV, whatever the destination is now.
   */
  private static boolean isSafCopy(Context context, String name) {
    return name.endsWith(CrumblesConstants.SENT_SUFFIX)
        && !context
            .getSharedPreferences(
                CrumblesDeleteSentFilesWorker.RETENTION_PREFS, Context.MODE_PRIVATE)
            .contains(name);
  }

  /**
   * Returns how many batches the last upload and wipe left on the device, because it could not
   * upload them, or could not delete them once uploaded.
   */
  public static int getBatchesLeft(Context context) {
    return context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .getInt(PREF_BATCHES_LEFT, /* defValue= */ 0);
  }

  
  @NonNull
  @Override
  public Result doWork() {
    Context context = getApplicationContext();

    // Batches that the upload leaves behind, whatever the reason, are counted below.
    var _ = CrumblesSendAndMarkProcessingWorker.uploadPendingBatches(context);

    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      // An upload in progress elsewhere would mark its batch as sent only after the wipe.
      CrumblesSendAndMarkProcessingWorker.awaitNoUploadInFlight(UPLOAD_WAIT);
      // Counting staged batches first waits for a drain in progress, so the listing sees its files.
      int stagedCount = new CrumblesLogStaging(context).countBatches();
      int deletedCount = 0;
      File[] binFiles = listBatches(context, (dir, name) -> name.endsWith(".bin"));
      int keptSentCount = 0;
      for (File file : binFiles) {
        if (!file.getName().endsWith(CrumblesConstants.SENT_SUFFIX)) {
          continue;
        }
        if (isSafCopy(context, file.getName())) {
          keptSentCount++;
        } else if (file.delete()) {
          deletedCount++;
        } else {
          Log.e(TAG, "Failed to delete batch: " + file.getName());
        }
      }
      if (keptSentCount > 0) {
        CrumblesAppAuditLogger.getInstance(context)
            .logEvent(
                "UPLOAD_AND_WIPE_SENT_KEPT",
                "Kept "
                    + keptSentCount
                    + " uploaded batch(es) on this device because Drive may still be syncing.");
      }

      int notUploadedCount = binFiles.length - deletedCount - keptSentCount;
      int batchesLeft = notUploadedCount + stagedCount;
      setBatchesLeft(context, batchesLeft);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "UPLOAD_AND_WIPE_FINISHED",
              "Deleted "
                  + deletedCount
                  + " uploaded batch(es). "
                  + batchesLeft
                  + " batch(es) could not be uploaded and are still on this device.");
      return Result.success();
    }
  }

  /**
   * Deletes every batch on this device, uploaded or not, except batches still being written, and
   * returns how many were deleted. Uploads in progress get {@link #WIPE_ALL_UPLOAD_WAIT} to finish
   * first; batches that they still hold are deleted anyway.
   *
   * <p>This destroys logs that never left the device: callers must have the user confirm the device
   * credential first.
   */
  public static int wipeAllBatches(Context context) {
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      wipeGeneration.incrementAndGet();
      CrumblesSendAndMarkProcessingWorker.awaitNoUploadInFlight(WIPE_ALL_UPLOAD_WAIT);
      CrumblesDeviceAdminReceiver.cancelDeferredLogsNotification(context);
      // Wiping staging first waits for a drain in progress, so the listing sees the files it wrote.
      int deletedCount = new CrumblesLogStaging(context).wipeAllBatches();
      deletedCount += deleteBatches(context, (dir, name) -> name.endsWith(".bin"));
      setBatchesLeft(context, 0);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "UPLOAD_AND_WIPE_FORCED",
              "Deleted "
                  + deletedCount
                  + " batch(es), including any that were not uploaded, after the user confirmed the"
                  + " device credential.");
      return deletedCount;
    }
  }

  /**
   * Returns a number that changes whenever {@link #wipeAllBatches} starts, so that an upload in
   * progress can tell that the batches it failed to upload were wiped rather than kept.
   */
  static int currentWipeGeneration() {
    return wipeGeneration.get();
  }

  private static int deleteBatches(Context context, FilenameFilter filter) {
    int deletedCount = 0;
    for (File batch : listBatches(context, filter)) {
      if (batch.delete()) {
        deletedCount++;
      } else {
        Log.e(TAG, "Failed to delete batch: " + batch.getName());
      }
    }
    return deletedCount;
  }

  private static File[] listBatches(Context context, FilenameFilter filter) {
    File[] batches =
        new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY)
            .listFiles(filter);
    return batches == null ? new File[0] : batches;
  }

  private static void setBatchesLeft(Context context, int batchesLeft) {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putInt(PREF_BATCHES_LEFT, batchesLeft)
        .apply();
  }


}
