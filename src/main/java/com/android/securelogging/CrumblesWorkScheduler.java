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

import static java.util.concurrent.TimeUnit.DAYS;

import android.content.Context;
import android.util.Log;
import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.ExistingWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import java.time.Duration;
import java.util.Calendar;

/** A utility class to schedule and manage periodic work for Crumbles. */
final class CrumblesWorkScheduler {

  private static final String TAG = "CrumblesWorkScheduler";

  /** First wait before an upload is retried; each further retry waits twice as long. */
  private static final Duration SEND_RETRY_INITIAL_BACKOFF = Duration.ofMinutes(1);

  /**
   * Schedules all periodic work for Crumbles.
   *
   * @param context The context of the application.
   * @param workManager The WorkManager to use for scheduling work.
   */
  public static void scheduleAllPeriodicWork(Context context, WorkManager workManager) {
    scheduleSendWork(workManager);
    // Cancel legacy periodic mark-sent work to avoid race conditions with active uploads.
    // Stale processing recovery is handled synchronously by CrumblesSendAndMarkProcessingWorker.
    workManager.cancelUniqueWork(CrumblesConstants.MARK_SENT_WORK_TAG);
    scheduleDailyFileDeletion(workManager);
    scheduleLoggingWatchdog(workManager);
    scheduleHeartbeat(workManager);
    Log.d(TAG, "All periodic work scheduled.");
  }

  /**
   * Schedules the periodic send+process work for Crumbles. It runs only with a network and a
   * battery that is not low, and backs off exponentially between retries.
   *
   * @param workManager The WorkManager to use for scheduling work.
   */
  private static void scheduleSendWork(WorkManager workManager) {
    PeriodicWorkRequest sendWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesSendAndMarkProcessingWorker.class, CrumblesConstants.SEND_REPEAT_INTERVAL)
            .setConstraints(
                new Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, SEND_RETRY_INITIAL_BACKOFF)
            .addTag(CrumblesConstants.SEND_WORK_TAG)
            .build();

    // UPDATE applies this request to work scheduled earlier without restarting its period.
    workManager.enqueueUniquePeriodicWork(
        CrumblesConstants.SEND_WORK_TAG, ExistingPeriodicWorkPolicy.UPDATE, sendWorkRequest);

    Log.d(
        TAG,
        "Periodic send+process work scheduled every "
            + CrumblesConstants.SEND_REPEAT_INTERVAL.toHours()
            + " hours.");
  }

  /**
   * Asks for the pending log files to be uploaded right away rather than at the next periodic run.
   *
   * <p>Queues another run after an earlier request that is already running, so that a batch sealed
   * while that upload is in flight is still uploaded right away.
   *
   * @param workManager The WorkManager to use for scheduling work.
   */
  public static void requestImmediateUpload(WorkManager workManager) {
    OneTimeWorkRequest sendNowWorkRequest =
        new OneTimeWorkRequest.Builder(CrumblesSendAndMarkProcessingWorker.class)
            .setConstraints(
                new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, SEND_RETRY_INITIAL_BACKOFF)
            .build();

    workManager.enqueueUniqueWork(
        CrumblesConstants.SEND_NOW_WORK_NAME,
        ExistingWorkPolicy.APPEND_OR_REPLACE,
        sendNowWorkRequest);
    Log.d(TAG, "One-time send+process work requested.");
  }

  /* Schedules the worker that deletes files with _sent suffix once a day at night. */
  private static void scheduleDailyFileDeletion(WorkManager workManager) {
    // Target time for deletion.
    int targetHour = 3;
    int targetMinute = 0;

    Calendar currentTime = Calendar.getInstance();
    Calendar targetTime = (Calendar) currentTime.clone();
    targetTime.set(Calendar.HOUR_OF_DAY, targetHour);
    targetTime.set(Calendar.MINUTE, targetMinute);
    targetTime.set(Calendar.SECOND, 0);
    targetTime.set(Calendar.MILLISECOND, 0);

    // If the target time for today is already past, schedule for tomorrow.
    if (targetTime.before(currentTime)) {
      targetTime.add(Calendar.DAY_OF_MONTH, 1);
    }

    long initialDelayMillis = targetTime.getTimeInMillis() - currentTime.getTimeInMillis();
    Log.d(TAG, "Current time: " + currentTime.getTime());
    Log.d(TAG, "Next deletion target time: " + targetTime.getTime());
    Log.d(TAG, "Initial delay for deletion: " + initialDelayMillis + " ms");

    // Define the work request for daily deletion.
    PeriodicWorkRequest deleteWorkRequest =
        new PeriodicWorkRequest.Builder(CrumblesDeleteSentFilesWorker.class, 1, DAYS)
            .setInitialDelay(Duration.ofMillis(initialDelayMillis))
            .addTag(CrumblesConstants.DELETE_WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesConstants.DELETE_WORK_TAG,
        ExistingPeriodicWorkPolicy.KEEP, // Keep existing work if already scheduled.
        deleteWorkRequest);

    Log.d(TAG, "Daily file deletion work scheduled for ~" + targetHour + ":00 at night.");
  }

  /** Schedules the worker that notices when security or network logging is turned on or off. */
  private static void scheduleLoggingWatchdog(WorkManager workManager) {
    PeriodicWorkRequest watchdogWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesLoggingWatchdogWorker.class,
                CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL)
            .addTag(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG,
        ExistingPeriodicWorkPolicy.KEEP,
        watchdogWorkRequest);
  }

  /** Schedules the worker that writes a heartbeat batch when no batch was signed for a day. */
  private static void scheduleHeartbeat(WorkManager workManager) {
    PeriodicWorkRequest heartbeatWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesHeartbeatWorker.class, CrumblesHeartbeatWorker.CHECK_INTERVAL)
            .addTag(CrumblesHeartbeatWorker.WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesHeartbeatWorker.WORK_TAG, ExistingPeriodicWorkPolicy.KEEP, heartbeatWorkRequest);
  }

  /**
   * Cancels all periodic work for Crumbles.
   *
   * @param context The context of the application.
   * @param workManager The WorkManager to use for cancelling work.
   */
  public static void cancelAllPeriodicWork(Context context, WorkManager workManager) {
    workManager.cancelUniqueWork(CrumblesConstants.SEND_WORK_TAG);
    workManager.cancelUniqueWork(CrumblesConstants.MARK_SENT_WORK_TAG);
    workManager.cancelUniqueWork(CrumblesConstants.DELETE_WORK_TAG);
    workManager.cancelUniqueWork(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    workManager.cancelUniqueWork(CrumblesHeartbeatWorker.WORK_TAG);
    Log.d(TAG, "All periodic work cancelled.");
  }

  private CrumblesWorkScheduler() {}
}
