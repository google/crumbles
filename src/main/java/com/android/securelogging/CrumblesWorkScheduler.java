package com.android.securelogging;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import android.content.Context;
import android.util.Log;
import androidx.work.BackoffPolicy;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import java.time.Duration;
import java.util.Calendar;

/** A utility class to schedule and manage periodic work for Crumbles. */
final class CrumblesWorkScheduler {

  private static final String TAG = "CrumblesWorkScheduler";

  /**
   * Schedules all periodic work for Crumbles.
   *
   * @param context The context of the application.
   * @param workManager The WorkManager to use for scheduling work.
   */
  public static void scheduleAllPeriodicWork(Context context, WorkManager workManager) {
    scheduleSendWork(workManager);
    scheduleMarkSentWork(workManager);
    scheduleDailyFileDeletion(workManager);
    Log.d(TAG, "All periodic work scheduled.");
  }

  /**
   * Schedules the periodic send+process work for Crumbles.
   *
   * @param workManager The WorkManager to use for scheduling work.
   */
  private static void scheduleSendWork(WorkManager workManager) {
    PeriodicWorkRequest sendWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesSendAndMarkProcessingWorker.class,
                CrumblesConstants.SEND_REPEAT_INTERVAL_HOURS,
                HOURS)
            .setBackoffCriteria(
                BackoffPolicy.LINEAR, PeriodicWorkRequest.MIN_BACKOFF_MILLIS, MILLISECONDS)
            .addTag(CrumblesConstants.SEND_WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesConstants.SEND_WORK_TAG, ExistingPeriodicWorkPolicy.KEEP, sendWorkRequest);

    Log.d(
        TAG,
        "Periodic send+process work scheduled every "
            + CrumblesConstants.SEND_REPEAT_INTERVAL_HOURS
            + " hours.");
  }

  /* Schedules the worker that marks _processing files as _sent. */
  private static void scheduleMarkSentWork(WorkManager workManager) {
    PeriodicWorkRequest markSentWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesMarkProcessingAsSentWorker.class,
                CrumblesConstants.MARK_SENT_REPEAT_INTERVAL_HOURS,
                HOURS)
            .setInitialDelay(
                Duration.ofMinutes(CrumblesConstants.MARK_SENT_INITIAL_DELAY_MINUTES_OFFSET))
            .setBackoffCriteria(
                BackoffPolicy.LINEAR, PeriodicWorkRequest.MIN_BACKOFF_MILLIS, MILLISECONDS)
            .addTag(CrumblesConstants.MARK_SENT_WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesConstants.MARK_SENT_WORK_TAG,
        ExistingPeriodicWorkPolicy.KEEP, // Keep existing work if already scheduled.
        markSentWorkRequest);

    Log.d(
        TAG,
        "Periodic mark as sent work scheduled every "
            + CrumblesConstants.MARK_SENT_REPEAT_INTERVAL_HOURS
            // + " hours with "
            + " minutes with "
            + CrumblesConstants.MARK_SENT_INITIAL_DELAY_MINUTES_OFFSET
            + " min offset.");
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
    Log.d(TAG, "All periodic work cancelled.");
  }

  private CrumblesWorkScheduler() {}
}
