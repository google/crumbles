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

import static com.google.common.util.concurrent.MoreExecutors.directExecutor;
import static java.util.concurrent.TimeUnit.DAYS;

import android.content.Context;
import android.os.Looper;
import android.util.Log;
import androidx.work.BackoffPolicy;
import androidx.work.Configuration;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.ExistingWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.WorkRequest;
import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import java.time.Duration;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

/** A utility class to schedule and manage periodic work for Crumbles. */
final class CrumblesWorkScheduler {

  private static final String TAG = "CrumblesWorkScheduler";

  /** First wait before an upload is retried; each further retry waits twice as long. */
  private static final Duration SEND_RETRY_INITIAL_BACKOFF = Duration.ofMinutes(1);

  /** Longest that WorkManager waits before it retries work, whatever the backoff of the work. */
  private static final Duration MAX_RETRY_BACKOFF =
      Duration.ofMillis(WorkRequest.MAX_BACKOFF_MILLIS);

  /**
   * Maximum initial delay any periodic job is expected to set (daily 03:00 AM deletion can be up to
   * 25 hours away on the day before a fall-back DST transition).
   */
  private static final Duration MAX_EXPECTED_INITIAL_DELAY = Duration.ofHours(25);

  /**
   * How much later than its interval, initial delay, or retry backoff from now work can be due
   * before it counts as scheduled at a clock set forward: small corrections that set the clock back
   * leave the schedules alone.
   */
  private static final Duration SCHEDULE_SLACK = Duration.ofMinutes(1);

  /** Maximum wait when a background caller queries {@link WorkManager} for existing schedules. */
  private static final Duration WORK_INFO_LOOKUP_TIMEOUT = Duration.ofSeconds(5);

  /** The periodic jobs managed by Crumbles, with their unique names, intervals, and policies. */
  private enum PeriodicJob {
    SEND(
        CrumblesConstants.SEND_WORK_TAG,
        CrumblesConstants.SEND_REPEAT_INTERVAL,
        // UPDATE applies this request to work scheduled earlier without restarting its period.
        ExistingPeriodicWorkPolicy.UPDATE) {
      @Override
      void enqueue(WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
        scheduleSendWork(workManager, policy);
      }
    },
    DELETE_SENT_FILES(
        CrumblesConstants.DELETE_WORK_TAG, Duration.ofDays(1), ExistingPeriodicWorkPolicy.KEEP) {
      @Override
      void enqueue(WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
        scheduleDailyFileDeletion(workManager, policy);
      }
    },
    LOGGING_WATCHDOG(
        CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG,
        CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL,
        ExistingPeriodicWorkPolicy.KEEP) {
      @Override
      void enqueue(WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
        scheduleLoggingWatchdog(workManager, policy);
      }
    },
    HEARTBEAT(
        CrumblesHeartbeatWorker.WORK_TAG,
        CrumblesHeartbeatWorker.CHECK_INTERVAL,
        ExistingPeriodicWorkPolicy.KEEP) {
      @Override
      void enqueue(WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
        scheduleHeartbeat(workManager, policy);
      }
    };

    final String uniqueWorkName;
    final Duration repeatInterval;
    final ExistingPeriodicWorkPolicy defaultPolicy;

    PeriodicJob(
        String uniqueWorkName, Duration repeatInterval, ExistingPeriodicWorkPolicy defaultPolicy) {
      this.uniqueWorkName = uniqueWorkName;
      this.repeatInterval = repeatInterval;
      this.defaultPolicy = defaultPolicy;
    }

    abstract void enqueue(WorkManager workManager, ExistingPeriodicWorkPolicy policy);
  }

  /**
   * Schedules all periodic work for Crumbles.
   *
   * <p>Each unique periodic job keeps its existing schedule ({@code UPDATE} for uploads, {@code
   * KEEP} for the others) unless its next run is due later than one interval (or initial delay)
   * plus {@link #SCHEDULE_SLACK} from now, in which case that job is re-enqueued with {@code
   * CANCEL_AND_REENQUEUE}. A pending immediate upload due later than its retry backoff allows is
   * likewise replaced with one due now. Looking up the schedules does not block the main thread;
   * background callers wait up to {@link #WORK_INFO_LOOKUP_TIMEOUT}, so this must not be called
   * from a {@link WorkManager} task-executor thread.
   *
   * @param context The context of the application.
   * @param workManager The WorkManager to use for scheduling work.
   */
  public static void scheduleAllPeriodicWork(Context context, WorkManager workManager) {
    for (PeriodicJob job : PeriodicJob.values()) {
      withExistingWork(
          workManager,
          job.uniqueWorkName,
          workInfos -> {
            ExistingPeriodicWorkPolicy policy =
                wasScheduledAtAForwardClock(workManager, job, workInfos)
                    ? ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE
                    : job.defaultPolicy;
            if (policy.equals(ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE)) {
              Log.w(
                  TAG,
                  "Periodic work "
                      + job.uniqueWorkName
                      + " is due later than its interval allows; re-enqueuing it.");
            }
            job.enqueue(workManager, policy);
          });
    }
    repairForwardImmediateUpload(workManager);
    // Cancel legacy periodic mark-sent work to avoid race conditions with active uploads.
    // Stale processing recovery is handled synchronously by CrumblesSendAndMarkProcessingWorker.
    workManager.cancelUniqueWork(CrumblesConstants.MARK_SENT_WORK_TAG);
    Log.d(TAG, "All periodic work scheduled.");
  }

  /**
   * Re-enqueues all periodic work after the wall clock changes, so a clock set forward and back
   * cannot leave its schedules waiting for the future time, and asks for the batches that waited
   * meanwhile to be uploaded right away, replacing an immediate upload that has not started.
   */
  static void rescheduleAfterTimeChange(WorkManager workManager) {
    for (PeriodicJob job : PeriodicJob.values()) {
      job.enqueue(workManager, ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE);
    }
    requestImmediateUpload(workManager);
  }

  /**
   * Re-enqueues any already-scheduled periodic job whose next run is due later than one interval
   * from now, and replaces a pending immediate upload due later than its retry backoff allows with
   * one due now, without scheduling unscheduled jobs or requesting a new immediate upload.
   *
   * <p>Must not be called from a {@link WorkManager} task-executor thread because background
   * callers wait up to {@link #WORK_INFO_LOOKUP_TIMEOUT} for schedule lookups.
   */
  static void repairForwardScheduledWork(WorkManager workManager) {
    for (PeriodicJob job : PeriodicJob.values()) {
      withExistingWork(
          workManager,
          job.uniqueWorkName,
          workInfos -> {
            if (wasScheduledAtAForwardClock(workManager, job, workInfos)) {
              Log.w(
                  TAG,
                  "Periodic work "
                      + job.uniqueWorkName
                      + " is due later than its interval allows; re-enqueuing it.");
              job.enqueue(workManager, ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE);
            }
          });
    }
    repairForwardImmediateUpload(workManager);
  }

  /**
   * Replaces a pending immediate upload that a clock set forward and back left due later than its
   * retry backoff allows, so that it no longer holds back the immediate uploads requested after it.
   */
  private static void repairForwardImmediateUpload(WorkManager workManager) {
    withExistingWork(
        workManager,
        CrumblesConstants.SEND_NOW_WORK_NAME,
        workInfos -> {
          if (wasImmediateUploadRequestedAtAForwardClock(workManager, workInfos)) {
            Log.w(TAG, "Immediate upload is due later than its retries allow; replacing it.");
            enqueueImmediateUpload(workManager, workInfos);
          }
        });
  }

  private static void withExistingWork(
      WorkManager workManager, String uniqueWorkName, Consumer<List<WorkInfo>> onWorkInfos) {
    ListenableFuture<List<WorkInfo>> scheduledWork =
        workManager.getWorkInfosForUniqueWork(uniqueWorkName);
    if (scheduledWork == null) {
      onWorkInfos.accept(ImmutableList.of());
      return;
    }
    if (scheduledWork.isDone() || !isMainThread()) {
      onWorkInfos.accept(awaitWorkInfos(scheduledWork, uniqueWorkName));
      return;
    }
    scheduledWork.addListener(
        () -> onWorkInfos.accept(doneWorkInfos(scheduledWork, uniqueWorkName)), directExecutor());
  }

  private static boolean isMainThread() {
    Looper mainLooper = Looper.getMainLooper();
    return mainLooper != null && Objects.equals(Looper.myLooper(), mainLooper);
  }

  private static List<WorkInfo> awaitWorkInfos(
      ListenableFuture<List<WorkInfo>> scheduledWork, String uniqueWorkName) {
    try {
      List<WorkInfo> workInfos =
          scheduledWork.get(WORK_INFO_LOOKUP_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
      return workInfos != null ? workInfos : ImmutableList.of();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      Log.e(TAG, "Interrupted while looking up work " + uniqueWorkName + ".", e);
    } catch (ExecutionException | CancellationException | TimeoutException e) {
      Log.e(TAG, "Failed to look up work " + uniqueWorkName + ".", e);
    }
    return ImmutableList.of();
  }

  private static List<WorkInfo> doneWorkInfos(
      ListenableFuture<List<WorkInfo>> scheduledWork, String uniqueWorkName) {
    try {
      List<WorkInfo> workInfos = Futures.getDone(scheduledWork);
      return workInfos != null ? workInfos : ImmutableList.of();
    } catch (ExecutionException | CancellationException e) {
      Log.e(TAG, "Failed to look up work " + uniqueWorkName + ".", e);
    }
    return ImmutableList.of();
  }

  /**
   * Returns whether any enqueued {@link WorkInfo} in {@code workInfos} is due later than one
   * interval (or capped initial delay) plus {@link #SCHEDULE_SLACK} from now.
   */
  private static boolean wasScheduledAtAForwardClock(
      WorkManager workManager, PeriodicJob job, List<WorkInfo> workInfos) {
    if (workInfos == null || workInfos.isEmpty()) {
      return false;
    }
    long nowMillis = currentTimeMillis(workManager);
    for (WorkInfo workInfo : workInfos) {
      if (isDueBeyondNextInterval(workInfo, job.repeatInterval, nowMillis)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns whether any enqueued immediate upload in {@code workInfos} is due later than {@link
   * #SCHEDULE_SLACK} from now, plus {@link #MAX_RETRY_BACKOFF} once it has been tried.
   */
  private static boolean wasImmediateUploadRequestedAtAForwardClock(
      WorkManager workManager, List<WorkInfo> workInfos) {
    long nowMillis = currentTimeMillis(workManager);
    for (WorkInfo workInfo : workInfos) {
      // A request is due as soon as it is enqueued, and a retry once its backoff has passed.
      Duration longestWait = workInfo.getRunAttemptCount() > 0 ? MAX_RETRY_BACKOFF : Duration.ZERO;
      if (isDueBeyondNextInterval(workInfo, longestWait, nowMillis)) {
        return true;
      }
    }
    return false;
  }

  private static long currentTimeMillis(WorkManager workManager) {
    Configuration configuration = workManager.getConfiguration();
    if (configuration != null && configuration.getClock() != null) {
      return configuration.getClock().currentTimeMillis();
    }
    return System.currentTimeMillis();
  }

  private static boolean isDueBeyondNextInterval(
      WorkInfo workInfo, Duration expectedInterval, long nowMillis) {
    if (workInfo == null || !Objects.equals(workInfo.getState(), WorkInfo.State.ENQUEUED)) {
      return false;
    }
    long nextScheduleTimeMillis = workInfo.getNextScheduleTimeMillis();
    if (nextScheduleTimeMillis == Long.MAX_VALUE || nextScheduleTimeMillis <= 0L) {
      return false;
    }
    WorkInfo.PeriodicityInfo periodicity = workInfo.getPeriodicityInfo();
    long repeatIntervalMillis =
        periodicity != null
            ? Math.min(periodicity.getRepeatIntervalMillis(), expectedInterval.toMillis())
            : expectedInterval.toMillis();
    long initialDelayMillis =
        Math.min(
            Math.max(0L, workInfo.getInitialDelayMillis()), MAX_EXPECTED_INITIAL_DELAY.toMillis());
    long longestWaitMillis =
        Math.max(repeatIntervalMillis, initialDelayMillis) + SCHEDULE_SLACK.toMillis();
    return nextScheduleTimeMillis > nowMillis
        && nextScheduleTimeMillis - nowMillis > longestWaitMillis;
  }

  /**
   * Schedules the periodic send+process work for Crumbles. It runs only with a network and a
   * battery that is not low, and backs off exponentially between retries.
   *
   * @param workManager The WorkManager to use for scheduling work.
   * @param policy What to do with send+process work scheduled earlier.
   */
  private static void scheduleSendWork(WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
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

    workManager.enqueueUniquePeriodicWork(CrumblesConstants.SEND_WORK_TAG, policy, sendWorkRequest);

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
   * while that upload is in flight is still uploaded right away. Any other earlier request, waiting
   * or finished, is replaced, so that neither its retry backoff nor a run due at a clock set
   * forward since then holds this one back. Looking up the earlier requests does not block the main
   * thread; background callers wait up to {@link #WORK_INFO_LOOKUP_TIMEOUT}, so this must not be
   * called from a {@link WorkManager} task-executor thread.
   *
   * @param workManager The WorkManager to use for scheduling work.
   */
  public static void requestImmediateUpload(WorkManager workManager) {
    withExistingWork(
        workManager,
        CrumblesConstants.SEND_NOW_WORK_NAME,
        workInfos -> enqueueImmediateUpload(workManager, workInfos));
  }

  /**
   * Enqueues an immediate upload to run after the earlier one in {@code existingWork} that is
   * running, or otherwise in place of the earlier ones.
   */
  private static void enqueueImmediateUpload(WorkManager workManager, List<WorkInfo> existingWork) {
    // A failed lookup finds nothing too, and appending then cannot cancel an upload in flight.
    ExistingWorkPolicy policy =
        existingWork.isEmpty() || hasRunningWork(existingWork)
            ? ExistingWorkPolicy.APPEND_OR_REPLACE
            : ExistingWorkPolicy.REPLACE;
    OneTimeWorkRequest sendNowWorkRequest =
        new OneTimeWorkRequest.Builder(CrumblesSendAndMarkProcessingWorker.class)
            .setConstraints(
                new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, SEND_RETRY_INITIAL_BACKOFF)
            .build();

    workManager.enqueueUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME, policy, sendNowWorkRequest);
    Log.d(TAG, "One-time send+process work requested.");
  }

  private static boolean hasRunningWork(List<WorkInfo> workInfos) {
    return workInfos.stream()
        .anyMatch(workInfo -> workInfo.getState().equals(WorkInfo.State.RUNNING));
  }

  /* Schedules the worker that deletes files with _sent suffix once a day at night. */
  private static void scheduleDailyFileDeletion(
      WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
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
        CrumblesConstants.DELETE_WORK_TAG, policy, deleteWorkRequest);

    Log.d(TAG, "Daily file deletion work scheduled for ~" + targetHour + ":00 at night.");
  }

  /** Schedules the worker that notices when security or network logging is turned on or off. */
  private static void scheduleLoggingWatchdog(
      WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
    PeriodicWorkRequest watchdogWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesLoggingWatchdogWorker.class,
                CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL)
            .addTag(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG, policy, watchdogWorkRequest);
  }

  /** Schedules the worker that writes a heartbeat batch when no batch was signed for a day. */
  private static void scheduleHeartbeat(
      WorkManager workManager, ExistingPeriodicWorkPolicy policy) {
    PeriodicWorkRequest heartbeatWorkRequest =
        new PeriodicWorkRequest.Builder(
                CrumblesHeartbeatWorker.class, CrumblesHeartbeatWorker.CHECK_INTERVAL)
            .addTag(CrumblesHeartbeatWorker.WORK_TAG)
            .build();

    workManager.enqueueUniquePeriodicWork(
        CrumblesHeartbeatWorker.WORK_TAG, policy, heartbeatWorkRequest);
  }

  /**
   * Cancels all periodic work for Crumbles.
   *
   * @param context The context of the application.
   * @param workManager The WorkManager to use for cancelling work.
   */
  public static void cancelAllPeriodicWork(Context context, WorkManager workManager) {
    for (PeriodicJob job : PeriodicJob.values()) {
      workManager.cancelUniqueWork(job.uniqueWorkName);
    }
    workManager.cancelUniqueWork(CrumblesConstants.MARK_SENT_WORK_TAG);
    Log.d(TAG, "All periodic work cancelled.");
  }

  private CrumblesWorkScheduler() {}
}
