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

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertNotNull;

import android.content.Context;
import android.os.Looper;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.BackoffPolicy;
import androidx.work.Configuration;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.ExistingWorkPolicy;
import androidx.work.ListenableWorker;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerFactory;
import androidx.work.WorkerParameters;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.google.common.truth.Expect;
import com.google.testing.junit.testparameterinjector.TestParameter;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;
import org.robolectric.Shadows;

/** Unit tests for {@link CrumblesWorkScheduler}. */
@RunWith(RobolectricTestParameterInjector.class)
public class CrumblesWorkSchedulerTest {

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private WorkManager realTestWorkManager;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();

    // Configure WorkManager for testing with a SynchronousExecutor for deterministic tests.
    Configuration config =
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(new SynchronousExecutor())
            .build();
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config);

    // Get the real, test-configured WorkManager instance.
    realTestWorkManager = WorkManager.getInstance(context);
    assertNotNull("Real test WorkManager should be initialized", realTestWorkManager);
  }

  @Test
  public void scheduleAllPeriodicWork_enqueuesCorrectWorkAndCancelsLegacyMarkSent()
      throws ExecutionException, InterruptedException {
    // Stand-in for mark-sent work from an older version; the initial delay keeps it from running.
    PeriodicWorkRequest legacyMarkSentWorkRequest =
        new PeriodicWorkRequest.Builder(CrumblesDeleteSentFilesWorker.class, Duration.ofDays(1))
            .setInitialDelay(Duration.ofDays(1))
            .build();
    realTestWorkManager.enqueueUniquePeriodicWork(
        CrumblesConstants.MARK_SENT_WORK_TAG,
        ExistingPeriodicWorkPolicy.KEEP,
        legacyMarkSentWorkRequest);

    // Pass the real test WorkManager instance.
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

    // Check that the SEND_WORK_TAG work is enqueued.
    List<WorkInfo> sendWorkInfos =
        realTestWorkManager.getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG).get();
    assertThat(sendWorkInfos).isNotNull();
    assertThat(sendWorkInfos).hasSize(1);
    WorkInfo sendWorkInfo = sendWorkInfos.get(0);
    assertThat(sendWorkInfo.getTags()).contains(CrumblesConstants.SEND_WORK_TAG);
    assertThat(sendWorkInfo.getState()).isEqualTo(WorkInfo.State.ENQUEUED);

    // Check that the DELETE_WORK_TAG work is enqueued.
    List<WorkInfo> deleteWorkInfos =
        realTestWorkManager.getWorkInfosForUniqueWork(CrumblesConstants.DELETE_WORK_TAG).get();
    assertThat(deleteWorkInfos).isNotNull();
    assertThat(deleteWorkInfos).hasSize(1);
    WorkInfo deleteWorkInfo = deleteWorkInfos.get(0);
    assertThat(deleteWorkInfo.getTags()).contains(CrumblesConstants.DELETE_WORK_TAG);
    assertThat(deleteWorkInfo.getState()).isEqualTo(WorkInfo.State.ENQUEUED);

    // Verify MARK_SENT_WORK_TAG is not active (was cancelled to prevent upload race conditions).
    assertWorkIsCancelled(CrumblesConstants.MARK_SENT_WORK_TAG);
  }

  @Test
  public void scheduleAllPeriodicWork_uploadsOnlyWithNetworkAndBatteryNotLow()
      throws ExecutionException, InterruptedException {
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

    Constraints constraints =
        realTestWorkManager
            .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
            .get()
            .get(0)
            .getConstraints();
    expect.that(constraints.getRequiredNetworkType()).isEqualTo(NetworkType.CONNECTED);
    expect.that(constraints.requiresBatteryNotLow()).isTrue();
  }

  @Test
  public void scheduleAllPeriodicWork_updatesUploadScheduledEarlierInPlace()
      throws ExecutionException, InterruptedException {
    // An unconstrained upload scheduled by an older version; the delay keeps it from running.
    PeriodicWorkRequest earlierUpload =
        new PeriodicWorkRequest.Builder(
                CrumblesSendAndMarkProcessingWorker.class, CrumblesConstants.SEND_REPEAT_INTERVAL)
            .setInitialDelay(Duration.ofDays(1))
            .build();
    realTestWorkManager.enqueueUniquePeriodicWork(
        CrumblesConstants.SEND_WORK_TAG, ExistingPeriodicWorkPolicy.KEEP, earlierUpload);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

    List<WorkInfo> uploads =
        realTestWorkManager.getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG).get();
    assertThat(uploads).hasSize(1);
    expect.that(uploads.get(0).getId()).isEqualTo(earlierUpload.getId());
    expect
        .that(uploads.get(0).getConstraints().getRequiredNetworkType())
        .isEqualTo(NetworkType.CONNECTED);
  }

  @Test
  public void scheduleAllPeriodicWork_schedulesFirstFileDeletionAtNextThreeAm()
      throws ExecutionException, InterruptedException {
    // The scheduler reads the clock, in whole milliseconds, between these two instants.
    Instant beforeScheduling = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);
    Instant afterScheduling = Instant.now();

    long initialDelayMillis =
        realTestWorkManager
            .getWorkInfosForUniqueWork(CrumblesConstants.DELETE_WORK_TAG)
            .get()
            .get(0)
            .getInitialDelayMillis();
    LocalTime earliestFirstRun = toLocalTime(beforeScheduling.plusMillis(initialDelayMillis));
    LocalTime latestFirstRun = toLocalTime(afterScheduling.plusMillis(initialDelayMillis));
    expect.that(initialDelayMillis).isAtLeast(0L);
    // The day before the fall-back DST change, the next 03:00 can be up to 25 hours away.
    expect.that(initialDelayMillis).isLessThan(Duration.ofHours(25).toMillis());
    expect.that(earliestFirstRun).isAtMost(LocalTime.of(3, 0));
    expect.that(latestFirstRun).isAtLeast(LocalTime.of(3, 0));
  }

  private static LocalTime toLocalTime(Instant instant) {
    return instant.atZone(ZoneId.systemDefault()).toLocalTime();
  }

  @Test
  public void scheduleAllPeriodicWork_enqueuesLoggingWatchdog()
      throws ExecutionException, InterruptedException {
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

    List<WorkInfo> watchdogWorkInfos =
        realTestWorkManager
            .getWorkInfosForUniqueWork(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .get();
    assertThat(watchdogWorkInfos).hasSize(1);
    assertThat(watchdogWorkInfos.get(0).getTags())
        .contains(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    assertThat(watchdogWorkInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
  }

  @Test
  public void scheduleAllPeriodicWork_enqueuesHourlyHeartbeatCheck()
      throws ExecutionException, InterruptedException {
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

    List<WorkInfo> heartbeatWorkInfos =
        realTestWorkManager.getWorkInfosForUniqueWork(CrumblesHeartbeatWorker.WORK_TAG).get();
    assertThat(heartbeatWorkInfos).hasSize(1);
    expect.that(heartbeatWorkInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
    expect
        .that(heartbeatWorkInfos.get(0).getPeriodicityInfo().getRepeatIntervalMillis())
        .isEqualTo(Duration.ofHours(1).toMillis());
  }

  private void assertWorkIsCancelled(String workTag)
      throws ExecutionException, InterruptedException {
    List<WorkInfo> workInfosAfterCancel =
        realTestWorkManager.getWorkInfosForUniqueWork(workTag).get();

    if (!workInfosAfterCancel.isEmpty()) {
      assertThat(workInfosAfterCancel.get(0).getState()).isEqualTo(WorkInfo.State.CANCELLED);
    } else {
      List<WorkInfo> allWorkWithTag = realTestWorkManager.getWorkInfosByTag(workTag).get();
      boolean activeWorkFound = false;
      for (WorkInfo wi : allWorkWithTag) {
        if (wi.getState() == WorkInfo.State.ENQUEUED || wi.getState() == WorkInfo.State.RUNNING) {
          activeWorkFound = true;
          break;
        }
      }
      assertThat(activeWorkFound).isFalse();
    }
  }

  @Test
  public void cancelAllPeriodicWork_cancelsAllUniqueWork()
      throws ExecutionException, InterruptedException {
    // Schedule periodic work first.
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

    // Verify work is initially enqueued for active tags
    assertThat(
            realTestWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_WORK_TAG)
                .get()
                .get(0)
                .getState())
        .isEqualTo(WorkInfo.State.ENQUEUED);
    assertThat(
            realTestWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.DELETE_WORK_TAG)
                .get()
                .get(0)
                .getState())
        .isEqualTo(WorkInfo.State.ENQUEUED);

    // Call the cancel method, passing the real test WorkManager.
    CrumblesWorkScheduler.cancelAllPeriodicWork(context, realTestWorkManager);

    // Verify each piece of unique work is cancelled.
    assertWorkIsCancelled(CrumblesConstants.SEND_WORK_TAG);
    assertWorkIsCancelled(CrumblesConstants.MARK_SENT_WORK_TAG);
    assertWorkIsCancelled(CrumblesConstants.DELETE_WORK_TAG);
    assertWorkIsCancelled(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    assertWorkIsCancelled(CrumblesHeartbeatWorker.WORK_TAG);
  }

  @Test
  public void rescheduleAfterTimeChange_replacesAllPeriodicWork()
      throws ExecutionException, InterruptedException {
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);
    UUID upload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    UUID fileDeletion = scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG);
    UUID watchdog = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    UUID heartbeat = scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG);

    CrumblesWorkScheduler.rescheduleAfterTimeChange(realTestWorkManager);

    expect.that(scheduledWorkId(CrumblesConstants.SEND_WORK_TAG)).isNotEqualTo(upload);
    expect.that(scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG)).isNotEqualTo(fileDeletion);
    expect
        .that(scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG))
        .isNotEqualTo(watchdog);
    expect.that(scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG)).isNotEqualTo(heartbeat);
  }

  @Test
  public void rescheduleAfterTimeChange_requestsAnImmediateUpload()
      throws ExecutionException, InterruptedException {
    CrumblesWorkScheduler.rescheduleAfterTimeChange(realTestWorkManager);

    assertThat(
            realTestWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
                .get())
        .hasSize(1);
  }

  /** Returns the ID of the only work that {@code uniqueWorkName} names. */
  private UUID scheduledWorkId(String uniqueWorkName)
      throws ExecutionException, InterruptedException {
    List<WorkInfo> workInfos = realTestWorkManager.getWorkInfosForUniqueWork(uniqueWorkName).get();
    assertThat(workInfos).hasSize(1);
    return workInfos.get(0).getId();
  }

  @Test
  public void requestImmediateUpload_enqueuesOneTimeSendWork()
      throws ExecutionException, InterruptedException {
    CrumblesWorkScheduler.requestImmediateUpload(realTestWorkManager);

    List<WorkInfo> sendNowWorkInfos =
        realTestWorkManager.getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME).get();
    assertThat(sendNowWorkInfos).hasSize(1);
    assertThat(sendNowWorkInfos.get(0).getTags())
        .contains(CrumblesSendAndMarkProcessingWorker.class.getName());
    expect
        .that(sendNowWorkInfos.get(0).getConstraints().getRequiredNetworkType())
        .isEqualTo(NetworkType.CONNECTED);
  }

  @Test
  public void requestImmediateUpload_afterFailedRun_replacesFailedChainInsteadOfBlocking()
      throws ExecutionException, InterruptedException {
    realTestWorkManager.enqueueUniqueWork(
        CrumblesConstants.SEND_NOW_WORK_NAME,
        ExistingWorkPolicy.REPLACE,
        new OneTimeWorkRequest.Builder(FailingWorker.class).build());
    assertThat(
            realTestWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
                .get()
                .get(0)
                .getState())
        .isEqualTo(WorkInfo.State.FAILED);

    CrumblesWorkScheduler.requestImmediateUpload(realTestWorkManager);

    List<WorkInfo> workInfos =
        realTestWorkManager.getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME).get();
    assertThat(workInfos).hasSize(1);
    assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
  }

  @Test
  public void requestImmediateUpload_whileEarlierUploadRuns_queuesFollowUpWithoutStoppingIt()
      throws Exception {
    CountDownLatch startedLatch = new CountDownLatch(1);
    CountDownLatch releaseLatch = new CountDownLatch(1);
    ExecutorService workerExecutor = Executors.newSingleThreadExecutor();
    try {
      initializeWorkManagerWithBlockingWorker(
          CrumblesSendAndMarkProcessingWorker.class, workerExecutor, startedLatch, releaseLatch);
      CrumblesWorkScheduler.requestImmediateUpload(realTestWorkManager);
      UUID runningUpload = scheduledWorkId(CrumblesConstants.SEND_NOW_WORK_NAME);
      WorkManagerTestInitHelper.getTestDriver(context).setAllConstraintsMet(runningUpload);
      awaitBlockingWorkerStarted(startedLatch);
      assertThat(onlyWorkInfo(CrumblesConstants.SEND_NOW_WORK_NAME).getState())
          .isEqualTo(WorkInfo.State.RUNNING);

      CrumblesWorkScheduler.requestImmediateUpload(realTestWorkManager);

      List<WorkInfo> uploads =
          realTestWorkManager.getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME).get();
      expect
          .that(uploads.stream().map(WorkInfo::getState).collect(toList()))
          .containsExactly(WorkInfo.State.RUNNING, WorkInfo.State.BLOCKED);
      expect
          .that(workInfoById(uploads, runningUpload).getState())
          .isEqualTo(WorkInfo.State.RUNNING);
    } finally {
      releaseBlockingWorkerAndShutDown(releaseLatch, workerExecutor);
    }
  }

  @Test
  public void requestImmediateUpload_whileEarlierUploadAwaitsRetry_replacesItToUploadRightAway()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(new AtomicLong(baseMillis));
    UUID retryingUpload =
        enqueueImmediateUploadAwaitingRetry(clockedWorkManager, Duration.ofMinutes(1));
    assertThat(onlyWorkInfo(CrumblesConstants.SEND_NOW_WORK_NAME).getRunAttemptCount())
        .isEqualTo(1);

    CrumblesWorkScheduler.requestImmediateUpload(clockedWorkManager);

    WorkInfo upload = onlyWorkInfo(CrumblesConstants.SEND_NOW_WORK_NAME);
    expect.that(upload.getId()).isNotEqualTo(retryingUpload);
    expect.that(upload.getState()).isEqualTo(WorkInfo.State.ENQUEUED);
    expect.that(upload.getNextScheduleTimeMillis()).isAtMost(baseMillis);
  }

  @Test
  public void repairForwardScheduledWork_whenImmediateUploadAwaitsRetry_keepsIt()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(new AtomicLong(baseMillis));
    UUID retryingUpload =
        enqueueImmediateUploadAwaitingRetry(clockedWorkManager, Duration.ofHours(1));
    assertThat(onlyWorkInfo(CrumblesConstants.SEND_NOW_WORK_NAME).getRunAttemptCount())
        .isEqualTo(1);

    CrumblesWorkScheduler.repairForwardScheduledWork(clockedWorkManager);

    WorkInfo upload = onlyWorkInfo(CrumblesConstants.SEND_NOW_WORK_NAME);
    expect.that(upload.getId()).isEqualTo(retryingUpload);
    expect
        .that(upload.getNextScheduleTimeMillis())
        .isEqualTo(baseMillis + Duration.ofHours(1).toMillis());
  }

  /** Enqueues as the immediate upload work that failed once and waits {@code backoff} to retry. */
  private static UUID enqueueImmediateUploadAwaitingRetry(
      WorkManager workManager, Duration backoff) {
    OneTimeWorkRequest retryingUpload =
        new OneTimeWorkRequest.Builder(RetryingWorker.class)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, backoff)
            .build();
    workManager.enqueueUniqueWork(
        CrumblesConstants.SEND_NOW_WORK_NAME, ExistingWorkPolicy.REPLACE, retryingUpload);
    return retryingUpload.getId();
  }

  /** Calls that must not leave immediate uploads queued behind one due at a clock set forward. */
  private enum SchedulingCall {
    REQUEST_IMMEDIATE_UPLOAD {
      @Override
      void run(Context context, WorkManager workManager) {
        CrumblesWorkScheduler.requestImmediateUpload(workManager);
      }
    },
    RESCHEDULE_AFTER_TIME_CHANGE {
      @Override
      void run(Context context, WorkManager workManager) {
        CrumblesWorkScheduler.rescheduleAfterTimeChange(workManager);
      }
    },
    SCHEDULE_ALL_PERIODIC_WORK {
      @Override
      void run(Context context, WorkManager workManager) {
        CrumblesWorkScheduler.scheduleAllPeriodicWork(context, workManager);
      }
    },
    REPAIR_FORWARD_SCHEDULED_WORK {
      @Override
      void run(Context context, WorkManager workManager) {
        CrumblesWorkScheduler.repairForwardScheduledWork(workManager);
      }
    };

    abstract void run(Context context, WorkManager workManager);
  }

  /**
   * How far the clock was set forward, shorter or longer than the longest retry backoff, which an
   * upload never tried yet does not wait out.
   */
  private enum ClockSetForward {
    WITHIN_MAX_RETRY_BACKOFF(Duration.ofHours(2)),
    BEYOND_MAX_RETRY_BACKOFF(Duration.ofDays(10));

    final Duration amount;

    ClockSetForward(Duration amount) {
      this.amount = amount;
    }
  }

  @Test
  public void schedulingCall_afterClockSetBack_replacesImmediateUploadDueAtForwardClock(
      @TestParameter SchedulingCall schedulingCall, @TestParameter ClockSetForward clockSetForward)
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis + clockSetForward.amount.toMillis());
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.requestImmediateUpload(clockedWorkManager);
    UUID forwardUpload = scheduledWorkId(CrumblesConstants.SEND_NOW_WORK_NAME);
    clockMillis.set(baseMillis);

    schedulingCall.run(context, clockedWorkManager);

    WorkInfo upload = onlyWorkInfo(CrumblesConstants.SEND_NOW_WORK_NAME);
    expect.that(upload.getId()).isNotEqualTo(forwardUpload);
    expect.that(upload.getState()).isEqualTo(WorkInfo.State.ENQUEUED);
    expect.that(upload.getNextScheduleTimeMillis()).isAtMost(baseMillis);
  }

  @Test
  public void scheduleAllPeriodicWork_whenScheduledAtForwardClock_repairsAllWorksWithinInterval()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    long forwardMillis = baseMillis + Duration.ofDays(10).toMillis();
    AtomicLong clockMillis = new AtomicLong(forwardMillis);
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);
    UUID forwardUpload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    UUID forwardDeletion = scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG);
    UUID forwardWatchdog = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    UUID forwardHeartbeat = scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG);
    clockMillis.set(baseMillis);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    WorkInfo uploadInfo = onlyWorkInfo(CrumblesConstants.SEND_WORK_TAG);
    WorkInfo deletionInfo = onlyWorkInfo(CrumblesConstants.DELETE_WORK_TAG);
    WorkInfo watchdogInfo = onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    WorkInfo heartbeatInfo = onlyWorkInfo(CrumblesHeartbeatWorker.WORK_TAG);
    expect.that(uploadInfo.getId()).isNotEqualTo(forwardUpload);
    expect
        .that(uploadInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.SEND_REPEAT_INTERVAL.toMillis());
    expect.that(deletionInfo.getId()).isNotEqualTo(forwardDeletion);
    expect
        .that(deletionInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + Duration.ofHours(25).toMillis());
    expect.that(watchdogInfo.getId()).isNotEqualTo(forwardWatchdog);
    expect
        .that(watchdogInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL.toMillis());
    expect.that(heartbeatInfo.getId()).isNotEqualTo(forwardHeartbeat);
    expect
        .that(heartbeatInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesHeartbeatWorker.CHECK_INTERVAL.toMillis());
    expect
        .that(
            clockedWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
                .get())
        .isEmpty();
  }

  @Test
  public void scheduleAllPeriodicWork_whenOnlyOneWorkIsDueInFuture_repairsOnlyThatWork()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis);
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);
    UUID normalUpload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    UUID normalDeletion = scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG);
    UUID normalHeartbeat = scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG);
    clockMillis.set(baseMillis + Duration.ofDays(10).toMillis());
    clockedWorkManager.enqueueUniquePeriodicWork(
        CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG,
        ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
        new PeriodicWorkRequest.Builder(
                CrumblesLoggingWatchdogWorker.class,
                CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL)
            .addTag(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .build());
    UUID futureWatchdog = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    clockMillis.set(baseMillis);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    expect.that(scheduledWorkId(CrumblesConstants.SEND_WORK_TAG)).isEqualTo(normalUpload);
    expect.that(scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG)).isEqualTo(normalDeletion);
    expect.that(scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG)).isEqualTo(normalHeartbeat);
    WorkInfo repairedWatchdog = onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    expect.that(repairedWatchdog.getId()).isNotEqualTo(futureWatchdog);
    expect
        .that(repairedWatchdog.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL.toMillis());
  }

  @Test
  public void scheduleAllPeriodicWork_whenClockCorrectionWithinSlack_keepsExistingSchedules()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis);
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);
    UUID upload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    UUID deletion = scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG);
    UUID watchdog = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    UUID heartbeat = scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG);
    clockMillis.set(baseMillis - Duration.ofSeconds(30).toMillis());

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    expect.that(scheduledWorkId(CrumblesConstants.SEND_WORK_TAG)).isEqualTo(upload);
    expect.that(scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG)).isEqualTo(deletion);
    expect.that(scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)).isEqualTo(watchdog);
    expect.that(scheduledWorkId(CrumblesHeartbeatWorker.WORK_TAG)).isEqualTo(heartbeat);
  }

  @Test
  public void scheduleAllPeriodicWork_whenStoredPeriodExceedsExpected_repairsUsingExpected()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis + Duration.ofHours(1).toMillis());
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    clockedWorkManager.enqueueUniquePeriodicWork(
        CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG,
        ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
        new PeriodicWorkRequest.Builder(CrumblesLoggingWatchdogWorker.class, Duration.ofHours(2))
            .setConstraints(new Constraints.Builder().setRequiresCharging(true).build())
            .addTag(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .build());
    UUID storedLongPeriodWatchdog = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    clockMillis.set(baseMillis);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    WorkInfo watchdogInfo = onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    expect.that(watchdogInfo.getId()).isNotEqualTo(storedLongPeriodWatchdog);
    expect
        .that(watchdogInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL.toMillis());
  }

  @Test
  public void scheduleAllPeriodicWork_whenExpectedExceedsStoredPeriod_repairsUsingStored()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis + Duration.ofHours(1).toMillis());
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    clockedWorkManager.enqueueUniquePeriodicWork(
        CrumblesConstants.SEND_WORK_TAG,
        ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
        new PeriodicWorkRequest.Builder(
                CrumblesSendAndMarkProcessingWorker.class, Duration.ofMinutes(15))
            .setConstraints(new Constraints.Builder().setRequiresCharging(true).build())
            .addTag(CrumblesConstants.SEND_WORK_TAG)
            .build());
    UUID storedShortPeriodUpload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    clockMillis.set(baseMillis);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    WorkInfo uploadInfo = onlyWorkInfo(CrumblesConstants.SEND_WORK_TAG);
    expect.that(uploadInfo.getId()).isNotEqualTo(storedShortPeriodUpload);
    expect
        .that(uploadInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.SEND_REPEAT_INTERVAL.toMillis());
  }

  @Test
  public void scheduleAllPeriodicWork_whenInitialDelayExceedsInterval_keepsExisting()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis);
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    clockedWorkManager.enqueueUniquePeriodicWork(
        CrumblesConstants.SEND_WORK_TAG,
        ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
        new PeriodicWorkRequest.Builder(
                CrumblesSendAndMarkProcessingWorker.class, CrumblesConstants.SEND_REPEAT_INTERVAL)
            .setInitialDelay(Duration.ofHours(20))
            .setConstraints(new Constraints.Builder().setRequiresCharging(true).build())
            .addTag(CrumblesConstants.SEND_WORK_TAG)
            .build());
    UUID delayedUpload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    assertThat(scheduledWorkId(CrumblesConstants.SEND_WORK_TAG)).isEqualTo(delayedUpload);
  }

  @Test
  public void scheduleAllPeriodicWork_whenDueWithinIntervalAndNoInitialDelay_keepsExisting()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis + Duration.ofHours(6).toMillis());
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);
    UUID upload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    clockMillis.set(baseMillis);

    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);

    assertThat(scheduledWorkId(CrumblesConstants.SEND_WORK_TAG)).isEqualTo(upload);
  }

  @Test
  public void repairForwardScheduledWork_whenOnlyNormalOrCancelledWorkExists_leavesWorkAlone()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis);
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);
    UUID upload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    UUID deletion = scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG);
    clockedWorkManager.cancelUniqueWork(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);

    CrumblesWorkScheduler.repairForwardScheduledWork(clockedWorkManager);

    expect.that(scheduledWorkId(CrumblesConstants.SEND_WORK_TAG)).isEqualTo(upload);
    expect.that(scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG)).isEqualTo(deletion);
    assertWorkIsCancelled(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    expect
        .that(
            clockedWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
                .get())
        .isEmpty();
  }

  @Test
  public void repairForwardScheduledWork_whenScheduledAtForwardClock_repairsWithoutImmediateUpload()
      throws ExecutionException, InterruptedException {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis + Duration.ofDays(10).toMillis());
    WorkManager clockedWorkManager = initializeWorkManagerWithClock(clockMillis);
    CrumblesWorkScheduler.scheduleAllPeriodicWork(context, clockedWorkManager);
    UUID forwardUpload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
    UUID forwardWatchdog = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    clockMillis.set(baseMillis);

    CrumblesWorkScheduler.repairForwardScheduledWork(clockedWorkManager);

    WorkInfo uploadInfo = onlyWorkInfo(CrumblesConstants.SEND_WORK_TAG);
    WorkInfo watchdogInfo = onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
    expect.that(uploadInfo.getId()).isNotEqualTo(forwardUpload);
    expect
        .that(uploadInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.SEND_REPEAT_INTERVAL.toMillis());
    expect.that(watchdogInfo.getId()).isNotEqualTo(forwardWatchdog);
    expect
        .that(watchdogInfo.getNextScheduleTimeMillis())
        .isAtMost(baseMillis + CrumblesConstants.LOGGING_WATCHDOG_REPEAT_INTERVAL.toMillis());
    expect
        .that(
            clockedWorkManager
                .getWorkInfosForUniqueWork(CrumblesConstants.SEND_NOW_WORK_NAME)
                .get())
        .isEmpty();
  }

  @Test
  public void scheduleAllPeriodicWork_whenWatchdogIsRunning_doesNotCancelRunningWork()
      throws Exception {
    CountDownLatch startedLatch = new CountDownLatch(1);
    CountDownLatch releaseLatch = new CountDownLatch(1);
    ExecutorService workerExecutor = Executors.newSingleThreadExecutor();
    try {
      initializeWorkManagerWithBlockingWorker(
          CrumblesLoggingWatchdogWorker.class, workerExecutor, startedLatch, releaseLatch);
      CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);
      UUID watchdogId = scheduledWorkId(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
      WorkManagerTestInitHelper.getTestDriver(context).setPeriodDelayMet(watchdogId);
      awaitBlockingWorkerStarted(startedLatch);
      assertThat(onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG).getState())
          .isEqualTo(WorkInfo.State.RUNNING);
      assertThat(
              onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG).getNextScheduleTimeMillis())
          .isEqualTo(Long.MAX_VALUE);

      CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);

      WorkInfo watchdogAfter = onlyWorkInfo(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG);
      expect.that(watchdogAfter.getId()).isEqualTo(watchdogId);
      expect.that(watchdogAfter.getState()).isEqualTo(WorkInfo.State.RUNNING);
    } finally {
      releaseBlockingWorkerAndShutDown(releaseLatch, workerExecutor);
    }
  }

  /**
   * Initializes WorkManager to run each worker of {@code workerClass} as a {@link BlockingWorker}
   * on {@code workerExecutor}.
   */
  private void initializeWorkManagerWithBlockingWorker(
      Class<? extends ListenableWorker> workerClass,
      ExecutorService workerExecutor,
      CountDownLatch startedLatch,
      CountDownLatch releaseLatch) {
    Configuration config =
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(workerExecutor)
            .setTaskExecutor(new SynchronousExecutor())
            .setWorkerFactory(
                new WorkerFactory() {
                  @Override
                  public ListenableWorker createWorker(
                      @NonNull Context appContext,
                      @NonNull String workerClassName,
                      @NonNull WorkerParameters workerParameters) {
                    if (workerClassName.equals(workerClass.getName())) {
                      return new BlockingWorker(
                          appContext, workerParameters, startedLatch, releaseLatch);
                    }
                    return null;
                  }
                })
            .build();
    WorkManagerTestInitHelper.initializeTestWorkManager(
        context, config, WorkManagerTestInitHelper.ExecutorsMode.PRESERVE_EXECUTORS);
    realTestWorkManager = WorkManager.getInstance(context);
  }

  /** Waits for a {@link BlockingWorker} to start, idling the main looper that starts it. */
  private static void awaitBlockingWorkerStarted(CountDownLatch startedLatch)
      throws InterruptedException {
    long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (!startedLatch.await(10, TimeUnit.MILLISECONDS)) {
      assertWithMessage("Timed out waiting for BlockingWorker to start")
          .that(System.nanoTime())
          .isLessThan(deadlineNanos);
      Shadows.shadowOf(Looper.getMainLooper()).idle();
    }
  }

  /** Releases a {@link BlockingWorker}, then cancels all work and closes the work database. */
  private void releaseBlockingWorkerAndShutDown(
      CountDownLatch releaseLatch, ExecutorService workerExecutor) throws Exception {
    releaseLatch.countDown();
    realTestWorkManager.cancelAllWork().getResult().get(10, TimeUnit.SECONDS);
    Shadows.shadowOf(Looper.getMainLooper()).idle();
    WorkManagerTestInitHelper.closeWorkDatabase();
    Shadows.shadowOf(Looper.getMainLooper()).idle();
    workerExecutor.shutdown();
    workerExecutor.awaitTermination(10, TimeUnit.SECONDS);
  }

  @Test
  public void repairForwardScheduledWork_whenWorkIsBlocked_leavesBlockedWorkUntouched()
      throws Exception {
    OneTimeWorkRequest blocker =
        new OneTimeWorkRequest.Builder(FailingWorker.class)
            .setConstraints(new Constraints.Builder().setRequiresCharging(true).build())
            .build();
    OneTimeWorkRequest blocked = new OneTimeWorkRequest.Builder(FailingWorker.class).build();
    realTestWorkManager
        .beginUniqueWork(
            CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG, ExistingWorkPolicy.REPLACE, blocker)
        .then(blocked)
        .enqueue();
    List<WorkInfo> before =
        realTestWorkManager
            .getWorkInfosForUniqueWork(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .get();
    assertThat(before).hasSize(2);
    WorkInfo blockedBefore = workInfoById(before, blocked.getId());
    assertThat(blockedBefore.getState()).isEqualTo(WorkInfo.State.BLOCKED);
    assertThat(blockedBefore.getNextScheduleTimeMillis()).isEqualTo(Long.MAX_VALUE);

    CrumblesWorkScheduler.repairForwardScheduledWork(realTestWorkManager);

    List<WorkInfo> after =
        realTestWorkManager
            .getWorkInfosForUniqueWork(CrumblesConstants.LOGGING_WATCHDOG_WORK_TAG)
            .get();
    assertThat(after).hasSize(2);
    WorkInfo blockedAfter = workInfoById(after, blocked.getId());
    expect.that(blockedAfter.getState()).isEqualTo(WorkInfo.State.BLOCKED);
  }

  private static WorkInfo workInfoById(List<WorkInfo> workInfos, UUID id) {
    for (WorkInfo workInfo : workInfos) {
      if (workInfo.getId().equals(id)) {
        return workInfo;
      }
    }
    throw new AssertionError("Missing WorkInfo for " + id);
  }

  @Test
  public void scheduleAllPeriodicWork_withAsyncTaskExecutor_repairsForwardWorksWithoutBlocking()
      throws Exception {
    long baseMillis = 1_700_000_000_000L;
    AtomicLong clockMillis = new AtomicLong(baseMillis + Duration.ofDays(10).toMillis());
    ExecutorService taskExecutor = Executors.newSingleThreadExecutor();
    try {
      Configuration config =
          new Configuration.Builder()
              .setMinimumLoggingLevel(Log.DEBUG)
              .setExecutor(new SynchronousExecutor())
              .setTaskExecutor(taskExecutor)
              .setClock(clockMillis::get)
              .build();
      WorkManagerTestInitHelper.initializeTestWorkManager(
          context, config, WorkManagerTestInitHelper.ExecutorsMode.PRESERVE_EXECUTORS);
      realTestWorkManager = WorkManager.getInstance(context);
      CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);
      awaitAsyncWorkManager(realTestWorkManager);
      UUID forwardUpload = scheduledWorkId(CrumblesConstants.SEND_WORK_TAG);
      UUID forwardDeletion = scheduledWorkId(CrumblesConstants.DELETE_WORK_TAG);
      clockMillis.set(baseMillis);

      CrumblesWorkScheduler.scheduleAllPeriodicWork(context, realTestWorkManager);
      awaitAsyncWorkManager(realTestWorkManager);

      WorkInfo uploadInfo = onlyWorkInfo(CrumblesConstants.SEND_WORK_TAG);
      WorkInfo deletionInfo = onlyWorkInfo(CrumblesConstants.DELETE_WORK_TAG);
      expect.that(uploadInfo.getId()).isNotEqualTo(forwardUpload);
      expect
          .that(uploadInfo.getNextScheduleTimeMillis())
          .isAtMost(baseMillis + CrumblesConstants.SEND_REPEAT_INTERVAL.toMillis());
      expect.that(deletionInfo.getId()).isNotEqualTo(forwardDeletion);
      expect
          .that(deletionInfo.getNextScheduleTimeMillis())
          .isAtMost(baseMillis + Duration.ofHours(25).toMillis());
    } finally {
      realTestWorkManager.cancelAllWork().getResult().get(10, TimeUnit.SECONDS);
      Shadows.shadowOf(Looper.getMainLooper()).idle();
      WorkManagerTestInitHelper.closeWorkDatabase();
      Shadows.shadowOf(Looper.getMainLooper()).idle();
      taskExecutor.shutdown();
      taskExecutor.awaitTermination(10, TimeUnit.SECONDS);
    }
  }

  private static void awaitAsyncWorkManager(WorkManager workManager) throws Exception {
    // First lookup drains the initial queries (whose directExecutor listeners queue follow-up
    // enqueues on WorkManager's serial executor); the second lookup waits behind those enqueues.
    workManager
        .getWorkInfosForUniqueWork(CrumblesConstants.MARK_SENT_WORK_TAG)
        .get(10, TimeUnit.SECONDS);
    Shadows.shadowOf(Looper.getMainLooper()).idle();
    workManager
        .getWorkInfosForUniqueWork(CrumblesConstants.MARK_SENT_WORK_TAG)
        .get(10, TimeUnit.SECONDS);
    Shadows.shadowOf(Looper.getMainLooper()).idle();
  }

  private WorkManager initializeWorkManagerWithClock(AtomicLong clockMillis) {
    Configuration config =
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(new SynchronousExecutor())
            .setClock(clockMillis::get)
            .build();
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config);
    realTestWorkManager = WorkManager.getInstance(context);
    return realTestWorkManager;
  }

  private WorkInfo onlyWorkInfo(String uniqueWorkName)
      throws ExecutionException, InterruptedException {
    List<WorkInfo> workInfos = realTestWorkManager.getWorkInfosForUniqueWork(uniqueWorkName).get();
    assertThat(workInfos).hasSize(1);
    return workInfos.get(0);
  }

  /** Worker that stays in {@link WorkInfo.State#RUNNING} until {@code releaseLatch} opens. */
  private static final class BlockingWorker extends Worker {
    private final CountDownLatch startedLatch;
    private final CountDownLatch releaseLatch;

    BlockingWorker(
        @NonNull Context context,
        @NonNull WorkerParameters workerParams,
        CountDownLatch startedLatch,
        CountDownLatch releaseLatch) {
      super(context, workerParams);
      this.startedLatch = startedLatch;
      this.releaseLatch = releaseLatch;
    }

    @NonNull
    @Override
    public Result doWork() {
      startedLatch.countDown();
      try {
        var unused = releaseLatch.await(10, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return Result.success();
    }
  }

  /** Stand-in for an immediate upload that exhausted its retries and ended in failure. */
  public static final class FailingWorker extends Worker {
    public FailingWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
      super(context, workerParams);
    }

    @NonNull
    @Override
    public Result doWork() {
      return Result.failure();
    }
  }

  /** Stand-in for an immediate upload whose attempt failed and that waits to be retried. */
  public static final class RetryingWorker extends Worker {
    public RetryingWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
      super(context, workerParams);
    }

    @NonNull
    @Override
    public Result doWork() {
      return Result.retry();
    }
  }
}
