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
import static org.junit.Assert.assertNotNull;

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.Configuration;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.ExistingWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.google.common.truth.Expect;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link CrumblesWorkScheduler}. */
@RunWith(RobolectricTestRunner.class)
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
}
