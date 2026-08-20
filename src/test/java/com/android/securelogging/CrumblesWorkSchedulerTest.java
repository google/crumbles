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
import androidx.test.core.app.ApplicationProvider;
import androidx.work.Configuration;
import androidx.work.WorkInfo;
import androidx.work.WorkManager;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.WorkManagerTestInitHelper;
import java.util.List;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link CrumblesWorkScheduler}. */
@RunWith(RobolectricTestRunner.class)
public class CrumblesWorkSchedulerTest {

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
  }
}
