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
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Optional;

/**
 * A {@link Worker} that writes an empty, numbered and signed batch when no batch was signed for
 * {@link #HEARTBEAT_INTERVAL}.
 *
 * <p>A quiet device still sends a batch at least that often, so a recipient who gets nothing for
 * longer knows that something stops the batches, such as collection being switched off, the app
 * being removed or uploads being blocked.
 */
public class CrumblesHeartbeatWorker extends Worker {

  /** Longest time without a signed batch before the worker writes one. */
  static final Duration HEARTBEAT_INTERVAL = Duration.ofHours(24);

  /** How often the worker checks, which bounds how late a heartbeat batch can be. */
  static final Duration CHECK_INTERVAL = Duration.ofHours(1);

  /** Unique name and tag of the periodic heartbeat work. */
  static final String WORK_TAG = "batch_heartbeat_work";

  public CrumblesHeartbeatWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  @NonNull
  @Override
  public Result doWork() {
    Context context = getApplicationContext();
    Optional<Instant> lastSignedAt = new CrumblesBatchSigner(context).lastSignedAt();
    if (lastSignedAt.isPresent()
        && InstantSource.system().instant().isBefore(lastSignedAt.get().plus(HEARTBEAT_INTERVAL))) {
      return Result.success();
    }
    CrumblesDeviceAdminReceiver.saveHeartbeatBatch(context);
    return Result.success();
  }
}
