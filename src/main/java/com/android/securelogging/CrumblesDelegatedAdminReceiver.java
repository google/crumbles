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

import android.app.admin.DelegatedAdminReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.annotation.NonNull;

/**
 * Receives security and network logs when the device owner delegated logging to Crumbles instead of
 * Crumbles being the device owner.
 *
 * <p>Once a scope is delegated, the platform sends its log callbacks to this receiver rather than
 * to {@link CrumblesDeviceAdminReceiver}. Both receivers retrieve and encrypt the logs the same
 * way.
 *
 * <p>{@link CrumblesDeviceAdminReceiver} alone handles the boot broadcast, which it receives
 * whether Crumbles is the device owner or a delegate: {@link DelegatedAdminReceiver} does not let a
 * subclass handle any other broadcast.
 */
public final class CrumblesDelegatedAdminReceiver extends DelegatedAdminReceiver {

  @Override
  public void onSecurityLogsAvailable(@NonNull Context context, @NonNull Intent intent) {
    CrumblesDeviceAdminReceiver.retrieveInBackground(
        goAsync(), () -> CrumblesDeviceAdminReceiver.retrieveAndSaveSecurityLogs(context));
  }

  @Override
  public void onNetworkLogsAvailable(
      @NonNull Context context, @NonNull Intent intent, long batchToken, int networkLogsCount) {
    CrumblesDeviceAdminReceiver.retrieveInBackground(
        goAsync(),
        () ->
            CrumblesDeviceAdminReceiver.retrieveAndSaveNetworkLogs(
                context, batchToken, networkLogsCount));
  }
}
