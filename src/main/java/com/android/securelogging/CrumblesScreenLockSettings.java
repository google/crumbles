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

import android.app.admin.DevicePolicyManager;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.ResolveInfoFlags;
import java.util.Optional;

/** Finds the system screen where the user sets a screen lock. */
final class CrumblesScreenLockSettings {

  /**
   * Returns an Intent for the system activity that handles {@link
   * DevicePolicyManager#ACTION_SET_NEW_PASSWORD}, or empty if no system app has one, as on some
   * modified ROMs. Naming that activity keeps any other app that claims the action from being
   * offered instead.
   */
  static Optional<Intent> intent(PackageManager packageManager) {
    Intent intent = new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
    return packageManager
        .queryIntentActivities(intent, ResolveInfoFlags.of(PackageManager.MATCH_SYSTEM_ONLY))
        .stream()
        .findFirst()
        .map(
            resolveInfo -> {
              ActivityInfo activity = resolveInfo.activityInfo;
              return intent.setClassName(activity.packageName, activity.name);
            });
  }

  private CrumblesScreenLockSettings() {}
}
