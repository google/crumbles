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

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;

/**
 * Chooses how Crumbles appears in the launcher: under its own name and icon, or under the neutral
 * name "Device sync" with a plain sync icon.
 *
 * <p>Both launcher entries are activity aliases of {@link CrumblesMain}, and exactly one of them is
 * enabled. Notifications and the app's own screens open {@link CrumblesMain} directly, so they work
 * whichever entry is enabled. The system closes a screen that was opened through the entry being
 * disabled.
 */
public final class CrumblesLauncherEntry {

  private static final String DEFAULT_ALIAS = "com.android.securelogging.CrumblesLauncher";
  private static final String NEUTRAL_ALIAS = "com.android.securelogging.CrumblesNeutralLauncher";

  /** Returns whether the launcher shows the neutral name and icon. */
  public static boolean isNeutral(Context context) {
    return context
            .getPackageManager()
            .getComponentEnabledSetting(new ComponentName(context, NEUTRAL_ALIAS))
        == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
  }

  /** Shows Crumbles in the launcher under the neutral name and icon. */
  public static void showNeutral(Context context) {
    switchEntry(context, /* enabledAlias= */ NEUTRAL_ALIAS, /* disabledAlias= */ DEFAULT_ALIAS);
  }

  /** Shows Crumbles in the launcher under its own name and icon. */
  public static void showDefault(Context context) {
    switchEntry(context, /* enabledAlias= */ DEFAULT_ALIAS, /* disabledAlias= */ NEUTRAL_ALIAS);
  }

  /**
   * Enables one entry before disabling the other, so that the launcher never lacks an entry if the
   * process dies in between. Neither change kills the app.
   */
  private static void switchEntry(Context context, String enabledAlias, String disabledAlias) {
    PackageManager packageManager = context.getPackageManager();
    packageManager.setComponentEnabledSetting(
        new ComponentName(context, enabledAlias),
        PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
        PackageManager.DONT_KILL_APP);
    packageManager.setComponentEnabledSetting(
        new ComponentName(context, disabledAlias),
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
        PackageManager.DONT_KILL_APP);
  }

  private CrumblesLauncherEntry() {}
}
