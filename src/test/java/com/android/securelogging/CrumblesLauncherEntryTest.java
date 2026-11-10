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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static org.robolectric.Shadows.shadowOf;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for {@link CrumblesLauncherEntry} and the launcher entries in the manifest. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesLauncherEntryTest {

  private static final String DEFAULT_ALIAS = "com.android.securelogging.CrumblesLauncher";
  private static final String NEUTRAL_ALIAS = "com.android.securelogging.CrumblesNeutralLauncher";

  @Rule public final Expect expect = Expect.create();

  private final Context context = ApplicationProvider.getApplicationContext();

  @Test
  public void byDefault_launcherShowsOnlyTheCrumblesEntry() {
    expect.that(launcherEntries()).containsExactly(DEFAULT_ALIAS);
    expect.that(CrumblesLauncherEntry.isNeutral(context)).isFalse();
  }

  @Test
  public void showNeutral_replacesTheCrumblesEntryWithTheNeutralEntryWithoutKillingTheApp() {
    CrumblesLauncherEntry.showNeutral(context);

    expect.that(launcherEntries()).containsExactly(NEUTRAL_ALIAS);
    expect.that(CrumblesLauncherEntry.isNeutral(context)).isTrue();
    expect.that(enabledSettingFlags(NEUTRAL_ALIAS)).isEqualTo(PackageManager.DONT_KILL_APP);
    expect.that(enabledSettingFlags(DEFAULT_ALIAS)).isEqualTo(PackageManager.DONT_KILL_APP);
  }

  @Test
  public void showDefault_afterShowNeutral_restoresTheCrumblesEntry() {
    CrumblesLauncherEntry.showNeutral(context);

    CrumblesLauncherEntry.showDefault(context);

    expect.that(launcherEntries()).containsExactly(DEFAULT_ALIAS);
    expect.that(CrumblesLauncherEntry.isNeutral(context)).isFalse();
  }

  @Test
  public void manifest_neutralEntryOpensCrumblesMainAsDeviceSyncWithSyncIcon() throws Exception {
    PackageManager packageManager = context.getPackageManager();

    ActivityInfo neutralEntry =
        packageManager.getActivityInfo(
            new ComponentName(context, NEUTRAL_ALIAS), PackageManager.MATCH_DISABLED_COMPONENTS);

    expect.that(neutralEntry.loadLabel(packageManager).toString()).isEqualTo("Device sync");
    expect.that(neutralEntry.getIconResource()).isEqualTo(R.mipmap.ic_launcher_neutral);
    expect.that(neutralEntry.targetActivity).isEqualTo(CrumblesMain.class.getName());
  }

  @Test
  public void manifest_exportsOnlyTheLauncherEntriesOfCrumblesMain() throws Exception {
    PackageManager packageManager = context.getPackageManager();

    ActivityInfo main =
        packageManager.getActivityInfo(
            new ComponentName(context, CrumblesMain.class), /* flags= */ 0);
    ActivityInfo defaultEntry =
        packageManager.getActivityInfo(new ComponentName(context, DEFAULT_ALIAS), /* flags= */ 0);

    expect.that(main.exported).isFalse();
    expect.that(defaultEntry.exported).isTrue();
    expect.that(defaultEntry.targetActivity).isEqualTo(CrumblesMain.class.getName());
  }

  private ImmutableList<String> launcherEntries() {
    Intent launcherIntent =
        new Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(context.getPackageName());
    return context
        .getPackageManager()
        .queryIntentActivities(launcherIntent, /* flags= */ 0)
        .stream()
        .map(resolveInfo -> resolveInfo.activityInfo.name)
        .collect(toImmutableList());
  }

  private int enabledSettingFlags(String alias) {
    return shadowOf(context.getPackageManager())
        .getComponentEnabledSettingFlags(new ComponentName(context, alias));
  }
}
