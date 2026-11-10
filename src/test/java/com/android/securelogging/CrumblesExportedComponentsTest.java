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

import android.Manifest;
import android.app.job.JobService;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.truth.Expect;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/**
 * Checks which components of the app, including those that libraries add to the merged manifest,
 * other apps can start or send intents to.
 */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public final class CrumblesExportedComponentsTest {

  /**
   * The two launcher activity aliases of {@link CrumblesMain}, only one of which is enabled at a
   * time.
   */
  private static final ImmutableSet<String> LAUNCHER_ENTRIES =
      ImmutableSet.of(
          "com.android.securelogging.CrumblesLauncher",
          "com.android.securelogging.CrumblesNeutralLauncher");

  /**
   * Permissions that only the system holds, or the shell for DUMP: BIND_DEVICE_ADMIN guards the
   * device admin and delegated logging receivers, BIND_QUICK_SETTINGS_TILE guards the Quick
   * Settings tile, and BIND_JOB_SERVICE and DUMP guard WorkManager's job service and diagnostics
   * receiver.
   */
  private static final ImmutableSet<String> SYSTEM_PERMISSIONS =
      ImmutableSet.of(
          Manifest.permission.BIND_DEVICE_ADMIN,
          Manifest.permission.BIND_QUICK_SETTINGS_TILE,
          JobService.PERMISSION_BIND,
          Manifest.permission.DUMP);

  private static final String TEST_FRAMEWORK_PACKAGE = "androidx.test.";

  @Rule public final Expect expect = Expect.create();

  private ImmutableList<ComponentInfo> components;

  @Before
  public void setUp() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    PackageInfo packageInfo =
        context
            .getPackageManager()
            .getPackageInfo(
                context.getPackageName(),
                PackageManager.GET_ACTIVITIES
                    | PackageManager.GET_RECEIVERS
                    | PackageManager.GET_SERVICES
                    | PackageManager.GET_PROVIDERS
                    | PackageManager.MATCH_DISABLED_COMPONENTS);
    components =
        Stream.of(
                packageInfo.activities,
                packageInfo.receivers,
                packageInfo.services,
                packageInfo.providers)
            .filter(Objects::nonNull)
            .flatMap(Arrays::stream)
            .collect(ImmutableList.toImmutableList());
  }

  @Test
  public void exportedComponents_otherThanTheLauncherRequireASystemPermission() {
    components.stream()
        .filter(component -> component.exported)
        .filter(component -> !LAUNCHER_ENTRIES.contains(component.name))
        // The test framework adds its own activities to the test's manifest, not to the app's.
        .filter(component -> !component.name.startsWith(TEST_FRAMEWORK_PACKAGE))
        .forEach(
            component ->
                expect
                    .withMessage("Permission guarding %s", component.name)
                    .that(permissionOf(component).orElse("no permission"))
                    .isIn(SYSTEM_PERMISSIONS));
  }

  @Test
  public void appComponents_exportOnlyTheLauncherAndSystemGuardedComponents() {
    expect
        .that(
            components.stream()
                .filter(component -> component.exported)
                .map(component -> component.name)
                .filter(name -> name.startsWith(CrumblesMain.class.getPackage().getName())))
        .containsExactly(
            "com.android.securelogging.CrumblesLauncher",
            "com.android.securelogging.CrumblesNeutralLauncher",
            CrumblesDeviceAdminReceiver.class.getName(),
            CrumblesDelegatedAdminReceiver.class.getName(),
            CrumblesSyncNowTileService.class.getName());
  }

  /** Returns the permission that callers need to reach {@code component}, if any. */
  private static Optional<String> permissionOf(ComponentInfo component) {
    if (component instanceof ActivityInfo activityOrReceiver) {
      return Optional.ofNullable(activityOrReceiver.permission);
    }
    if (component instanceof ServiceInfo service) {
      return Optional.ofNullable(service.permission);
    }
    return Optional.ofNullable(((ProviderInfo) component).readPermission);
  }
}
