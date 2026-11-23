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
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.WorkManager;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.google.common.truth.Expect;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;

/** Unit tests for {@link CrumblesSyncNowTileService} and its manifest entry. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesSyncNowTileServiceTest {

  @Rule public final Expect expect = Expect.create();

  private final Context context = ApplicationProvider.getApplicationContext();

  @Before
  public void setUp() {
    WorkManagerTestInitHelper.initializeTestWorkManager(context);
  }

  @Test
  public void manifest_exportsTheTileOnlyToHoldersOfTheTilePermission() throws Exception {
    PackageManager packageManager = context.getPackageManager();

    ServiceInfo tile =
        packageManager.getServiceInfo(
            new ComponentName(context, CrumblesSyncNowTileService.class), /* flags= */ 0);

    expect.that(tile.exported).isTrue();
    expect.that(tile.permission).isEqualTo(Manifest.permission.BIND_QUICK_SETTINGS_TILE);
    expect.that(tile.loadLabel(packageManager).toString()).isEqualTo("Sync now");
  }

  @Test
  public void manifest_offersTheTileToSystemUi() {
    Intent tileIntent = new Intent(TileService.ACTION_QS_TILE).setPackage(context.getPackageName());

    assertThat(
            context.getPackageManager().queryIntentServices(tileIntent, /* flags= */ 0).stream()
                .map(resolveInfo -> resolveInfo.serviceInfo.name)
                .collect(toImmutableList()))
        .containsExactly(CrumblesSyncNowTileService.class.getName());
  }

  @Test
  public void onClick_startsAnUploadAndWipeAndSaysSo() throws Exception {
    CrumblesSyncNowTileService service = Robolectric.setupService(CrumblesSyncNowTileService.class);

    service.onClick();

    expect
        .that(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesUploadAndWipeWorker.UNIQUE_WORK_NAME)
                .get())
        .hasSize(1);
    expect.that(service.getQsTile().getSubtitle().toString()).isEqualTo("Started");
  }

  @Test
  public void onClick_onTheLockScreen_hasTheUserUnlockThePhoneFirst() throws Exception {
    CrumblesSyncNowTileService service = Robolectric.setupService(CrumblesSyncNowTileService.class);
    shadowOf(service).setLocked(true);

    service.onClick();

    // Robolectric's unlockAndRun unlocks the phone, then runs the action.
    expect.that(service.isLocked()).isFalse();
    expect
        .that(
            WorkManager.getInstance(context)
                .getWorkInfosForUniqueWork(CrumblesUploadAndWipeWorker.UNIQUE_WORK_NAME)
                .get())
        .hasSize(1);
  }

  @Test
  public void onStartListening_showsAnInactiveTileWithoutSubtitle() {
    CrumblesSyncNowTileService service = Robolectric.setupService(CrumblesSyncNowTileService.class);
    service.onClick();

    service.onStartListening();

    expect.that(service.getQsTile().getState()).isEqualTo(Tile.STATE_INACTIVE);
    expect.that(service.getQsTile().getSubtitle()).isNull();
  }

  @Test
  public void onStartListening_whileCopiesForAFolderAreKept_saysThatDataIsLeft() throws Exception {
    Files.write(
        createLogsDirectory().resolve("batch" + CrumblesConstants.SENT_SUFFIX), "c".getBytes(UTF_8));
    CrumblesSyncNowTileService service = Robolectric.setupService(CrumblesSyncNowTileService.class);

    service.onStartListening();

    assertThat(service.getQsTile().getSubtitle().toString()).isEqualTo("Data left on phone");
  }

  @Test
  public void onStartListening_afterASyncLeftABatch_saysThatDataIsLeft() throws Exception {
    Files.write(createLogsDirectory().resolve("batch.bin"), "not uploaded".getBytes(UTF_8));
    CrumblesSyncNowTileService service = Robolectric.setupService(CrumblesSyncNowTileService.class);
    service.onClick();
    assertThat(CrumblesUploadAndWipeWorker.getBatchesLeft(context)).isEqualTo(1);

    service.onStartListening();

    assertThat(service.getQsTile().getSubtitle().toString()).isEqualTo("Data left on phone");
  }

  private Path createLogsDirectory() throws IOException {
    return Files.createDirectories(
        new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY)
            .toPath());
  }
}
