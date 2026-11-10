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

import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/**
 * Quick Settings tile "Sync now", which starts an upload and wipe without opening the app.
 *
 * <p>The wipe deletes the copies that the phone keeps of uploaded batches in case the server loses
 * them, so on the lock screen the tile has the user unlock the phone first. While the phone still
 * holds batches that it could not upload, or copies kept for a folder, the tile says so.
 *
 * <p>The service is exported so that System UI can bind it, but it requires {@code
 * BIND_QUICK_SETTINGS_TILE}, which only the system holds.
 */
public final class CrumblesSyncNowTileService extends TileService {

  @Override
  public void onStartListening() {
    Tile tile = getQsTile();
    tile.setState(Tile.STATE_INACTIVE);
    tile.setSubtitle(
        CrumblesUploadAndWipeWorker.getBatchesLeft(this) > 0
                || CrumblesUploadAndWipeWorker.countKeptSafBatches(this) > 0
            ? getString(R.string.sync_now_tile_data_left)
            : null);
    tile.updateTile();
  }

  @Override
  public void onClick() {
    if (isLocked()) {
      unlockAndRun(this::startUploadAndWipe);
    } else {
      startUploadAndWipe();
    }
  }

  private void startUploadAndWipe() {
    CrumblesUploadAndWipeWorker.start(this);
    Tile tile = getQsTile();
    tile.setSubtitle(getString(R.string.sync_now_tile_started));
    tile.updateTile();
  }
}
