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

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import androidx.core.app.NotificationCompat;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.InstantSource;
import java.util.Arrays;
import java.util.Comparator;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

/** Unit tests for {@link CrumblesLogStorageQuota}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesLogStorageQuotaTest {

  private static final long CAP_BYTES = 1000;
  private static final long OLDEST_MILLIS = 1_700_000_000_000L;

  @Rule public final TemporaryFolder temporaryFolder = new TemporaryFolder();

  private Context context;
  private Path logsDirectory;
  private NotificationManager notificationManager;

  @Before
  public void setUp() throws IOException {
    context = ApplicationProvider.getApplicationContext();
    logsDirectory = temporaryFolder.newFolder().toPath();
    notificationManager = context.getSystemService(NotificationManager.class);
    notificationManager.cancelAll();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
  }

  @Test
  public void admitNewBatch_warnThresholdBoundary_warnsOnlyAtOrAboveThreshold() throws Exception {
    Path batch = writeBatch("batch_1.bin", /* sizeBytes= */ 799, OLDEST_MILLIS);
    assertThat(CrumblesLogStorageQuota.admitNewBatch(context, logsDirectory.toFile(), CAP_BYTES))
        .isTrue();
    assertThat(Files.exists(batch)).isTrue();
    assertThat(findStorageNotification()).isNull();

    writeBatch("batch_2.bin", /* sizeBytes= */ 1, OLDEST_MILLIS);
    assertThat(CrumblesLogStorageQuota.admitNewBatch(context, logsDirectory.toFile(), CAP_BYTES))
        .isTrue();
    Notification notification = findStorageNotification();
    assertThat(notification.flags & Notification.FLAG_AUTO_CANCEL)
        .isEqualTo(Notification.FLAG_AUTO_CANCEL);
    assertThat(notification.priority).isEqualTo(NotificationCompat.PRIORITY_HIGH);
    assertThat(notification.extras.getString(Notification.EXTRA_TITLE))
        .isEqualTo(context.getString(R.string.notification_title_storage));
    assertThat(notification.extras.getString(Notification.EXTRA_TEXT))
        .isEqualTo(context.getString(R.string.notification_text_storage_approaching));
    assertThat(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    NotificationChannel channel =
        notificationManager.getNotificationChannel(
            CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID);
    assertThat(channel.getDescription())
        .isEqualTo(context.getString(R.string.notification_channel_description_action_needed));
    assertThat(channel.getLockscreenVisibility()).isEqualTo(Notification.VISIBILITY_SECRET);
  }

  @Test
  public void admitNewBatch_whenAtCap_reclaimsOnlyUploadedCopiesOutsideTheReserve()
      throws Exception {
    Path reserved =
        writeBatch("batch_1" + CrumblesConstants.SENT_SUFFIX, /* sizeBytes= */ 250, OLDEST_MILLIS);
    Path pending = writeBatch("batch_2.bin", /* sizeBytes= */ 500, OLDEST_MILLIS + 1000);
    Path uploaded =
        writeBatch(
            "batch_3" + CrumblesConstants.SENT_SUFFIX, /* sizeBytes= */ 250, OLDEST_MILLIS + 2000);

    assertThat(CrumblesLogStorageQuota.admitNewBatch(context, listedNewestFirst(), CAP_BYTES))
        .isTrue();
    assertThat(Files.exists(reserved)).isTrue();
    assertThat(Files.exists(pending)).isTrue();
    assertThat(Files.exists(uploaded)).isFalse();
    assertThat(hasAuditMessage("LOGS_STORAGE_CAP_REACHED")).isTrue();
  }

  @Test
  public void admitNewBatch_whenUploadedCopyOverrunsTheReserve_reclaimsIt() throws Exception {
    Path overrunning =
        writeBatch("batch_1" + CrumblesConstants.SENT_SUFFIX, /* sizeBytes= */ 300, OLDEST_MILLIS);
    writeBatch("batch_2.bin", /* sizeBytes= */ 700, OLDEST_MILLIS + 1000);

    assertThat(CrumblesLogStorageQuota.admitNewBatch(context, logsDirectory.toFile(), CAP_BYTES))
        .isTrue();
    assertThat(Files.exists(overrunning)).isFalse();
  }

  @Test
  public void admitNewBatch_whenAtCapWithRecentBurst_stopsCollectingAndLogsBurst()
      throws Exception {
    long nowMillis = InstantSource.system().instant().toEpochMilli();
    Path oldest = writeBatch("batch_1.bin", /* sizeBytes= */ 600, nowMillis - 2000);
    Path newest = writeBatch("batch_2.bin", /* sizeBytes= */ 600, nowMillis - 1000);

    assertThat(CrumblesLogStorageQuota.admitNewBatch(context, logsDirectory.toFile(), CAP_BYTES))
        .isFalse();
    assertThat(Files.exists(oldest)).isTrue();
    assertThat(Files.exists(newest)).isTrue();
    assertThat(hasAuditMessage("LOGS_COLLECTION_STOPPED")).isTrue();
    assertThat(hasAuditMessage("arrived in a burst")).isTrue();
    assertThat(findStorageNotification().extras.getString(Notification.EXTRA_TEXT))
        .isEqualTo(context.getString(R.string.notification_text_storage_stopped));
  }

  @Test
  public void admitNewBatch_whenDirectoryCannotBeListed_admitsTheBatch() {
    File missing = logsDirectory.resolve("missing").toFile();

    assertThat(CrumblesLogStorageQuota.admitNewBatch(context, missing, CAP_BYTES)).isTrue();
  }

  @CanIgnoreReturnValue
  private Path writeBatch(String name, int sizeBytes, long lastModifiedMillis) throws IOException {
    Path batch = logsDirectory.resolve(name);
    Files.write(batch, new byte[sizeBytes]);
    Files.setLastModifiedTime(batch, FileTime.fromMillis(lastModifiedMillis));
    return batch;
  }

  /** Returns the logs directory, listing its batches newest first rather than oldest first. */
  private File listedNewestFirst() {
    return new File(logsDirectory.toString()) {
      @Override
      public File[] listFiles(FileFilter filter) {
        File[] batches = super.listFiles(filter);
        Arrays.sort(batches, Comparator.comparingLong(File::lastModified).reversed());
        return batches;
      }
    };
  }

  private boolean hasAuditMessage(String text) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .anyMatch(e -> e.getEventType().equals(text) || e.getMessage().contains(text));
  }

  private Notification findStorageNotification() {
    return shadowOf(notificationManager)
        .getNotification(CrumblesLogStorageQuota.STORAGE_NOTIFICATION_ID);
  }
}
