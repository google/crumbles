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

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import androidx.annotation.StringRes;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import java.io.File;
import java.time.InstantSource;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Keeps the encrypted log directory within a byte cap without destroying evidence by reclaiming
 * only already-uploaded copies ({@code _sent.bin}) outside the protected earliest window.
 */
final class CrumblesLogStorageQuota {

  private static final String TAG = "CrumblesLogStorageQuota";
  static final int STORAGE_NOTIFICATION_ID = 2003;

  private CrumblesLogStorageQuota() {}

  static boolean admitNewBatch(Context context, File directory, long capBytes) {
    File[] batches = directory.listFiles(File::isFile);
    if (batches == null) {
      Log.w(TAG, "Unable to list the logs directory; admitting the batch unchecked.");
      return true;
    }
    Arrays.sort(batches, Comparator.comparingLong(File::lastModified));
    long usedBytes = Arrays.stream(batches).mapToLong(File::length).sum();
    if (usedBytes < capBytes) {
      warnIfApproachingCap(context, usedBytes, capBytes);
      return true;
    }
    long remainingBytes = reclaimUploadedCopies(batches, usedBytes, capBytes);
    boolean admitted = remainingBytes < capBytes;
    reportCapReached(context, batches, remainingBytes, capBytes, admitted);
    return admitted;
  }

  private static void warnIfApproachingCap(Context context, long usedBytes, long capBytes) {
    if (usedBytes < capBytes * CrumblesConstants.LOGS_DIRECTORY_WARN_PERCENT / 100) {
      return;
    }
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            "LOGS_STORAGE_CAP_APPROACHING",
            "Stored log batches use " + usedBytes + " of " + capBytes + " permitted bytes.");
    notifyUser(context, R.string.notification_text_storage_approaching);
  }

  private static long reclaimUploadedCopies(File[] oldestFirst, long usedBytes, long capBytes) {
    long reservedBytes = capBytes * CrumblesConstants.LOGS_DIRECTORY_RESERVED_PERCENT / 100;
    long olderBytes = 0;
    for (File batch : oldestFirst) {
      if (usedBytes < capBytes) {
        break;
      }
      long batchBytes = batch.length();
      olderBytes += batchBytes;
      // Only batches lying wholly inside the reserve are kept, so it never outgrows its share.
      boolean withinReserve = olderBytes <= reservedBytes;
      if (withinReserve || !batch.getName().endsWith(CrumblesConstants.SENT_SUFFIX)) {
        continue;
      }
      if (batch.delete()) {
        usedBytes -= batchBytes;
      } else {
        Log.e(TAG, "Failed to reclaim the uploaded copy " + batch.getName());
      }
    }
    return usedBytes;
  }

  private static void reportCapReached(
      Context context, File[] batches, long usedBytes, long capBytes, boolean admitted) {
    long windowStartMillis =
        InstantSource.system()
            .instant()
            .minus(CrumblesConstants.LOGS_DIRECTORY_SPIKE_WINDOW)
            .toEpochMilli();
    long recentBytes =
        Arrays.stream(batches)
            .filter(batch -> batch.lastModified() >= windowStartMillis)
            .mapToLong(File::length)
            .sum();
    String burst =
        recentBytes >= capBytes * CrumblesConstants.LOGS_DIRECTORY_SPIKE_PERCENT / 100
            ? " " + recentBytes + " bytes of them arrived in a burst, an unusual volume."
            : "";
    Log.w(TAG, "Storage cap reached; new batches are " + (admitted ? "kept." : "dropped."));
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            admitted ? "LOGS_STORAGE_CAP_REACHED" : "LOGS_COLLECTION_STOPPED",
            "Log batches use " + usedBytes + " of " + capBytes + " permitted bytes." + burst);
    notifyUser(
        context,
        admitted
            ? R.string.notification_text_storage_pressure
            : R.string.notification_text_storage_stopped);
  }

  // Suppress "MissingPermission" because the platform drops, rather than rejects, notifications
  // posted without POST_NOTIFICATIONS, and "PendingIntentMutability" because FLAG_IMMUTABLE is set.
  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private static void notifyUser(Context context, @StringRes int contentTextId) {
    NotificationManagerCompat manager = NotificationManagerCompat.from(context);
    NotificationChannel channel =
        new NotificationChannel(
            CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID,
            context.getString(R.string.notification_channel_name_action_needed),
            NotificationManager.IMPORTANCE_HIGH);
    channel.setDescription(
        context.getString(R.string.notification_channel_description_action_needed));
    // Keep the content off the lock screen: revealing that the device collects security logs
    // endangers at-risk users.
    channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
    manager.createNotificationChannel(channel);
    Intent openIntent =
        new Intent(context, CrumblesMain.class)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    PendingIntent pendingIntent =
        PendingIntent.getActivity(
            context,
            /* requestCode= */ 0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    Notification notification =
        new NotificationCompat.Builder(
                context, CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(context.getString(R.string.notification_title_storage))
            .setContentText(context.getString(contentTextId))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setAutoCancel(true)
            .build();
    manager.notify(STORAGE_NOTIFICATION_ID, notification);
  }
}
