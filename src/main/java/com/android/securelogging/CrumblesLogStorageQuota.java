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
import android.content.SharedPreferences;
import android.util.Log;
import androidx.annotation.StringRes;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.common.collect.ImmutableList;
import java.io.File;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Keeps the encrypted log directory within a byte cap without destroying evidence by reclaiming
 * only already-uploaded copies ({@code _sent.bin}) outside the protected earliest window.
 */
final class CrumblesLogStorageQuota {

  private static final String TAG = "CrumblesLogStorageQuota";
  static final int SIGNATURE_ALLOWANCE_BYTES = 8192;
  private static final String PREF_ALERTED_APPROACHING = "quotaAlertedApproaching";
  private static final String PREF_ALERTED_REACHED = "quotaAlertedReached";

  /** Preferences numbering each batch, by its name without suffix, in the order first seen. */
  private static final String ADMISSION_ORDER_PREFS = "CrumblesBatchAdmissionOrder";

  /** Suffixes that a batch file name takes through its upload, with .bin, which ends all, last. */
  private static final ImmutableList<String> UPLOAD_STATE_SUFFIXES =
      ImmutableList.of(CrumblesConstants.SENT_SUFFIX, CrumblesConstants.PROCESSING_SUFFIX, ".bin");

  private CrumblesLogStorageQuota() {}

  static boolean admitNewBatch(
      Context context, File directory, long capBytes, boolean isNetworkBatch, long incomingBytes) {
    return admitNewBatch(
        context,
        directory,
        capBytes,
        isNetworkBatch,
        incomingBytes,
        /* signatureAllowanceBytes= */ 0L);
  }

  static boolean admitNewBatch(
      Context context,
      File directory,
      long capBytes,
      boolean isNetworkBatch,
      long batchBytes,
      long signatureAllowanceBytes) {
    File[] batches = directory.listFiles(File::isFile);
    if (batches == null) {
      Log.w(TAG, "Unable to list the logs directory; admitting the batch unchecked.");
      return true;
    }
    sortByAdmissionOrder(context, batches);
    long usedBytes = Arrays.stream(batches).mapToLong(File::length).sum();
    long effectiveCapBytes =
        isNetworkBatch
            ? capBytes - (capBytes * CrumblesConstants.LOGS_DIRECTORY_RESERVED_PERCENT / 100)
            : capBytes;
    long admissionBytes = batchBytes + signatureAllowanceBytes;
    long onDiskNonReclaimableBytes = getNonReclaimableBytes(batches, capBytes);
    if (usedBytes + admissionBytes >= effectiveCapBytes
        && onDiskNonReclaimableBytes + admissionBytes < effectiveCapBytes) {
      usedBytes =
          reclaimUploadedCopies(
              context, batches, usedBytes, capBytes, effectiveCapBytes - admissionBytes);
    }

    boolean admitted = usedBytes + admissionBytes < effectiveCapBytes;

    String prefApproaching =
        PREF_ALERTED_APPROACHING + "_" + effectiveCapBytes + "_" + isNetworkBatch;
    String prefReached = PREF_ALERTED_REACHED + "_" + effectiveCapBytes + "_" + isNetworkBatch;

    if (admitted) {
      warnIfApproachingCap(
          context, onDiskNonReclaimableBytes + batchBytes, effectiveCapBytes, prefApproaching);
      context
          .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
          .edit()
          .putBoolean(prefReached, false)
          .apply();
    } else {
      reportCapReached(
          context,
          batches,
          onDiskNonReclaimableBytes,
          capBytes,
          effectiveCapBytes,
          prefReached,
          isNetworkBatch);
    }
    return admitted;
  }

  /**
   * Sorts {@code batches} oldest first in the order in which this class first saw them, which it
   * records. Their modification times follow the wall clock and change at upload, so a clock set
   * back would let new batches take the reserve. Batches first seen together, as when this order
   * was introduced, keep the order of their modification times.
   */
  private static void sortByAdmissionOrder(Context context, File[] batches) {
    SharedPreferences preferences =
        context.getSharedPreferences(ADMISSION_ORDER_PREFS, Context.MODE_PRIVATE);
    Map<String, ?> recorded = preferences.getAll();
    long next =
        1
            + recorded.values().stream()
                .filter(Long.class::isInstance)
                .mapToLong(Long.class::cast)
                .max()
                .orElse(0);
    Arrays.sort(batches, Comparator.comparingLong(File::lastModified));
    Map<String, Long> order = new HashMap<>();
    for (File batch : batches) {
      String name = nameWithoutSuffix(batch);
      if (!order.containsKey(name)) {
        order.put(name, recorded.get(name) instanceof Long number ? number : next++);
      }
    }
    if (!order.equals(recorded)) {
      SharedPreferences.Editor editor = preferences.edit().clear();
      order.forEach(editor::putLong);
      editor.apply();
    }
    Arrays.sort(batches, Comparator.comparingLong(batch -> order.get(nameWithoutSuffix(batch))));
  }

  /** Returns the name of {@code batch} without the suffix that its upload changes. */
  private static String nameWithoutSuffix(File batch) {
    String name = batch.getName();
    for (String suffix : UPLOAD_STATE_SUFFIXES) {
      if (name.endsWith(suffix)) {
        return name.substring(0, name.length() - suffix.length());
      }
    }
    return name;
  }

  private static long getNonReclaimableBytes(File[] oldestFirst, long capBytes) {
    long reservedBytes = capBytes * CrumblesConstants.LOGS_DIRECTORY_RESERVED_PERCENT / 100;
    long nonReclaimableBytes = 0;
    long olderBytes = 0;
    for (File batch : oldestFirst) {
      long batchBytes = batch.length();
      olderBytes += batchBytes;
      boolean withinReserve = olderBytes <= reservedBytes;
      if (withinReserve || !batch.getName().endsWith(CrumblesConstants.SENT_SUFFIX)) {
        nonReclaimableBytes += batchBytes;
      }
    }
    return nonReclaimableBytes;
  }

  private static void warnIfApproachingCap(
      Context context, long nonReclaimableBytes, long capBytes, String prefApproaching) {
    SharedPreferences prefs =
        context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    if (nonReclaimableBytes < capBytes * CrumblesConstants.LOGS_DIRECTORY_WARN_PERCENT / 100) {
      prefs.edit().putBoolean(prefApproaching, false).apply();
      return;
    }
    if (!prefs.getBoolean(prefApproaching, false)) {
      prefs.edit().putBoolean(prefApproaching, true).apply();
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_STORAGE_CAP_APPROACHING",
              "Stored log batches use "
                  + nonReclaimableBytes
                  + " of "
                  + capBytes
                  + " permitted bytes.");
      notifyUser(context, R.string.notification_text_storage_approaching);
    }
  }

  private static long reclaimUploadedCopies(
      Context context, File[] oldestFirst, long usedBytes, long capBytes, long targetBytes) {
    long reservedBytes = capBytes * CrumblesConstants.LOGS_DIRECTORY_RESERVED_PERCENT / 100;
    long olderBytes = 0;
    long freedBytes = 0;
    List<String> reclaimed = new ArrayList<>();
    List<String> unverified = new ArrayList<>();
    for (File batch : oldestFirst) {
      if (usedBytes < targetBytes) {
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
        freedBytes += batchBytes;
        reclaimed.add(batch.getName());
        if (CrumblesDeleteSentFilesWorker.isUnverifiedSafCopy(context, batch.getName())) {
          unverified.add(batch.getName());
        }
      } else {
        Log.e(TAG, "Failed to reclaim the uploaded copy " + batch.getName());
      }
    }
    if (!reclaimed.isEmpty()) {
      String msg =
          "Reclaimed " + reclaimed.size() + " uploaded copy(ies) (" + freedBytes + " bytes): ";
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent("LOGS_STORAGE_CAP_REACHED", msg + String.join(", ", reclaimed) + ".");
    }
    if (!unverified.isEmpty()) {
      // The folder may have lost these copies since their upload, taking their logs with them.
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              CrumblesDeviceAdminReceiver.AUDIT_EVENT_LOGS_LOST,
              "Reclaimed "
                  + unverified.size()
                  + " uploaded copy(ies) that no re-check found at the destination: "
                  + String.join(", ", unverified)
                  + ".");
    }
    return usedBytes;
  }

  private static void reportCapReached(
      Context context,
      File[] batches,
      long nonReclaimableBytes,
      long capBytes,
      long effectiveCapBytes,
      String prefReached,
      boolean isNetworkBatch) {
    SharedPreferences prefs =
        context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    if (prefs.getBoolean(prefReached, false)) {
      return;
    }
    prefs.edit().putBoolean(prefReached, true).apply();
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
    Log.w(TAG, "Storage cap reached; new batches are dropped.");
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            isNetworkBatch ? "NETWORK_LOGS_COLLECTION_STOPPED" : "LOGS_COLLECTION_STOPPED",
            "Log batches use "
                + nonReclaimableBytes
                + " of "
                + effectiveCapBytes
                + " permitted bytes."
                + burst);
    notifyUser(context, R.string.notification_text_storage_stopped);
  }

  // Suppress "MissingPermission" because the platform drops, rather than rejects, notifications
  // posted without POST_NOTIFICATIONS, and "PendingIntentMutability" because FLAG_IMMUTABLE is set.
  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  static void notifyUser(Context context, @StringRes int contentTextId) {
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
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .build();
    manager.notify(CrumblesConstants.STORAGE_NOTIFICATION_ID, notification);
  }
}
