/*
 * Copyright 2025 Google LLC
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
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.ProtoSerializer;
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler;
import androidx.datastore.guava.GuavaDataStore;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Manages the process-wide singleton {@link GuavaDataStore} instance for Crumbles key preferences.
 *
 * <p>Jetpack DataStore strictly enforces at most one active DataStore instance per file per process
 * to avoid file locking collisions. This holder ensures a single shared instance is used across
 * Activities, Receivers, and Workers.
 *
 * <p>A store that cannot be parsed is replaced by an empty one, which drops every configured
 * recipient key. Because corruption is also what tampering looks like, the replacement is never
 * silent: the unreadable file is preserved, the event is recorded in the audit trail and the user
 * is notified, all before the empty preferences are returned to the caller.
 */
public final class CrumblesDataStoreHolder {

  public static final String DATA_STORE_FILE_NAME = "user_key_prefs.pb";

  /** Audit event type recorded when the key preferences store cannot be read. */
  @VisibleForTesting
  static final String AUDIT_EVENT_PREFERENCES_UNREADABLE = "KEY_PREFERENCES_UNREADABLE";

  /** Suffix of the single slot in which an unreadable store is preserved. */
  @VisibleForTesting static final String CORRUPT_FILE_SUFFIX = ".corrupt";

  // Notification ids 2001 (upload), 2002 (deferred retrieval) and 2003 (storage) are taken.
  @VisibleForTesting static final int PREFERENCES_UNREADABLE_NOTIFICATION_ID = 2004;

  private static final String TAG = "CrumblesDataStoreHolder";
  private static final String DATA_STORE_DIR = "datastore";

  // Suppress "NonFinalStaticField" because the GuavaDataStore instance must be lazily
  // initialized with the Android Application Context to maintain a process-wide singleton.
  @SuppressWarnings("NonFinalStaticField")
  private static GuavaDataStore<UserKeyPreferences> instance;

  private CrumblesDataStoreHolder() {}

  /**
   * Returns the process-wide singleton {@link GuavaDataStore} instance.
   *
   * @param context the Android application or component context
   * @return the shared {@link GuavaDataStore} instance
   */
  public static synchronized GuavaDataStore<UserKeyPreferences> getInstance(Context context) {
    if (instance == null) {
      Context appContext = context.getApplicationContext();
      File dataStoreFile =
          new File(
              appContext.getFilesDir(), DATA_STORE_DIR + File.separator + DATA_STORE_FILE_NAME);
      instance = createDataStore(dataStoreFile, appContext);
    }
    return instance;
  }

  /**
   * Creates a {@link GuavaDataStore} backed by the specified file, reporting corruption to the
   * logcat only.
   *
   * @param file the backing Protobuf file
   * @return a configured {@link GuavaDataStore} instance
   */
  public static GuavaDataStore<UserKeyPreferences> createDataStore(File file) {
    return createDataStore(file, /* context= */ null);
  }

  /**
   * Creates a {@link GuavaDataStore} backed by the specified file.
   *
   * @param file the backing Protobuf file
   * @param context the context used to record and surface corruption, or null to only log it
   * @return a configured {@link GuavaDataStore} instance
   */
  public static GuavaDataStore<UserKeyPreferences> createDataStore(
      File file, @Nullable Context context) {
    return new GuavaDataStore.Builder<UserKeyPreferences>(
            new ProtoSerializer<>(
                UserKeyPreferences.getDefaultInstance(),
                ExtensionRegistryLite.getGeneratedRegistry()),
            () -> file)
        .setCorruptionHandler(
            new ReplaceFileCorruptionHandler<>(
                (CorruptionException e) -> reportUnreadableStore(file, context, e)))
        .build();
  }

  /**
   * Preserves and reports an unreadable store, and returns the empty preferences replacing it.
   *
   * <p>DataStore runs this before completing the read that hit the corruption, so callers cannot
   * act on the empty preferences before the user has been told about them.
   */
  private static UserKeyPreferences reportUnreadableStore(
      File file, @Nullable Context context, CorruptionException exception) {
    Log.e(TAG, "Key preferences store is unreadable; replacing it with an empty one.", exception);
    preserveUnreadableFile(file);
    if (context == null) {
      return UserKeyPreferences.getDefaultInstance();
    }
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_PREFERENCES_UNREADABLE,
            "Key preferences store could not be read and was replaced by an empty one. Any"
                + " configured recipient key is gone. The unreadable file was kept as "
                + file.getName()
                + CORRUPT_FILE_SUFFIX
                + ".");
    notifyPreferencesUnreadable(context);
    return UserKeyPreferences.getDefaultInstance();
  }

  /**
   * Copies the unreadable store aside so that the replacement write does not discard it.
   *
   * <p>An unreadable store is potential evidence of tampering, so it is kept instead of being
   * dropped. A single slot is reused and overwritten by each new corruption, which caps the extra
   * space at one copy of the store.
   *
   * <p>The file is copied rather than renamed so that {@link GuavaDataStore} remains the sole
   * writer of {@code file}: after the corruption handler returns, DataStore acquires its write
   * lock, re-reads {@code file} to confirm it is still corrupt, and atomically replaces it via a
   * temporary file.
   */
  private static synchronized void preserveUnreadableFile(File file) {
    File preservedFile = new File(file.getAbsolutePath() + CORRUPT_FILE_SUFFIX);
    try {
      Files.copy(file.toPath(), preservedFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      Log.e(TAG, "Failed to preserve the unreadable key preferences store.", e);
    }
  }

  // Suppress "MissingPermission" and "PendingIntentMutability" because a missing notification
  // permission is handled at runtime and PendingIntent.FLAG_IMMUTABLE is explicitly supplied.
  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private static void notifyPreferencesUnreadable(Context context) {
    NotificationChannel channel =
        new NotificationChannel(
            CrumblesConstants.DATA_INTEGRITY_NOTIFICATION_CHANNEL_ID,
            context.getString(R.string.notification_channel_name_data_integrity),
            NotificationManager.IMPORTANCE_HIGH);
    channel.setDescription(
        context.getString(R.string.notification_channel_description_data_integrity));
    // Keep the content off the lock screen: revealing that the device collects security logs
    // endangers at-risk users.
    channel.setLockscreenVisibility(Notification.VISIBILITY_SECRET);
    NotificationManagerCompat.from(context).createNotificationChannel(channel);

    Intent openIntent = new Intent(context, CrumblesMain.class);
    openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    PendingIntent pendingIntent =
        PendingIntent.getActivity(
            context,
            /* requestCode= */ 0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

    Notification notification =
        new NotificationCompat.Builder(
                context, CrumblesConstants.DATA_INTEGRITY_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(context.getString(R.string.notification_title_data_integrity))
            .setContentText(context.getString(R.string.notification_text_data_integrity))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build();

    try {
      NotificationManagerCompat.from(context)
          .notify(PREFERENCES_UNREADABLE_NOTIFICATION_ID, notification);
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted, skipping notification.", e);
    }
  }
}
