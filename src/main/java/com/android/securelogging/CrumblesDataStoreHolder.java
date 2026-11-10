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

import static com.google.common.util.concurrent.MoreExecutors.directExecutor;

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
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler;
import androidx.datastore.guava.GuavaDataStore;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.common.base.Throwables;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.ProviderException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages the process-wide singleton {@link GuavaDataStore} instance for Crumbles key preferences.
 *
 * <p>Jetpack DataStore strictly enforces at most one active DataStore instance per file per process
 * to avoid file locking collisions. This holder ensures a single shared instance is used across
 * Activities, Receivers, and Workers.
 *
 * <p>A store that cannot be parsed, or that fails its HMAC check (see {@link
 * CrumblesPreferencesSerializer}), is replaced by {@link #UNREADABLE_STORE_REPLACEMENT}, which
 * drops every configured recipient key while keeping a sentinel {@code active_key_id} so callers
 * fail closed (staging logs rather than falling back to the on-device Keystore key) until the user
 * explicitly chooses an encryption key. Because corruption is also what tampering looks like, the
 * replacement is never silent: the unreadable file is preserved, the event is recorded in the audit
 * trail and the user is notified, all before the replacement preferences are returned to the
 * caller. A store deleted after its first write is replaced, recorded and notified the same way.
 */
public final class CrumblesDataStoreHolder {

  public static final String DATA_STORE_FILE_NAME = "user_key_prefs.pb";

  /**
   * Sentinel {@code active_key_id} set when the key preferences store is unreadable or deleted, so
   * that {@link CrumblesExternalPublicKeyManager#isExternalKeySelected} returns {@code true} and
   * {@link CrumblesExternalPublicKeyManager#getActiveExternalPublicKey} returns {@code null}
   * (failing closed into staged logs) until the user explicitly chooses an encryption key.
   */
  static final String UNREADABLE_STORE_ACTIVE_KEY_ID = "__corrupted_or_deleted__";

  static final UserKeyPreferences UNREADABLE_STORE_REPLACEMENT =
      UserKeyPreferences.newBuilder().setActiveKeyId(UNREADABLE_STORE_ACTIVE_KEY_ID).build();

  /** Audit event type recorded when the key preferences store cannot be read. */
  @VisibleForTesting
  static final String AUDIT_EVENT_PREFERENCES_UNREADABLE = "KEY_PREFERENCES_UNREADABLE";

  /** Audit event type recorded when the key preferences store fails its HMAC check. */
  @VisibleForTesting
  static final String AUDIT_EVENT_PREFERENCES_ALTERED = "KEY_PREFERENCES_ALTERED";

  /** Suffix of the single slot in which an unreadable store is preserved. */
  @VisibleForTesting static final String CORRUPT_FILE_SUFFIX = ".corrupt";

  private static final String TAG = "CrumblesDataStoreHolder";
  private static final String DATA_STORE_DIR = "datastore";

  // Suppress "NonFinalStaticField" because the GuavaDataStore instance must be lazily
  // initialized with the Android Application Context to maintain a process-wide singleton.
  @SuppressWarnings("NonFinalStaticField")
  private static GuavaDataStore<UserKeyPreferences> instance;

  private static final AtomicBoolean firstMacWriteInFlight = new AtomicBoolean();

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
      @SuppressWarnings("unused")
      ListenableFuture<UserKeyPreferences> unused = initializeDataStore(instance);
    }
    return instance;
  }

  /**
   * Queues an initial write on {@code dataStore} that creates the HMAC key and populates {@code
   * store_mac} on any pre-update store before subsequent reads or writes run.
   *
   * <p>Because {@link CrumblesPreferencesSerializer#withMac} creates the HMAC key inside the
   * transform before {@link CrumblesPreferencesSerializer#writeTo} runs, a failure of that initial
   * write deletes a newly created key so the next startup does not mistake a missing or unmigrated
   * store for tampering.
   */
  static ListenableFuture<UserKeyPreferences> initializeDataStore(
      GuavaDataStore<UserKeyPreferences> dataStore) {
    AtomicBoolean createdMacKey = new AtomicBoolean(false);
    ListenableFuture<UserKeyPreferences> writeFuture =
        dataStore.updateDataAsync(
            preferences -> {
              if (!createdMacKey.get() && !macKeyExistsBeforeInit()) {
                createdMacKey.set(true);
              }
              // Set before withMac creates the key, so that no reader sees the key without it.
              if (createdMacKey.get()) {
                firstMacWriteInFlight.set(true);
              }
              return CrumblesPreferencesSerializer.withMac(preferences);
            });
    return Futures.whenAllComplete(writeFuture)
        .callAsync(
            () -> {
              try {
                Futures.getDone(writeFuture);
              } catch (ExecutionException | CancellationException e) {
                if (createdMacKey.get()) {
                  deleteNewlyCreatedMacKey();
                }
                Log.e(TAG, "Initial preferences write failed", e);
              }
              // Only after any rollback, and before callers see the outcome.
              firstMacWriteInFlight.set(false);
              return writeFuture;
            },
            directExecutor());
  }

  /**
   * Returns whether the initial write that creates the HMAC key is in flight: readers that do not
   * wait for it can then see the key before the store has been written with it.
   */
  static boolean isFirstMacWriteInFlight() {
    return firstMacWriteInFlight.get();
  }

  private static boolean macKeyExistsBeforeInit() {
    try {
      return CrumblesPreferencesSerializer.macKeyExists();
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      return true;
    }
  }

  private static void deleteNewlyCreatedMacKey() {
    try {
      CrumblesPreferencesSerializer.deleteMacKey();
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      Log.w(TAG, "Failed to delete newly created preferences MAC key after init failure", e);
    }
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
    return createDataStore(file, context, new CrumblesPreferencesSerializer(file, context));
  }

  @VisibleForTesting
  static GuavaDataStore<UserKeyPreferences> createDataStore(
      File file, @Nullable Context context, CrumblesPreferencesSerializer serializer) {
    return new GuavaDataStore.Builder<>(serializer, () -> file)
        .setCorruptionHandler(
            new ReplaceFileCorruptionHandler<>(
                (CorruptionException e) -> reportUnreadableStore(file, context, e)))
        .build();
  }

  /**
   * Reports a store that is missing although its HMAC key exists, which means the store was written
   * and then deleted.
   *
   * <p>DataStore reads a missing file as empty preferences without calling the serializer, so the
   * HMAC check cannot catch the deletion. Like an altered store, it drops every configured
   * recipient key, so it is reported the same way before any read returns the empty preferences.
   */
  static void reportDeletedStore(File file, Context context) {
    Log.e(TAG, "Key preferences store is missing although its HMAC key exists.");
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_PREFERENCES_ALTERED,
            "Key preferences store "
                + file.getName()
                + " was deleted after it had been written and was replaced by an empty one. Any"
                + " configured recipient key is gone.");
    notifyPreferencesUnreadable(context);
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
      return UNREADABLE_STORE_REPLACEMENT;
    }
    // Coroutines can rethrow a copy of the exception with the original as its cause, so the whole
    // causal chain is searched.
    boolean altered =
        Throwables.getCausalChain(exception).stream()
            .anyMatch(
                cause ->
                    cause instanceof CrumblesPreferencesSerializer.IntegrityCheckFailedException);
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            altered ? AUDIT_EVENT_PREFERENCES_ALTERED : AUDIT_EVENT_PREFERENCES_UNREADABLE,
            "Key preferences store "
                + (altered ? "failed its integrity check" : "could not be read")
                + " and was replaced by an empty one. Any configured recipient key is gone. The"
                + " unreadable file was kept as "
                + file.getName()
                + CORRUPT_FILE_SUFFIX
                + ".");
    notifyPreferencesUnreadable(context);
    return UNREADABLE_STORE_REPLACEMENT;
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
          .notify(CrumblesConstants.PREFERENCES_UNREADABLE_NOTIFICATION_ID, notification);
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted, skipping notification.", e);
    }
  }
}
