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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.util.stream.Collectors.joining;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.admin.ConnectEvent;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.app.admin.DnsEvent;
import android.app.admin.NetworkEvent;
import android.app.admin.SecurityLog;
import android.app.admin.SecurityLog.SecurityEvent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.PersistableBundle;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.work.WorkManager;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesAuditExcerpt;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.common.util.concurrent.Futures;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.KeyEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.InstantSource;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.TimeZone;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Device admin receiver for Crumbles.
 *
 * <p>Receives security and network logs from Crumbles.
 *
 * <p>When Crumbles is only a logging delegate, the user can still activate it as a device admin, so
 * that Android blocks clearing its storage, force stopping it and uninstalling it.
 */
public class CrumblesDeviceAdminReceiver extends DeviceAdminReceiver {
  private static final String TAG = "[CrumblesDeviceAdminReceiver]";

  /** Minimum usable storage for security logs: 64 MiB max batch plus 16 MiB staging cap. */
  static final long MIN_SECURITY_USABLE_SPACE_BYTES = 80L * 1024 * 1024;

  /** Minimum usable storage for network logs: 4 MiB batch headroom plus 16 MiB staging cap. */
  @VisibleForTesting static final long MIN_NETWORK_USABLE_SPACE_BYTES = 20L * 1024 * 1024;
  @VisibleForTesting static final String DEFERRED_TOKENS_FILE = "deferred_network_tokens.bin";
  private static final int MAX_DEFERRED_NETWORK_TOKENS = 32;
  private static final int DEFERRED_TOKENS_FILE_BYTES =
      Long.BYTES + Integer.BYTES + MAX_DEFERRED_NETWORK_TOKENS * Long.BYTES;

  /** Audit event type recorded when a batch is written unsigned and unnumbered. */
  static final String AUDIT_EVENT_BATCH_SIGNING_FAILED = "BATCH_SIGNING_FAILED";

  /** Audit event type recorded when Crumbles is deactivated as a device admin. */
  @VisibleForTesting
  static final String AUDIT_EVENT_DEVICE_ADMIN_DISABLED = "DEVICE_ADMIN_DISABLED";

  /** Audit event type recorded when the selected external key cannot be read. */
  @VisibleForTesting
  static final String AUDIT_EVENT_EXTERNAL_KEY_UNAVAILABLE = "EXTERNAL_KEY_UNAVAILABLE";

  /** Audit event type recorded when the final batch cannot be sealed. */
  @VisibleForTesting static final String AUDIT_EVENT_FINAL_BATCH_FAILED = "FINAL_BATCH_FAILED";

  /** Audit event type recorded when unshipped activity records cannot be sealed before a clear. */
  public static final String AUDIT_EVENT_CLEAR_SEAL_FAILED = "AUDIT_LOG_CLEAR_SEAL_FAILED";

  static final String AUDIT_EVENT_COLLECTION_PAUSED = "COLLECTION_PAUSED_SECONDARY_USER";
  static final String AUDIT_EVENT_COLLECTION_RESUMED = "COLLECTION_RESUMED_SINGLE_USER";
  static final String AUDIT_EVENT_PAUSE_BATCH_FAILED = "PAUSE_BATCH_FAILED";
  static final String PREF_MANAGED_DISALLOW_ADD_USER = "managedDisallowAddUser";
  static final String PREF_PAUSED_BY_SECONDARY_USER = "pausedBySecondaryUser";
  static final String PREF_SECURITY_LOGGING_ENABLE_EPOCH = "securityLoggingEnableEpoch";
  static final String PREF_NETWORK_LOGGING_ENABLE_EPOCH = "networkLoggingEnableEpoch";
  private static final String PREF_SECURITY_ID_SESSION = "securityIdSession";
  private static final String PREF_LAST_SECURITY_ID = "lastSecurityId";
  private static final String PREF_NETWORK_TOKEN_SESSION = "networkTokenSession";
  private static final String PREF_LAST_NETWORK_TOKEN = "lastNetworkToken";

  /** The value of {@code UserManager.DISALLOW_ADD_CLONE_PROFILE}, which the SDK hides. */
  private static final String DISALLOW_ADD_CLONE_PROFILE = "no_add_clone_profile";

  /** Device-encrypted preferences recording pre-unlock events across restarts. */
  private static final String BOOT_RECORD_PREFS_NAME = "crumbles_boot_record";

  /**
   * Device-encrypted preference recording that {@link Intent#ACTION_TIME_CHANGED} arrived before
   * the first unlock after a restart while credential-encrypted storage and {@link WorkManager}
   * were locked.
   */
  private static final String PREF_TIME_CHANGED_BEFORE_UNLOCK = "timeChangedBeforeUnlock";

  /** Directory under device-encrypted files holding batches collected before the first unlock. */
  private static final String DIRECT_BOOT_BATCHES_SUBDIRECTORY = "logs_before_unlock";

  /** The type of the security logs kept from before a restart, in log and audit messages. */
  private static final String PRE_REBOOT_SECURITY_LOG_TYPE = "Pre-reboot security";

  /** Opens a batch of security logs kept from before a restart, for whoever reads the batches. */
  private static final String PRE_REBOOT_LOGS_NOTICE =
      "Crumbles: security logs that the platform kept from before the device restarted. The"
          + " platform does not authenticate these records, so treat them as unverified. They can"
          + " repeat events of earlier batches.\n\n";

  /** Opens a batch of security logs collected before the first unlock after a restart. */
  private static final String BEFORE_UNLOCK_LOGS_NOTICE =
      "Crumbles: security logs collected before the first unlock after a restart. The batch was"
          + " signed after the unlock and holds no activity log records.\n\n";

  /** Reports that security logs were left with the platform before the unlock, for lack of room. */
  private static final String BEFORE_UNLOCK_NO_ROOM =
      "Security logs announced before the first unlock were left with the platform: the batches"
          + " kept before the unlock had reached their cap, or usable space was low. They were lost"
          + " if the device restarted again before the unlock.";

  /** Reports a boot count that did not grow across a restart. */
  private static final String BOOT_COUNT_DID_NOT_GROW =
      "The boot count did not grow across a restart, as when it is lowered through adb, which can"
          + " hide a restart whose security logs were lost.";

  /** Audit event type recorded when the Keystore permanently invalidated the device key pair. */
  @VisibleForTesting static final String AUDIT_EVENT_KEY_INVALIDATED = "KEYSTORE_KEY_INVALIDATED";

  /** Preference holding the public key hash of the last reported invalidated device key pair. */
  private static final String PREF_REPORTED_INVALIDATED_KEY = "reportedInvalidatedKeyHash";

  /**
   * The fingerprint of the internal key last found recorded, so that each key is checked once per
   * process.
   */
  @Nullable private static volatile String confirmedInternalKeyFingerprint;

  /** Audit event type recorded when logs handed over by the platform cannot be saved. */
  static final String AUDIT_EVENT_LOGS_LOST = "LOGS_LOST";

  /** Audit event type recorded when logs are staged until they can be encrypted and saved. */
  @VisibleForTesting static final String AUDIT_EVENT_LOGS_STAGED = "LOGS_STAGED";

  /** Audit event type recorded when the user dismisses an alert whose problem lasts. */
  @VisibleForTesting static final String AUDIT_EVENT_ALERT_DISMISSED = "ALERT_DISMISSED";

  /** Prefix of the preferences that mark the "action needed" alerts not cancelled as solved. */
  private static final String PREF_ACTIVE_ALERT_PREFIX = "activeAlert";

  private static final Object PAUSE_LOCK = new Object();
  private static final Object DEFERRED_TOKENS_LOCK = new Object();

  /**
   * The deferred tokens that saving could not write, led by their session key, or null if the file
   * holds the queue. It holds an empty queue only to hide a stale file that could not be deleted.
   */
  private static final AtomicReference<ImmutableList<Long>> fallbackDeferredTokens =
      new AtomicReference<>();

  /** Whether saves must leave the token file alone: it is unreadable and could not be moved. */
  private static final AtomicBoolean leaveDeferredTokensFile = new AtomicBoolean();

  /** Runs log retrievals one at a time, off the main thread. */
  private static final Executor retrievalExecutor = Executors.newSingleThreadExecutor();

  /** Random bytes in a batch file name: 128 bits, so that names never collide in practice. */
  private static final int BATCH_FILE_NAME_RANDOM_BYTES = 16;

  private static final SecureRandom secureRandom = new SecureRandom();

  private DevicePolicyManager dpm;
  private ComponentName adminComponentName;

  @Override
  public void onEnabled(Context context, Intent intent) {
    Log.i(TAG, "onEnabled");
  }

  /** Returns the warning that Android shows before the user deactivates Crumbles as an admin. */
  @Override
  public CharSequence onDisableRequested(@NonNull Context context, @NonNull Intent intent) {
    return context.getString(R.string.device_admin_disable_warning);
  }

  /**
   * Records that Crumbles is no longer a device admin, then seals the record into a batch and asks
   * for the pending batches to be uploaded right away, since anyone holding the device can now
   * clear the storage of Crumbles or uninstall it.
   *
   * <p>Android keeps Crumbles an active admin until this broadcast finishes, so the batch is
   * written before either is allowed.
   */
  @Override
  public void onDisabled(@NonNull Context context, @NonNull Intent intent) {
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_DEVICE_ADMIN_DISABLED,
            "Deactivated as a device admin: clearing storage, force stopping and uninstalling are"
                + " no longer blocked.");
    retrieveInBackground(goAsync(), () -> sealActivityLogAndUpload(context));
  }

  /**
   * Seals the activity log records not shipped yet into an empty batch, then asks for the pending
   * batches to be uploaded right away. Without an encryption key, the records wait for the next
   * batch and the batches already pending are uploaded all the same.
   */
  private static void sealActivityLogAndUpload(Context context) {
    CrumblesLogStaging staging = new CrumblesLogStaging(context);
    // Read before the key, so that a key change in between keeps the recipient forgotten.
    long forgottenRecipients = CrumblesDirectBootStore.forgottenRecipients();
    Optional<PublicKey> activeKey = resolveActiveEncryptionKey(context);
    boolean saved = false;
    if (activeKey.isPresent()) {
      saved =
          drainStagedBatches(context, activeKey.get())
              && saveActivityLogBatch(context, activeKey.get(), forgottenRecipients);
    }
    if (!saved) {
      Log.w(TAG, "Failed to seal the activity log into a batch.");
      try {
        var unused = staging.stage(/* isNetworkBatch= */ false, new byte[0]);
      } catch (GeneralSecurityException | IOException e) {
        Log.e(TAG, "Failed to stage empty batch on admin disable.", e);
      }
    }
    CrumblesWorkScheduler.requestImmediateUpload(WorkManager.getInstance(context));
  }

  private static boolean saveActivityLogBatch(
      Context context, PublicKey activeKey, long forgottenRecipients) {
    File baseDir = getLogsDirectory(context);
    baseDir.mkdirs();
    try {
      return writeEncryptedBatch(
              context,
              baseDir,
              new byte[0],
              activeKey,
              /* isNetworkBatch= */ null,
              forgottenRecipients)
          .isPresent();
    } catch (CrumblesLogsEncryptionException | QuotaRefusedException e) {
      Log.e(TAG, "Failed to encrypt or write logs.", e);
      return false;
    }
  }

  @Override
  public void onProfileProvisioningComplete(@NonNull Context context, @NonNull Intent intent) {
    Log.i(TAG, "Profile provisioning complete.");
    initDpm(context);

    if (!dpm.isDeviceOwnerApp(context.getPackageName())) {
      Log.w(TAG, "Not device owner, skipping automatic logging enablement.");
      return;
    }

    PersistableBundle adminExtras =
        intent.getParcelableExtra(
            DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, PersistableBundle.class);
    boolean enableLogging = false;
    if (adminExtras != null) {
      enableLogging = adminExtras.getBoolean("enable_logging", /* defaultValue= */ false);
    }
    Log.i(TAG, "Provisioning admin extras enable_logging flag: " + enableLogging);

    if (!enableLogging) {
      Log.i(TAG, "Logging not enabled during provisioning (enable_logging was false or missing).");
      return;
    }

    try {
      dpm.setSecurityLoggingEnabled(adminComponentName, /* enabled= */ true);
      Log.i(TAG, "Security logging automatically enabled post-provisioning.");
    } catch (SecurityException e) {
      Log.e(TAG, "Failed to enable security logging post-provisioning.", e);
    }

    boolean enableNetworkLogging = CrumblesCollectionScope.isNetworkCollectionEnabled(context);
    try {
      dpm.setNetworkLoggingEnabled(adminComponentName, enableNetworkLogging);
      context
          .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
          .edit()
          .putBoolean(CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED, true)
          .putBoolean(
              CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED, enableNetworkLogging)
          .apply();
      Log.i(
          TAG,
          enableNetworkLogging
              ? "Network logging automatically enabled post-provisioning."
              : "Network collection turned off by the user; network logging disabled.");
    } catch (SecurityException e) {
      Log.e(TAG, "Failed to set network logging post-provisioning.", e);
    }
    CrumblesLoggingWatchdogWorker.recordLoggingTurnedOn(context);
    bumpLoggingEnableEpoch(context);
    syncDisallowAddUserRestriction(context, /* enabled= */ true);

    try {
      Context appContext = context.getApplicationContext();
      CrumblesWorkScheduler.scheduleAllPeriodicWork(
          appContext, WorkManager.getInstance(appContext));
      Log.i(TAG, "Periodic work automatically scheduled post-provisioning.");
    } catch (RuntimeException e) {
      Log.e(TAG, "Failed to schedule periodic work post-provisioning.", e);
    }
  }

  private void initDpm(Context context) {
    this.dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
    if (this.dpm == null) {
      throw new IllegalStateException("Unable to get DevicePolicyManager");
    }
    this.adminComponentName =
        new ComponentName(context.getApplicationContext(), CrumblesDeviceAdminReceiver.class);
  }

  static Optional<PublicKey> resolveActiveEncryptionKey(Context context) {
    CrumblesExternalPublicKeyManager keyManager =
        CrumblesExternalPublicKeyManager.getInstance(context);
    PublicKey externalKey = keyManager.getActiveExternalPublicKey();
    if (externalKey != null) {
      return Optional.of(externalKey);
    }
    if (keyManager.isExternalKeySelected()) {
      // Fail closed: encrypting to any other key would make the logs readable by someone other than
      // the recipient the user chose. The logs are staged, sealed to this device, meanwhile.
      Log.e(TAG, "Selected external key is unreadable; not falling back to another key.");
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              AUDIT_EVENT_EXTERNAL_KEY_UNAVAILABLE,
              "Selected external encryption key could not be read; logs were not encrypted to any"
                  + " other key.");
      return Optional.empty();
    }
    return getValidDevicePublicKey(context);
  }

  /**
   * Returns whether the device key pair is missing or permanently invalidated, recording and
   * alerting the user once per key pair when a previously generated device key pair is gone.
   */
  static boolean reportIfDeviceKeyInvalidated(Context context) {
    return getValidDevicePublicKey(context).isEmpty();
  }

  private static Optional<PublicKey> getValidDevicePublicKey(Context context) {
    CrumblesLogsEncryptor encryptor = CrumblesMain.getLogsEncryptorInstance();
    if (!encryptor.doesPrivateKeyExist()) {
      try {
        reportInvalidatedKey(
            context,
            Futures.getChecked(
                    CrumblesDataStoreHolder.getInstance(context).getDataAsync(), Exception.class)
                .getInternalKeyFingerprint());
      } catch (Exception e) {
        Log.e(TAG, "Failed to read internal key fingerprint.", e);
      }
      return Optional.empty();
    }
    PublicKey currentKey = encryptor.getPublicKey();
    if (encryptor.isPrivateKeyPermanentlyInvalidated()) {
      try {
        reportInvalidatedKey(
            context, CrumblesLogsEncryptor.getPublicKeyFingerprint(currentKey));
      } catch (Exception e) {
        Log.e(TAG, "Failed to get fingerprint for invalidated key.", e);
      }
      return Optional.empty();
    }
    if (currentKey != null) {
      recordInternalKeyIfUnrecorded(context, currentKey);
    }
    return Optional.ofNullable(currentKey);
  }

  /**
   * Records {@code currentKey} as the internal key unless its fingerprint is stored already, as for
   * a key generated before fingerprints were recorded or whose recording failed, so that the loss
   * of that key is reported too.
   */
  private static void recordInternalKeyIfUnrecorded(Context context, PublicKey currentKey) {
    try {
      String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(currentKey);
      if (fingerprint.equals(confirmedInternalKeyFingerprint)) {
        return;
      }
      String recorded =
          Futures.getChecked(
                  CrumblesDataStoreHolder.getInstance(context).getDataAsync(), Exception.class)
              .getInternalKeyFingerprint();
      if (fingerprint.equals(recorded)) {
        confirmedInternalKeyFingerprint = fingerprint;
      } else {
        recordActivatedInternalKey(context, currentKey);
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to check the recorded internal key fingerprint.", e);
    }
  }

  /** Records and alerts once per key pair when the Keystore invalidated the device key pair. */
  static synchronized void reportInvalidatedKey(Context context, String fingerprint) {
    if (fingerprint.isEmpty()) {
      return;
    }
    SharedPreferences preferences =
        context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    if (fingerprint.equals(
        preferences.getString(PREF_REPORTED_INVALIDATED_KEY, /* defValue= */ null))) {
      return;
    }
    preferences.edit().putString(PREF_REPORTED_INVALIDATED_KEY, fingerprint).apply();
    CrumblesDirectBootStore.forgetRecipient(context);
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_KEY_INVALIDATED,
            "The Keystore permanently invalidated the device key pair, as when the screen lock is"
                + " removed. Logs are staged instead of encrypted to it until a new key pair is"
                + " generated. Fingerprint: " + fingerprint.replace('\n', ':'));
    notifyActionNeeded(
        context,
        CrumblesConstants.KEY_DELETED_NOTIFICATION_ID,
        "screen lock removed; built-in key and its batches are lost");
  }

  /**
   * Records {@code publicKey} as the active internal Keystore key pair and clears any key-deleted
   * notification from an earlier invalidated key pair.
   */
  static void recordActivatedInternalKey(Context context, PublicKey publicKey) {
    CrumblesDirectBootStore.forgetRecipient(context);
    try {
      String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(publicKey);
      Futures.getChecked(
          CrumblesDataStoreHolder.getInstance(context)
              .updateDataAsync(
                  prefs -> prefs.toBuilder().setInternalKeyFingerprint(fingerprint).build()),
          Exception.class);
    } catch (Exception e) {
      Log.e(TAG, "Failed to record internal key fingerprint.", e);
    }
    cancelKeyInvalidatedNotification(context);
  }

  /** Clears the stored internal Keystore key fingerprint when no internal key remains active. */
  static void clearActivatedInternalKey(Context context) {
    CrumblesDirectBootStore.forgetRecipient(context);
    confirmedInternalKeyFingerprint = null;
    try {
      Futures.getChecked(
          CrumblesDataStoreHolder.getInstance(context)
              .updateDataAsync(prefs -> prefs.toBuilder().clearInternalKeyFingerprint().build()),
          Exception.class);
    } catch (Exception e) {
      Log.e(TAG, "Failed to clear internal key fingerprint.", e);
    }
  }

  public static void cancelKeyInvalidatedNotification(Context context) {
    cancelActionNeeded(context, CrumblesConstants.KEY_DELETED_NOTIFICATION_ID);
  }

  private static boolean isReadyForLogging(Context context) {
    File baseDir = getLogsDirectory(context);
    return baseDir.exists() || baseDir.mkdirs();
  }

  private static File getLogsDirectory(Context context) {
    return new File(
        context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
  }

  private static void notifyActionNeeded(Context context) {
    notifyActionNeeded(
        context,
        CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID,
        context.getString(R.string.notification_text_action_needed));
  }

  private static void notifyActionNeeded(Context context, int notificationId, String text) {
    // Marked before it is posted, so that dismissing it at once still posts it again.
    prefs(context).edit().putBoolean(PREF_ACTIVE_ALERT_PREFIX + notificationId, true).apply();
    postOngoingAlert(
        context,
        notificationId,
        context.getString(R.string.notification_title_action_needed),
        text,
        /* cancelWhenOpened= */ false);
  }

  /**
   * Alerts the user that security logs may have been lost, until the user opens the alert. Unlike
   * the alert about deferred logs, saving a later batch does not withdraw it.
   */
  private static void notifyLossReported(Context context) {
    postOngoingAlert(
        context,
        CrumblesConstants.LOSS_REPORTED_NOTIFICATION_ID,
        context.getString(R.string.notification_title_data_missing),
        context.getString(R.string.notification_text_data_missing),
        /* cancelWhenOpened= */ true);
  }

  static void notifyCollectionPaused(Context context) {
    postOngoingAlert(
        context,
        CrumblesConstants.COLLECTION_PAUSED_NOTIFICATION_ID,
        context.getString(R.string.notification_title_sync_paused_other_user),
        context.getString(R.string.notification_text_sync_paused_other_user),
        /* cancelWhenOpened= */ false);
  }

  /**
   * Cancels the "action needed" alert {@code notificationId} because its problem is solved. Its
   * mark is cleared first, so that a dismissal of the alert still being delivered does not post it
   * again.
   */
  private static void cancelActionNeeded(Context context, int notificationId) {
    prefs(context).edit().remove(PREF_ACTIVE_ALERT_PREFIX + notificationId).apply();
    NotificationManagerCompat.from(context).cancel(notificationId);
  }

  /**
   * Posts alert {@code notificationId} again with {@code title} and {@code text} once it was
   * dismissed, and records the dismissal, unless the problem it reports is solved.
   */
  static void repostDismissedAlert(Context context, int notificationId, String title, String text) {
    if (!isAlertActive(context, notificationId)) {
      return;
    }
    postOngoingAlert(context, notificationId, title, text, /* cancelWhenOpened= */ false);
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_ALERT_DISMISSED,
            "Alert \""
                + title
                + "\" was dismissed while its problem lasted, so it was posted again: "
                + text);
  }

  /** Returns whether Crumbles has not cancelled alert {@code notificationId} as solved. */
  private static boolean isAlertActive(Context context, int notificationId) {
    // setSecondaryUserPaused ends a pause by clearing this preference before cancelling the alert.
    String preference =
        notificationId == CrumblesConstants.COLLECTION_PAUSED_NOTIFICATION_ID
            ? PREF_PAUSED_BY_SECONDARY_USER
            : PREF_ACTIVE_ALERT_PREFIX + notificationId;
    return prefs(context).getBoolean(preference, /* defValue= */ false);
  }

  // Suppress "MissingPermission" and "PendingIntentMutability" because notification permissions are
  // checked at runtime and PendingIntent.FLAG_IMMUTABLE is explicitly supplied.
  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private static void postOngoingAlert(
      Context context, int notificationId, String title, String text, boolean cancelWhenOpened) {
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
    NotificationManagerCompat.from(context).createNotificationChannel(channel);

    Intent openIntent = new Intent(context, CrumblesMain.class);
    openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    PendingIntent pendingIntent =
        PendingIntent.getActivity(
            context,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    // Android 14 lets the user swipe the alert away unless Crumbles is a device or profile owner.
    Intent dismissIntent =
        new Intent(context, CrumblesAlertDismissedReceiver.class)
            .putExtra(CrumblesAlertDismissedReceiver.EXTRA_NOTIFICATION_ID, notificationId)
            .putExtra(CrumblesAlertDismissedReceiver.EXTRA_TITLE, title)
            .putExtra(CrumblesAlertDismissedReceiver.EXTRA_TEXT, text);
    PendingIntent deleteIntent =
        PendingIntent.getBroadcast(
            context,
            /* requestCode= */ notificationId,
            dismissIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

    Notification notification =
        new NotificationCompat.Builder(
                context, CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(pendingIntent)
            // Stay up until the condition clears, or until the user opens a loss alert: a dismissed
            // alert would leave the user believing logs are still being collected.
            .setOngoing(true)
            .setAutoCancel(cancelWhenOpened)
            .setDeleteIntent(deleteIntent)
            .build();

    try {
      NotificationManagerCompat.from(context).notify(notificationId, notification);
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted, skipping notification.", e);
    }
  }

  static void cancelDeferredLogsNotification(Context context) {
    cancelActionNeeded(context, CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID);
  }

  static boolean hasUnuploadedBinFiles(Context context) {
    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    File[] files =
        directory.listFiles(
            (dir, name) ->
                name.endsWith(".bin") && !name.endsWith(CrumblesConstants.SENT_SUFFIX));
    return files != null && files.length > 0;
  }

  /**
   * Returns whether logs can be retrieved now, deferring their retrieval if storage is not ready or
   * usable space is below {@code minUsableBytes}.
   */
  // ...
  @SuppressLint("UsableSpace")
  private static boolean prepareLogRetrieval(
      Context context, String logType, long minUsableBytes) {
    Log.i(TAG, logType + " logs available.");
    if (!isReadyForLogging(context)) {
      Log.w(
          TAG,
          "Storage not ready; deferring " + logType.toLowerCase(Locale.US) + " log retrieval.");
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOG_RETRIEVAL_DEFERRED", logType + " log retrieval deferred: storage not ready.");
      notifyActionNeeded(context);
      return false;
    }
    long usableBytes = context.getFilesDir().getUsableSpace();
    if (usableBytes < minUsableBytes) {
      deferLowSpace(context, logType, usableBytes);
      return false;
    }
    synchronized (DEFERRED_TOKENS_LOCK) {
      // Write only tokens that a failed save kept in memory: otherwise nothing has changed.
      if (fallbackDeferredTokens.get() != null) {
        saveDeferredTokensLocked(context, loadDeferredTokensLocked(context));
      }
    }
    return true;
  }

  private static void deferLowSpace(Context context, String logType, long usableBytes) {
    String message =
        logType
            + " log retrieval deferred: insufficient usable storage ("
            + usableBytes
            + " bytes available).";
    CrumblesAppAuditLogger.getInstance(context).logEvent("LOG_RETRIEVAL_DEFERRED", message);
    notifyActionNeeded(context);
  }

  @Override
  public void onSecurityLogsAvailable(@NonNull Context context, @NonNull Intent intent) {
    retrieveInBackground(goAsync(), () -> retrieveAndSaveSecurityLogs(context));
  }

  /**
   * Runs {@code retrieval} on the retrieval thread, then finishes {@code pendingResult}.
   *
   * <p>Retrieving, encrypting and writing a full log buffer can take seconds. On the main thread
   * that freezes the app and can overrun the broadcast deadline, and the platform deletes the logs
   * it hands over, so a process killed mid-batch loses them. Holding the broadcast until the batch
   * is written keeps the process alive meanwhile.
   */
  static void retrieveInBackground(@Nullable PendingResult pendingResult, Runnable retrieval) {
    retrievalExecutor.execute(() -> {
      try {
        retrieval.run();
      } finally {
        if (pendingResult != null) {
          pendingResult.finish();
        }
      }
    });
  }

  /**
   * Retrieves, encrypts and saves the available security logs, as the device owner or as the
   * security logging delegate, after those that the platform kept from before the device restarted
   * unless this boot has handled them already.
   */
  static synchronized void retrieveAndSaveSecurityLogs(Context context) {
    if (!isUserUnlocked(context)) {
      collectSecurityLogsBeforeUnlock(context);
      return;
    }
    saveLogsCollectedBeforeUnlock(context);
    drainDeferredNetworkLogsIfPossible(context);
    CrumblesLoggingAccess access = CrumblesLoggingAccess.forSecurityLogging(context);
    // The logs kept from before the restart are older, so their batch goes first.
    savePreRebootLogs(context, access);
    if (!prepareLogRetrieval(context, "Security", MIN_SECURITY_USABLE_SPACE_BYTES)) {
      return;
    }
    if (!access.isAvailable()) {
      Log.w(TAG, "Neither device owner nor security logging delegate; skipping retrieval.");
      return;
    }
    DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
    List<SecurityEvent> securityLogs;
    try {
      securityLogs =
          retrieveLogsOrPause(
              context,
              () -> dpm.retrieveSecurityLogs(access.admin()),
              () -> CrumblesLoggingAccess.forSecurityLogging(context));
    } catch (SecurityException e) {
      Log.w(TAG, "SecurityException retrieving security logs.", e);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(AUDIT_EVENT_LOGS_LOST, "Security logs lost due to SecurityException.");
      notifyLossReported(context);
      return;
    }
    if (securityLogs == null) {
      Log.i(TAG, "Security logs are null.");
      return;
    }
    new CrumblesBootRecord(context).recordSecurityRetrieval(InstantSource.system().millis());
    saveRetrievedLogs(
        context,
        "Security",
        securityLogs.size(),
        logsToBytes(getSerializableSecurityLogs(securityLogs)));
    recordSecurityEventIds(context, securityLogs);
  }

  /**
   * Saves the security logs that the platform kept from before the device restarted, unless this
   * boot has handled them, Crumbles has no access, or usable space is below {@link
   * #MIN_NETWORK_USABLE_SPACE_BYTES}. Those logs are small, so they do not wait for the space that
   * the live buffer needs.
   */
  private static void savePreRebootLogs(Context context, CrumblesLoggingAccess access) {
    if (access.isAvailable()
        && !arePreRebootLogsHandledThisBoot(context)
        && prepareLogRetrieval(
            context, PRE_REBOOT_SECURITY_LOG_TYPE, MIN_NETWORK_USABLE_SPACE_BYTES)) {
      retrieveAndSavePreRebootLogs(
          context, context.getSystemService(DevicePolicyManager.class), access);
    }
  }

  /**
   * Saves the security logs kept from before the restart if security logging is on and this boot
   * has not handled them yet, as after a refusal while another user was present, so that they are
   * not left until the next platform notification, which can come after the next restart.
   */
  static synchronized void savePreRebootLogsIfPending(Context context) {
    CrumblesLoggingAccess access = CrumblesLoggingAccess.forSecurityLogging(context);
    if (isSecurityLoggingEnabled(context, access)) {
      new CrumblesBootRecord(context).recordSecurityLoggingOn();
      savePreRebootLogs(context, access);
    }
  }

  /**
   * Catches up once the device has booted and the user has unlocked it: schedules the periodic work
   * if Crumbles needs it, which also repairs schedules made at a clock set forward, records the
   * restart, saves the security logs that the platform kept from before the restart and those that
   * it announced before the unlock, which this receiver could not receive, and saves the logs that
   * waited for storage or for an encryption key.
   */
  private static void handleBootCompleted(Context context) {
    schedulePeriodicWork(context);
    CrumblesLoggingAccess securityAccess = CrumblesLoggingAccess.forSecurityLogging(context);
    boolean bootCountGrew =
        new CrumblesBootRecord(context)
            .recordRestart(currentBootCount(context), /* beforeUnlock= */ false);
    saveLogsCollectedBeforeUnlock(context);
    // While security logging is off, the platform returns no logs instead of refusing: retrieving
    // would resume collection paused by another user, or defer logs that do not exist. Nor did it
    // keep any logs from before the restart.
    if (isSecurityLoggingEnabled(context, securityAccess)) {
      new CrumblesBootRecord(context).recordSecurityLoggingOn();
      retrieveAndSaveSecurityLogs(context);
    } else if (securityAccess.isAvailable()) {
      // Boots skipped since security logging was last seen on may have lost logs; others had none.
      markPreRebootLogsHandledThisBoot(
          context, new CrumblesBootRecord(context).wasSecurityLoggingOnSinceLastHandledBoot());
    }
    drainDeferredNetworkLogsIfPossible(context);
    drainStagedBatchesToCurrentKey(context);
    // Reported last, so that it is the newest record of the restart in the activity log.
    if (!bootCountGrew) {
      reportPossibleLoss(context, BOOT_COUNT_DID_NOT_GROW, /* alertUser= */ true);
    }
    CrumblesDirectBootStore store = new CrumblesDirectBootStore(context);
    boolean alertUser = store.isAlertDeferred();
    for (String report : store.takeLossReports()) {
      reportPossibleLoss(context, report, alertUser);
    }
  }

  /**
   * Before the first unlock after a restart, records the restart, then saves the security logs in
   * device-encrypted storage, including those that the platform announced before this broadcast.
   */
  private static void handleLockedBootCompleted(Context context) {
    if (!new CrumblesBootRecord(context)
        .recordRestart(currentBootCount(context), /* beforeUnlock= */ true)) {
      reportPossibleLoss(context, BOOT_COUNT_DID_NOT_GROW, /* alertUser= */ true);
    }
    collectSecurityLogsBeforeUnlock(context);
  }

  /**
   * Before the first unlock after a restart, saves the security logs that the platform kept from
   * before the restart, unless this boot handled them, and the available security logs, each in a
   * batch for the recipient of the last batch saved while unlocked, in device-encrypted storage.
   * Without such a recipient, access or room for a batch, the logs wait with the platform, as they
   * do until the locked boot broadcast has recorded the restart into this boot. Once the user
   * unlocks the device, {@code BOOT_COMPLETED} retrieves them instead.
   */
  private static synchronized void collectSecurityLogsBeforeUnlock(Context context) {
    CrumblesDirectBootStore store = new CrumblesDirectBootStore(context);
    CrumblesLoggingAccess access = CrumblesLoggingAccess.forSecurityLogging(context);
    CrumblesBootRecord record = new CrumblesBootRecord(context);
    // Until the locked boot broadcast records the restart into this boot, a retrieval would record
    // its event IDs for the boot before: the logs wait for that broadcast, which retrieves them. As
    // at BOOT_COMPLETED: while security logging is off, the platform returns no pre-reboot logs,
    // which is no loss.
    if (isUserUnlocked(context)
        || !record.isRestartRecordedBeforeUnlock(currentBootCount(context))
        || !isSecurityLoggingEnabled(context, access)) {
      return;
    }
    // Recorded as at BOOT_COMPLETED, whether or not there is room for the logs of this boot.
    record.recordSecurityLoggingOn();
    if (!store.canSaveBatch()) {
      Log.w(TAG, "Leaving the security logs with the platform until the device is unlocked.");
      if (store.hasRecipient()) {
        store.deferLossReport(BEFORE_UNLOCK_NO_ROOM, /* alertUser= */ false);
      }
      return;
    }
    DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
    try {
      if (!arePreRebootLogsHandledThisBoot(context)) {
        List<SecurityEvent> preRebootLogs = dpm.retrievePreRebootSecurityLogs(access.admin());
        if (preRebootLogs == null || preRebootLogs.isEmpty()) {
          reportUnrecoverableRestartWindow(context, /* keepsNone= */ preRebootLogs == null);
          markPreRebootLogsHandledThisBoot(context);
        } else if (store.saveBatch(securityLogsBytes(PRE_REBOOT_LOGS_NOTICE, preRebootLogs))) {
          markPreRebootLogsHandledThisBoot(context);
        }
      }
      List<SecurityEvent> securityLogs = dpm.retrieveSecurityLogs(access.admin());
      if (securityLogs != null) {
        recordSecurityEventIdsBeforeUnlock(context, securityLogs);
        record.recordSecurityRetrieval(InstantSource.system().millis());
        if (!securityLogs.isEmpty()
            && !store.saveBatch(securityLogsBytes(BEFORE_UNLOCK_LOGS_NOTICE, securityLogs))) {
          reportPossibleLoss(
              context,
              "Security log batch of "
                  + securityLogs.size()
                  + " event(s), retrieved before the first unlock, was lost: saving it failed.",
              /* alertUser= */ true);
        }
      }
    } catch (SecurityException e) {
      // Another user is present, or Crumbles lost its access: the retrieval after the unlock tells.
      Log.w(TAG, "Security logs cannot be retrieved before the unlock.", e);
    }
  }

  private static byte[] securityLogsBytes(String notice, List<SecurityEvent> securityLogs) {
    return logsToBytes(
        ImmutableList.<String>builder()
            .add(notice)
            .addAll(getSerializableSecurityLogs(securityLogs))
            .build());
  }

  /**
   * Once the user has unlocked the device, saves the batches collected before the unlock as pending
   * batches, oldest first and signed, once no older batch is staged. Uploads, wipes and key changes
   * call it first, so that these batches are not left out.
   */
  static void saveLogsCollectedBeforeUnlock(Context context) {
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      ImmutableList<File> batches = new CrumblesDirectBootStore(context).batches();
      if (batches.isEmpty()
          || (!drainStagedBatchesToCurrentKey(context)
              && !new CrumblesLogStaging(context).isEmpty())) {
        return;
      }
      File logsDirectory = getLogsDirectory(context);
      logsDirectory.mkdirs();
      for (File file : batches) {
        if (!saveBatchCollectedBeforeUnlock(context, file, logsDirectory)) {
          return;
        }
      }
    }
  }

  /**
   * Signs the batch that {@code file} holds, collected before the unlock, saves it in {@code
   * logsDirectory} and deletes {@code file}. Returns false if the batch must wait, keeping {@code
   * file}, or if {@code file} cannot be deleted. A batch that sealed no attestation chain, or
   * another chain than that of the batch-signing key, as after a rotation of the key, is saved
   * unsigned, since its signature would not verify against the chain it carries.
   */
  private static boolean saveBatchCollectedBeforeUnlock(
      Context context, File file, File logsDirectory) {
    CrumblesDirectBootStore store = new CrumblesDirectBootStore(context);
    LogBatch batch;
    try {
      batch =
          LogBatch.parseFrom(
              Files.readAllBytes(file.toPath()), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      reportPossibleLoss(
          context,
          "A security log batch collected before the first unlock was unreadable and was dropped.",
          /* alertUser= */ true);
      return store.deleteBatch(file);
    } catch (IOException e) {
      Log.e(TAG, "Failed to read a batch collected before the first unlock.", e);
      return false;
    }
    if (!CrumblesLogStorageQuota.admitNewBatch(
        context,
        logsDirectory,
        CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES,
        /* isNetworkBatch= */ false,
        batch.getSerializedSize(),
        CrumblesLogStorageQuota.SIGNATURE_ALLOWANCE_BYTES)) {
      return false;
    }
    ImmutableList<ByteString> sealedChain = store.sealedChain(file);
    ImmutableList<ByteString> signingChain =
        new CrumblesBatchSigner(context).attestationChainToSeal();
    boolean sealsSigningChain = !sealedChain.isEmpty() && sealedChain.equals(signingChain);
    if (!sealsSigningChain) {
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              AUDIT_EVENT_BATCH_SIGNING_FAILED,
              "Security log batch collected before the first unlock written without a signature:"
                  + " it sealed no attestation chain or another one than the batch-signing key's.");
    }
    try {
      @SuppressWarnings("unused")
      var unusedSerialized =
          CrumblesMain.getLogsEncryptorInstance()
              .serializeBytes(
                  sealsSigningChain ? signIfPossible(context, batch, signingChain) : batch,
                  logsDirectory,
                  newBatchFileName());
    } catch (CrumblesLogsEncryptionException e) {
      Log.e(TAG, "Failed to save a batch collected before the first unlock.", e);
      return false;
    }
    return store.deleteBatch(file);
  }

  /** Returns whether the user has unlocked the device since it last restarted. */
  private static boolean isUserUnlocked(Context context) {
    UserManager userManager = context.getSystemService(UserManager.class);
    return userManager == null || userManager.isUserUnlocked();
  }

  /**
   * Records in device-encrypted storage that {@link Intent#ACTION_TIME_CHANGED} arrived before the
   * first unlock after a restart so {@link #handleBootCompleted} can re-enqueue periodic work.
   */
  private static void recordTimeChangedBeforeUnlock(Context context) {
    SharedPreferences preferences = bootRecordPreferences(context);
    if (preferences != null) {
      preferences.edit().putBoolean(PREF_TIME_CHANGED_BEFORE_UNLOCK, true).commit();
    }
  }

  /**
   * Returns whether {@link Intent#ACTION_TIME_CHANGED} arrived before the first unlock since the
   * last boot check, clearing the flag in device-encrypted storage.
   */
  private static boolean takeTimeChangedBeforeUnlock(Context context) {
    SharedPreferences preferences = bootRecordPreferences(context);
    if (preferences == null) {
      return false;
    }
    boolean changed =
        preferences.getBoolean(PREF_TIME_CHANGED_BEFORE_UNLOCK, /* defValue= */ false);
    if (changed) {
      preferences.edit().remove(PREF_TIME_CHANGED_BEFORE_UNLOCK).commit();
    }
    return changed;
  }

  @Nullable
  private static SharedPreferences bootRecordPreferences(Context context) {
    Context deviceContext = context.createDeviceProtectedStorageContext();
    if (deviceContext == null) {
      return null;
    }
    return deviceContext.getSharedPreferences(BOOT_RECORD_PREFS_NAME, Context.MODE_PRIVATE);
  }

  /** Returns whether security logging is on and {@code access} lets Crumbles retrieve its logs. */
  private static boolean isSecurityLoggingEnabled(Context context, CrumblesLoggingAccess access) {
    if (!access.isAvailable()) {
      return false;
    }
    try {
      return context
          .getSystemService(DevicePolicyManager.class)
          .isSecurityLoggingEnabled(access.admin());
    } catch (SecurityException e) {
      Log.w(TAG, "SecurityException checking security logging status.", e);
      return false;
    }
  }

  /**
   * Schedules or repairs periodic work after unlock: re-enqueues all periodic work and requests an
   * immediate upload if {@link Intent#ACTION_TIME_CHANGED} arrived while locked, or otherwise
   * schedules periodic work when needed and repairs any schedule left due far in the future.
   */
  private static void schedulePeriodicWork(Context context) {
    Context appContext = context.getApplicationContext();
    WorkManager workManager;
    try {
      workManager = WorkManager.getInstance(appContext);
    } catch (IllegalStateException e) {
      // WorkManager.getInstance throws when WorkManager could not be initialized.
      Log.e(TAG, "Failed to schedule periodic work after boot.", e);
      return;
    }
    boolean timeChangedBeforeUnlock = takeTimeChangedBeforeUnlock(context);
    if (!needsPeriodicWork(context)) {
      CrumblesWorkScheduler.repairForwardScheduledWork(workManager);
      return;
    }
    if (timeChangedBeforeUnlock) {
      CrumblesWorkScheduler.rescheduleAfterTimeChange(workManager);
    } else {
      CrumblesWorkScheduler.scheduleAllPeriodicWork(appContext, workManager);
    }
  }

  /**
   * Re-enqueues the periodic work once the wall clock changes, clearing any pending pre-unlock
   * time-change flag so a subsequent unlock catch-up does not reschedule twice, or repairs
   * already-scheduled work left due far in the future.
   */
  private static void handleTimeChanged(Context context) {
    WorkManager workManager;
    try {
      workManager = WorkManager.getInstance(context.getApplicationContext());
    } catch (IllegalStateException e) {
      Log.e(TAG, "Failed to reschedule periodic work after time change.", e);
      return;
    }
    var unused = takeTimeChangedBeforeUnlock(context);
    if (needsPeriodicWork(context)) {
      CrumblesWorkScheduler.rescheduleAfterTimeChange(workManager);
    } else {
      CrumblesWorkScheduler.repairForwardScheduledWork(workManager);
    }
  }

  /**
   * Returns whether Crumbles needs its periodic work: it can retrieve logs; logging was still on
   * when the watchdog last checked (before a revocation was recorded); or batches wait in saved
   * logs, staging, or Direct Boot storage.
   */
  private static boolean needsPeriodicWork(Context context) {
    return CrumblesLoggingAccess.forSecurityLogging(context).isAvailable()
        || CrumblesLoggingAccess.forNetworkLogging(context).isAvailable()
        || wasLoggingLastSeenOn(context)
        || hasSavedBatches(context)
        || !new CrumblesLogStaging(context).isEmpty()
        || hasDirectBootBatches(context);
  }

  private static boolean wasLoggingLastSeenOn(Context context) {
    SharedPreferences preferences = prefs(context);
    return preferences.getBoolean(
            CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED, /* defValue= */ false)
        || preferences.getBoolean(
            CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED, /* defValue= */ false);
  }

  /** Returns whether the logs directory holds a batch, waiting, being uploaded or uploaded. */
  private static boolean hasSavedBatches(Context context) {
    String[] batches = getLogsDirectory(context).list((dir, name) -> name.endsWith(".bin"));
    return batches != null && batches.length > 0;
  }

  /** Returns whether batches collected before the first unlock are waiting to be moved. */
  private static boolean hasDirectBootBatches(Context context) {
    Context deviceContext = context.createDeviceProtectedStorageContext();
    if (deviceContext == null) {
      return false;
    }
    File batchesDirectory = new File(deviceContext.getFilesDir(), DIRECT_BOOT_BATCHES_SUBDIRECTORY);
    String[] batches = batchesDirectory.list((dir, name) -> name.endsWith(".bin"));
    return batches != null && batches.length > 0;
  }

  /**
   * Retrieves the security logs that the platform kept from before the device restarted, saves or
   * stages them in a batch of their own and records that this boot needs them no more.
   *
   * <p>The platform delivers only the logs of the current boot, so those written after the last
   * retrieval before a restart are lost unless retrieved here. Unlike the logs of the current boot,
   * the platform keeps these until the next restart: a retrieval that it refuses, or whose logs can
   * be neither saved nor staged, is tried again with the next one and is not a loss. Crumbles asks
   * only while security logging is on, so null means that the device keeps no logs across a
   * restart, and an empty list that none were kept or could be read. Neither changes during a boot,
   * so neither is asked for again, and both mean that the events logged after the last retrieval
   * before the restart may be lost, which is recorded.
   *
   * <p>Their event IDs belong to the logging session before the restart, so they are not checked
   * for gaps against those of the current session.
   */
  private static void retrieveAndSavePreRebootLogs(
      Context context, DevicePolicyManager dpm, CrumblesLoggingAccess access) {
    List<SecurityEvent> preRebootLogs;
    try {
      preRebootLogs = dpm.retrievePreRebootSecurityLogs(access.admin());
    } catch (SecurityException e) {
      // Another user is present, or Crumbles lost its access: the next retrieval tries again.
      Log.w(TAG, "Pre-reboot security logs cannot be retrieved now.", e);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOG_RETRIEVAL_DEFERRED",
              PRE_REBOOT_SECURITY_LOG_TYPE
                  + " log retrieval was refused, as while another user is present. The platform"
                  + " keeps the logs until the device restarts.");
      return;
    }
    if (preRebootLogs == null || preRebootLogs.isEmpty()) {
      Log.i(TAG, "No pre-reboot security logs.");
      reportUnrecoverableRestartWindow(context, /* keepsNone= */ preRebootLogs == null);
      markPreRebootLogsHandledThisBoot(context);
      return;
    }
    int eventCount = preRebootLogs.size();
    SaveOutcome outcome =
        saveOrStageRetrievedLogs(
            context,
            PRE_REBOOT_SECURITY_LOG_TYPE,
            eventCount,
            securityLogsBytes(PRE_REBOOT_LOGS_NOTICE, preRebootLogs),
            reason -> deferPreRebootLogs(context, eventCount, reason));
    if (!outcome.equals(SaveOutcome.NOT_KEPT)) {
      markPreRebootLogsHandledThisBoot(context);
    }
  }

  /**
   * Records that the security logs kept from before the restart could be neither saved nor staged,
   * for {@code reason}. The next retrieval of security logs tries again.
   */
  private static void deferPreRebootLogs(Context context, int eventCount, String reason) {
    String message =
        PRE_REBOOT_SECURITY_LOG_TYPE
            + " log batch of "
            + eventCount
            + " event(s) was deferred: "
            + reason
            + ". The platform keeps it until the device restarts.";
    Log.w(TAG, message);
    CrumblesAppAuditLogger.getInstance(context).logEvent("LOG_RETRIEVAL_DEFERRED", message);
    notifyActionNeeded(context);
  }

  /**
   * Returns whether this boot has handled the security logs kept from before the last restart:
   * saved or staged them, or found none.
   */
  private static boolean arePreRebootLogsHandledThisBoot(Context context) {
    return new CrumblesBootRecord(context).arePreRebootLogsHandled();
  }

  /**
   * Records that this boot handled the security logs kept from before its restart, and reports the
   * boots in between that never did, whose own logs the platform no longer keeps.
   */
  private static void markPreRebootLogsHandledThisBoot(Context context) {
    markPreRebootLogsHandledThisBoot(context, /* reportSkippedBoots= */ true);
  }

  /**
   * As {@link #markPreRebootLogsHandledThisBoot(Context)}, but reports the boots in between only if
   * {@code reportSkippedBoots}.
   */
  private static void markPreRebootLogsHandledThisBoot(
      Context context, boolean reportSkippedBoots) {
    int skippedBoots = new CrumblesBootRecord(context).markPreRebootLogsHandled();
    if (reportSkippedBoots && skippedBoots > 0) {
      reportPossibleLoss(
          context,
          "Security logs kept from before "
              + skippedBoots
              + " restart(s) may have been lost: the device restarted again before Crumbles"
              + " retrieved them.",
          /* alertUser= */ true);
    }
  }

  /**
   * Records that the security events logged after the last retrieval before the restart, and the
   * network events not handed over by then, may have been lost, since the platform kept no logs
   * from before the restart: it keeps none across restarts if {@code keepsNone}, and none survive a
   * cold boot. Records nothing unless security logs were retrieved before the restart, which the
   * record kept at the restart, with the last network batch retrieved before it.
   */
  private static void reportUnrecoverableRestartWindow(Context context, boolean keepsNone) {
    CrumblesBootRecord record = new CrumblesBootRecord(context);
    OptionalLong lastRetrieval = record.lastSecurityRetrievalBeforeRestart();
    if (lastRetrieval.isEmpty()) {
      return;
    }
    OptionalLong networkToken = record.lastNetworkTokenBeforeRestart();
    String networkBatch =
        networkToken.isPresent()
            ? " (after network batch token " + networkToken.getAsLong() + ")"
            : "";
    reportPossibleLoss(
        context,
        "The platform kept no security logs from before the restart"
            + (keepsNone ? ": this device keeps none across restarts." : ", as after a cold boot.")
            + " Security events logged after the last retrieval, at "
            + Instant.ofEpochMilli(lastRetrieval.getAsLong()).truncatedTo(ChronoUnit.SECONDS)
            + ", and network events not yet handed over"
            + networkBatch
            + " may have been lost.",
        /* alertUser= */ false);
  }

  /**
   * Records that security logs may have been lost, and alerts the user if {@code alertUser}. Before
   * the first unlock after a restart, keeps the report until the unlock.
   */
  private static void reportPossibleLoss(Context context, String message, boolean alertUser) {
    Log.w(TAG, message);
    if (!isUserUnlocked(context)) {
      new CrumblesDirectBootStore(context).deferLossReport(message, alertUser);
      return;
    }
    CrumblesAppAuditLogger.getInstance(context).logEvent(AUDIT_EVENT_LOGS_LOST, message);
    if (alertUser) {
      notifyLossReported(context);
    }
  }

  @Override
  public void onNetworkLogsAvailable(
      @NonNull Context context, @NonNull Intent intent, long batchToken, int networkLogsCount) {
    retrieveInBackground(
        goAsync(), () -> retrieveAndSaveNetworkLogs(context, batchToken, networkLogsCount));
  }

  /**
   * Retrieves, encrypts and saves the network logs batch identified by {@code batchToken}, as the
   * device owner or as the network logging delegate.
   */
  // ...
  @SuppressLint("UsableSpace")
  static synchronized void retrieveAndSaveNetworkLogs(
      Context context, long batchToken, int networkLogsCount) {
    if (!isUserUnlocked(context)) {
      // Whether the user collects network logs is recorded in credential-encrypted storage, and the
      // platform hands over only the latest batch.
      reportPossibleLoss(
          context,
          "Network log batch (token "
              + batchToken
              + ", "
              + networkLogsCount
              + " events) was announced before the first unlock and could not be retrieved while"
              + " locked.",
          /* alertUser= */ false);
      return;
    }
    if (!CrumblesCollectionScope.isNetworkCollectionEnabled(context)) {
      Log.i(TAG, "Network collection turned off by the user; skipping network log retrieval.");
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "NETWORK_COLLECTION_OFF",
              "Network log batch not retrieved: network collection is turned off by the user.");
      return;
    }
    if (!prepareLogRetrieval(context, "Network", MIN_NETWORK_USABLE_SPACE_BYTES)) {
      enqueueDeferredNetworkToken(context, batchToken);
      return;
    }
    CrumblesLoggingAccess access = CrumblesLoggingAccess.forNetworkLogging(context);
    if (!access.isAvailable()) {
      Log.w(TAG, "Neither device owner nor network logging delegate; skipping retrieval.");
      return;
    }
    boolean wasDeferred = getDeferredNetworkTokens(context).contains(batchToken);
    drainDeferredNetworkLogsIfPossible(context);
    if (wasDeferred) {
      // The drain has retrieved this batch, or keeps its token queued.
      return;
    }
    long usableBytes = context.getFilesDir().getUsableSpace();
    if (usableBytes < MIN_NETWORK_USABLE_SPACE_BYTES) {
      deferLowSpace(context, "Network", usableBytes);
      enqueueDeferredNetworkToken(context, batchToken);
      return;
    }
    AtomicBoolean retrieved = new AtomicBoolean(false);
    List<NetworkEvent> networkLogs;
    try {
      networkLogs = retrieveNetworkLogsOrPause(context, access, batchToken, retrieved);
    } catch (SecurityException e) {
      Log.w(TAG, "SecurityException retrieving network logs.", e);
      reportLogsLost(context, "Network", networkLogsCount, "retrieval threw SecurityException");
      return;
    }
    if (networkLogs == null) {
      Log.i(TAG, "Network logs are null.");
      if (!retrieved.get()) {
        // The platform rejected the retrieval and still holds the batch: drain it later.
        enqueueDeferredNetworkToken(context, batchToken);
      }
      return;
    }
    saveRetrievedLogs(
        context,
        "Network",
        networkLogs.size(),
        logsToBytes(getSerializableNetworkLogs(networkLogs)));
    recordNetworkBatchToken(context, batchToken);
    // The last batch handed over, which a restart window names; a deferred one is not.
    new CrumblesBootRecord(context).recordNetworkBatchToken(batchToken);
  }

  // ...
  @SuppressLint("UsableSpace")
  static synchronized void drainDeferredNetworkLogsIfPossible(Context context) {
    if (!CrumblesCollectionScope.isNetworkCollectionEnabled(context)
        || !isReadyForLogging(context)
        || getDeferredNetworkTokens(context).isEmpty()) {
      return;
    }
    CrumblesLoggingAccess access = CrumblesLoggingAccess.forNetworkLogging(context);
    if (!access.isAvailable()) {
      return;
    }
    boolean lost = false;
    try {
      while (context.getFilesDir().getUsableSpace() >= MIN_NETWORK_USABLE_SPACE_BYTES) {
        ImmutableList<Long> deferred = getDeferredNetworkTokens(context);
        if (deferred.isEmpty()) {
          break;
        }
        long token = deferred.get(0);
        AtomicBoolean retrieved = new AtomicBoolean(false);
        List<NetworkEvent> logs = retrieveNetworkLogsOrPause(context, access, token, retrieved);
        if (!retrieved.get()) {
          break;
        }
        boolean saved = false;
        if (logs == null) {
          logLostDeferredToken(context, token, "discarded by platform before retrieval.");
          lost = true;
        } else {
          saved =
              saveRetrievedLogs(
                  context, "Network", logs.size(), logsToBytes(getSerializableNetworkLogs(logs)));
        }
        // Dequeue only now: if this thread dies first, the next drain gets the batch again.
        removeDeferredNetworkToken(context, token);
        if (saved && getDeferredNetworkTokens(context).isEmpty()) {
          cancelDeferredLogsNotification(context);
        }
      }
    } catch (SecurityException e) {
      Log.w(TAG, "Lost network logging access; keeping the deferred batches.", e);
    }
    if (lost) {
      notifyLossReported(context);
    }
  }

  /**
   * Retrieves network logs batch {@code token} and sets {@code retrieved}, unless the platform
   * rejected the retrieval and so still holds the batch. Rethrows if Crumbles lost its access.
   */
  @Nullable
  private static List<NetworkEvent> retrieveNetworkLogsOrPause(
      Context context, CrumblesLoggingAccess access, long token, AtomicBoolean retrieved) {
    DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
    return retrieveLogsOrPause(
        context,
        () -> {
          List<NetworkEvent> batch = dpm.retrieveNetworkLogs(access.admin(), token);
          retrieved.set(true);
          return batch;
        },
        () -> CrumblesLoggingAccess.forNetworkLogging(context));
  }

  private static ImmutableList<Long> getDeferredNetworkTokens(Context context) {
    synchronized (DEFERRED_TOKENS_LOCK) {
      return ImmutableList.copyOf(loadDeferredTokensLocked(context));
    }
  }

  private static void removeDeferredNetworkToken(Context context, long token) {
    synchronized (DEFERRED_TOKENS_LOCK) {
      List<Long> tokens = loadDeferredTokensLocked(context);
      tokens.remove(token);
      saveDeferredTokensLocked(context, tokens);
    }
  }

  private static void enqueueDeferredNetworkToken(Context context, long batchToken) {
    Long evictedToken = null;
    synchronized (DEFERRED_TOKENS_LOCK) {
      List<Long> tokens = loadDeferredTokensLocked(context);
      if (tokens.contains(batchToken)) {
        return;
      }
      recordNetworkBatchToken(context, batchToken);
      if (tokens.size() == MAX_DEFERRED_NETWORK_TOKENS) {
        evictedToken = tokens.remove(0);
      }
      tokens.add(batchToken);
      saveDeferredTokensLocked(context, tokens);
    }
    if (evictedToken != null) {
      logLostDeferredToken(context, evictedToken, "deferred queue full.");
    }
  }

  private static void logLostDeferredToken(Context context, long token, String reason) {
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_LOGS_LOST,
            "Deferred network log batch (token " + token + ") was lost: " + reason);
    notifyLossReported(context);
  }

  private static List<Long> loadDeferredTokensLocked(Context context) {
    long currentSession = currentNetworkLoggingSessionKey(context);
    ImmutableList<Long> fallback = fallbackDeferredTokens.get();
    if (fallback != null) {
      List<Long> rest = new ArrayList<>(fallback.subList(1, fallback.size()));
      return validateTokenSessionLocked(context, fallback.get(0), currentSession, rest);
    }
    Path path = context.getNoBackupFilesDir().toPath().resolve(DEFERRED_TOKENS_FILE);
    boolean reported = leaveDeferredTokensFile.getAndSet(false);
    try {
      byte[] bytes = Files.readAllBytes(path);
      ByteBuffer buffer = ByteBuffer.wrap(bytes);
      long storedSession = bytes.length >= DEFERRED_TOKENS_FILE_BYTES ? buffer.getLong() : 0L;
      int count = bytes.length >= DEFERRED_TOKENS_FILE_BYTES ? buffer.getInt() : -1;
      if (Integer.compareUnsigned(count, MAX_DEFERRED_NETWORK_TOKENS) > 0) {
        return keepUnreadableTokensLocked(context, path, reported);
      }
      List<Long> tokens = new ArrayList<>(count);
      for (int i = 0; i < count; i++) {
        tokens.add(buffer.getLong());
      }
      return validateTokenSessionLocked(context, storedSession, currentSession, tokens);
    } catch (NoSuchFileException e) {
      return new ArrayList<>();
    } catch (IOException e) {
      return keepUnreadableTokensLocked(context, path, reported);
    }
  }

  /**
   * Moves an unreadable token file aside, or else leaves it alone, so that no save overwrites the
   * tokens it may hold, and records once that their batches were lost.
   */
  private static List<Long> keepUnreadableTokensLocked(
      Context context, Path path, boolean reported) {
    try {
      Files.move(path, path.resolveSibling(DEFERRED_TOKENS_FILE + ".unreadable"), REPLACE_EXISTING);
    } catch (IOException e) {
      Log.w(TAG, "Failed to move the unreadable deferred token file aside; leaving it alone.", e);
      leaveDeferredTokensFile.set(true);
    }
    if (!reported) {
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              AUDIT_EVENT_LOGS_LOST,
              "Deferred network log batches were lost: their token file could not be read. It was"
                  + " kept.");
      notifyLossReported(context);
    }
    return new ArrayList<>();
  }

  private static List<Long> validateTokenSessionLocked(
      Context context, long storedSession, long currentSession, List<Long> tokens) {
    if (storedSession == currentSession || tokens.isEmpty()) {
      return tokens;
    }
    for (long staleToken : tokens) {
      logLostDeferredToken(context, staleToken, "logging session restarted before retrieval.");
    }
    saveDeferredTokensLocked(context, new ArrayList<>());
    return new ArrayList<>();
  }

  private static void saveDeferredTokensLocked(Context context, List<Long> tokens) {
    long session = currentNetworkLoggingSessionKey(context);
    ImmutableList<Long> unsaved =
        tokens.isEmpty() ? null : ImmutableList.<Long>builder().add(session).addAll(tokens).build();
    if (leaveDeferredTokensFile.get()) {
      fallbackDeferredTokens.set(unsaved);
      return;
    }
    ByteBuffer buffer =
        ByteBuffer.allocate(DEFERRED_TOKENS_FILE_BYTES).putLong(session).putInt(tokens.size());
    tokens.forEach(buffer::putLong);
    File file = new File(context.getNoBackupFilesDir(), DEFERRED_TOKENS_FILE);
    try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
      raf.write(buffer.array());
      raf.getFD().sync();
      fallbackDeferredTokens.set(null);
    } catch (IOException e) {
      Log.w(TAG, "Failed to persist deferred network tokens; keeping in memory.", e);
      // The file still holds the tokens that were just removed: delete it, or else hide it.
      if (unsaved == null && !file.delete() && file.exists()) {
        unsaved = ImmutableList.of(session);
      }
      fallbackDeferredTokens.set(unsaved);
    }
  }

  /** What became of logs that the platform handed over. */
  private enum SaveOutcome {
    /** They were encrypted and saved as a pending batch. */
    SAVED,
    /** They were staged, sealed to this device, until they can be encrypted and saved. */
    STAGED,
    /** They could be neither saved nor staged. */
    NOT_KEPT
  }

  /**
   * Encrypts and saves logs that the platform has handed over, after any staged ones, or stages
   * them until that is possible. Reports their loss loudly if they cannot be staged either, since
   * the platform keeps no copy. Returns whether they were saved rather than staged or lost.
   */
  @CanIgnoreReturnValue
  private static boolean saveRetrievedLogs(
      Context context, String logType, int eventCount, byte[] logsBytes) {
    return saveOrStageRetrievedLogs(
            context,
            logType,
            eventCount,
            logsBytes,
            reason -> reportLogsLost(context, logType, eventCount, reason))
        .equals(SaveOutcome.SAVED);
  }

  /**
   * Encrypts and saves logs that the platform has handed over, after any staged ones, or stages
   * them until that is possible, also when the save attempt throws an unchecked exception. If they
   * can be neither saved nor staged, or an unchecked exception interrupts staging, hands the reason
   * to {@code onNotKept}, which reports a loss unless the platform still keeps the logs.
   */
  private static SaveOutcome saveOrStageRetrievedLogs(
      Context context,
      String logType,
      int eventCount,
      byte[] logsBytes,
      Consumer<String> onNotKept) {
    try {
      return saveOrStageRetrievedLogsOrThrow(context, logType, eventCount, logsBytes, onNotKept);
    } catch (RuntimeException e) {
      // Keystore on some OEM builds throws unchecked exceptions other than ProviderException, and
      // the platform keeps no copy of the logs: report them as not kept rather than crash the app.
      Log.e(TAG, "Failed to stage " + logType.toLowerCase(Locale.US) + " logs.", e);
      onNotKept.accept("staging it threw " + e.getClass().getSimpleName());
      return SaveOutcome.NOT_KEPT;
    }
  }

  /**
   * Does what {@link #saveOrStageRetrievedLogs} does, but lets unchecked exceptions thrown while
   * staging escape.
   */
  private static SaveOutcome saveOrStageRetrievedLogsOrThrow(
      Context context,
      String logType,
      int eventCount,
      byte[] logsBytes,
      Consumer<String> onNotKept) {
    String reason = "no encryption key is available";
    boolean saved = false;
    try {
      Optional<PublicKey> activeKey = resolveActiveEncryptionKey(context);
      if (activeKey.isPresent()) {
        if (!drainStagedBatches(context, activeKey.get())) {
          // Saving this batch now would put it ahead of older batches that are still staged.
          reason = "older staged batches are waiting";
        } else if (saveEncrypted(context, logType.equals("Network"), logsBytes, activeKey.get())) {
          saved = true;
        } else {
          reason = "encrypting or saving it failed";
        }
      }
    } catch (QuotaRefusedException e) {
      if (logType.equals("Network")) {
        onNotKept.accept("storage quota reached");
        return SaveOutcome.NOT_KEPT;
      }
      reason = "storage quota reached";
    } catch (RuntimeException e) {
      // Keystore on some OEM builds throws unchecked exceptions other than ProviderException.
      // Staging seals the logs with another Keystore key, so it may still keep them.
      Log.e(TAG, "Failed to save " + logType.toLowerCase(Locale.US) + " logs; staging them.", e);
      reason = "saving it threw " + e.getClass().getSimpleName();
    }
    if (saved) {
      if (getDeferredNetworkTokens(context).isEmpty()) {
        cancelDeferredLogsNotification(context);
      }
      return SaveOutcome.SAVED;
    }
    return stageRetrievedLogs(context, logType, eventCount, logsBytes, reason, onNotKept);
  }

  /** Returns whether {@code logsBytes} were encrypted to {@code activeKey} and saved. */
  private static boolean saveEncrypted(
      Context context, boolean isNetworkBatch, byte[] logsBytes, PublicKey activeKey)
      throws QuotaRefusedException {
    try {
      return encryptAndSaveLogs(context, isNetworkBatch, logsBytes, activeKey).isPresent();
    } catch (CrumblesLogsEncryptionException e) {
      Log.e(TAG, "Failed to encrypt or write logs.", e);
      return false;
    }
  }

  /**
   * Stages {@code logsBytes}, which could not be saved for {@code reason}, or hands {@code
   * onNotKept} the reason that they could not be staged either.
   */
  private static SaveOutcome stageRetrievedLogs(
      Context context,
      String logType,
      int eventCount,
      byte[] logsBytes,
      String reason,
      Consumer<String> onNotKept) {
    boolean staged;
    try {
      staged = new CrumblesLogStaging(context).stage(logType.equals("Network"), logsBytes);
    } catch (GeneralSecurityException | IOException e) {
      Log.e(TAG, "Failed to stage " + logType.toLowerCase(Locale.US) + " logs.", e);
      onNotKept.accept("staging it failed");
      return SaveOutcome.NOT_KEPT;
    }
    if (!staged) {
      onNotKept.accept("the staging area is full");
      return SaveOutcome.NOT_KEPT;
    }
    String message =
        logType + " log batch of " + eventCount + " event(s) was staged: " + reason + ".";
    Log.w(TAG, message);
    CrumblesAppAuditLogger.getInstance(context).logEvent(AUDIT_EVENT_LOGS_STAGED, message);
    notifyActionNeeded(context);
    return SaveOutcome.STAGED;
  }

  private static void reportLogsLost(
      Context context, String logType, int eventCount, String reason) {
    String message =
        logType + " log batch of " + eventCount + " event(s) was lost: " + reason + ".";
    Log.e(TAG, message);
    CrumblesAppAuditLogger.getInstance(context).logEvent(AUDIT_EVENT_LOGS_LOST, message);
    notifyLossReported(context);
  }

  /**
   * Seals a final batch saying that logging was turned off, then asks for it to be uploaded right
   * away.
   *
   * <p>Batches are otherwise only made when the platform delivers logs, which stops once logging is
   * off. This batch lets whoever reads the batches know why they stopped. A failure is recorded in
   * the activity log.
   *
   * @return whether the batch was written
   */
  @CanIgnoreReturnValue
  static boolean sealFinalBatch(Context context) {
    Optional<PublicKey> activeKey = resolveActiveEncryptionKey(context);
    if (activeKey.isEmpty()) {
      logFinalBatchFailed(context, "no usable encryption key");
      return false;
    }
    @SuppressWarnings("unused")
    var unusedDrained = drainStagedBatches(context, activeKey.get());
    int pending = new CrumblesLogStaging(context).countBatches();
    if (!saveLoggingOffBatch(context, activeKey.get(), pending)) {
      logFinalBatchFailed(context, "the batch could not be encrypted or saved");
      return false;
    }
    if (pending > 0) {
      String message = "Notice sealed, " + pending + " staged batch(es) still pending.";
      Log.w(TAG, message);
      CrumblesAppAuditLogger.getInstance(context).logEvent("FINAL_BATCH_SEALED", message);
    }
    CrumblesWorkScheduler.requestImmediateUpload(WorkManager.getInstance(context));
    return true;
  }

  /**
   * Seals a batch saying that log collection paused because another user is present, after the
   * staged batches that can be drained, then asks for it to be uploaded right away. A failure is
   * recorded in the activity log.
   */
  private static void sealCollectionPausedBatch(Context context) {
    String reason = "no usable encryption key";
    Optional<PublicKey> activeKey = resolveActiveEncryptionKey(context);
    if (activeKey.isPresent()) {
      @SuppressWarnings("unused")
      var unusedDrained = drainStagedBatches(context, activeKey.get());
      int pending = new CrumblesLogStaging(context).countBatches();
      String notice =
          "Crumbles: Collection paused: secondary or guest user present at "
              + InstantSource.system().instant().truncatedTo(ChronoUnit.SECONDS)
              + ". Unretrieved platform logs are discarded by the platform when other users are"
              + " removed.";
      if (saveNoticeBatch(context, notice, activeKey.get(), pending)) {
        CrumblesWorkScheduler.requestImmediateUpload(WorkManager.getInstance(context));
        return;
      }
      reason = "the batch could not be encrypted or saved";
    }
    String message =
        "No pause batch was sealed when a secondary or guest user was present: " + reason + ".";
    Log.e(TAG, message);
    CrumblesAppAuditLogger.getInstance(context).logEvent(AUDIT_EVENT_PAUSE_BATCH_FAILED, message);
  }

  /**
   * Drains staged batches to {@code activeKey} and returns whether none remain, so that a new batch
   * is not numbered ahead of older staged batches.
   */
  @CanIgnoreReturnValue
  static boolean drainStagedBatches(Context context, PublicKey activeKey) {
    // Uploads and wipes take UPLOAD_LOCK before the staging lock. Taking them in the same order
    // avoids a deadlock, and a wipe then waits for the drain instead of missing what it moves.
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      return drainStagedBatchesLocked(context, activeKey);
    }
  }

  /**
   * Drains staged batches to the key that is active once UPLOAD_LOCK is held, and returns whether
   * none remain. An upload run resolves its key before it uploads, which can take minutes, and the
   * staged logs must not go to a key replaced meanwhile, which may no longer exist.
   */
  @CanIgnoreReturnValue
  static boolean drainStagedBatchesToCurrentKey(Context context) {
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      Optional<PublicKey> currentKey = resolveActiveEncryptionKey(context);
      return currentKey.isPresent() && drainStagedBatchesLocked(context, currentKey.get());
    }
  }

  private static boolean drainStagedBatchesLocked(Context context, PublicKey activeKey) {
    CrumblesLogStaging staging = new CrumblesLogStaging(context);
    int saved =
        staging.drain(
            (isNetworkBatch, staged) -> {
              try {
                return saveEncrypted(context, isNetworkBatch, staged, activeKey)
                    ? CrumblesLogStaging.WriteResult.STORED
                    : CrumblesLogStaging.WriteResult.FAILED;
              } catch (QuotaRefusedException e) {
                if (hasUnuploadedBinFiles(context)) {
                  return CrumblesLogStaging.WriteResult.FAILED;
                }
                if (isNetworkBatch) {
                  int stagedEventCount =
                      new String(staged, UTF_8).split("Network log ID: ", -1).length - 1;
                  reportLogsLost(context, "Network", stagedEventCount, "storage quota reached");
                  return CrumblesLogStaging.WriteResult.DROPPED;
                }
                return CrumblesLogStaging.WriteResult.FAILED;
              }
            });
    Log.i(TAG, saved + " staged log batch(es) were encrypted and saved.");
    boolean empty = staging.isEmpty();
    if (saved > 0 && empty && getDeferredNetworkTokens(context).isEmpty()) {
      cancelDeferredLogsNotification(context);
    }
    return empty;
  }

  private static boolean saveLoggingOffBatch(
      Context context, PublicKey activeKey, int pendingBatches) {
    return saveNoticeBatch(
        context,
        "Crumbles: logging was turned off at "
            + InstantSource.system().instant().truncatedTo(ChronoUnit.SECONDS)
            + ". No more batches until it is turned back on.",
        activeKey,
        pendingBatches);
  }

  /**
   * Saves {@code notice}, followed by how many staged batches are still pending and will follow,
   * as a batch encrypted to {@code activeKey}.
   */
  private static boolean saveNoticeBatch(
      Context context, String notice, PublicKey activeKey, int pendingBatches) {
    String text = notice;
    if (pendingBatches > 0) {
      text += " " + pendingBatches + " staged batch(es) are still pending and will follow.";
    }
    text += "\n";
    try {
      return encryptAndSaveLogs(
              context, /* isNetworkBatch= */ false, text.getBytes(UTF_8), activeKey)
          .isPresent();
    } catch (CrumblesLogsEncryptionException | QuotaRefusedException e) {
      Log.e(TAG, "Failed to encrypt or save a notice batch.", e);
      return false;
    }
  }

  private static void logFinalBatchFailed(Context context, String reason) {
    Log.e(TAG, "Failed to seal the final batch: " + reason + ".");
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_FINAL_BATCH_FAILED,
            "No final batch was sealed when logging was turned off: " + reason + ".");
  }

  /**
   * Seals any unshipped activity log records into a signed notice batch, asks for pending batches
   * to be uploaded right away before the local activity log is cleared, and returns how many
   * unshipped records could not be sealed into a stored batch.
   *
   * <p>Records logged after they were read, such as one saying that this batch could not be
   * signed, stay unshipped: {@link CrumblesAppAuditLogger#clearShippedLogs} keeps them.
   */
  @CanIgnoreReturnValue
  public static int sealActivityLogBeforeClear(Context context) {
    // Like every drain, upload and wipe, take UPLOAD_LOCK before the staging lock, which draining
    // takes below: two threads that took them in opposite orders could wait for each other forever.
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(context);
      if (auditLogger.getUnshippedExcerpt().isEmpty()) {
        return 0;
      }
      byte[] noticeBytes =
          ("Crumbles: activity log was cleared at "
                  + InstantSource.system().instant().truncatedTo(ChronoUnit.SECONDS)
                  + "; sealing unshipped activity records before clearing.\n")
              .getBytes(UTF_8);
      boolean savedBatch;
      try {
        Optional<PublicKey> activeKey = resolveActiveEncryptionKey(context);
        savedBatch =
            activeKey.isPresent()
                && drainStagedBatches(context, activeKey.get())
                && saveClearNoticeBatch(context, noticeBytes, activeKey.get());
      } catch (RuntimeException e) {
        // Keystore on some OEM builds throws unchecked exceptions other than ProviderException.
        // Refusing the clear keeps the records, where the exception would crash the app.
        Log.e(TAG, "Failed to seal the activity log before clearing it.", e);
        savedBatch = false;
      }
      int unsealedRecordCount = 0;
      if (!savedBatch) {
        unsealedRecordCount = Math.max(1, auditLogger.getUnshippedExcerpt().size());
        auditLogger.logEvent(
            AUDIT_EVENT_CLEAR_SEAL_FAILED,
            "Unshipped activity records could not be sealed before clearing the activity log.");
      }
      CrumblesWorkScheduler.requestImmediateUpload(WorkManager.getInstance(context));
      return unsealedRecordCount;
    }
  }

  private static boolean saveClearNoticeBatch(
      Context context, byte[] noticeBytes, PublicKey activeKey) {
    try {
      return encryptAndSaveLogs(context, /* isNetworkBatch= */ false, noticeBytes, activeKey)
          .isPresent();
    } catch (CrumblesLogsEncryptionException | QuotaRefusedException e) {
      Log.e(TAG, "Failed to encrypt or save the pre-clear activity log batch.", e);
      return false;
    }
  }

  /** Creates and configures a SimpleDateFormat for a standardized UTC format. */
  private static SimpleDateFormat getUtcDateFormatter() {
    // Note: SimpleDateFormat is not thread-safe, but it's safe to create a new
    // instance for each use here as these callbacks are not highly concurrent.
    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
    return formatter;
  }

  @VisibleForTesting
  public static List<String> getSerializableNetworkLogs(List<NetworkEvent> networkLogs) {
    List<String> serializableNetworkLogs = new ArrayList<>();
    if (networkLogs == null) {
      return serializableNetworkLogs;
    }
    StringBuilder sb;
    SimpleDateFormat formatter = getUtcDateFormatter();
    for (NetworkEvent networkLog : networkLogs) {
      sb = new StringBuilder();
      sb.append("Network log ID: ").append(networkLog.getId()).append("\n");
      // Format the millisecond timestamp into a human-readable UTC string.
      Instant timestampInstant = Instant.ofEpochMilli(networkLog.getTimestamp());
      sb.append("Timestamp (UTC): ")
          .append(formatter.format(Date.from(timestampInstant)))
          .append("\n");
      sb.append("Package name: ").append(escape(networkLog.getPackageName())).append("\n");
      if (networkLog instanceof DnsEvent dnsEvent) {
        sb.append("DNS event ID: ").append(dnsEvent.getId()).append("\n");
        sb.append("Domain name: ").append(escape(dnsEvent.getHostname())).append("\n");
        sb.append("Inet addresses: ").append(dnsEvent.getInetAddresses()).append("\n");
        sb.append("Total resolved addresses: ")
            .append(dnsEvent.getTotalResolvedAddressCount())
            .append("\n");
      } else if (networkLog instanceof ConnectEvent connectEvent) {
        sb.append("Connect event ID: ").append(connectEvent.getId()).append("\n");
        sb.append("Inet address: ").append(connectEvent.getInetAddress()).append("\n");
        sb.append("Port: ").append(connectEvent.getPort()).append("\n");
      }
      serializableNetworkLogs.add(sb.append("\n").toString());
    }
    return serializableNetworkLogs;
  }

  @VisibleForTesting
  public static List<String> getSerializableSecurityLogs(List<SecurityEvent> securityLogs) {
    List<String> serializableNetworkLogs = new ArrayList<>();
    if (securityLogs == null) {
      return serializableNetworkLogs;
    }
    StringBuilder sb;
    SimpleDateFormat formatter = getUtcDateFormatter();
    for (SecurityEvent securityEvent : securityLogs) {
      sb = new StringBuilder();
      sb.append("Security log ID: ").append(securityEvent.getId()).append("\n");
      // Format the nanosecond timestamp into a human-readable UTC string by converting to millis.
      long nanos = securityEvent.getTimeNanos();
      Instant timestampInstant = Instant.ofEpochMilli(nanos / 1_000_000L);
      sb.append("Timestamp (UTC): ")
          .append(formatter.format(Date.from(timestampInstant)))
          .append("\n");
      sb.append(getSecurityEventSeverity(securityEvent.getLogLevel())).append("\n");
      sb.append(getSecurityEventType(securityEvent.getTag())).append("\n");
      if (securityEvent.getData() != null) {
        sb.append(formatPayload(securityEvent.getData())).append("\n");
      }
      serializableNetworkLogs.add(sb.append("\n").toString());
    }
    return serializableNetworkLogs;
  }

  /**
   * Returns the payload of a security event on one line: an array as its elements in brackets, a
   * string in double quotes and {@link #escape escaped}, and a number as it prints.
   */
  @VisibleForTesting
  static String formatPayload(Object payload) {
    if (payload instanceof Object[] values) {
      return Arrays.stream(values)
          .map(CrumblesDeviceAdminReceiver::formatPayload)
          .collect(joining(", ", "[", "]"));
    }
    if (payload instanceof String text) {
      return "\"" + escape(text) + "\"";
    }
    return String.valueOf(payload);
  }

  /**
   * Maximum number of escaped code points kept from an app label before appending {@code "…"}, so
   * that neither padded filler characters nor expanded Unicode escapes can push the app's package
   * name out of view.
   */
  private static final int MAX_ESCAPED_LABEL_CODE_POINTS = 40;

  /**
   * Maximum number of escaped code points kept from a file name before appending {@code "…"}, so
   * that neither long names nor expanded Unicode escapes can grow unboundedly.
   */
  private static final int MAX_ESCAPED_FILE_NAME_CODE_POINTS = 255;

  private static String escapeAndCap(@Nullable CharSequence text, int maxEscapedCodePoints) {
    String value = String.valueOf(text);
    StringBuilder escaped = new StringBuilder();
    int escapedCodePoints = 0;
    for (int i = 0; i < value.length(); ) {
      int codePoint = value.codePointAt(i);
      int mark = escaped.length();
      appendEscapedCodePoint(escaped, codePoint);
      escapedCodePoints += escaped.codePointCount(mark, escaped.length());
      // Reaching the cap exactly still fits, so text that escapes to exactly maxEscapedCodePoints
      // is kept whole. If more follows, the next escape goes past the cap and is replaced by "…".
      if (escapedCodePoints > maxEscapedCodePoints) {
        escaped.setLength(mark);
        return escaped.append('…').toString();
      }
      i += Character.charCount(codePoint);
    }
    return escaped.toString();
  }

  /**
   * Returns {@code label} {@link #escape escaped} and capped to {@value
   * #MAX_ESCAPED_LABEL_CODE_POINTS} escaped code points (followed by {@code "…"} when truncated),
   * so that neither expanded control escapes nor long runs of filler glyphs can push the package
   * name shown next to the label out of view.
   */
  static String escapeLabel(@Nullable CharSequence label) {
    return escapeAndCap(label, MAX_ESCAPED_LABEL_CODE_POINTS);
  }

  /**
   * Returns {@code fileName} {@link #escape escaped} and capped to {@value
   * #MAX_ESCAPED_FILE_NAME_CODE_POINTS} escaped code points (followed by {@code "…"} when
   * truncated).
   */
  static String escapeFileName(@Nullable CharSequence fileName) {
    return escapeAndCap(fileName, MAX_ESCAPED_FILE_NAME_CODE_POINTS);
  }

  /**
   * Returns {@code text} with backslashes and double quotes escaped, and every control, format and
   * line or paragraph separator character written as the Java Unicode escapes of its UTF-16 units,
   * which read back unambiguously even above U+FFFF. Log values can come from other apps or from
   * the network, and such characters would let them end a line and start what reads as a record of
   * their own, or hide or reorder the text around them.
   */
  static String escape(@Nullable String text) {
    String value = String.valueOf(text);
    StringBuilder escaped = new StringBuilder();
    value.codePoints().forEach(codePoint -> appendEscapedCodePoint(escaped, codePoint));
    return escaped.toString();
  }

  private static void appendEscapedCodePoint(StringBuilder escaped, int codePoint) {
    switch (Character.getType(codePoint)) {
      case Character.CONTROL,
          Character.FORMAT,
          Character.LINE_SEPARATOR,
          Character.PARAGRAPH_SEPARATOR -> {
        for (char unit : Character.toChars(codePoint)) {
          escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) unit));
        }
      }
      default -> {
        if (codePoint == '\\' || codePoint == '"') {
          escaped.append('\\');
        }
        escaped.appendCodePoint(codePoint);
      }
    }
  }

  private static String getSecurityEventSeverity(int logLevel) {
    String severity =
        switch (logLevel) {
          case SecurityLog.LEVEL_ERROR -> "Severity: HIGH";
          case SecurityLog.LEVEL_WARNING -> "Severity: MEDIUM";
          case SecurityLog.LEVEL_INFO -> "Severity: LOW";
          default -> "Severity: UNKNOWN";
        };
    return severity;
  }

  private static String getSecurityEventType(int tag) {
    String type =
        switch (tag) {
          case SecurityLog.TAG_ADB_SHELL_CMD -> "ADB shell command: ";
          case SecurityLog.TAG_ADB_SHELL_INTERACTIVE ->
              "ADB interactive shell was opened via \"adb shell\":";
          case SecurityLog.TAG_APP_PROCESS_START -> "App process started: ";
          case SecurityLog.TAG_BACKUP_SERVICE_TOGGLED ->
              "Admin has enabled or disabled backup service: ";
          case SecurityLog.TAG_BLUETOOTH_CONNECTION -> "Attempted to connect to Bluetooth device: ";
          case SecurityLog.TAG_BLUETOOTH_DISCONNECTION ->
              "Attempted to disconnect from Bluetooth device: ";
          case SecurityLog.TAG_CAMERA_POLICY_SET -> "Admin has set policy to disable camera: ";
          case SecurityLog.TAG_CERT_AUTHORITY_INSTALLED ->
              "New root certificate has been installed into system's trusted credential storage: ";
          case SecurityLog.TAG_CERT_AUTHORITY_REMOVED ->
              "New root certificate has been removed from system's trusted credential storage:"
                  + " ";
          case SecurityLog.TAG_CERT_VALIDATION_FAILURE ->
              "Failed to validate X.509v3 certificate: ";
          case SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED ->
              "Cryptographic functionality self test has completed: ";
          case SecurityLog.TAG_KEYGUARD_DISABLED_FEATURES_SET ->
              "Admin has set disabled keyguard features: ";
          case SecurityLog.TAG_KEYGUARD_DISMISSED -> "Keyguard has been dismissed: ";
          case SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT ->
              "Authentication attempt to dismiss the keyguard: ";
          case SecurityLog.TAG_KEYGUARD_SECURED ->
              "The device has been locked, either by the user or by a timeout: ";
          case SecurityLog.TAG_KEY_DESTRUCTION -> "Cryptographic key was destroyed: ";
          case SecurityLog.TAG_KEY_GENERATED -> "Cryptographic key was generated: ";
          case SecurityLog.TAG_KEY_IMPORT -> "Cryptographic key was imported: ";
          case SecurityLog.TAG_KEY_INTEGRITY_VIOLATION ->
              "Failed cryptographic key integrity check: ";
          case SecurityLog.TAG_LOGGING_STARTED -> "Start-up of audit logging: ";
          case SecurityLog.TAG_LOGGING_STOPPED -> "Stop of audit logging: ";
          case SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL ->
              "The audit log buffer has reached 90% of its capacity: ";
          case SecurityLog.TAG_MAX_PASSWORD_ATTEMPTS_SET ->
              "Admin has set a maximum number of failed password attempts before wiping data: ";
          case SecurityLog.TAG_MAX_SCREEN_LOCK_TIMEOUT_SET ->
              "Admin has set a maximum screen lock timeout: ";
          case SecurityLog.TAG_MEDIA_MOUNT -> "Removable media has been mounted on the device: ";
          case SecurityLog.TAG_MEDIA_UNMOUNT ->
              "Removable media has been unmounted from the device: ";
          case SecurityLog.TAG_OS_SHUTDOWN -> "OS shutdown: ";
          case SecurityLog.TAG_OS_STARTUP -> "OS startup: ";
          case SecurityLog.TAG_PACKAGE_INSTALLED -> "Package has been installed: ";
          case SecurityLog.TAG_PACKAGE_UNINSTALLED -> "Package has been uninstalled: ";
          case SecurityLog.TAG_PACKAGE_UPDATED -> "Package has been updated: ";
          case SecurityLog.TAG_PASSWORD_CHANGED ->
              "A user has just changed their lockscreen password: ";
          case SecurityLog.TAG_PASSWORD_COMPLEXITY_REQUIRED ->
              "Admin has set a password complexity requirement, using the platform's pre-defined"
                  + " complexity levels: ";
          case SecurityLog.TAG_PASSWORD_COMPLEXITY_SET ->
              "Admin has set a requirement for password complexity: ";
          case SecurityLog.TAG_PASSWORD_EXPIRATION_SET ->
              "Admin has set a password expiration timeout: ";
          case SecurityLog.TAG_PASSWORD_HISTORY_LENGTH_SET ->
              "Admin has set a password history length: ";
          case SecurityLog.TAG_REMOTE_LOCK -> "Admin remotely locked the device or profile: ";
          case SecurityLog.TAG_SYNC_RECV_FILE ->
              "File was pulled from the device via the adb daemon, for example via adb pull: ";
          case SecurityLog.TAG_SYNC_SEND_FILE ->
              "File was pushed to the device via the adb daemon, for example via adb push: ";
          case SecurityLog.TAG_USER_RESTRICTION_ADDED -> "Admin has set a user restriction: ";
          case SecurityLog.TAG_USER_RESTRICTION_REMOVED -> "Admin has removed a user restriction: ";
          case SecurityLog.TAG_WIFI_CONNECTION ->
              "An event occurred as the device attempted to connect to a managed WiFi network: ";
          case SecurityLog.TAG_WIFI_DISCONNECTION ->
              "The device disconnects from a managed WiFi network: ";
          case SecurityLog.TAG_WIPE_FAILURE -> "Failure to wipe device or user data: ";
          default -> "Unknown security event type";
        };
    return type;
  }

  private static byte[] logsToBytes(List<String> logs) {
    if (logs == null || logs.isEmpty()) {
      return new byte[0];
    }
    return String.join("", logs).getBytes(UTF_8);
  }

  /** Encrypts {@code logsBytes} to {@code activeKey} and saves them as a new pending batch. */
  @CanIgnoreReturnValue
  static Optional<Path> encryptAndSaveLogs(
      Context context, boolean isNetworkBatch, byte[] logsBytes, PublicKey activeKey)
      throws QuotaRefusedException {
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      // Read before the key, so that a key change in between keeps the recipient forgotten.
      long forgottenRecipients = CrumblesDirectBootStore.forgottenRecipients();
      Optional<PublicKey> currentKey = resolveActiveEncryptionKey(context);
      if (currentKey.isEmpty()) {
        return Optional.empty();
      }
      File baseDir = getLogsDirectory(context);
      if (!baseDir.exists()) {
        baseDir.mkdirs();
      }
      return writeEncryptedBatch(
          context, baseDir, logsBytes, currentKey.get(), isNetworkBatch, forgottenRecipients);
    }
  }

  private static Optional<Path> writeEncryptedBatch(
      Context context,
      File baseDir,
      byte[] logsBytes,
      PublicKey activeKey,
      @Nullable Boolean isNetworkBatch,
      long forgottenRecipients)
      throws QuotaRefusedException {
    synchronized (CrumblesSendAndMarkProcessingWorker.UPLOAD_LOCK) {
      CrumblesLogsEncryptor logsEncryptor = CrumblesMain.getLogsEncryptorInstance();
      // Every batch carries the activity log records written since the previous stored batch.
      CrumblesAuditExcerpt auditExcerpt =
          CrumblesAppAuditLogger.getInstance(context).getUnshippedExcerpt();
      // Read once, so that the recipient is remembered with what this batch sealed.
      String deviceId = CrumblesDeviceIdManager.getDeviceId(context);
      ImmutableList<ByteString> attestationChain =
          new CrumblesBatchSigner(context).attestationChainToSeal();
      LogBatch logBatch =
          logsEncryptor.encryptLogs(
              context,
              Bytes.concat(logsBytes, auditExcerpt.toBytes()),
              activeKey,
              deviceId,
              attestationChain);
      if (logBatch == null) {
        Log.e(TAG, "Failed to encrypt logs: encryption returned null.");
        CrumblesAppAuditLogger.getInstance(context)
            .logEvent("ENCRYPT_FAILED", "Log batch encryption failed.");
        return Optional.empty();
      }
      if (isNetworkBatch != null
          && !CrumblesLogStorageQuota.admitNewBatch(
              context,
              baseDir,
              CrumblesConstants.MAX_LOGS_DIRECTORY_BYTES,
              isNetworkBatch,
              logBatch.getSerializedSize(),
              CrumblesLogStorageQuota.SIGNATURE_ALLOWANCE_BYTES)) {
        Log.w(TAG, "Storage cap reached; the batch was not written rather than evicting evidence.");
        throw new QuotaRefusedException();
      }
      // A random name never repeats in practice, which matters because serializeBytes replaces an
      // existing file of the same name.
      Path encryptedLogFilePath =
          logsEncryptor.serializeBytes(
              signIfPossible(context, logBatch, attestationChain), baseDir, newBatchFileName());
      // Only a stored batch delivers the records; otherwise the next batch carries them again.
      CrumblesAppAuditLogger.getInstance(context).markShipped(auditExcerpt);
      // The security logs collected before the next first unlock go to the same recipient, in
      // batches without a batch-wrapped key: only a recipient that unwraps this batch's key itself,
      // with RSA-OAEP, can read them.
      if (logBatch
              .getKey()
              .getKeyEncryptionType()
              .equals(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256)
          && logBatch.getKey().getBatchWrappedSymmetricKey().isEmpty()) {
        new CrumblesDirectBootStore(context)
            .rememberRecipient(forgottenRecipients, activeKey, deviceId, attestationChain);
      }
      Log.i(TAG, "Logs encrypted and serialized to file: " + encryptedLogFilePath);
      return Optional.of(encryptedLogFilePath);
    }
  }

  /**
   * Returns a name for a new batch file: {@value #BATCH_FILE_NAME_RANDOM_BYTES} random bytes, in
   * hex.
   *
   * <p>The storage provider sees this name, so it carries neither the collection time nor the name
   * of the app. Recipients order batches by their signed sequence numbers instead.
   */
  private static String newBatchFileName() {
    byte[] randomBytes = new byte[BATCH_FILE_NAME_RANDOM_BYTES];
    secureRandom.nextBytes(randomBytes);
    return BaseEncoding.base16().lowerCase().encode(randomBytes) + ".bin";
  }

  /**
   * Returns {@code batch} numbered and signed, or unchanged if it cannot be signed, as when it does
   * not seal {@code attestationChain} of the signing key. Its recipient can still read an unsigned
   * batch, while dropping it would lose logs the platform no longer has.
   */
  private static LogBatch signIfPossible(
      Context context, LogBatch batch, List<ByteString> attestationChain) {
    try {
      return new CrumblesBatchSigner(context).sign(batch, attestationChain);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to sign a log batch; writing it unsigned.", e);
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              AUDIT_EVENT_BATCH_SIGNING_FAILED,
              "Log batch written without a signature or sequence number: signing failed.");
      return batch;
    }
  }

  @Override
  public void onUserAdded(
      @NonNull Context context, @NonNull Intent intent, @NonNull UserHandle addedUser) {
    retrieveInBackground(goAsync(), () -> reconcileSecondaryUserPause(context));
  }

  @Override
  public void onUserRemoved(
      @NonNull Context context, @NonNull Intent intent, @NonNull UserHandle removedUser) {
    retrieveInBackground(
        goAsync(),
        () -> {
          // Collection resumes with the logs kept from before the restart, if they wait.
          if (!reconcileSecondaryUserPause(context)) {
            savePreRebootLogsIfPending(context);
          }
        });
  }

  /**
   * As device owner, keeps other users and profiles off the device while security logging is on,
   * since any of them pauses log delivery. Adds whichever of {@code DISALLOW_ADD_USER} and the
   * managed, clone and private profile restrictions are not in effect yet, and on disable clears
   * only those it added, so pre-existing policy stays. Android already applies the profile
   * restrictions to any device owner, so Crumbles only reasserts them if they were lifted, for
   * example through adb; Android then removes a private space created meanwhile.
   */
  static void syncDisallowAddUserRestriction(Context context, boolean enabled) {
    CrumblesLoggingAccess access = CrumblesLoggingAccess.forSecurityLogging(context);
    if (!access.mode().equals(CrumblesLoggingAccess.Mode.DEVICE_OWNER)) {
      return;
    }
    DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
    UserManager userManager = context.getSystemService(UserManager.class);
    SharedPreferences prefs = prefs(context);
    for (Map.Entry<String, String> managed : managedUserRestrictions().entrySet()) {
      String restriction = managed.getKey();
      try {
        if (enabled && !userManager.hasUserRestriction(restriction)) {
          dpm.addUserRestriction(access.admin(), restriction);
          prefs.edit().putBoolean(managed.getValue(), true).apply();
        } else if (!enabled && prefs.getBoolean(managed.getValue(), false)) {
          dpm.clearUserRestriction(access.admin(), restriction);
          prefs.edit().remove(managed.getValue()).apply();
        }
      } catch (SecurityException e) {
        Log.w(TAG, "Unable to update the " + restriction + " restriction.", e);
      }
    }
  }

  /**
   * Returns the user restrictions that Crumbles manages as device owner, each mapped to the
   * preference recording that Crumbles added it.
   */
  private static ImmutableMap<String, String> managedUserRestrictions() {
    ImmutableMap.Builder<String, String> restrictions =
        ImmutableMap.<String, String>builder()
            .put(UserManager.DISALLOW_ADD_USER, PREF_MANAGED_DISALLOW_ADD_USER)
            .put(UserManager.DISALLOW_ADD_MANAGED_PROFILE, "managedDisallowAddManagedProfile")
            .put(DISALLOW_ADD_CLONE_PROFILE, "managedDisallowAddCloneProfile");
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
      restrictions.put(
          UserManager.DISALLOW_ADD_PRIVATE_PROFILE, "managedDisallowAddPrivateProfile");
    }
    return restrictions.buildOrThrow();
  }

  /**
   * Returns whether another user pauses platform log delivery: any secondary or guest user visible
   * to a device owner, or an unaffiliated user or profile for which the platform refuses logs to
   * the device owner or a logging delegate.
   */
  static boolean hasSecondaryUsers(Context context) {
    DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
    CrumblesLoggingAccess sec = CrumblesLoggingAccess.forSecurityLogging(context);
    if (sec.mode().equals(CrumblesLoggingAccess.Mode.DEVICE_OWNER)) {
      try {
        List<UserHandle> users = dpm.getSecondaryUsers(sec.admin());
        if (users != null && !users.isEmpty()) {
          return true;
        }
      } catch (SecurityException e) {
        Log.w(TAG, "Unable to read secondary users.", e);
      }
      // The secondary users leave out managed profiles, so a device owner probes as well.
      return isRetrievalRefused(
          sec,
          () -> dpm.retrievePreRebootSecurityLogs(sec.admin()),
          () -> CrumblesLoggingAccess.forSecurityLogging(context));
    }
    return isRetrievalRefused(
            sec,
            () -> dpm.retrievePreRebootSecurityLogs(/* admin= */ null),
            () -> CrumblesLoggingAccess.forSecurityLogging(context))
        || isRetrievalRefused(
            CrumblesLoggingAccess.forNetworkLogging(context),
            () -> dpm.retrieveNetworkLogs(/* admin= */ null, Long.MIN_VALUE),
            () -> CrumblesLoggingAccess.forNetworkLogging(context));
  }

  /**
   * Returns whether the platform refuses {@code probe} while Crumbles keeps {@code access}, as it
   * does while an unaffiliated user or profile is present.
   */
  private static boolean isRetrievalRefused(
      CrumblesLoggingAccess access, Supplier<?> probe, Supplier<CrumblesLoggingAccess> recheck) {
    if (!access.isAvailable()) {
      return false;
    }
    try {
      var unused = probe.get();
      return false;
    } catch (SecurityException e) {
      return recheck.get().mode().equals(access.mode());
    }
  }

  /**
   * Retrieves logs and resumes collection, or pauses it and returns null if the platform refuses
   * while Crumbles keeps its access, since another user is present. Rethrows if access was lost.
   */
  @Nullable
  private static <T> List<T> retrieveLogsOrPause(
      Context context, Supplier<List<T>> retrieval, Supplier<CrumblesLoggingAccess> currentAccess) {
    try {
      List<T> logs = retrieval.get();
      setSecondaryUserPaused(context, /* paused= */ false, /* loggingOn= */ true);
      return logs;
    } catch (SecurityException e) {
      if (!currentAccess.get().isAvailable()) {
        throw e;
      }
      Log.w(TAG, "Platform rejected log retrieval while another user is present.", e);
      setSecondaryUserPaused(context, /* paused= */ true, /* loggingOn= */ true);
      return null;
    }
  }

  /** Reconciles the audit log, ongoing alert and pause notice batch with secondary-user state. */
  @CanIgnoreReturnValue
  static boolean reconcileSecondaryUserPause(Context context) {
    synchronized (PAUSE_LOCK) {
      boolean loggingOn = isSecurityOrNetworkLoggingOn(context, /* auditAccessLoss= */ false);
      boolean paused = loggingOn && hasSecondaryUsers(context);
      setSecondaryUserPaused(context, paused, loggingOn);
      return paused;
    }
  }

  private static void setSecondaryUserPaused(Context context, boolean paused, boolean loggingOn) {
    synchronized (PAUSE_LOCK) {
      SharedPreferences prefs = prefs(context);
      boolean wasPaused = prefs.getBoolean(PREF_PAUSED_BY_SECONDARY_USER, false);
      CrumblesAppAuditLogger logger = CrumblesAppAuditLogger.getInstance(context);
      if (paused) {
        notifyCollectionPaused(context);
        if (!wasPaused) {
          prefs.edit().putBoolean(PREF_PAUSED_BY_SECONDARY_USER, true).apply();
          logger.logEvent(
              AUDIT_EVENT_COLLECTION_PAUSED,
              "Log collection paused while a secondary or guest user is present.");
          sealCollectionPausedBatch(context);
        }
      } else if (wasPaused) {
        prefs.edit().remove(PREF_PAUSED_BY_SECONDARY_USER).apply();
        NotificationManagerCompat.from(context)
            .cancel(CrumblesConstants.COLLECTION_PAUSED_NOTIFICATION_ID);
        if (loggingOn) {
          logger.logEvent(
              AUDIT_EVENT_COLLECTION_RESUMED,
              "Log collection resumed after secondary or guest users were removed; unretrieved"
                  + " platform logs buffered before removal were discarded by the platform.");
        }
      }
    }
  }

  static SharedPreferences prefs(Context context) {
    return context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
  }

  static long currentSecurityLoggingSessionKey(Context context) {
    return loggingSessionKey(context, PREF_SECURITY_LOGGING_ENABLE_EPOCH);
  }

  static long currentNetworkLoggingSessionKey(Context context) {
    return loggingSessionKey(context, PREF_NETWORK_LOGGING_ENABLE_EPOCH);
  }

  private static long loggingSessionKey(Context context, String epochKey) {
    int bootCount = currentBootCount(context);
    int epoch = prefs(context).getInt(epochKey, 0);
    return (((long) bootCount) << 32) | (epoch & 0xFFFFFFFFL);
  }

  /** Returns how many times the device has booted, or -1 if the platform does not tell. */
  private static int currentBootCount(Context context) {
    return Settings.Global.getInt(
        context.getContentResolver(), Settings.Global.BOOT_COUNT, /* def= */ -1);
  }

  static void bumpSecurityLoggingEnableEpoch(Context context) {
    bumpEpoch(context, PREF_SECURITY_LOGGING_ENABLE_EPOCH);
  }

  static void bumpNetworkLoggingEnableEpoch(Context context) {
    bumpEpoch(context, PREF_NETWORK_LOGGING_ENABLE_EPOCH);
  }

  static void bumpLoggingEnableEpoch(Context context) {
    bumpSecurityLoggingEnableEpoch(context);
    bumpNetworkLoggingEnableEpoch(context);
  }

  private static void bumpEpoch(Context context, String key) {
    synchronized (PAUSE_LOCK) {
      SharedPreferences prefs = prefs(context);
      prefs.edit().putInt(key, prefs.getInt(key, 0) + 1).apply();
    }
  }

  private static void recordSecurityEventIds(Context context, List<SecurityEvent> events) {
    if (events.isEmpty()) {
      return;
    }
    long firstId = events.get(0).getId();
    long lastId = Iterables.getLast(events).getId();
    synchronized (PAUSE_LOCK) {
      SharedPreferences prefs = prefs(context);
      long session = currentSecurityLoggingSessionKey(context);
      long previousSession = prefs.getLong(PREF_SECURITY_ID_SESSION, Long.MIN_VALUE);
      OptionalLong previousLastId =
          previousSession == session && prefs.contains(PREF_LAST_SECURITY_ID)
              ? OptionalLong.of(prefs.getLong(PREF_LAST_SECURITY_ID, -1L))
              // The first retrieval after the unlock follows those before it.
              : new CrumblesBootRecord(context).takeLastEventIdBeforeUnlock();
      if (previousLastId.isPresent()) {
        long prevLastId = previousLastId.getAsLong();
        if (firstId > prevLastId + 1) {
          logSequenceGap(context, "Security log event ID", prevLastId + 1, firstId - 1);
        } else if (firstId <= prevLastId) {
          logSequenceReset(context, "Security log event IDs", firstId, prevLastId);
        }
      } else if (previousSession != Long.MIN_VALUE
          && (int) previousSession == (int) session
          && firstId > 0) {
        // Logging stayed on across the restart, so this boot's event IDs started at 0.
        logSequenceGap(context, "Security log event ID", 0, firstId - 1);
      }
      prefs
          .edit()
          .putLong(PREF_SECURITY_ID_SESSION, session)
          .putLong(PREF_LAST_SECURITY_ID, lastId)
          .apply();
    }
  }

  static void recordNetworkBatchToken(Context context, long batchToken) {
    synchronized (PAUSE_LOCK) {
      SharedPreferences prefs = prefs(context);
      long session = currentNetworkLoggingSessionKey(context);
      long previousSession = prefs.getLong(PREF_NETWORK_TOKEN_SESSION, Long.MIN_VALUE);
      if (previousSession == session && prefs.contains(PREF_LAST_NETWORK_TOKEN)) {
        long prevToken = prefs.getLong(PREF_LAST_NETWORK_TOKEN, -1L);
        if (batchToken > prevToken + 1) {
          logSequenceGap(context, "Network log batch token", prevToken + 1, batchToken - 1);
        } else if (batchToken <= prevToken) {
          logSequenceReset(context, "Network log batch token", batchToken, prevToken);
        }
      } else if (previousSession != Long.MIN_VALUE
          && (int) previousSession == (int) session
          && batchToken > 1) {
        // Logging stayed on across the restart, so this boot's tokens started at 1.
        logSequenceGap(context, "Network log batch token", 1, batchToken - 1);
      }
      prefs
          .edit()
          .putLong(PREF_NETWORK_TOKEN_SESSION, session)
          .putLong(PREF_LAST_NETWORK_TOKEN, batchToken)
          .apply();
    }
  }

  /**
   * Before the first unlock, checks that the event IDs of {@code events} follow those retrieved
   * before them in this boot, or start at 0 if none were, and records the last one in
   * device-encrypted storage, for the first retrieval after the unlock to check.
   */
  private static void recordSecurityEventIdsBeforeUnlock(
      Context context, List<SecurityEvent> events) {
    if (events.isEmpty()) {
      return;
    }
    CrumblesBootRecord record = new CrumblesBootRecord(context);
    OptionalLong previousLastId = record.lastEventIdBeforeUnlock();
    long firstId = events.get(0).getId();
    // Security logging is on, and the platform numbers its events from 0 at every boot and at every
    // enable, so the first retrieval of a boot starts at 0 unless events were lost.
    long expectedFirstId = previousLastId.isPresent() ? previousLastId.getAsLong() + 1 : 0;
    if (firstId > expectedFirstId) {
      reportPossibleLoss(
          context,
          sequenceGapMessage("Security log event ID", expectedFirstId, firstId - 1),
          /* alertUser= */ true);
    } else if (previousLastId.isPresent() && firstId <= previousLastId.getAsLong()) {
      reportPossibleLoss(
          context,
          sequenceResetMessage("Security log event IDs", firstId, previousLastId.getAsLong()),
          /* alertUser= */ true);
    }
    record.recordLastEventIdBeforeUnlock(Iterables.getLast(events).getId());
  }

  private static String sequenceGapMessage(String label, long missingStart, long missingEnd) {
    return label
        + " gap detected ("
        + missingStart
        + ".."
        + missingEnd
        + " missing): platform logs were lost before retrieval.";
  }

  private static String sequenceResetMessage(String label, long newValue, long prevValue) {
    return label
        + " reset ("
        + newValue
        + " after "
        + prevValue
        + "): platform logs were lost before retrieval.";
  }

  private static void logSequenceGap(
      Context context, String label, long missingStart, long missingEnd) {
    String message = sequenceGapMessage(label, missingStart, missingEnd);
    Log.e(TAG, message);
    CrumblesAppAuditLogger.getInstance(context).logEvent(AUDIT_EVENT_LOGS_LOST, message);
    notifyLossReported(context);
  }

  private static void logSequenceReset(
      Context context, String label, long newValue, long prevValue) {
    String message = sequenceResetMessage(label, newValue, prevValue);
    Log.e(TAG, message);
    CrumblesAppAuditLogger.getInstance(context).logEvent(AUDIT_EVENT_LOGS_LOST, message);
    notifyLossReported(context);
  }

  /**
   * Saves an empty batch, numbered and signed like any other, so that its recipient keeps hearing
   * from a device that collects logs but has produced none for a while.
   */
  static void saveHeartbeatBatch(Context context) {
    if (reconcileSecondaryUserPause(context)
        || !isSecurityOrNetworkLoggingOn(context, /* auditAccessLoss= */ true)) {
      Log.i(TAG, "Security and network logging are off, paused or out of reach; skipping.");
      return;
    }
    Optional<PublicKey> activeKey = resolveActiveEncryptionKey(context);
    if (activeKey.isEmpty() || !isReadyForLogging(context)) {
      Log.w(TAG, "Encryption key or storage not ready; skipping the heartbeat.");
      return;
    }
    if (!drainStagedBatches(context, activeKey.get())) {
      Log.w(TAG, "Older staged batches are waiting; skipping the heartbeat.");
      return;
    }
    try {
      encryptAndSaveLogs(context, /* isNetworkBatch= */ false, new byte[0], activeKey.get());
    } catch (CrumblesLogsEncryptionException | QuotaRefusedException e) {
      Log.e(TAG, "Failed to save the heartbeat batch.", e);
    }
  }

  /**
   * Returns whether security or network logging is on and Crumbles may retrieve those logs, as the
   * device owner or as their delegate.
   *
   * <p>Network logging counts too: a device owner can delegate it alone, and the recipient of the
   * network batches also needs heartbeats to tell a quiet device apart from dropped batches.
   *
   * <p>Only callers that set {@code auditAccessLoss} record a lost access in the audit log, so that
   * the pause reconciliation doesn't repeat what the watchdog or the heartbeat records.
   */
  private static boolean isSecurityOrNetworkLoggingOn(Context context, boolean auditAccessLoss) {
    DevicePolicyManager devicePolicyManager = context.getSystemService(DevicePolicyManager.class);
    // Ask only about logs that Crumbles may access, because the platform throws for anyone else.
    CrumblesLoggingAccess securityAccess = CrumblesLoggingAccess.forSecurityLogging(context);
    try {
      if (securityAccess.isAvailable()
          && devicePolicyManager.isSecurityLoggingEnabled(securityAccess.admin())) {
        return true;
      }
    } catch (SecurityException e) {
      Log.w(TAG, "SecurityException checking security logging status.", e);
      if (auditAccessLoss) {
        CrumblesAppAuditLogger.getInstance(context)
            .logEvent("SECURITY_LOGGING_ACCESS_LOST", "Crumbles lost access to security logging.");
      }
    }

    CrumblesLoggingAccess networkAccess = CrumblesLoggingAccess.forNetworkLogging(context);
    try {
      return networkAccess.isAvailable()
          && devicePolicyManager.isNetworkLoggingEnabled(networkAccess.admin());
    } catch (SecurityException e) {
      Log.w(TAG, "SecurityException checking network logging status.", e);
      if (auditAccessLoss) {
        CrumblesAppAuditLogger.getInstance(context)
            .logEvent("NETWORK_LOGGING_ACCESS_LOST", "Crumbles lost access to network logging.");
      }
      return false;
    }
  }

  /**
   * Retrieves in the background, once the device has booted and the user has unlocked it, the logs
   * that are waiting, records wall-clock changes that arrive before the first unlock, and hands
   * every other broadcast to {@link DeviceAdminReceiver}.
   *
   * <p>Before the first unlock after a restart, only device-encrypted storage is available: the
   * receiver then collects security logs at the locked boot and when the platform announces them,
   * and leaves every other broadcast.
   *
   * <p>Only the system can send this receiver a broadcast: it alone holds {@code
   * BIND_DEVICE_ADMIN}, and the boot broadcasts are protected broadcasts.
   */
  @Override
  public void onReceive(@NonNull Context context, @NonNull Intent intent) {
    Log.i(TAG, "onReceive: " + intent.getAction());
    String action = intent.getAction();
    if (!isUserUnlocked(context)) {
      if (Objects.equals(action, Intent.ACTION_LOCKED_BOOT_COMPLETED)) {
        retrieveInBackground(goAsync(), () -> handleLockedBootCompleted(context));
      } else if (Objects.equals(action, Intent.ACTION_TIME_CHANGED)) {
        retrieveInBackground(goAsync(), () -> recordTimeChangedBeforeUnlock(context));
      } else if (Objects.equals(action, ACTION_SECURITY_LOGS_AVAILABLE)
          || Objects.equals(action, ACTION_NETWORK_LOGS_AVAILABLE)) {
        super.onReceive(context, intent);
      }
      return;
    }
    if (Objects.equals(action, Intent.ACTION_BOOT_COMPLETED)) {
      retrieveInBackground(goAsync(), () -> handleBootCompleted(context));
      return;
    }
    if (Objects.equals(action, Intent.ACTION_TIME_CHANGED)) {
      retrieveInBackground(goAsync(), () -> handleTimeChanged(context));
      return;
    }
    super.onReceive(context, intent);
    initDpm(context);
  }
}
