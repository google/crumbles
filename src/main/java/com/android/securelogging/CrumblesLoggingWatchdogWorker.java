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
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.UserManager;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.common.base.Ascii;
import java.util.EnumSet;

/**
 * A {@link Worker} that notices when security or network logging is turned on or off, whether from
 * the app, by another admin or by a policy reset.
 *
 * <p>Each run compares the current state with the one observed by the previous run and records any
 * transition in the app audit log. Turning logging off also alerts the user. Network logging is
 * only watched while the user allows network collection, since turning that off turns network
 * logging off.
 *
 * <p>The worker also runs when Crumbles is a security or network logging delegate rather than the
 * device owner. Losing access to a type of logging while it was on, because the device owner
 * revoked the delegation or Crumbles lost device owner status, is treated like that logging being
 * turned off.
 *
 * <p>Each run also reports a device key pair that the Keystore permanently invalidated, as log
 * retrieval does, so that it shows even while no logs arrive.
 */
public class CrumblesLoggingWatchdogWorker extends Worker {

  private static final String TAG = "CrumblesLoggingWatchdogWorker";

  @VisibleForTesting
  static final String AUDIT_EVENT_USER_ADDITION_ALLOWED = "USER_ADDITION_ALLOWED";

  @VisibleForTesting
  static final String AUDIT_EVENT_USER_ADDITION_BLOCKED = "USER_ADDITION_BLOCKED";

  /** Preference holding whether the previous run found that users can be added unseen. */
  private static final String PREF_USER_ADDITION_ALLOWED = "userAdditionAllowed";

  @VisibleForTesting static final String AUDIT_EVENT_LOGGING_DISABLED = "SECURITY_LOGGING_DISABLED";
  @VisibleForTesting static final String AUDIT_EVENT_LOGGING_ENABLED = "SECURITY_LOGGING_ENABLED";

  @VisibleForTesting
  static final String AUDIT_EVENT_LOGGING_ACCESS_LOST = "SECURITY_LOGGING_ACCESS_LOST";

  @VisibleForTesting
  static final String AUDIT_EVENT_NETWORK_LOGGING_DISABLED = "NETWORK_LOGGING_DISABLED";

  @VisibleForTesting
  static final String AUDIT_EVENT_NETWORK_LOGGING_ENABLED = "NETWORK_LOGGING_ENABLED";

  @VisibleForTesting
  static final String AUDIT_EVENT_NETWORK_LOGGING_ACCESS_LOST = "NETWORK_LOGGING_ACCESS_LOST";

  /** The state of a type of logging that a run observes. */
  private enum ObservedState {
    ENABLED,
    DISABLED,
    /** Crumbles is neither the device owner nor the delegate for the type of logging. */
    NO_ACCESS
  }

  /** A type of logging that the worker watches. */
  private enum WatchedLogging {
    SECURITY(
        "Security logging",
        CrumblesConstants.PREF_LAST_OBSERVED_LOGGING_ENABLED,
        AUDIT_EVENT_LOGGING_ENABLED,
        AUDIT_EVENT_LOGGING_DISABLED,
        AUDIT_EVENT_LOGGING_ACCESS_LOST) {
      @Override
      boolean isWatched(Context context) {
        return true;
      }

      @Override
      CrumblesLoggingAccess access(Context context) {
        return CrumblesLoggingAccess.forSecurityLogging(context);
      }

      @Override
      boolean isEnabled(DevicePolicyManager devicePolicyManager, @Nullable ComponentName admin) {
        return devicePolicyManager.isSecurityLoggingEnabled(admin);
      }
    },
    NETWORK(
        "Network logging",
        CrumblesConstants.PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED,
        AUDIT_EVENT_NETWORK_LOGGING_ENABLED,
        AUDIT_EVENT_NETWORK_LOGGING_DISABLED,
        AUDIT_EVENT_NETWORK_LOGGING_ACCESS_LOST) {
      @Override
      boolean isWatched(Context context) {
        return CrumblesCollectionScope.isNetworkCollectionEnabled(context);
      }

      @Override
      CrumblesLoggingAccess access(Context context) {
        return CrumblesLoggingAccess.forNetworkLogging(context);
      }

      @Override
      boolean isEnabled(DevicePolicyManager devicePolicyManager, @Nullable ComponentName admin) {
        return devicePolicyManager.isNetworkLoggingEnabled(admin);
      }
    };

    /** Names the type of logging at the start of a sentence. */
    final String label;

    /** Preference holding whether the type of logging was on when the previous run checked. */
    final String lastObservedPreference;

    final String enabledEvent;
    final String disabledEvent;
    final String accessLostEvent;

    WatchedLogging(
        String label,
        String lastObservedPreference,
        String enabledEvent,
        String disabledEvent,
        String accessLostEvent) {
      this.label = label;
      this.lastObservedPreference = lastObservedPreference;
      this.enabledEvent = enabledEvent;
      this.disabledEvent = disabledEvent;
      this.accessLostEvent = accessLostEvent;
    }

    /** Returns whether the type of logging is watched now. */
    abstract boolean isWatched(Context context);

    /** Resolves how Crumbles accesses the type of logging. */
    abstract CrumblesLoggingAccess access(Context context);

    /** Returns whether the type of logging is on, asking as {@code admin}. */
    abstract boolean isEnabled(
        DevicePolicyManager devicePolicyManager, @Nullable ComponentName admin);
  }

  public CrumblesLoggingWatchdogWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  @NonNull
  @Override
  public Result doWork() {
    Context context = getApplicationContext();
    reportInvalidatedDeviceKey(context);
    boolean anyTurnedOff = false;
    for (WatchedLogging logging : EnumSet.allOf(WatchedLogging.class)) {
      if (logging.isWatched(context)) {
        if (checkLoggingState(context, logging)) {
          anyTurnedOff = true;
        }
      }
    }
    if (anyTurnedOff) {
      boolean anyEnabled = false;
      for (WatchedLogging logging : EnumSet.allOf(WatchedLogging.class)) {
        if (logging.isWatched(context)
            && observeLoggingState(context, logging) == ObservedState.ENABLED) {
          anyEnabled = true;
          break;
        }
      }
      if (!anyEnabled) {
        CrumblesDeviceAdminReceiver.sealFinalBatch(context);
      }
    }
    recordUserAdditionAllowedChange(context);
    if (!CrumblesDeviceAdminReceiver.reconcileSecondaryUserPause(context)) {
      CrumblesDeviceAdminReceiver.drainDeferredNetworkLogsIfPossible(context);
    }
    return Result.success();
  }

  /**
   * Compares the state of {@code logging} with the one observed by the previous run and records any
   * transition. Returns true if the state transitioned to DISABLED or NO_ACCESS.
   */
  private static boolean checkLoggingState(Context context, WatchedLogging logging) {
    ObservedState state = observeLoggingState(context, logging);

    SharedPreferences preferences =
        context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    boolean hasPreviousState = preferences.contains(logging.lastObservedPreference);
    boolean wasEnabled =
        preferences.getBoolean(logging.lastObservedPreference, /* defValue= */ false);
    // Without access the state is unknown: only report losing access if logging was last seen on.
    if (state == ObservedState.NO_ACCESS && !wasEnabled) {
      Log.w(TAG, "No access to " + Ascii.toLowerCase(logging.label) + "; skipping its check.");
      return false;
    }
    boolean isEnabled = state == ObservedState.ENABLED;
    preferences.edit().putBoolean(logging.lastObservedPreference, isEnabled).apply();
    if (logging == WatchedLogging.SECURITY) {
      CrumblesDeviceAdminReceiver.syncDisallowAddUserRestriction(context, isEnabled);
    }

    // The first run only records a baseline, since there is no earlier state to compare with.
    if (hasPreviousState && wasEnabled != isEnabled) {
      if (logging == WatchedLogging.SECURITY) {
        CrumblesDeviceAdminReceiver.bumpSecurityLoggingEnableEpoch(context);
      }
      logTransition(context, logging, state);
      if (state == ObservedState.DISABLED || state == ObservedState.NO_ACCESS) {
        return true;
      }
    }
    return false;
  }

  /** Reports a permanently invalidated device key pair, unless logs go to an external key. */
  private static void reportInvalidatedDeviceKey(Context context) {
    if (!CrumblesExternalPublicKeyManager.getInstance(context).isExternalKeySelected()) {
      var _ = CrumblesDeviceAdminReceiver.reportIfDeviceKeyInvalidated(context);
    }
  }

  /** Reads the state of {@code logging}, as the device owner or as its delegate. */
  private static ObservedState observeLoggingState(Context context, WatchedLogging logging) {
    CrumblesLoggingAccess access = logging.access(context);
    DevicePolicyManager devicePolicyManager =
        (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
    if (devicePolicyManager == null || !access.isAvailable()) {
      return ObservedState.NO_ACCESS;
    }
    boolean isEnabled;
    try {
      isEnabled = logging.isEnabled(devicePolicyManager, access.admin());
    } catch (SecurityException e) {
      // The device owner can revoke the delegation between the access check and this call.
      Log.w(TAG, "Lost access to " + Ascii.toLowerCase(logging.label) + " while reading it.", e);
      return ObservedState.NO_ACCESS;
    }
    return isEnabled ? ObservedState.ENABLED : ObservedState.DISABLED;
  }

  /** Records a logging state change in the audit log and alerts the user if logging stopped. */
  private static void logTransition(Context context, WatchedLogging logging, ObservedState state) {
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(context);
    switch (state) {
      case ENABLED -> auditLogger.logEvent(logging.enabledEvent, logging.label + " was turned on.");
      case DISABLED -> {
        auditLogger.logEvent(logging.disabledEvent, logging.label + " was turned off.");
        notifyLoggingDisabled(context);
      }
      case NO_ACCESS -> {
        auditLogger.logEvent(
            logging.accessLostEvent,
            "Crumbles lost access to " + Ascii.toLowerCase(logging.label) + ".");
        notifyLoggingDisabled(context);
      }
    }
  }

  // Suppress "MissingPermission" and "PendingIntentMutability" because a missing notification
  // permission is handled at runtime and PendingIntent.FLAG_IMMUTABLE is explicitly supplied.
  @SuppressWarnings({"MissingPermission", "PendingIntentMutability"})
  private static void notifyLoggingDisabled(Context context) {
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
            /* requestCode= */ 0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

    Notification notification =
        new NotificationCompat.Builder(
                context, CrumblesConstants.ACTION_NEEDED_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(context.getString(R.string.notification_title_sync_turned_off))
            .setContentText(context.getString(R.string.notification_text_sync_turned_off))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build();

    try {
      NotificationManagerCompat.from(context)
          .notify(CrumblesConstants.LOGGING_DISABLED_NOTIFICATION_ID, notification);
    } catch (SecurityException e) {
      Log.w(TAG, "Notification permission not granted, skipping notification.", e);
    }
  }

  /**
   * Records once per change whether users can be added while Crumbles collects as a delegate. A
   * delegate gets no callback when a user is added or removed, so a user added and removed between
   * two runs pauses collection and discards the logs buffered meanwhile without a pause record;
   * only the device owner's {@code DISALLOW_ADD_USER} prevents that.
   */
  private static void recordUserAdditionAllowedChange(Context context) {
    boolean isDelegate =
        CrumblesLoggingAccess.forSecurityLogging(context)
                .mode()
                .equals(CrumblesLoggingAccess.Mode.DELEGATE)
            || CrumblesLoggingAccess.forNetworkLogging(context)
                .mode()
                .equals(CrumblesLoggingAccess.Mode.DELEGATE);
    boolean allowed =
        isDelegate
            && !context
                .getSystemService(UserManager.class)
                .hasUserRestriction(UserManager.DISALLOW_ADD_USER);
    SharedPreferences preferences =
        context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    if (allowed == preferences.getBoolean(PREF_USER_ADDITION_ALLOWED, /* defValue= */ false)) {
      return;
    }
    preferences.edit().putBoolean(PREF_USER_ADDITION_ALLOWED, allowed).apply();
    CrumblesAppAuditLogger auditLogger = CrumblesAppAuditLogger.getInstance(context);
    if (allowed) {
      auditLogger.logEvent(
          AUDIT_EVENT_USER_ADDITION_ALLOWED,
          "The device owner lets users be added: a user added and removed between two checks"
              + " would pause collection and discard buffered logs without a pause record.");
    } else {
      auditLogger.logEvent(
          AUDIT_EVENT_USER_ADDITION_BLOCKED,
          "Users can no longer be added unseen: the device owner disallows adding users, or"
              + " Crumbles no longer collects as a delegate.");
    }
  }
}
