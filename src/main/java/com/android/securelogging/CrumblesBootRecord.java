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

import android.content.Context;
import android.content.SharedPreferences;
import java.util.Map;
import java.util.OptionalLong;

/**
 * Records what Crumbles knows about the restarts of the device, so that it can tell when security
 * logs may have been lost across one: whether this boot handled the security logs that the platform
 * kept from before its restart, the boot counts of the restarts, and what was retrieved before the
 * last restart.
 *
 * <p>Everything is keyed on the restarts that Crumbles recorded, not on the live boot count, which
 * the adb shell can change at any time: a boot handles its pre-reboot logs once, and the boot
 * counts recorded at the restarts tell how many boots never did.
 *
 * <p>The record lives in device-encrypted storage, which is readable before the first unlock after
 * a restart, unlike the credential-encrypted storage that holds everything else.
 */
final class CrumblesBootRecord {

  private static final String PREFS_NAME = "crumbles_boot_record";
  private static final String PREF_RESTARTS = "restarts";
  private static final String PREF_RESTART_BOOT_COUNT = "restartBootCount";
  private static final String PREF_CURRENT_BOOT_COUNT = "currentBootCount";
  private static final String PREF_PRE_REBOOT_LOGS_PENDING = "preRebootLogsPending";
  private static final String PREF_HANDLED_BOOT_COUNT = "preRebootLogsBootCount";
  private static final String PREF_HANDLED_RESTART = "preRebootLogsRestart";
  private static final String PREF_LOGGING_ON_RESTART = "securityLoggingOnRestart";
  private static final String PREF_RETRIEVAL_MILLIS = "securityRetrievalMillis";
  private static final String PREF_RETRIEVAL_BEFORE_RESTART_MILLIS = "retrievalBeforeRestartMillis";
  private static final String PREF_NETWORK_TOKEN = "networkToken";
  private static final String PREF_NETWORK_TOKEN_BEFORE_RESTART = "networkTokenBeforeRestart";
  private static final String PREF_RESTART_BEFORE_UNLOCK = "restartBeforeUnlock";
  private static final String PREF_EVENT_ID_RESTART = "eventIdBeforeUnlockRestart";
  private static final String PREF_LAST_EVENT_ID = "lastEventIdBeforeUnlock";

  private final SharedPreferences preferences;

  CrumblesBootRecord(Context context) {
    preferences =
        context
            .createDeviceProtectedStorageContext()
            .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
  }

  /**
   * Returns whether this boot handled the security logs kept from before it. Until Crumbles records
   * a first restart, they count as not handled, so that they are retrieved once.
   */
  boolean arePreRebootLogsHandled() {
    return !preferences.getBoolean(PREF_PRE_REBOOT_LOGS_PENDING, true);
  }

  /**
   * Records that this boot handled the security logs kept from before it, and returns how many
   * boots since the last one that did so never did, from the boot counts recorded at the restarts.
   * The platform keeps the logs of only the boot before the current one, so the logs of those boots
   * may be lost. An unknown boot count tells nothing.
   */
  int markPreRebootLogsHandled() {
    int bootCount = preferences.getInt(PREF_CURRENT_BOOT_COUNT, -1);
    int lastHandled = preferences.getInt(PREF_HANDLED_BOOT_COUNT, -1);
    SharedPreferences.Editor editor =
        preferences
            .edit()
            .putBoolean(PREF_PRE_REBOOT_LOGS_PENDING, false)
            .putInt(PREF_HANDLED_RESTART, preferences.getInt(PREF_RESTARTS, 0));
    if (bootCount >= 0) {
      editor.putInt(PREF_HANDLED_BOOT_COUNT, bootCount);
    }
    editor.apply();
    return lastHandled >= 0 && bootCount > lastHandled ? bootCount - lastHandled - 1 : 0;
  }

  /**
   * Records a restart into boot {@code bootCount}, seen {@code beforeUnlock} or once the user
   * unlocked the device, whose pre-reboot logs are then to be handled, and keeps what was retrieved
   * before it. Returns false if the boot count has not grown since the previous restart, as when
   * the adb shell lowered or deleted it to hide a restart. The unlock of a boot already seen before
   * it is no new restart. An unknown boot count is not kept as the last known one, so that it
   * cannot replace it.
   */
  boolean recordRestart(int bootCount, boolean beforeUnlock) {
    if (!beforeUnlock && isRestartRecordedBeforeUnlock(bootCount)) {
      preferences.edit().putBoolean(PREF_RESTART_BEFORE_UNLOCK, false).apply();
      return true;
    }
    int previousBootCount = preferences.getInt(PREF_RESTART_BOOT_COUNT, -1);
    boolean grew = previousBootCount < 0 || bootCount > previousBootCount;
    Map<String, ?> values = preferences.getAll();
    SharedPreferences.Editor editor =
        preferences
            .edit()
            .putInt(PREF_RESTARTS, preferences.getInt(PREF_RESTARTS, 0) + 1)
            .putInt(PREF_CURRENT_BOOT_COUNT, bootCount)
            .putBoolean(PREF_RESTART_BEFORE_UNLOCK, beforeUnlock)
            .putBoolean(PREF_PRE_REBOOT_LOGS_PENDING, true)
            .remove(PREF_RETRIEVAL_BEFORE_RESTART_MILLIS)
            .remove(PREF_NETWORK_TOKEN_BEFORE_RESTART);
    if (values.get(PREF_RETRIEVAL_MILLIS) instanceof Long millis) {
      editor.putLong(PREF_RETRIEVAL_BEFORE_RESTART_MILLIS, millis);
    }
    if (values.get(PREF_NETWORK_TOKEN) instanceof Long token) {
      editor.putLong(PREF_NETWORK_TOKEN_BEFORE_RESTART, token);
    }
    if (bootCount >= 0) {
      editor.putInt(PREF_RESTART_BOOT_COUNT, bootCount);
    }
    editor.apply();
    return grew;
  }

  /**
   * Returns whether the restart into boot {@code bootCount} was recorded before the first unlock,
   * as its locked boot does, and the user has not unlocked the device since.
   */
  boolean isRestartRecordedBeforeUnlock(int bootCount) {
    return preferences.getBoolean(PREF_RESTART_BEFORE_UNLOCK, false)
        && bootCount == preferences.getInt(PREF_CURRENT_BOOT_COUNT, -1);
  }

  /** Records that security logging was on during this boot. */
  void recordSecurityLoggingOn() {
    int restarts = preferences.getInt(PREF_RESTARTS, 0);
    preferences.edit().putInt(PREF_LOGGING_ON_RESTART, restarts).apply();
  }

  /**
   * Returns whether security logging was on at some point since the last boot that handled its
   * pre-reboot logs began, so that the boots skipped since then may have had logs to lose.
   */
  boolean wasSecurityLoggingOnSinceLastHandledBoot() {
    return preferences.getInt(PREF_LOGGING_ON_RESTART, -1)
        >= preferences.getInt(PREF_HANDLED_RESTART, 0);
  }

  /** Records that security logs were retrieved at {@code millis}, so logging was on. */
  void recordSecurityRetrieval(long millis) {
    preferences
        .edit()
        .putLong(PREF_RETRIEVAL_MILLIS, millis)
        .putInt(PREF_LOGGING_ON_RESTART, preferences.getInt(PREF_RESTARTS, 0))
        .apply();
  }

  /** Records that the network log batch {@code token} was retrieved. */
  void recordNetworkBatchToken(long token) {
    preferences.edit().putLong(PREF_NETWORK_TOKEN, token).apply();
  }

  /**
   * Returns when security logs were last retrieved before the last restart, or empty if they never
   * were.
   */
  OptionalLong lastSecurityRetrievalBeforeRestart() {
    return preferences.getAll().get(PREF_RETRIEVAL_BEFORE_RESTART_MILLIS) instanceof Long millis
        ? OptionalLong.of(millis)
        : OptionalLong.empty();
  }

  /** Returns the last network log batch retrieved before the last restart, if any. */
  OptionalLong lastNetworkTokenBeforeRestart() {
    return preferences.getAll().get(PREF_NETWORK_TOKEN_BEFORE_RESTART) instanceof Long token
        ? OptionalLong.of(token)
        : OptionalLong.empty();
  }

  /**
   * Records that the last security event retrieved before the first unlock after the last restart
   * has ID {@code eventId}.
   */
  void recordLastEventIdBeforeUnlock(long eventId) {
    preferences
        .edit()
        .putInt(PREF_EVENT_ID_RESTART, preferences.getInt(PREF_RESTARTS, 0))
        .putLong(PREF_LAST_EVENT_ID, eventId)
        .apply();
  }

  /**
   * Returns the ID of the last security event retrieved before the first unlock after the last
   * restart, if any.
   */
  OptionalLong lastEventIdBeforeUnlock() {
    Map<String, ?> values = preferences.getAll();
    return values.get(PREF_EVENT_ID_RESTART) instanceof Integer restart
            && restart == preferences.getInt(PREF_RESTARTS, 0)
            && values.get(PREF_LAST_EVENT_ID) instanceof Long eventId
        ? OptionalLong.of(eventId)
        : OptionalLong.empty();
  }

  /** Returns {@link #lastEventIdBeforeUnlock} and forgets it, once the user unlocked the device. */
  OptionalLong takeLastEventIdBeforeUnlock() {
    OptionalLong eventId = lastEventIdBeforeUnlock();
    preferences.edit().remove(PREF_EVENT_ID_RESTART).remove(PREF_LAST_EVENT_ID).apply();
    return eventId;
  }
}
