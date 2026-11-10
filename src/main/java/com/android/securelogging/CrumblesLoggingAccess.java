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

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import androidx.annotation.Nullable;

/**
 * Decides whether Crumbles may control and retrieve a type of logs, either as the device owner or
 * as an app the device owner delegated that type of logs to.
 *
 * <p>A device owner delegates logging with {@link DevicePolicyManager#setDelegatedScopes} and the
 * {@link DevicePolicyManager#DELEGATION_SECURITY_LOGGING} or {@link
 * DevicePolicyManager#DELEGATION_NETWORK_LOGGING} scope.
 */
final class CrumblesLoggingAccess {

  /** How Crumbles accesses a type of logs. */
  enum Mode {
    /** Crumbles is the device owner. */
    DEVICE_OWNER,
    /** The device owner delegated the type of logs to Crumbles. */
    DELEGATE,
    /** Crumbles cannot access the type of logs. */
    NONE
  }

  private final Mode mode;
  @Nullable private final ComponentName admin;

  private CrumblesLoggingAccess(Mode mode, @Nullable ComponentName admin) {
    this.mode = mode;
    this.admin = admin;
  }

  /** Resolves how Crumbles accesses security logs. */
  static CrumblesLoggingAccess forSecurityLogging(Context context) {
    return resolve(context, DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
  }

  /** Resolves how Crumbles accesses network logs. */
  static CrumblesLoggingAccess forNetworkLogging(Context context) {
    return resolve(context, DevicePolicyManager.DELEGATION_NETWORK_LOGGING);
  }

  private static CrumblesLoggingAccess resolve(Context context, String delegationScope) {
    DevicePolicyManager dpm =
        (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
    if (dpm == null) {
      return new CrumblesLoggingAccess(Mode.NONE, /* admin= */ null);
    }
    String packageName = context.getPackageName();
    if (dpm.isDeviceOwnerApp(packageName)) {
      return new CrumblesLoggingAccess(
          Mode.DEVICE_OWNER,
          new ComponentName(context.getApplicationContext(), CrumblesDeviceAdminReceiver.class));
    }
    // A delegate reads its own scopes by passing a null admin and its own package name.
    if (dpm.getDelegatedScopes(/* admin= */ null, packageName).contains(delegationScope)) {
      return new CrumblesLoggingAccess(Mode.DELEGATE, /* admin= */ null);
    }
    return new CrumblesLoggingAccess(Mode.NONE, /* admin= */ null);
  }

  /** Returns how Crumbles accesses the type of logs. */
  Mode mode() {
    return mode;
  }

  /** Returns whether Crumbles may control and retrieve the type of logs. */
  boolean isAvailable() {
    return mode != Mode.NONE;
  }

  /**
   * Returns the admin to pass to the {@link DevicePolicyManager} logging methods: the device admin
   * component for a device owner, or {@code null} for a delegate, as those methods require.
   */
  @Nullable
  ComponentName admin() {
    return admin;
  }
}
