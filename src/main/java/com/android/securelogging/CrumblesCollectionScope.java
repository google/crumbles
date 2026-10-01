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

/**
 * A collection scope containing user preferences for which categories of logs Crumbles is allowed
 * to collect.
 *
 * <p>The platform only exposes a device-wide on/off switch per category: {@code
 * DevicePolicyManager#setNetworkLoggingEnabled} cannot be scoped to a package, a user or a time
 * window. Turning network collection off therefore means the events are never captured, rather than
 * captured and then filtered out.
 *
 * <p>Network collection defaults to enabled so that existing installations keep their current
 * behaviour.
 */
public final class CrumblesCollectionScope {

  private static final String NETWORK_COLLECTION_ENABLED_KEY = "network_collection_enabled";

  /** Returns whether the user allows device-wide network (DNS and connection) log collection. */
  public static boolean isNetworkCollectionEnabled(Context context) {
    return context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .getBoolean(NETWORK_COLLECTION_ENABLED_KEY, /* defValue= */ true);
  }

  /** Persists whether device-wide network log collection is allowed. */
  public static void setNetworkCollectionEnabled(Context context, boolean enabled) {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(NETWORK_COLLECTION_ENABLED_KEY, enabled)
        .apply();
  }

  private CrumblesCollectionScope() {}
}
