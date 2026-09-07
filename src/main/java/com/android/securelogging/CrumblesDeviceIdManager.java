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

import static com.google.common.base.Strings.isNullOrEmpty;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import androidx.annotation.Nullable;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Resolves a persistent device identifier for attributing encrypted log batches.
 *
 * <p>Identifies devices via a prioritized fallback chain: hardware serial via {@link
 * Build#getSerial()}, Android ID via {@link Settings.Secure#ANDROID_ID}, or a persistent UUID.
 */
public final class CrumblesDeviceIdManager {
  private static final String TAG = "CrumblesDeviceIdManager";

  public static final String PREF_DEVICE_ID = "crumbles_device_id";
  public static final String FALLBACK_DEVICE_ID = "unknown_device";

  private final Context context;

  public CrumblesDeviceIdManager(@Nullable Context context) {
    this.context = context != null ? context.getApplicationContext() : null;
  }

  public static String getDeviceId(@Nullable Context context) {
    return new CrumblesDeviceIdManager(context).getDeviceId();
  }

  public String getDeviceId() {
    Optional<String> serial = getHardwareSerial();
    if (serial.isPresent()) {
      return serial.get();
    }
    if (context != null) {
      Optional<String> androidId = getAndroidId(context);
      if (androidId.isPresent()) {
        return androidId.get();
      }
      return getOrCreatePersistedId(context);
    }
    return FALLBACK_DEVICE_ID;
  }

  // Suppress "HardwareIds" because Crumbles is an enterprise Device Owner security tool
  // collecting audit telemetry and requires a hardware identifier for log attribution.
  @SuppressLint("HardwareIds")
  private static Optional<String> getHardwareSerial() {
    try {
      String serial = Build.getSerial();
      if (!isNullOrEmpty(serial) && !Objects.equals(serial, Build.UNKNOWN)) {
        return Optional.of(serial);
      }
    } catch (SecurityException e) {
      // Build.getSerial() throws SecurityException when caller is not Device Owner.
      Log.d(TAG, "Hardware serial number not accessible via Build.getSerial()", e);
    }
    return Optional.empty();
  }

  // Suppress "HardwareIds" because Crumbles is an enterprise Device Owner security tool
  // collecting audit telemetry and requires a stable device identifier for log attribution.
  @SuppressLint("HardwareIds")
  private static Optional<String> getAndroidId(Context ctx) {
    if (ctx.getContentResolver() == null) {
      return Optional.empty();
    }
    try {
      String androidId =
          Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
      if (!isNullOrEmpty(androidId)) {
        return Optional.of(androidId);
      }
    } catch (SecurityException e) {
      // Some customized ROMs or restricted profiles may restrict access to secure settings.
      Log.w(TAG, "Settings.Secure.ANDROID_ID not accessible", e);
    }
    return Optional.empty();
  }

  private static String getOrCreatePersistedId(Context ctx) {
    try {
      SharedPreferences prefs =
          ctx.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
      String persistedId = prefs.getString(PREF_DEVICE_ID, null);
      if (!isNullOrEmpty(persistedId)) {
        return persistedId;
      }
      String newId = UUID.randomUUID().toString();
      prefs.edit().putString(PREF_DEVICE_ID, newId).apply();
      return newId;
    } catch (RuntimeException e) {
      // In certain headless test contexts, SharedPreferences may lack a data directory.
      Log.d(TAG, "SharedPreferences not available for device ID persistence", e);
      return FALLBACK_DEVICE_ID;
    }
  }
}
