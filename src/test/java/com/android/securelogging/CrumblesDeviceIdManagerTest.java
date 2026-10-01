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

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.provider.Settings;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.shadows.ShadowBuild;

/** Unit tests for {@link CrumblesDeviceIdManager}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesDeviceIdManagerTest {

  private Context context;
  private SharedPreferences preferences;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    preferences = context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    preferences.edit().clear().commit();
  }

  @After
  public void tearDown() {
    ShadowBuild.reset();
  }

  @Test
  public void getDeviceId_byDefault_ignoresHardwareIdsAndPersistsRandomUuid() {
    ShadowBuild.setSerial("hardware_serial_12345");
    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "android_id_feedbeef12345678");

    String deviceId = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceId).isNotEqualTo("hardware_serial_12345");
    assertThat(deviceId).isNotEqualTo("android_id_feedbeef12345678");
    assertThat(deviceId).isNotEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
    assertThat(preferences.getString(CrumblesDeviceIdManager.PREF_DEVICE_ID, null))
        .isEqualTo(deviceId);
  }

  @Test
  public void getDeviceId_calledRepeatedly_returnsStablePersistedUuid() {
    String firstId = CrumblesDeviceIdManager.getDeviceId(context);

    String secondId = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(secondId).isEqualTo(firstId);
  }

  @Test
  public void getDeviceId_withPersistedUuid_reusesStoredValue() {
    preferences.edit().putString(CrumblesDeviceIdManager.PREF_DEVICE_ID, "persisted_uuid").commit();

    String deviceId = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceId).isEqualTo("persisted_uuid");
  }

  @Test
  public void getDeviceId_onSeparateInstallations_attributesSeparately() {
    String deviceOne = CrumblesDeviceIdManager.getDeviceId(context);
    preferences.edit().clear().commit();

    String deviceTwo = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceTwo).isNotEqualTo(deviceOne);
  }

  @Test
  public void isHardwareAttributionEnabled_byDefault_returnsFalse() {
    assertThat(CrumblesDeviceIdManager.isHardwareAttributionEnabled(context)).isFalse();
  }

  @Test
  public void getDeviceId_whenHardwareAttributionEnabled_prioritizesSerial() {
    ShadowBuild.setSerial("hardware_serial_12345");
    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "android_id_feedbeef12345678");
    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);

    String deviceId = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceId).isEqualTo("hardware_serial_12345");
  }

  @Test
  public void getDeviceId_whenHardwareAttributionEnabledWithoutSerial_usesAndroidId() {
    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "android_id_feedbeef12345678");
    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);

    String deviceId = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceId).isEqualTo("android_id_feedbeef12345678");
  }

  @Test
  public void getDeviceId_whenHardwareAttributionDisabledAgain_returnsPersistedUuid() {
    ShadowBuild.setSerial("hardware_serial_12345");
    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);

    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ false);

    assertThat(CrumblesDeviceIdManager.getDeviceId(context)).isNotEqualTo("hardware_serial_12345");
  }

  @Test
  public void getDeviceId_withoutContext_returnsFallbackIdentifier() {
    ShadowBuild.setSerial("hardware_serial_12345");

    String deviceId = CrumblesDeviceIdManager.getDeviceId(null);

    assertThat(deviceId).isEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
  }

  @Test
  public void constructor_instantiatesWithValidContext() {
    String deviceId = new CrumblesDeviceIdManager(context).getDeviceId();

    assertThat(deviceId)
        .isEqualTo(preferences.getString(CrumblesDeviceIdManager.PREF_DEVICE_ID, null));
  }

  @Test
  public void getDeviceId_whenSharedPreferencesUnavailable_returnsFallbackIdentifier() {
    ShadowBuild.setSerial("hardware_serial_12345");
    Context brokenPrefsContext =
        new ContextWrapper(context) {
          @Override
          public Context getApplicationContext() {
            return this;
          }

          @Override
          public SharedPreferences getSharedPreferences(String name, int mode) {
            throw new RuntimeException("SharedPreferences unavailable");
          }
        };

    assertThat(CrumblesDeviceIdManager.isHardwareAttributionEnabled(brokenPrefsContext)).isFalse();
    assertThat(CrumblesDeviceIdManager.getDeviceId(brokenPrefsContext))
        .isEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
  }

  @Test
  public void getDeviceId_whenHardwareAttributionEnabledAndHardwareIdsMissing_fallsBackToUuid() {
    Settings.Secure.putString(context.getContentResolver(), Settings.Secure.ANDROID_ID, "");
    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);

    String deviceId = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceId)
        .isEqualTo(preferences.getString(CrumblesDeviceIdManager.PREF_DEVICE_ID, null));
  }
}
