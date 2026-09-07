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
import android.content.SharedPreferences;
import android.provider.Settings;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
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

  @Test
  public void getDeviceId_withHardwareSerial_prioritizesSerial() {
    ShadowBuild.setSerial("hardware_serial_12345");
    try {
      Settings.Secure.putString(
          context.getContentResolver(), Settings.Secure.ANDROID_ID, "android_id_feedbeef12345678");
      assertThat(CrumblesDeviceIdManager.getDeviceId(context)).isEqualTo("hardware_serial_12345");
      assertThat(CrumblesDeviceIdManager.getDeviceId(null)).isEqualTo("hardware_serial_12345");
    } finally {
      ShadowBuild.reset();
    }
  }

  @Test
  public void getDeviceId_withContext_resolvesAndroidIdOrPersistedUuid() {
    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "android_id_feedbeef12345678");
    assertThat(CrumblesDeviceIdManager.getDeviceId(context))
        .isEqualTo("android_id_feedbeef12345678");

    // Falls back to generating and persisting a UUID when Android ID is empty.
    Settings.Secure.putString(context.getContentResolver(), Settings.Secure.ANDROID_ID, "");
    String generatedId = CrumblesDeviceIdManager.getDeviceId(context);
    assertThat(generatedId).isNotEmpty();
    assertThat(generatedId).isNotEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
    assertThat(preferences.getString(CrumblesDeviceIdManager.PREF_DEVICE_ID, null))
        .isEqualTo(generatedId);
    assertThat(CrumblesDeviceIdManager.getDeviceId(context)).isEqualTo(generatedId);
  }

  @Test
  public void getDeviceId_withoutContext_returnsNonEmptyIdentifier() {
    assertThat(CrumblesDeviceIdManager.getDeviceId(null)).isNotEmpty();
  }

  @Test
  public void getDeviceId_differentAndroidIds_attributesSeparately() {
    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "device_alpha_1111");
    String deviceOne = CrumblesDeviceIdManager.getDeviceId(context);

    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "device_beta_2222");
    String deviceTwo = CrumblesDeviceIdManager.getDeviceId(context);

    assertThat(deviceOne).isEqualTo("device_alpha_1111");
    assertThat(deviceTwo).isEqualTo("device_beta_2222");
    assertThat(deviceOne).isNotEqualTo(deviceTwo);
  }

  @Test
  public void constructor_instantiatesWithValidContext() {
    Settings.Secure.putString(
        context.getContentResolver(), Settings.Secure.ANDROID_ID, "constructor_test_id");
    assertThat(new CrumblesDeviceIdManager(context).getDeviceId())
        .isEqualTo("constructor_test_id");
  }
}
