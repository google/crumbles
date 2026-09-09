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

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.XmlResourceParser;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.Objects;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;
import org.xmlpull.v1.XmlPullParser;

/** Unit tests verifying that backup and device-to-device migration are disabled in the manifest. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesBackupPolicyTest {

  @Test
  public void manifest_disablesBackupAndD2D() throws Exception {
    // Arrange
    Context context = ApplicationProvider.getApplicationContext();

    // Act
    ApplicationInfo ai =
        context
            .getPackageManager()
            .getApplicationInfo(context.getPackageName(), PackageManager.GET_META_DATA);
    int dataExtractionRulesResId =
        context
            .getResources()
            .getIdentifier("data_extraction_rules", "xml", context.getPackageName());

    boolean hasCloudBackup = false;
    boolean hasDeviceTransfer = false;
    try (XmlResourceParser parser = context.getResources().getXml(dataExtractionRulesResId)) {
      int eventType = parser.getEventType();
      while (eventType != XmlPullParser.END_DOCUMENT) {
        if (eventType == XmlPullParser.START_TAG) {
          if (Objects.equals(parser.getName(), "cloud-backup")) {
            hasCloudBackup = true;
          } else if (Objects.equals(parser.getName(), "device-transfer")) {
            hasDeviceTransfer = true;
          }
        }
        eventType = parser.next();
      }
    }

    // Assert
    assertThat(ai.flags & ApplicationInfo.FLAG_ALLOW_BACKUP).isEqualTo(0);
    assertThat(dataExtractionRulesResId).isNotEqualTo(0);
    assertThat(hasCloudBackup).isTrue();
    assertThat(hasDeviceTransfer).isTrue();
  }
}
