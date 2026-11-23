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

import android.content.res.XmlResourceParser;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.xmlpull.v1.XmlPullParser;

/** Unit tests for the network security config that the manifest applies to the app. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesNetworkSecurityConfigTest {

  @Test
  public void networkSecurityConfig_trustsOnlySystemCasAndPermitsNoCleartext() throws Exception {
    List<String> outline = outlineXmlResource(R.xml.network_security_config);

    assertThat(outline)
        .containsExactly(
            "network-security-config",
            "  base-config cleartextTrafficPermitted=false",
            "    trust-anchors",
            "      certificates src=system")
        .inOrder();
  }

  /**
   * Returns one line per element and per non-blank text node of the XML resource {@code xmlResId},
   * indented two spaces per level of nesting. An element's line lists its attributes as {@code
   * name=value}.
   */
  private static List<String> outlineXmlResource(int xmlResId) throws Exception {
    List<String> lines = new ArrayList<>();
    try (XmlResourceParser parser =
        ApplicationProvider.getApplicationContext().getResources().getXml(xmlResId)) {
      for (int event = parser.next(); event != XmlPullParser.END_DOCUMENT; event = parser.next()) {
        if (event == XmlPullParser.START_TAG) {
          StringBuilder line =
              new StringBuilder("  ".repeat(parser.getDepth() - 1)).append(parser.getName());
          for (int i = 0; i < parser.getAttributeCount(); i++) {
            line.append(' ')
                .append(parser.getAttributeName(i))
                .append('=')
                .append(parser.getAttributeValue(i));
          }
          lines.add(line.toString());
        } else if (event == XmlPullParser.TEXT && !parser.isWhitespace()) {
          lines.add("  ".repeat(parser.getDepth()) + parser.getText());
        }
      }
    }
    return lines;
  }
}
