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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for {@link CrumblesSigningCertificate}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesSigningCertificateTest {

  // SHA-256 of the empty input, as published in NIST FIPS 180-4 test vectors.
  private static final String EMPTY_INPUT_FINGERPRINT =
      "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:"
          + "27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55";

  // SHA-256 of the ASCII string "abc", as published in NIST FIPS 180-4 test vectors.
  private static final String ABC_FINGERPRINT =
      "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:"
          + "B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";

  // Not static: each test needs its own Robolectric application and installed package.
  private final Context context = ApplicationProvider.getApplicationContext();

  @Test
  public void formatSha256Fingerprint_withKnownInput_matchesPublishedDigest() throws Exception {
    String fingerprint = CrumblesSigningCertificate.formatSha256Fingerprint("abc".getBytes(UTF_8));

    assertThat(fingerprint).isEqualTo(ABC_FINGERPRINT);
  }

  @Test
  public void formatSha256Fingerprint_withEmptyInput_matchesPublishedDigest() throws Exception {
    String fingerprint = CrumblesSigningCertificate.formatSha256Fingerprint(new byte[0]);

    assertThat(fingerprint).isEqualTo(EMPTY_INPUT_FINGERPRINT);
  }

  @Test
  public void formatSha256Fingerprint_returnsThirtyTwoUppercaseHexOctets() throws Exception {
    String fingerprint =
        CrumblesSigningCertificate.formatSha256Fingerprint("crumbles".getBytes(UTF_8));

    assertThat(fingerprint.split(":", -1)).hasLength(32);
    assertThat(fingerprint).matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");
  }

  @Test
  public void formatSha256Fingerprint_withDifferentInputs_returnsDifferentFingerprints()
      throws Exception {
    String first = CrumblesSigningCertificate.formatSha256Fingerprint(new byte[] {0x01});
    String second = CrumblesSigningCertificate.formatSha256Fingerprint(new byte[] {0x02});

    assertThat(first).isNotEqualTo(second);
  }

  @Test
  public void getInstalledAppFingerprint_withApkContentsSigner_returnsSignerFingerprint() {
    setApkContentsSigners(new Signature("abc".getBytes(UTF_8)));

    assertThat(CrumblesSigningCertificate.getInstalledAppFingerprint(context))
        .hasValue(ABC_FINGERPRINT);
  }

  @Test
  public void getInstalledAppFingerprint_withoutApkContentsSigners_returnsEmpty() {
    setApkContentsSigners();

    assertThat(CrumblesSigningCertificate.getInstalledAppFingerprint(context)).isEmpty();
  }

  private void setApkContentsSigners(Signature... signers) {
    PackageInfo packageInfo =
        shadowOf(context.getPackageManager())
            .getInternalMutablePackageInfo(context.getPackageName());
    packageInfo.signingInfo = new SigningInfo();
    shadowOf(packageInfo.signingInfo).setSignatures(signers);
  }
}
