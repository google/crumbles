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
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.util.Log;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Optional;

/**
 * Exposes the SHA-256 fingerprint of the certificate that signed the installed Crumbles APK.
 *
 * <p>The fingerprint lets a user compare the build actually present on the device against a value
 * published through a channel independent of the provisioning QR code. It establishes which key
 * signed the installed app; it does not establish that the key is the legitimate one.
 */
public final class CrumblesSigningCertificate {
  private static final String TAG = "CrumblesSigningCert";

  private CrumblesSigningCertificate() {}

  /**
   * Formats the SHA-256 digest of a DER-encoded X.509 certificate as colon-separated uppercase
   * hexadecimal, matching the rendering used by {@code apksigner verify --print-certs}.
   *
   * @param derEncodedCertificate the DER bytes of the signing certificate
   * @return the digest as 32 colon-separated uppercase hexadecimal octets
   * @throws NoSuchAlgorithmException if the platform does not provide SHA-256
   */
  public static String formatSha256Fingerprint(byte[] derEncodedCertificate)
      throws NoSuchAlgorithmException {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(derEncodedCertificate);
    StringBuilder fingerprint = new StringBuilder();
    for (byte digestByte : digest) {
      if (fingerprint.length() > 0) {
        fingerprint.append(':');
      }
      fingerprint.append(String.format(Locale.US, "%02X", digestByte));
    }
    return fingerprint.toString();
  }

  /**
   * Returns the SHA-256 fingerprint of the certificate that signed the installed Crumbles package,
   * or an empty {@link Optional} if the platform does not report it.
   */
  public static Optional<String> getInstalledAppFingerprint(Context context) {
    try {
      SigningInfo signingInfo =
          context
              .getPackageManager()
              .getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES)
              .signingInfo;
      if (signingInfo == null) {
        return Optional.empty();
      }
      Signature[] signers = signingInfo.getApkContentsSigners();
      if (signers == null || signers.length == 0) {
        return Optional.empty();
      }
      return Optional.of(formatSha256Fingerprint(signers[0].toByteArray()));
    } catch (NameNotFoundException | NoSuchAlgorithmException e) {
      Log.w(TAG, "Signing certificate of the installed package is not readable", e);
      return Optional.empty();
    }
  }
}
