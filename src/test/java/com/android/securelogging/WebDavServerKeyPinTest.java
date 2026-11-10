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
import static org.junit.Assert.assertThrows;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.common.truth.Expect;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for {@link WebDavServerKeyPin}. */
@RunWith(AndroidJUnit4.class)
public final class WebDavServerKeyPinTest {

  @Rule public final Expect expect = Expect.create();

  @Test
  public void of_equalsThePinOfTheSha256DigestOfTheEncodedKey() throws Exception {
    PublicKey publicKey = newPublicKey();
    WebDavServerKeyPin pinOfDigest =
        WebDavServerKeyPin.ofSha256(
            MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));

    WebDavServerKeyPin pin = WebDavServerKeyPin.of(publicKey);

    expect.that(pin).isEqualTo(pinOfDigest);
    expect.that(pin.hashCode()).isEqualTo(pinOfDigest.hashCode());
  }

  @Test
  public void equals_forPinsOfDifferentKeys_isFalse() throws Exception {
    WebDavServerKeyPin pin = WebDavServerKeyPin.of(newPublicKey());

    expect.that(pin).isNotEqualTo(WebDavServerKeyPin.of(newPublicKey()));
    expect.that(pin).isNotEqualTo(null);
  }

  @Test
  public void toSha256_returnsACopyThatCannotChangeThePin() throws Exception {
    WebDavServerKeyPin pin = WebDavServerKeyPin.of(newPublicKey());
    byte[] digest = pin.toSha256();
    byte[] expectedDigest = digest.clone();

    Arrays.fill(digest, (byte) 0);

    assertThat(pin.toSha256()).isEqualTo(expectedDigest);
  }

  @Test
  public void fingerprint_formatsTheDigestAsUppercaseHexInLinesOfEightBytes() {
    byte[] digest = new byte[32];
    for (int i = 0; i < digest.length; i++) {
      digest[i] = (byte) i;
    }

    String fingerprint = WebDavServerKeyPin.ofSha256(digest).fingerprint();

    assertThat(fingerprint)
        .isEqualTo(
            """
            00:01:02:03:04:05:06:07
            08:09:0A:0B:0C:0D:0E:0F
            10:11:12:13:14:15:16:17
            18:19:1A:1B:1C:1D:1E:1F\
            """);
  }

  @Test
  public void pinningTrustManager_delegatesChecksAndRequiresPinnedKey() throws Exception {
    X509Certificate[] issuers = WebDavServerKeyPin.platformTrustManager().getAcceptedIssuers();
    X509Certificate[] chain = {issuers[0]};
    List<String> calls = new ArrayList<>();
    X509ExtendedTrustManager delegate =
        new X509ExtendedTrustManager() {
          @Override
          public void checkServerTrusted(X509Certificate[] c, String authType, Socket socket) {
            calls.add("server-socket:" + authType);
          }

          @Override
          public void checkServerTrusted(X509Certificate[] c, String authType, SSLEngine engine) {
            calls.add("server-engine:" + authType);
          }

          @Override
          public void checkServerTrusted(X509Certificate[] c, String authType) {
            calls.add("server-chain:" + authType);
          }

          @Override
          public void checkClientTrusted(X509Certificate[] c, String authType, Socket socket) {
            calls.add("client-socket:" + authType);
          }

          @Override
          public void checkClientTrusted(X509Certificate[] c, String authType, SSLEngine engine) {
            calls.add("client-engine:" + authType);
          }

          @Override
          public void checkClientTrusted(X509Certificate[] c, String authType) {
            calls.add("client-chain:" + authType);
          }

          @Override
          public X509Certificate[] getAcceptedIssuers() {
            return issuers;
          }
        };
    WebDavServerKeyPin.PinningTrustManager matchingPinTm =
        WebDavServerKeyPin.of(issuers[0].getPublicKey()).new PinningTrustManager(delegate);
    WebDavServerKeyPin.PinningTrustManager wrongPinTm =
        WebDavServerKeyPin.of(newPublicKey()).new PinningTrustManager(delegate);

    matchingPinTm.checkServerTrusted(chain, "RSA", (Socket) null);
    matchingPinTm.checkServerTrusted(chain, "EC", (SSLEngine) null);
    matchingPinTm.checkServerTrusted(chain, "ED25519");
    matchingPinTm.checkClientTrusted(chain, "RSA", (Socket) null);
    matchingPinTm.checkClientTrusted(chain, "EC", (SSLEngine) null);
    matchingPinTm.checkClientTrusted(chain, "ED25519");

    assertThrows(
        CertificateException.class, () -> wrongPinTm.checkServerTrusted(chain, "RSA", (Socket) null));
    assertThrows(
        CertificateException.class,
        () -> wrongPinTm.checkServerTrusted(chain, "EC", (SSLEngine) null));
    assertThrows(CertificateException.class, () -> wrongPinTm.checkServerTrusted(chain, "ED25519"));
    expect
        .that(calls)
        .containsExactly(
            "server-socket:RSA",
            "server-engine:EC",
            "server-chain:ED25519",
            "client-socket:RSA",
            "client-engine:EC",
            "client-chain:ED25519",
            "server-socket:RSA",
            "server-engine:EC",
            "server-chain:ED25519")
        .inOrder();
    expect.that(matchingPinTm.getAcceptedIssuers()).isEqualTo(issuers);
  }

  private static PublicKey newPublicKey() throws Exception {
    return KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic();
  }
}
