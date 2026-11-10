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

import static com.google.common.base.Preconditions.checkArgument;

import android.annotation.SuppressLint;
import androidx.annotation.Nullable;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * The public key that a WebDAV server must present, identified by the SHA-256 digest of its
 * DER-encoded SubjectPublicKeyInfo. A pin only narrows what a trust manager accepts: the CA chain
 * and hostname are still verified.
 */
final class WebDavServerKeyPin {

  private static final int SHA256_LENGTH_BYTES = 32;
  private static final int FINGERPRINT_BYTES_PER_LINE = 8;

  private final byte[] publicKeySha256;

  private WebDavServerKeyPin(byte[] publicKeySha256) {
    this.publicKeySha256 = publicKeySha256;
  }

  /** Returns the pin for {@code publicKey}. */
  static WebDavServerKeyPin of(PublicKey publicKey) {
    return new WebDavServerKeyPin(sha256(publicKey.getEncoded()));
  }

  /**
   * Returns the pin for the key whose DER-encoded SubjectPublicKeyInfo has the SHA-256 digest
   * {@code publicKeySha256}. Copies the array.
   */
  static WebDavServerKeyPin ofSha256(byte[] publicKeySha256) {
    checkArgument(
        publicKeySha256.length == SHA256_LENGTH_BYTES,
        "Expected a %s-byte SHA-256 digest, got %s bytes",
        SHA256_LENGTH_BYTES,
        publicKeySha256.length);
    return new WebDavServerKeyPin(publicKeySha256.clone());
  }

  /** Returns a copy of the SHA-256 digest that this pin requires, for storing the pin. */
  byte[] toSha256() {
    return publicKeySha256.clone();
  }

  /**
   * Returns the digest formatted for a person to compare against a value from the server's
   * operator: colon-separated uppercase hex in lines of {@value #FINGERPRINT_BYTES_PER_LINE} bytes,
   * the format of {@link CrumblesLogsEncryptor#getPublicKeyFingerprint}.
   */
  String fingerprint() {
    StringBuilder fingerprint = new StringBuilder();
    for (int i = 0; i < publicKeySha256.length; i++) {
      if (i > 0) {
        fingerprint.append(i % FINGERPRINT_BYTES_PER_LINE == 0 ? '\n' : ':');
      }
      fingerprint.append(String.format(Locale.ROOT, "%02X", publicKeySha256[i]));
    }
    return fingerprint.toString();
  }

  @Override
  public boolean equals(@Nullable Object other) {
    return other instanceof WebDavServerKeyPin otherPin
        && MessageDigest.isEqual(publicKeySha256, otherPin.publicKeySha256);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(publicKeySha256);
  }

  /**
   * Returns a socket factory whose connections accept a server only if {@code trustManager} accepts
   * its certificate chain and the first certificate in the chain holds the pinned key.
   */
  SSLSocketFactory newSocketFactory(X509ExtendedTrustManager trustManager)
      throws GeneralSecurityException {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        /* km= */ null,
        new TrustManager[] {new PinningTrustManager(trustManager)},
        /* random= */ null);
    return sslContext.getSocketFactory();
  }

  /**
   * Returns the platform's default trust manager, which applies the app's network security config.
   *
   * @throws GeneralSecurityException if the platform offers no {@link X509ExtendedTrustManager}
   */
  static X509ExtendedTrustManager platformTrustManager() throws GeneralSecurityException {
    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init((KeyStore) null);
    for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
      if (trustManager instanceof X509ExtendedTrustManager extendedTrustManager) {
        return extendedTrustManager;
      }
    }
    throw new GeneralSecurityException("The platform offers no X509ExtendedTrustManager");
  }

  /**
   * Throws unless the server's own certificate, which comes first in {@code chain}, holds the
   * pinned key.
   */
  private void checkPinnedKey(X509Certificate[] chain) throws ServerKeyMismatchException {
    byte[] presentedKeySha256 = sha256(chain[0].getPublicKey().getEncoded());
    if (!MessageDigest.isEqual(presentedKeySha256, publicKeySha256)) {
      throw new ServerKeyMismatchException();
    }
  }

  private static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError("Every Java platform supports SHA-256", e);
    }
  }

  /** Thrown during the TLS handshake when a server presents a key other than the pinned one. */
  static final class ServerKeyMismatchException extends CertificateException {
    ServerKeyMismatchException() {
      super("The server's public key does not match the pinned key");
    }
  }

  /**
   * Has a server's certificate chain checked by the wrapped trust manager, then requires the pinned
   * key. Extends {@link X509ExtendedTrustManager} so the TLS stack passes the connection for
   * domain-specific network security config rules.
   */
  // Suppress "CustomX509TrustManager" because this trust manager adds a check to the wrapped one
  // and skips none of its checks.
  @SuppressLint("CustomX509TrustManager")
  final class PinningTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager trustManager;

    PinningTrustManager(X509ExtendedTrustManager trustManager) {
      this.trustManager = trustManager;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      trustManager.checkServerTrusted(chain, authType, socket);
      checkPinnedKey(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      trustManager.checkServerTrusted(chain, authType, engine);
      checkPinnedKey(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      trustManager.checkServerTrusted(chain, authType);
      checkPinnedKey(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      trustManager.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      trustManager.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return trustManager.getAcceptedIssuers();
    }
  }
}
