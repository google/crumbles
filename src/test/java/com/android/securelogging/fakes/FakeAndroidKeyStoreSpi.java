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

package com.android.securelogging.fakes;

import android.security.keystore.KeyGenParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * Basic fake implementation of AndroidKeyStore for testing.
 *
 * <p>This fake has been updated to support testing of user-authenticated keys. It now tracks the
 * {@link KeyGenParameterSpec} for each key and a global authentication state.
 *
 * <p><b>IMPORTANT FAKE CIPHER INTERACTION:</b> The real {@code UserNotAuthenticatedException} is
 * thrown by {@code Cipher.doFinal()} or {@code Cipher.unwrap()}, not by {@code KeyStore.getKey()}.
 * To fully test the logic, a corresponding fake {@code CipherSpi} is required. That fake cipher
 * would need to:
 *
 * <ol>
 *   <li>On {@code engineInit()}, get the Key and check if it's from the AndroidKeyStore.
 *   <li>Call {@code FakeAndroidKeyStoreSpi.getPrivateKeyEntry(alias)} to get the entry.
 *   <li>Check if {@code entry.getSpec().isUserAuthenticationRequired()} is true.
 *   <li>If it is, check the global {@code FakeAndroidKeyStoreSpi.isUserAuthenticated()}.
 *   <li>If auth is required but the user is not authenticated, the fake cipher must throw {@code
 *       UserNotAuthenticatedException} from its {@code engineUnwrap} or {@code engineDoFinal}
 *       method.
 * </ol>
 */
public class FakeAndroidKeyStoreSpi extends KeyStoreSpi {

  // --- Static state for the fake keystore ---

  public static final Map<String, Entry> keystoreEntries = new HashMap<>();

  /**
   * This holds the KeyGenParameterSpec from the last KeyPairGenerator initialization. The fake
   * KeyPairGenerator should set this before storing the key.
   */
  @Nullable
  @SuppressWarnings("NonFinalStaticField")
  private static KeyGenParameterSpec latestSpec;

  /**
   * This flag simulates the user's authentication state. Tests can set this to true or false to
   * simulate successful or failed authentication.
   */
  @SuppressWarnings("NonFinalStaticField")
  private static boolean isUserAuthenticated = false;

  // --- Entry classes to hold key material and metadata ---

  /** Marker interface for entries in the keystore. */
  public interface Entry {}

  /** An entry representing a private key, its certificate chain, and its generation specs. */
  public static class PrivateKeyEntry implements Entry {
    private final PrivateKey privateKey;
    private final Certificate[] certificateChain;
    @Nullable private final KeyGenParameterSpec spec;

    public PrivateKey getPrivateKey() {
      return privateKey;
    }

    @SuppressWarnings("AvoidObjectArrays")
    public Certificate[] getCertificateChain() {
      return certificateChain;
    }

    @Nullable
    public KeyGenParameterSpec getSpec() {
      return spec;
    }

    @SuppressWarnings("AvoidObjectArrays")
    public PrivateKeyEntry(
        PrivateKey privateKey, Certificate[] certificateChain, @Nullable KeyGenParameterSpec spec) {
      this.privateKey = privateKey;
      this.certificateChain = certificateChain;
      this.spec = spec;
    }
  }

  // --- Static control methods for tests ---

  /**
   * Sets the authentication state for the fake keystore. A fake Cipher should check this state.
   *
   * @param authenticated The simulated authentication status.
   */
  public static void setUserAuthenticated(boolean authenticated) {
    isUserAuthenticated = authenticated;
  }

  /** Returns the current simulated authentication state. */
  public static boolean isUserAuthenticated() {
    return isUserAuthenticated;
  }

  /**
   * Used by a fake KeyPairGenerator to provide the spec before storing the key.
   *
   * @param spec The spec used to generate the key.
   */
  public static void setLatestKeyGenParameterSpec(@Nullable KeyGenParameterSpec spec) {
    latestSpec = spec;
  }

  /**
   * Used by tests to retrieve and assert on the spec that was used for key generation.
   *
   * @return The last {@link KeyGenParameterSpec} that was set.
   */
  @Nullable
  public static KeyGenParameterSpec getLatestKeyGenParameterSpec() {
    return latestSpec;
  }

  /**
   * Helper for fake Ciphers or tests to retrieve the full private key entry.
   *
   * @param alias The alias of the key.
   * @return The {@link PrivateKeyEntry} or null if not found.
   */
  @Nullable
  public static PrivateKeyEntry getPrivateKeyEntry(String alias) {
    Entry entry = keystoreEntries.get(alias);
    if (entry instanceof PrivateKeyEntry privateKeyEntry) {
      return privateKeyEntry;
    }
    return null;
  }

  // --- Overridden KeyStoreSpi Methods ---

  @Override
  public Key engineGetKey(String alias, char[] password)
      throws NoSuchAlgorithmException, UnrecoverableKeyException {
    PrivateKeyEntry entry = getPrivateKeyEntry(alias);
    if (entry != null) {
      // This is a concession for unit testing. In the real world, getKey() succeeds and
      // Cipher.unwrap() throws UserNotAuthenticatedException. Here, we simulate the failure
      // earlier to make unit tests feasible without a fake Cipher implementation.
      if (entry.getSpec() != null
          && entry.getSpec().isUserAuthenticationRequired()
          && !isUserAuthenticated()) {
        throw new UnrecoverableKeyException("User not authenticated");
      }
      return entry.getPrivateKey();
    }
    return null;
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    PrivateKeyEntry entry = getPrivateKeyEntry(alias);
    return (entry != null) ? entry.getCertificateChain() : null;
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    PrivateKeyEntry entry = getPrivateKeyEntry(alias);
    if (entry != null
        && entry.getCertificateChain() != null
        && entry.getCertificateChain().length > 0) {
      return entry.getCertificateChain()[0];
    }
    return null;
  }

  @Override
  public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
      throws KeyStoreException {
    if (key instanceof PrivateKey privateKey) {
      // When the key is stored, associate it with the spec that was just used for generation.
      keystoreEntries.put(alias, new PrivateKeyEntry(privateKey, chain, latestSpec));
      // Clear the spec so it's not accidentally reused for a different key.
      latestSpec = null;
    } else {
      throw new KeyStoreException("Only PrivateKey entries are supported by this fake.");
    }
  }

  @Override
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
      throws KeyStoreException {
    throw new KeyStoreException("Byte array key entries not supported by this fake.");
  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    keystoreEntries.remove(alias);
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    return keystoreEntries.containsKey(alias);
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    return keystoreEntries.get(alias) instanceof PrivateKeyEntry;
  }

  // --- Other standard KeyStoreSpi methods ---

  @Override
  @SuppressWarnings("JavaUtilDate") // Implementation needs to match KeyStoreSpi.
  public Date engineGetCreationDate(String alias) {
    return Date.from(Instant.EPOCH); // Fake: epoch.
  }

  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    throw new KeyStoreException(
        "Certificate-only entries not supported by this fake for simplicity.");
  }

  @Override
  public Enumeration<String> engineAliases() {
    return Collections.enumeration(keystoreEntries.keySet());
  }

  @Override
  public int engineSize() {
    return keystoreEntries.size();
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    return false; // Not supporting cert-only entries in this simple fake.
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    return null; // Not implemented.
  }

  @Override
  public void engineStore(OutputStream stream, char[] password)
      throws IOException, NoSuchAlgorithmException, CertificateException {
    // No-op for in-memory fake.
  }

  @Override
  public void engineLoad(InputStream stream, char[] password) {
    // No-op for in-memory fake. If stream is null, a real KeyStore is re-initialized.
    // For test isolation, it's better to clear keystoreEntries explicitly in test @Before.
  }
}
