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
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.security.keystore.StrongBoxUnavailableException;
import android.security.keystore.UserNotAuthenticatedException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Basic fake implementation of AndroidKeyStore for testing.
 *
 * <p>This fake has been updated to support testing of user-authenticated keys. It now tracks the
 * {@link KeyGenParameterSpec} or {@link KeyProtection} of each key, and whether the user
 * authenticated for every key or for the key of a single alias.
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

  /** Authentication states set for the key of a single alias, which override the flag above. */
  private static final Map<String, Boolean> aliasAuthenticationStates = new HashMap<>();

  @SuppressWarnings("NonFinalStaticField")
  public static boolean isStrongBoxSupported = true;

  /**
   * Makes StrongBox key pair generation fail with a {@link java.security.ProviderException} other
   * than {@link StrongBoxUnavailableException}, as on a StrongBox that has no attestation key.
   */
  @SuppressWarnings("NonFinalStaticField")
  public static boolean isStrongBoxFailing = false;

  /**
   * Makes StrongBox key generation fail with a checked {@link java.security.GeneralSecurityException}.
   */
  @SuppressWarnings("NonFinalStaticField")
  public static boolean isStrongBoxThrowingGeneralSecurityException = false;

  /**
   * Unchecked exception that StrongBox key generation throws instead of creating the key, if not
   * null, as on OEM builds whose Keystore throws exceptions other than {@link ProviderException}.
   */
  @Nullable
  @SuppressWarnings("NonFinalStaticField")
  public static RuntimeException strongBoxFailure = null;

  @SuppressWarnings("NonFinalStaticField")
  public static boolean isCertificateChainNull = false;

  /** Makes this many next certificate chain lookups return null, as a Keystore that recovers. */
  @SuppressWarnings("NonFinalStaticField")
  public static int certificateChainFailuresLeft = 0;

  @SuppressWarnings("NonFinalStaticField")
  public static boolean isDeleteFailing = false;

  /** Unchecked exception that {@link #engineDeleteEntry} throws, if not null. */
  @Nullable
  @SuppressWarnings("NonFinalStaticField")
  public static RuntimeException deleteFailure = null;

  /** Makes every secret key import fail, as on a Keystore that refuses the import. */
  @SuppressWarnings("NonFinalStaticField")
  public static boolean isSecretKeyImportRefused = false;

  /** Makes secret key generation throw an unchecked ProviderException, as an ailing Keystore. */
  @SuppressWarnings("NonFinalStaticField")
  public static boolean isSecretKeyGenerationFailing = false;

  /** Optional failure thrown by {@link #engineGetCertificate} to simulate Keystore read errors. */
  @Nullable
  @SuppressWarnings("NonFinalStaticField")
  public static RuntimeException certificateLookupFailure = null;

  private static final AtomicBoolean authorizingCipher = new AtomicBoolean();
  private static final AtomicReference<FakeCipherSpi> latestPendingCipher = new AtomicReference<>();

  // --- Entry classes to hold key material and metadata ---

  /** Marker interface for entries in the keystore. */
  public interface Entry {
    @Nullable
    Key getKey();

    /** Returns whether the key can only be used once the user has authenticated. */
    default boolean isUserAuthenticationRequired() {
      return false;
    }
  }

  /** Fake AndroidKeyStore KeyGeneratorSpi that stores each generated secret key under its alias. */
  private abstract static class SecretKeyGeneratorSpi extends KeyGeneratorSpi {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final String algorithm;
    @Nullable private KeyGenParameterSpec spec;

    SecretKeyGeneratorSpi(String algorithm) {
      this.algorithm = algorithm;
    }

    @Override
    protected void engineInit(SecureRandom random) {}

    @Override
    protected void engineInit(int keysize, SecureRandom random) {}

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException {
      if (!(params instanceof KeyGenParameterSpec keySpec)) {
        throw new InvalidAlgorithmParameterException("Expected KeyGenParameterSpec");
      }
      if (keySpec.isStrongBoxBacked()) {
        if (!isStrongBoxSupported) {
          throw new StrongBoxUnavailableException("StrongBox unavailable");
        }
        if (isStrongBoxFailing) {
          throw new ProviderException("StrongBox failed");
        }
        if (isStrongBoxThrowingGeneralSecurityException) {
          throw new InvalidAlgorithmParameterException("StrongBox rejected parameters");
        }
        if (strongBoxFailure != null) {
          throw strongBoxFailure;
        }
      }
      this.spec = keySpec;
      setLatestKeyGenParameterSpec(keySpec);
    }

    @Override
    protected SecretKey engineGenerateKey() {
      if (isSecretKeyGenerationFailing) {
        throw new ProviderException("Keystore failed");
      }
      byte[] keyBytes = new byte[32];
      RANDOM.nextBytes(keyBytes);
      SecretKey key = new SecretKeySpec(keyBytes, algorithm);
      if (spec != null) {
        keystoreEntries.put(spec.getKeystoreAlias(), () -> key);
      }
      return key;
    }
  }

  /** Fake AndroidKeyStore HMAC-SHA256 KeyGeneratorSpi. */
  public static final class HmacKeyGeneratorSpi extends SecretKeyGeneratorSpi {
    public HmacKeyGeneratorSpi() {
      super("HmacSHA256");
    }
  }

  /** Fake AndroidKeyStore AES-256 KeyGeneratorSpi. */
  public static final class AesKeyGeneratorSpi extends SecretKeyGeneratorSpi {
    public AesKeyGeneratorSpi() {
      super("AES");
    }
  }

  private record AuthBoundKey(PrivateKey raw) implements PrivateKey {
    @Override
    public String getAlgorithm() {
      return raw.getAlgorithm();
    }

    @Override
    public String getFormat() {
      return null;
    }

    @Override
    public byte[] getEncoded() {
      return null;
    }
  }

  /**
   * Handle of a secret key that the user must authenticate to use. Like an AndroidKeyStore key, it
   * holds no key material that another provider could use, such as the Conscrypt provider that
   * Robolectric installs ahead of the fake one, so only {@link FakeCipherSpi} accepts it.
   */
  private record AuthBoundSecretKey(SecretKey raw) implements SecretKey {
    @Override
    public String getAlgorithm() {
      return raw.getAlgorithm();
    }

    @Override
    @Nullable
    public String getFormat() {
      return null;
    }

    @Override
    @Nullable
    public byte[] getEncoded() {
      return null;
    }
  }

  /** An entry representing a private key, its certificate chain, and its generation specs. */
  public static class PrivateKeyEntry implements Entry {
    private final PrivateKey privateKey;
    private final Certificate[] certificateChain;
    @Nullable private final KeyGenParameterSpec spec;

    @Override
    public Key getKey() {
      PrivateKey key = getPrivateKey();
      return key != null && isUserAuthenticationRequired() ? new AuthBoundKey(key) : key;
    }

    @Override
    public boolean isUserAuthenticationRequired() {
      return !(privateKey instanceof InvalidatedPrivateKey)
          && spec != null
          && spec.isUserAuthenticationRequired();
    }

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

  /** An entry representing an imported secret key and the {@link KeyProtection} it enforces. */
  public record SecretKeyEntry(SecretKey secretKey, KeyProtection protection) implements Entry {
    @Override
    public Key getKey() {
      return isUserAuthenticationRequired() ? new AuthBoundSecretKey(secretKey) : secretKey;
    }

    @Override
    public boolean isUserAuthenticationRequired() {
      return protection.isUserAuthenticationRequired();
    }
  }

  /** Handle of a private key that {@link #invalidateKey} invalidated. */
  static final class InvalidatedPrivateKey implements PrivateKey {
    @Override
    public String getAlgorithm() {
      return "RSA";
    }

    @Override
    @Nullable
    public String getFormat() {
      return null;
    }

    @Override
    @Nullable
    public byte[] getEncoded() {
      return null;
    }
  }

  /** Fake AndroidKeyStore RSA CipherSpi that refuses keys invalidated by {@link #invalidateKey}. */
  public static final class InvalidatedKeyCipherSpi extends CipherSpi {
    @Override
    protected void engineSetMode(String mode) {}

    @Override
    protected void engineSetPadding(String padding) {}

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
      PrivateKeyEntry entry = findPrivateKeyEntry(key);
      if (entry != null
          && entry.getSpec() != null
          && !Arrays.asList(entry.getSpec().getEncryptionPaddings())
              .contains(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)) {
        throw new InvalidKeyException("Key is not authorized for PKCS#1 padding.");
      }
      throw new KeyPermanentlyInvalidatedException();
    }

    @Override
    protected void engineInit(
        int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException {
      PrivateKeyEntry entry = findPrivateKeyEntry(key);
      if (entry != null
          && entry.getSpec() != null
          && !Arrays.asList(entry.getSpec().getEncryptionPaddings())
              .contains(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)) {
        throw new InvalidKeyException("Key is not authorized for OAEP padding.");
      }
      throw new KeyPermanentlyInvalidatedException();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException {
      throw new KeyPermanentlyInvalidatedException();
    }

    @Override
    protected int engineGetBlockSize() {
      return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      return 0;
    }

    @Override
    @Nullable
    protected byte[] engineGetIV() {
      return null;
    }

    @Override
    @Nullable
    protected AlgorithmParameters engineGetParameters() {
      return null;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      throw new IllegalStateException("Cipher not initialized.");
    }

    @Override
    protected int engineUpdate(
        byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
      throw new IllegalStateException("Cipher not initialized.");
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
      throw new IllegalStateException("Cipher not initialized.");
    }

    @Override
    protected int engineDoFinal(
        byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
      throw new IllegalStateException("Cipher not initialized.");
    }
  }

  // --- Static control methods for tests ---

  /**
   * Sets the authentication state for the fake keystore. A fake Cipher should check this state.
   * This also clears the states set for single aliases.
   *
   * @param authenticated The simulated authentication status.
   */
  public static void setUserAuthenticated(boolean authenticated) {
    isUserAuthenticated = authenticated;
    aliasAuthenticationStates.clear();
    latestPendingCipher.set(null);
  }

  /**
   * Sets the authentication state of the key of {@code alias} alone, like a {@code BiometricPrompt}
   * that authorizes a {@code CryptoObject} of that key. It overrides the state set for every key.
   */
  public static void setUserAuthenticated(String alias, boolean authenticated) {
    aliasAuthenticationStates.put(alias, authenticated);
  }

  /** Authorizes {@code cipher} for its next single operation, like a {@code CryptoObject}. */
  public static void authorizeOperation(Cipher cipher) {
    authorizingCipher.set(true);
    try {
      cipher.getParameters();
    } finally {
      authorizingCipher.set(false);
    }
  }

  /** Authorizes the most recently initialized per-operation {@code Cipher}, if any. */
  public static void authorizeLatestPendingCipher() {
    FakeCipherSpi pending = latestPendingCipher.get();
    if (pending != null) {
      pending.authorizedForNextOperation = true;
    }
  }

  /** Returns the current simulated authentication state. */
  public static boolean isUserAuthenticated() {
    return isUserAuthenticated;
  }

  /** Returns the simulated authentication state of the key of {@code alias}. */
  public static boolean isUserAuthenticated(String alias) {
    return aliasAuthenticationStates.getOrDefault(alias, isUserAuthenticated);
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

  /**
   * Helper for fake key factories to retrieve the entry holding a private key.
   *
   * @param key The private key to look up.
   * @return The {@link PrivateKeyEntry} holding {@code key}, or null if not found.
   */
  @Nullable
  public static PrivateKeyEntry findPrivateKeyEntry(Key key) {
    Key rawKey = key instanceof AuthBoundKey bound ? bound.raw : key;
    for (Entry entry : keystoreEntries.values()) {
      if (entry instanceof PrivateKeyEntry privateKeyEntry
          && Objects.equals(privateKeyEntry.getPrivateKey(), rawKey)) {
        return privateKeyEntry;
      }
    }
    return null;
  }

  static boolean holdsKey(Object key) {
    if (key instanceof InvalidatedPrivateKey) {
      // InvalidatedKeyCipherSpi refuses the keys that invalidateKey() invalidated.
      return false;
    }
    return key instanceof AuthBoundKey
        || key instanceof AuthBoundSecretKey
        || keystoreEntries.values().stream()
            .anyMatch(
                entry ->
                    Objects.equals(
                        key, entry instanceof PrivateKeyEntry k ? k.privateKey : entry.getKey()));
  }

  /** Permanently invalidates the private key of {@code alias} for {@code Cipher.init}. */
  public static void invalidateKey(String alias) {
    PrivateKeyEntry entry = Objects.requireNonNull(getPrivateKeyEntry(alias));
    keystoreEntries.put(
        alias,
        new PrivateKeyEntry(
            new InvalidatedPrivateKey(), entry.getCertificateChain(), entry.getSpec()));
  }

  /** Makes loading the key of {@code alias} throw {@code failure}, as an ailing Keystore does. */
  public static void failKeyLookup(String alias, RuntimeException failure) {
    keystoreEntries.put(
        alias,
        new PrivateKeyEntry(
            /* privateKey= */ null, /* certificateChain= */ null, /* spec= */ null) {
          @Override
          public Key getKey() {
            throw failure;
          }
        });
  }

  // --- Overridden KeyStoreSpi Methods ---

  @Override
  public Key engineGetKey(String alias, char[] password)
      throws NoSuchAlgorithmException, UnrecoverableKeyException {
    Entry entry = keystoreEntries.get(alias);
    // FakeCipherSpi checks a key that decrypts when it is used, like the real Keystore. Any other
    // key, such as a MAC key, still fails here, since no fake operation checks it.
    if (entry != null
        && entry.isUserAuthenticationRequired()
        && !isUserAuthenticated(alias)
        && !(entry instanceof PrivateKeyEntry)
        && !(entry instanceof SecretKeyEntry secret
            && (secret.protection().getPurposes() & KeyProperties.PURPOSE_DECRYPT) != 0)) {
      throw new UnrecoverableKeyException("User not authenticated");
    }
    return entry != null ? entry.getKey() : null;
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    if (certificateChainFailuresLeft > 0) {
      certificateChainFailuresLeft--;
      return null;
    }
    if (isCertificateChainNull) {
      return null;
    }
    PrivateKeyEntry entry = getPrivateKeyEntry(alias);
    return (entry != null) ? entry.getCertificateChain() : null;
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    if (certificateLookupFailure != null) {
      throw certificateLookupFailure;
    }
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
  public void engineSetEntry(
      String alias, KeyStore.Entry entry, @Nullable KeyStore.ProtectionParameter protParam)
      throws KeyStoreException {
    if (!(entry instanceof KeyStore.SecretKeyEntry secretKeyEntry)) {
      super.engineSetEntry(alias, entry, protParam);
    } else if (isSecretKeyImportRefused) {
      throw new KeyStoreException("Secret key import refused.");
    } else if (protParam instanceof KeyProtection protection) {
      keystoreEntries.put(alias, new SecretKeyEntry(secretKeyEntry.getSecretKey(), protection));
    } else {
      // Like AndroidKeyStore, which cannot import a secret key without the protection to enforce.
      throw new KeyStoreException("Importing a secret key requires a KeyProtection.");
    }
  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    if (isDeleteFailing) {
      throw new ProviderException("Delete failed.");
    }
    if (deleteFailure != null) {
      throw deleteFailure;
    }
    keystoreEntries.remove(alias);
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    return keystoreEntries.containsKey(alias);
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    return keystoreEntries.get(alias) != null;
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

  static final class FakeCipherSpi extends CipherSpi {
    private final Cipher delegate;
    @Nullable private String authAlias;
    private boolean perOperation;
    private boolean authorizedForNextOperation;

    FakeCipherSpi(String transformation) {
      try {
        delegate =
            switch (transformation) {
              case "RSA/ECB/PKCS1Padding" -> Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
              case "AES/CBC/NoPadding" -> Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
              default -> Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "SunJCE");
            };
      } catch (GeneralSecurityException e) {
        throw new ProviderException(e);
      }
    }

    @Override
    protected void engineSetMode(String mode) {}

    @Override
    protected void engineSetPadding(String padding) {}

    @Override
    protected int engineGetBlockSize() {
      return delegate.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      return delegate.getOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
      return delegate.getIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      authorizedForNextOperation |= authorizingCipher.get();
      return delegate.getParameters();
    }

    private Key beforeInit(int opmode, Key key) throws UserNotAuthenticatedException {
      Key rawKey = key;
      if (key instanceof AuthBoundKey bound) {
        rawKey = bound.raw();
      } else if (key instanceof AuthBoundSecretKey bound) {
        rawKey = bound.raw();
      }
      authorizedForNextOperation = false;
      authAlias = null;
      if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
        for (var candidate : keystoreEntries.entrySet()) {
          Entry entry = candidate.getValue();
          if (entry instanceof PrivateKeyEntry keyEntry
              && keyEntry.spec != null
              && keyEntry.spec.isUserAuthenticationRequired()
              && Objects.equals(rawKey, keyEntry.privateKey)) {
            authAlias = candidate.getKey();
            perOperation = keyEntry.spec.getUserAuthenticationValidityDurationSeconds() <= 0;
            break;
          }
          if (entry instanceof SecretKeyEntry secret
              && entry.isUserAuthenticationRequired()
              && (secret.protection().getPurposes() & KeyProperties.PURPOSE_DECRYPT) != 0
              && Objects.equals(rawKey, secret.secretKey())) {
            authAlias = candidate.getKey();
            perOperation = secret.protection().getUserAuthenticationValidityDurationSeconds() <= 0;
            break;
          }
        }
        if (authAlias != null && perOperation) {
          latestPendingCipher.set(this);
        } else if (authAlias != null && !isUserAuthenticated(authAlias)) {
          throw new UserNotAuthenticatedException("User not authenticated");
        }
      }
      return rawKey;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
      delegate.init(opmode, beforeInit(opmode, key), random);
    }

    @Override
    protected void engineInit(
        int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
      delegate.init(opmode, beforeInit(opmode, key), params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
      delegate.init(opmode, beforeInit(opmode, key), params, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int offset, int length) {
      return delegate.update(input, offset, length);
    }

    @Override
    protected int engineUpdate(
        byte[] input, int offset, int length, byte[] output, int outputOffset)
        throws ShortBufferException {
      return delegate.update(input, offset, length, output, outputOffset);
    }

    private void consumeOperationAuth() throws IllegalBlockSizeException {
      boolean wasAuthorized = authorizedForNextOperation;
      authorizedForNextOperation = false;
      if (authAlias != null && !(perOperation ? wasAuthorized : isUserAuthenticated(authAlias))) {
        throw new IllegalBlockSizeException("Key user not authenticated");
      }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int offset, int length)
        throws IllegalBlockSizeException, BadPaddingException {
      consumeOperationAuth();
      return input == null ? delegate.doFinal() : delegate.doFinal(input, offset, length);
    }

    @Override
    protected int engineDoFinal(
        byte[] input, int offset, int length, byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      consumeOperationAuth();
      return delegate.doFinal(input, offset, length, output, outputOffset);
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException {
      try {
        consumeOperationAuth();
      } catch (IllegalBlockSizeException e) {
        throw new InvalidKeyException("Failed to unwrap key", e);
      }
      return delegate.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }
  }
}
