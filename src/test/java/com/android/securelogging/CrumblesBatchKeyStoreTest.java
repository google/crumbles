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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import com.android.securelogging.CrumblesBatchKeyStore.WrappedKey;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import com.google.testing.junit.testparameterinjector.TestParameter;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;

/** Tests for {@link CrumblesBatchKeyStore} with a fake AndroidKeyStore provider. */
@RunWith(RobolectricTestParameterInjector.class)
public final class CrumblesBatchKeyStoreTest {
  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUpClass() {
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
  }

  @AfterClass
  public static void tearDownClass() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Before
  public void setUp() {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
  }

  private static FakeAndroidKeyStoreSpi.SecretKeyEntry storedEntry(String alias) {
    return (FakeAndroidKeyStoreSpi.SecretKeyEntry)
        FakeAndroidKeyStoreSpi.keystoreEntries.get(alias);
  }

  private static SecretKey newAesKey(int sizeBytes) {
    byte[] keyBytes = new byte[sizeBytes];
    new SecureRandom().nextBytes(keyBytes);
    return new SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES);
  }

  private static ImmutableList<ByteString> encodings(List<SecretKey> keys) {
    return keys.stream()
        .map(key -> ByteString.copyFrom(key.getEncoded()))
        .collect(toImmutableList());
  }

  private static Cipher authorizedUnwrapCipher() throws CrumblesKeysException {
    Cipher cipher = CrumblesBatchKeyStore.createUnwrapCipher();
    FakeAndroidKeyStoreSpi.authorizeOperation(cipher);
    return cipher;
  }

  @Test
  public void createKeys_importsEncryptOnlyWrapKeyWithoutAuthentication() throws Exception {
    CrumblesBatchKeyStore.createKeys();

    KeyProtection protection = storedEntry(CrumblesBatchKeyStore.WRAP_KEY_ALIAS).protection();
    expect.that(protection.getPurposes()).isEqualTo(KeyProperties.PURPOSE_ENCRYPT);
    expect.that(protection.getBlockModes()).asList().containsExactly(KeyProperties.BLOCK_MODE_CBC);
    expect
        .that(protection.getEncryptionPaddings())
        .asList()
        .containsExactly(KeyProperties.ENCRYPTION_PADDING_NONE);
    expect.that(protection.isRandomizedEncryptionRequired()).isTrue();
    expect.that(protection.isUserAuthenticationRequired()).isFalse();
    expect.that(protection.isUnlockedDeviceRequired()).isFalse();
  }

  @Test
  public void createKeys_importsDecryptOnlyUnwrapKeyWithPerOperationAuthentication()
      throws Exception {
    CrumblesBatchKeyStore.createKeys();

    KeyProtection protection = storedEntry(CrumblesBatchKeyStore.UNWRAP_KEY_ALIAS).protection();
    expect.that(protection.getPurposes()).isEqualTo(KeyProperties.PURPOSE_DECRYPT);
    expect.that(protection.getBlockModes()).asList().containsExactly(KeyProperties.BLOCK_MODE_CBC);
    expect
        .that(protection.getEncryptionPaddings())
        .asList()
        .containsExactly(KeyProperties.ENCRYPTION_PADDING_NONE);
    expect.that(protection.isUserAuthenticationRequired()).isTrue();
    expect.that(protection.getUserAuthenticationValidityDurationSeconds()).isEqualTo(0);
    expect
        .that(protection.getUserAuthenticationType())
        .isEqualTo(KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
    expect.that(protection.isInvalidatedByBiometricEnrollment()).isFalse();
    expect.that(protection.isUnlockedDeviceRequired()).isTrue();
  }

  @Test
  public void createKeys_importsTheSameAes256KeyUnderBothAliases() throws Exception {
    CrumblesBatchKeyStore.createKeys();

    SecretKey wrapKey = storedEntry(CrumblesBatchKeyStore.WRAP_KEY_ALIAS).secretKey();
    expect.that(storedEntry(CrumblesBatchKeyStore.UNWRAP_KEY_ALIAS).secretKey()).isEqualTo(wrapKey);
    expect.that(wrapKey.getAlgorithm()).isEqualTo(KeyProperties.KEY_ALGORITHM_AES);
    expect.that(wrapKey.getEncoded()).hasLength(32);
  }

  @Test
  public void createKeys_replacesThePreviousKey() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    SecretKey previousKey = storedEntry(CrumblesBatchKeyStore.WRAP_KEY_ALIAS).secretKey();

    CrumblesBatchKeyStore.createKeys();

    assertThat(storedEntry(CrumblesBatchKeyStore.WRAP_KEY_ALIAS).secretKey())
        .isNotEqualTo(previousKey);
  }

  @Test
  public void createKeys_whenKeystoreIsUnavailable_throws() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    try {
      assertThrows(CrumblesKeysException.class, CrumblesBatchKeyStore::createKeys);
    } finally {
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  @Test
  public void createKeys_whenUnwrapKeyImportFails_deletesWrapKey() {
    Provider failingProvider = new FakeAndroidKeyStoreProvider();
    failingProvider.put(
        "KeyStore." + FakeAndroidKeyStoreProvider.PROVIDER_NAME,
        RejectUnwrapKeyStoreSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(failingProvider, 1);
    try {
      assertThrows(CrumblesKeysException.class, CrumblesBatchKeyStore::createKeys);
      assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  /**
   * A {@link FakeAndroidKeyStoreSpi} that fails when importing {@link
   * CrumblesBatchKeyStore#UNWRAP_KEY_ALIAS}.
   */
  public static final class RejectUnwrapKeyStoreSpi extends FakeAndroidKeyStoreSpi {
    @Override
    public void engineSetEntry(
        String alias, KeyStore.Entry entry, @Nullable KeyStore.ProtectionParameter protParam)
        throws KeyStoreException {
      if (alias.equals(CrumblesBatchKeyStore.UNWRAP_KEY_ALIAS)) {
        throw new KeyStoreException("Simulated unwrap key import failure.");
      }
      super.engineSetEntry(alias, entry, protParam);
    }
  }

  @Test
  public void hasKeys_afterCreateKeys_returnsTrue() throws Exception {
    CrumblesBatchKeyStore.createKeys();

    assertThat(CrumblesBatchKeyStore.hasKeys()).isTrue();
  }

  @Test
  public void hasKeys_withOneAliasMissing_returnsFalse(
      @TestParameter({CrumblesBatchKeyStore.WRAP_KEY_ALIAS, CrumblesBatchKeyStore.UNWRAP_KEY_ALIAS})
          String missingAlias)
      throws Exception {
    CrumblesBatchKeyStore.createKeys();
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(missingAlias);

    assertThat(CrumblesBatchKeyStore.hasKeys()).isFalse();
  }

  @Test
  public void hasKeys_whenKeystoreIsUnavailable_returnsFalse() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    try {
      assertThat(CrumblesBatchKeyStore.hasKeys()).isFalse();
    } finally {
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  @Test
  public void deleteKeys_removesBothAliases() throws Exception {
    CrumblesBatchKeyStore.createKeys();

    CrumblesBatchKeyStore.deleteKeys();

    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();
  }

  @Test
  public void wrap_returnsTheBatchKeyEncryptedUnderTheIvItStartsWith() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    SecretKey batchKey = newAesKey(32);

    byte[] wrappedKey = CrumblesBatchKeyStore.wrap(batchKey).wrappedKey().toByteArray();

    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        storedEntry(CrumblesBatchKeyStore.UNWRAP_KEY_ALIAS).secretKey(),
        new IvParameterSpec(wrappedKey, 0, 16));
    FakeAndroidKeyStoreSpi.authorizeOperation(cipher);
    expect.that(wrappedKey).hasLength(48);
    expect.that(cipher.doFinal(wrappedKey, 16, 32)).isEqualTo(batchKey.getEncoded());
  }

  @Test
  public void wrap_returnsTheStartOfTheZeroBlockEncryptionAsKeyId() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    cipher.init(
        Cipher.ENCRYPT_MODE,
        storedEntry(CrumblesBatchKeyStore.WRAP_KEY_ALIAS).secretKey(),
        new IvParameterSpec(new byte[16]));
    ByteString zeroBlockEncryption = ByteString.copyFrom(cipher.doFinal(new byte[16]));

    WrappedKey wrappedKey = CrumblesBatchKeyStore.wrap(newAesKey(32));

    assertThat(wrappedKey.keyId()).isEqualTo(zeroBlockEncryption.substring(0, 8));
  }

  @Test
  public void wrap_withAKeyThatIsNotAes256_throws() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    SecretKey aes128Key = newAesKey(16);

    assertThrows(IllegalArgumentException.class, () -> CrumblesBatchKeyStore.wrap(aes128Key));
  }

  @Test
  public void wrap_withoutKeys_throws() {
    SecretKey batchKey = newAesKey(32);

    assertThrows(CrumblesKeysException.class, () -> CrumblesBatchKeyStore.wrap(batchKey));
  }

  @Test
  public void unwrap_returnsTheBatchKeyOfEachWrappedKeyInOrder() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    ImmutableList<SecretKey> batchKeys =
        ImmutableList.of(newAesKey(32), newAesKey(32), newAesKey(32));
    ImmutableList.Builder<ByteString> wrappedKeys = ImmutableList.builder();
    for (SecretKey batchKey : batchKeys) {
      wrappedKeys.add(CrumblesBatchKeyStore.wrap(batchKey).wrappedKey());
    }
    Cipher unwrapCipher = authorizedUnwrapCipher();

    ImmutableList<SecretKey> unwrappedKeys =
        CrumblesBatchKeyStore.unwrap(unwrapCipher, wrappedKeys.build());

    assertThat(encodings(unwrappedKeys)).containsExactlyElementsIn(encodings(batchKeys)).inOrder();
  }

  @Test
  public void unwrap_withAWrappedKeyOfAnotherSize_throws() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    ByteString wrappedKey = CrumblesBatchKeyStore.wrap(newAesKey(32)).wrappedKey();
    ImmutableList<ByteString> twoWrappedKeysAsOne = ImmutableList.of(wrappedKey.concat(wrappedKey));
    Cipher unwrapCipher = authorizedUnwrapCipher();

    assertThrows(
        IllegalArgumentException.class,
        () -> CrumblesBatchKeyStore.unwrap(unwrapCipher, twoWrappedKeysAsOne));
  }

  @Test
  public void unwrap_whenTheCipherFails_throws() throws Exception {
    Cipher failingCipher = Cipher.getInstance("AES/GCM/NoPadding");
    failingCipher.init(Cipher.DECRYPT_MODE, newAesKey(32), new GCMParameterSpec(128, new byte[12]));
    ImmutableList<ByteString> wrappedKeys = ImmutableList.of(ByteString.copyFrom(new byte[48]));

    assertThrows(
        CrumblesKeysException.class,
        () -> CrumblesBatchKeyStore.unwrap(failingCipher, wrappedKeys));
  }

  @Test
  public void createUnwrapCipher_withoutKeys_throws() {
    assertThrows(CrumblesKeysException.class, CrumblesBatchKeyStore::createUnwrapCipher);
  }

  public static final class ProviderExceptionKeyStoreSpi extends FakeAndroidKeyStoreSpi {
    @Override
    public boolean engineContainsAlias(String alias) {
      throw new ProviderException("Keystore failed");
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
      throw new ProviderException("Keystore failed");
    }

    @Override
    public void engineDeleteEntry(String alias) {
      throw new ProviderException("Keystore failed");
    }
  }

  @Test
  public void deleteKeys_whenKeystoreThrowsProviderException_doesNotThrow() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    Provider failingProvider = new FakeAndroidKeyStoreProvider();
    failingProvider.put(
        "KeyStore." + FakeAndroidKeyStoreProvider.PROVIDER_NAME,
        ProviderExceptionKeyStoreSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(failingProvider, 1);
    try {
      CrumblesBatchKeyStore.deleteKeys();
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  @Test
  public void hasKeys_whenKeystoreThrowsProviderException_returnsFalse() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    Provider failingProvider = new FakeAndroidKeyStoreProvider();
    failingProvider.put(
        "KeyStore." + FakeAndroidKeyStoreProvider.PROVIDER_NAME,
        ProviderExceptionKeyStoreSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(failingProvider, 1);
    try {
      assertThat(CrumblesBatchKeyStore.hasKeys()).isFalse();
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  @Test
  public void wrap_whenKeystoreThrowsProviderException_throwsCrumblesKeysException()
      throws Exception {
    CrumblesBatchKeyStore.createKeys();
    Provider failingProvider = new FakeAndroidKeyStoreProvider();
    failingProvider.put(
        "KeyStore." + FakeAndroidKeyStoreProvider.PROVIDER_NAME,
        ProviderExceptionKeyStoreSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(failingProvider, 1);
    try {
      assertThrows(CrumblesKeysException.class, () -> CrumblesBatchKeyStore.wrap(newAesKey(32)));
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  @Test
  public void createUnwrapCipher_whenKeystoreThrowsProviderException_throwsCrumblesKeysException()
      throws Exception {
    CrumblesBatchKeyStore.createKeys();
    Provider failingProvider = new FakeAndroidKeyStoreProvider();
    failingProvider.put(
        "KeyStore." + FakeAndroidKeyStoreProvider.PROVIDER_NAME,
        ProviderExceptionKeyStoreSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(failingProvider, 1);
    try {
      assertThrows(CrumblesKeysException.class, CrumblesBatchKeyStore::createUnwrapCipher);
    } finally {
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
      Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    }
  }

  @Test
  public void unwrap_whenCipherThrowsProviderException_throwsCrumblesKeysException()
      throws Exception {
    Cipher providerFailingCipher =
        new Cipher(
            new CipherSpi() {
              @Override
              protected void engineSetMode(String mode) {}

              @Override
              protected void engineSetPadding(String padding) {}

              @Override
              protected int engineGetBlockSize() {
                return 16;
              }

              @Override
              protected int engineGetOutputSize(int inputLen) {
                return inputLen;
              }

              @Override
              protected byte[] engineGetIV() {
                return new byte[16];
              }

              @Override
              protected AlgorithmParameters engineGetParameters() {
                return null;
              }

              @Override
              protected void engineInit(int opmode, Key key, SecureRandom random) {}

              @Override
              protected void engineInit(
                  int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {}

              @Override
              protected void engineInit(
                  int opmode, Key key, AlgorithmParameters params, SecureRandom random) {}

              @Override
              protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
                return new byte[0];
              }

              @Override
              protected int engineUpdate(
                  byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
                return 0;
              }

              @Override
              protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
                throw new ProviderException("Keystore operation failed");
              }

              @Override
              protected int engineDoFinal(
                  byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
                throw new ProviderException("Keystore operation failed");
              }
            },
            new FakeAndroidKeyStoreProvider(),
            "AES/CBC/NoPadding") {};
    providerFailingCipher.init(Cipher.DECRYPT_MODE, newAesKey(32));
    ImmutableList<ByteString> wrappedKeys = ImmutableList.of(ByteString.copyFrom(new byte[48]));

    assertThrows(
        CrumblesKeysException.class,
        () -> CrumblesBatchKeyStore.unwrap(providerFailingCipher, wrappedKeys));
  }

  @Test
  public void unwrap_withoutAuthorizedCipher_throws() throws Exception {
    CrumblesBatchKeyStore.createKeys();
    ByteString wrappedKey = CrumblesBatchKeyStore.wrap(newAesKey(32)).wrappedKey();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    Cipher unauthorizedCipher = CrumblesBatchKeyStore.createUnwrapCipher();

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class,
            () -> CrumblesBatchKeyStore.unwrap(unauthorizedCipher, ImmutableList.of(wrappedKey)));

    assertThat(thrown).hasCauseThat().isInstanceOf(IllegalBlockSizeException.class);
  }
}
