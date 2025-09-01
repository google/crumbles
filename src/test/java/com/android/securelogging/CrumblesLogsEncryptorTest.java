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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsDecryptionException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.android.securelogging.LogBatch;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Tests for {@link CrumblesLogsEncryptor} using a fake AndroidKeyStore provider. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = {Build.VERSION_CODES.TIRAMISU})
public final class CrumblesLogsEncryptorTest {

  private static Provider fakeProviderInstance;
  private CrumblesLogsEncryptor encryptor;

  // Helper to generate a non-Keystore RSA KeyPair for testing external keys.
  private static KeyPair generateTestExternalRsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return kpg.generateKeyPair();
  }

  @BeforeClass
  public static void setUpClass() {
    // Given: A test environment requires a fake AndroidKeyStore provider.
    // When: The test class is being set up.
    // Then: The fake provider is inserted to intercept Keystore calls.
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    fakeProviderInstance = new FakeAndroidKeyStoreProvider();
    Security.insertProviderAt(fakeProviderInstance, 1);
  }

  @AfterClass
  public static void tearDownClass() {
    // Given: The fake provider was used for tests.
    // When: All tests in the class are finished.
    // Then: The fake provider is removed to clean up the security environment.
    if (fakeProviderInstance != null) {
      Security.removeProvider(fakeProviderInstance.getName());
      fakeProviderInstance = null;
    }
  }

  @Before
  public void setUp() {
    // Given: A new test is about to run.
    // When: The test environment is set up.
    // Then: The fake Keystore is cleared and a new encryptor instance is created for isolation.
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
    encryptor = new CrumblesLogsEncryptor();
  }

  @After
  public void tearDown() {
    // Given: A test has just finished.
    // When: The test environment is torn down.
    // Then: Any residual keys from the fake Keystore are cleared.
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
  }

  // --- Keystore KeyPair Management Tests ---

  @Test
  public void doesPrivateKeyExist_whenKeyNotPresent_isFalse() {
    // Given: A new CrumblesLogsEncryptor instance and empty keystore.
    // When: doesPrivateKeyExist is called.
    // Then: The result is false.
    assertThat(encryptor.doesPrivateKeyExist()).isFalse();
  }

  @Test
  public void getPublicKey_returnsNullWhenKeyAliasDoesNotExist() {
    // Given: The fake Keystore is empty.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();
    // When: getPublicKey is called.
    // Then: The result is null because no key with the alias exists.
    assertThat(encryptor.getPublicKey()).isNull();
  }

  @Test
  public void generateKeyPair_whenCalledFirstTime_createsAndStoresNewKeyPairInFakeKeyStore()
      throws Exception {
    // Given: An empty fake Keystore and a new CrumblesLogsEncryptor instance.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesLogsEncryptor.KEY_ALIAS);

    // When: generateKeyPair is called for the first time.
    KeyPair generatedKeyPair = encryptor.generateKeyPair();

    // Then: A new KeyPair is generated and returned.
    assertThat(generatedKeyPair).isNotNull();
    assertThat(generatedKeyPair.getPrivate()).isNotNull();
    assertThat(generatedKeyPair.getPublic()).isNotNull();
    // And: The generated key pair is stored in the fake Keystore.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).containsKey(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.Entry entry =
        FakeAndroidKeyStoreSpi.keystoreEntries.get(CrumblesLogsEncryptor.KEY_ALIAS);
    assertThat(entry).isInstanceOf(FakeAndroidKeyStoreSpi.PrivateKeyEntry.class);
    FakeAndroidKeyStoreSpi.PrivateKeyEntry pke = (FakeAndroidKeyStoreSpi.PrivateKeyEntry) entry;
    assertThat(pke.getPrivateKey().getEncoded())
        .isEqualTo(generatedKeyPair.getPrivate().getEncoded());
  }

  @Test
  public void generateKeyPair_specRequiresUserAuthentication() throws Exception {
    // When a key pair is generated
    encryptor.generateKeyPair();

    // Then the KeyGenParameterSpec used should require user authentication
    FakeAndroidKeyStoreSpi.PrivateKeyEntry entry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    assertThat(entry).isNotNull();
    KeyGenParameterSpec spec = entry.getSpec();
    assertThat(spec).isNotNull();
    assertThat(spec.isUserAuthenticationRequired()).isTrue();
    assertThat(spec.getUserAuthenticationValidityDurationSeconds()).isEqualTo(30);
  }

  @Test
  public void
      generateKeyPair_whenKeyAlreadyExistsInKeystore_thenLoadsExistingKeyPairFromFakeKeyStore()
          throws Exception {
    // Given: A key already exists in the fake Keystore from a previous operation.
    new CrumblesLogsEncryptor().generateKeyPair();
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).containsKey(CrumblesLogsEncryptor.KEY_ALIAS);

    // And: We simulate successful user authentication so the Keystore can be unlocked.
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    KeyPair initiallyGeneratedKeyPair = encryptor.generateKeyPair(); // Load it for comparison.

    // When: getPublicKey is called on a new instance.
    CrumblesLogsEncryptor newEncryptor = new CrumblesLogsEncryptor();
    PublicKey loadedPublicKey = newEncryptor.getPublicKey();

    // Then: The existing public key is loaded from the fake Keystore and its contents match the
    // original.
    assertThat(loadedPublicKey).isNotNull();
    assertThat(loadedPublicKey.getEncoded())
        .isEqualTo(initiallyGeneratedKeyPair.getPublic().getEncoded());
  }

  // --- External KeyPair Management Tests ---
  @Test
  public void setExternalEncryptionPublicKey_whenKeyProvided_thenGetterReturnsSameKey()
      throws Exception {
    // Given: A valid external PublicKey.
    PublicKey externalPublicKey = generateTestExternalRsaKeyPair().getPublic();

    // When: The key is set via setExternalEncryptionPublicKey.
    encryptor.setExternalEncryptionPublicKey(externalPublicKey);

    // Then: The same key is retrievable via getExternalEncryptionPublicKey.
    assertThat(encryptor.getExternalEncryptionPublicKey()).isSameInstanceAs(externalPublicKey);
  }

  @Test
  public void generateAndSetExternalKeyPair_whenCalled_providesBytesAndSetsPublicKey()
      throws Exception {
    // Given: A consumer to capture the generated private key bytes.
    final AtomicReference<byte[]> privateKeyBytesRef = new AtomicReference<>();

    // When: generateAndSetExternalKeyPair is called with the consumer.
    encryptor.generateAndSetExternalKeyPair(privateKeyBytesRef::set);

    // Then: The consumer receives valid private key bytes.
    assertThat(privateKeyBytesRef.get()).isNotNull();
    assertThat(privateKeyBytesRef.get().length).isGreaterThan(0);
    // And: The encryptor has its external public key set.
    PublicKey externalPublicKey = encryptor.getExternalEncryptionPublicKey();
    assertThat(externalPublicKey).isNotNull();
    assertThat(externalPublicKey.getAlgorithm()).isEqualTo("RSA");
    // And: The encryptor does not use the Keystore.
    assertThat(encryptor.doesPrivateKeyExist()).isFalse();
  }

  @Test
  public void generateAndSetExternalKeyPair_whenCalled_thenDoesNotUseKeystore() throws Exception {
    // Given: An empty fake Keystore.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();

    // When: generateAndSetExternalKeyPair is called.
    encryptor.generateAndSetExternalKeyPair(bytes -> {});

    // Then: The fake Keystore remains empty.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();
  }

  // --- Encryption Path Tests ---

  @Test
  public void encryptLogs_producesDifferentIVsOnSubsequentCalls() throws Exception {
    // Given: The encryptor will use a Keystore key for encryption.
    // And: The user is authenticated to allow key generation/loading.
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    encryptor.generateKeyPair();
    byte[] logData = "some log data".getBytes(UTF_8);

    // When: encryptLogs is called twice.
    LogBatch batch1 = encryptor.encryptLogs(logData);
    LogBatch batch2 = encryptor.encryptLogs(logData);

    // Then: The Initialization Vectors (IVs) in each LogBatch must be different.
    byte[] iv1 = batch1.getKey().getIv().toByteArray();
    byte[] iv2 = batch2.getKey().getIv().toByteArray();
    assertThat(iv1).isNotNull();
    assertThat(iv2).isNotNull();
    assertThat(iv1).hasLength(12);
    assertThat(iv2).hasLength(12);
    assertThat(Arrays.equals(iv1, iv2)).isFalse();
  }

  @Test
  public void encryptLogs_whenExternalPublicKeyIsSet_thenDoesNotInitializeKeystoreKeyIfNotPresent()
      throws Exception {
    // Given: A valid external PublicKey is set on the encryptor.
    encryptor.setExternalEncryptionPublicKey(generateTestExternalRsaKeyPair().getPublic());
    // And: The fake Keystore is empty.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();

    // When: encryptLogs is called.
    encryptor.encryptLogs("test encryption with external key.".getBytes(UTF_8));

    // Then: The encryption proceeds without accessing or generating a Keystore key.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();
  }

  @Test
  public void encryptLogs_whenNoEncryptionKeyIsSet_logsIgnored() throws Exception {
    // Given: A valid external PublicKey is not set on the encryptor.
    // And: The fake Keystore is empty.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();

    // When: encryptLogs is called.
    // Then: it returns null.
    assertThat(encryptor.encryptLogs("test encryption with external key.".getBytes(UTF_8)))
        .isNull();
  }

  // --- Decryption Tests (Primarily Keystore Path) ---

  @Test
  public void decryptLogs_withAuthRequiredKeyAndUserAuthenticated_succeeds() throws Exception {
    // Given: A LogBatch encrypted with a Keystore key that requires authentication.
    String originalContent = "test decryption with loaded and authenticated Keystore key.";
    encryptor.generateKeyPair(); // Generates key.

    // And: The user provides successful authentication for the fake keystore to allow encryption.
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch logBatch = encryptor.encryptLogs(originalContent.getBytes(UTF_8));

    // And: A new CrumblesLogsEncryptor instance, simulating an app restart.
    CrumblesLogsEncryptor decryptingEncryptor = new CrumblesLogsEncryptor();
    // And: Auth state is still true.

    // When: decryptLogs is called on the new instance.
    byte[] decryptedBytes = decryptingEncryptor.decryptLogs(logBatch);

    // Then: The key is loaded from the fake Keystore and decryption succeeds.
    assertThat(new String(decryptedBytes, UTF_8)).isEqualTo(originalContent);
  }

  @Test
  public void decryptLogs_withAuthRequiredKeyAndNoAuth_throwsCrumblesKeysException()
      throws Exception {
    // Given: A LogBatch encrypted with a Keystore key that requires authentication.
    String originalContent = "this should not be decrypted";
    encryptor.generateKeyPair();

    // And: Authenticate temporarily to allow the encryption step to succeed.
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch logBatch = encryptor.encryptLogs(originalContent.getBytes(UTF_8));

    // And: Lock the keystore again by revoking authentication.
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);

    CrumblesLogsEncryptor decryptingEncryptor = new CrumblesLogsEncryptor();

    // When: decryptLogs is called while not authenticated.
    // Then: A CrumblesKeysException is thrown because the underlying UnrecoverableKeyException is
    // caught and wrapped by the production code.
    CrumblesKeysException e =
        assertThrows(CrumblesKeysException.class, () -> decryptingEncryptor.decryptLogs(logBatch));

    // And: The cause of the exception should be the authentication error.
    assertThat(e).hasCauseThat().isInstanceOf(UnrecoverableKeyException.class);
    assertThat(e).hasCauseThat().hasMessageThat().contains("User not authenticated");
  }

  @Test
  public void decryptLogs_whenEncryptedWithExternalKey_thenFailsWithKeystoreKey() throws Exception {
    // Given: A LogBatch encrypted with an external key.
    encryptor.setExternalEncryptionPublicKey(generateTestExternalRsaKeyPair().getPublic());
    LogBatch logBatch = encryptor.encryptLogs("encrypted with external key.".getBytes(UTF_8));

    // When: Decryption is attempted with an encryptor that can only access the Keystore.
    CrumblesLogsEncryptor decryptorWithKeystore = new CrumblesLogsEncryptor();
    // And: No Keystore key exists.
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();

    // Then: A CrumblesKeysException is thrown because no decryption key is available.
    assertThrows(CrumblesKeysException.class, () -> decryptorWithKeystore.decryptLogs(logBatch));

    // And: When a different Keystore key exists.
    decryptorWithKeystore.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true); // Allow key access for decryption attempt

    // Then: A CrumblesLogsDecryptionException is still thrown because the keys do not match.
    assertThrows(
        CrumblesLogsDecryptionException.class, () -> decryptorWithKeystore.decryptLogs(logBatch));
  }

  // --- Hashing and Helper Method Tests are omitted for brevity as they were not failing ---

  // --- Serialization/Deserialization Test ---

  @Test
  public void
      serializeBytesAndDeserializeFile_whenLogBatchIsValid_thenMaintainsDataIntegrityAndCanBeDecrypted()
          throws Exception {
    // Given: A valid LogBatch encrypted with a Keystore key.
    String originalContent = "serialize deserialize test with fake keystore.";
    encryptor.generateKeyPair();
    // And: The user authenticates before encryption.
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch originalLogBatch = encryptor.encryptLogs(originalContent.getBytes(UTF_8));

    // And: A temporary directory for file operations.
    Path tempDir = Files.createTempDirectory("crumbles_test_");
    File baseDir = tempDir.toFile();
    String fileName = "test_log_fake.bin";

    // When: The LogBatch is serialized to a file and then deserialized back.
    Path filePath = encryptor.serializeBytes(originalLogBatch, baseDir, fileName);
    LogBatch deserializedLogBatch = encryptor.deserializeFile(filePath);

    // And: The authentication is still valid for decryption.

    // Then: The resulting LogBatch is identical and can be successfully decrypted.
    assertThat(Files.exists(filePath)).isTrue();
    assertThat(deserializedLogBatch).isNotNull();
    byte[] decryptedData = encryptor.decryptLogs(deserializedLogBatch);
    assertThat(new String(decryptedData, UTF_8)).isEqualTo(originalContent);

    // Cleanup.
    Files.delete(filePath);
    Files.delete(tempDir);
  }
}
