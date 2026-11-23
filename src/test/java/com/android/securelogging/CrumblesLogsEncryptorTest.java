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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.robolectric.Shadows.shadowOf;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import androidx.biometric.BiometricManager.Authenticators;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.test.core.app.ApplicationProvider;
import com.android.securelogging.CrumblesLogsEncryptor.BulkDecryptPartition;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsDecryptionException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.Timestamp;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.KeyEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogKey;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.SealedLogs;
import com.google.testing.junit.testparameterinjector.TestParameter;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Nullable;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;
import org.robolectric.annotation.Config;

/** Tests for {@link CrumblesLogsEncryptor} using a fake AndroidKeyStore provider. */
@RunWith(RobolectricTestParameterInjector.class)
@Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
public final class CrumblesLogsEncryptorTest {

  @Rule public final Expect expect = Expect.create();

  private static Provider fakeProviderInstance;
  private CrumblesLogsEncryptor encryptor;

  // Helper to generate a non-Keystore RSA KeyPair for testing external keys.
  private static KeyPair generateTestExternalRsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    return kpg.generateKeyPair();
  }

  /**
   * Creates the device key as earlier versions did after their OAEP capability probe failed:
   * authorized for PKCS#1 v1.5 padding only.
   */
  private static void generateLegacyPkcs1OnlyDeviceKey() throws Exception {
    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance("RSA", FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    keyPairGenerator.initialize(
        new KeyGenParameterSpec.Builder(
                CrumblesLogsEncryptor.KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(2048)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build());
    keyPairGenerator.generateKeyPair();
  }

  // Decrypts a batch the way an external reader holding an RSA-OAEP key pair does.
  private static byte[] decryptWithOaepKeyPair(KeyPair recipientKeyPair, LogBatch logBatch)
      throws Exception {
    return sealedLogsDecryptedWith(
            recipientKeyPair.getPrivate(), recipientKeyPair.getPublic(), logBatch)
        .getLogs()
        .toByteArray();
  }

  // Decrypts the SealedLogs of a version 2 batch with an RSA-OAEP private key, computing the
  // associated data for the given bound recipient.
  private static SealedLogs sealedLogsDecryptedWith(
      PrivateKey privateKey, PublicKey boundRecipient, LogBatch logBatch) throws Exception {
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsaCipher.init(
        Cipher.UNWRAP_MODE,
        privateKey,
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT));
    Key aesKey =
        rsaCipher.unwrap(
            logBatch.getKey().getEncryptedSymmetricKey().toByteArray(), "AES", Cipher.SECRET_KEY);
    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    aesCipher.init(
        Cipher.DECRYPT_MODE,
        aesKey,
        new GCMParameterSpec(128, logBatch.getKey().getIv().toByteArray()));
    aesCipher.updateAAD(
        CrumblesLogsEncryptor.computeAssociatedData(
            logBatch.getMetadata(), logBatch.getKey().getKeyEncryptionType(), boundRecipient));
    return sealedLogsInPaddedPlaintext(
        aesCipher.doFinal(logBatch.getData().getLogBlob().toByteArray()));
  }

  private static byte[] decrypt(CrumblesLogsEncryptor target, LogBatch logBatch) throws Exception {
    Cipher cipher = target.createUnwrapCipher(logBatch);
    FakeAndroidKeyStoreSpi.authorizeOperation(cipher);
    return target.decryptLogs(logBatch, cipher);
  }

  private static DecryptedLogBatch decryptLogBatch(CrumblesLogsEncryptor target, LogBatch logBatch)
      throws Exception {
    Cipher cipher = target.createUnwrapCipher(logBatch);
    FakeAndroidKeyStoreSpi.authorizeOperation(cipher);
    return target.decryptLogBatch(logBatch, cipher);
  }

  // Decrypts a batch with its batch-wrapped key, unwrapped with the stored batch-unwrap key.
  private static byte[] decryptWithBatchWrappedKey(LogBatch logBatch) throws Exception {
    byte[] wrappedKey = logBatch.getKey().getBatchWrappedSymmetricKey().toByteArray();
    Cipher unwrapCipher = Cipher.getInstance("AES/CBC/NoPadding");
    unwrapCipher.init(
        Cipher.DECRYPT_MODE,
        ((FakeAndroidKeyStoreSpi.SecretKeyEntry)
                FakeAndroidKeyStoreSpi.keystoreEntries.get(CrumblesBatchKeyStore.UNWRAP_KEY_ALIAS))
            .secretKey(),
        new IvParameterSpec(wrappedKey, 0, 16));
    FakeAndroidKeyStoreSpi.authorizeOperation(unwrapCipher);
    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    aesCipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(unwrapCipher.doFinal(wrappedKey, 16, 32), "AES"),
        new GCMParameterSpec(128, logBatch.getKey().getIv().toByteArray()));
    aesCipher.updateAAD(
        CrumblesLogsEncryptor.computeAssociatedData(
            logBatch.getMetadata(),
            logBatch.getKey().getKeyEncryptionType(),
            new CrumblesLogsEncryptor().getPublicKey()));
    return logsInPaddedPlaintext(aesCipher.doFinal(logBatch.getData().getLogBlob().toByteArray()));
  }

  // Reads the logs out of a padded version 2 plaintext the way logs.proto describes the layout.
  private static byte[] logsInPaddedPlaintext(byte[] paddedPlaintext) throws Exception {
    return sealedLogsInPaddedPlaintext(paddedPlaintext).getLogs().toByteArray();
  }

  // Reads the SealedLogs out of a padded version 2 plaintext the way logs.proto describes it.
  private static SealedLogs sealedLogsInPaddedPlaintext(byte[] paddedPlaintext) throws Exception {
    ByteBuffer paddedLogs = ByteBuffer.wrap(paddedPlaintext);
    byte[] sealedLogs = new byte[paddedLogs.getInt()];
    paddedLogs.get(sealedLogs);
    return SealedLogs.parseFrom(sealedLogs, ExtensionRegistryLite.getEmptyRegistry());
  }

  // Lays out content of at most 4092 bytes as the padded plaintext that logs.proto describes.
  private static byte[] inSmallestPaddingBucket(byte[] content) {
    return ByteBuffer.allocate(4096).putInt(content.length).put(content).array();
  }

  // Returns the DER certificates of the batch-signing key in the fake Keystore, leaf first.
  private static ImmutableList<ByteString> batchSigningKeyChain() throws Exception {
    ImmutableList.Builder<ByteString> chain = ImmutableList.builder();
    for (Certificate certificate :
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesBatchSigningKey.ALIAS)
            .getCertificateChain()) {
      chain.add(ByteString.copyFrom(certificate.getEncoded()));
    }
    return chain.build();
  }

  // Assembles a batch for the device key whose AES-GCM plaintext is exactly the given bytes.
  private LogBatch batchWithPlaintext(
      PublicKey devicePublicKey, byte[] plaintext, LogEncryptionType encryptionType)
      throws Exception {
    return batchWithPlaintext(devicePublicKey, plaintext, encryptionType, devicePublicKey);
  }

  // As above, but with associated data that binds boundRecipient rather than the device key.
  private LogBatch batchWithPlaintext(
      PublicKey devicePublicKey,
      byte[] plaintext,
      LogEncryptionType encryptionType,
      PublicKey boundRecipient)
      throws Exception {
    LogMetadata metadata =
        CrumblesLogsEncryptor.assembleMetadata(
                plaintext.length + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES, "device")
            .toBuilder()
            .setEncryptionType(encryptionType)
            .build();
    KeyEncryptionType keyEncryptionType = KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256;
    CrumblesLogsEncryptor.EncryptedData encryptedData =
        encryptor.encryptData(
            plaintext,
            CrumblesLogsEncryptor.computeAssociatedData(
                metadata, keyEncryptionType, boundRecipient),
            devicePublicKey);
    return CrumblesLogsEncryptor.assembleCipherText(
        encryptedData.ciphertext,
        encryptedData.encryptedSymmetricKey,
        encryptedData.initializationVector,
        metadata,
        keyEncryptionType);
  }

  // Replaces the batch-wrap key with one that the AES cipher refuses, so that wrapping fails.
  private static void breakBatchWrapKey() {
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesBatchKeyStore.WRAP_KEY_ALIAS, () -> new SecretKeySpec(new byte[5], "AES"));
  }

  private static ImmutableList<String> auditEventTypes(Context context) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .map(CrumblesAuditEvent::getEventType)
        .collect(toImmutableList());
  }

  private static Context getContext() {
    return ApplicationProvider.getApplicationContext();
  }

  private static void setDeviceSecure(boolean deviceSecure) {
    shadowOf((KeyguardManager) getContext().getSystemService(Context.KEYGUARD_SERVICE))
        .setIsDeviceSecure(deviceSecure);
  }

  private static KeyGenParameterSpec getStoredSpec(String keyAlias) {
    FakeAndroidKeyStoreSpi.PrivateKeyEntry entry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(keyAlias);
    assertThat(entry).isNotNull();
    KeyGenParameterSpec spec = entry.getSpec();
    assertThat(spec).isNotNull();
    return spec;
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
    setUpClass();
    CrumblesLogsEncryptor.setApplicationContext(null);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
    FakeAndroidKeyStoreSpi.certificateLookupFailure = null;
    CrumblesLogsEncryptor.clearKeyPaddingCacheForTest();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    encryptor = new CrumblesLogsEncryptor();
  }

  @After
  public void tearDown() {
    // Given: A test has just finished.
    // When: The test environment is torn down.
    // Then: Any residual keys from the fake Keystore are cleared.
    CrumblesLogsEncryptor.setApplicationContext(null);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = false;
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = false;
    FakeAndroidKeyStoreSpi.isCertificateChainNull = false;
    FakeAndroidKeyStoreSpi.certificateLookupFailure = null;
    CrumblesLogsEncryptor.clearKeyPaddingCacheForTest();
    CrumblesAppAuditLogger.setInstanceForTest(null);
  }

  private static void resetPreferencesAndAuditLogger(Context context) throws Exception {
    CrumblesDataStoreHolder.getInstance(context)
        .updateDataAsync(prefs -> UserKeyPreferences.getDefaultInstance())
        .get();
    CrumblesAppAuditLogger.setInstanceForTest(null);
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
  public void generateKeyPair_specRequiresPerOperationUserAuthentication() throws Exception {
    encryptor.generateKeyPair();

    KeyGenParameterSpec spec = getStoredSpec(CrumblesLogsEncryptor.KEY_ALIAS);
    assertThat(spec.isUserAuthenticationRequired()).isTrue();
    assertThat(spec.getUserAuthenticationValidityDurationSeconds()).isEqualTo(0);
    assertThat(spec.getUserAuthenticationType())
        .isEqualTo(KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
  }

  @Test
  public void generateKeyPair_specIsNotInvalidatedByBiometricEnrollment() throws Exception {
    encryptor.generateKeyPair();

    KeyGenParameterSpec spec = getStoredSpec(CrumblesLogsEncryptor.KEY_ALIAS);
    assertThat(spec.isInvalidatedByBiometricEnrollment()).isFalse();
  }

  @Test
  public void generateKeyPair_whenAuthenticationNotRequired_specDoesNotRequireAuthentication()
      throws Exception {
    encryptor.generateKeyPair(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS, /* requireUserAuthentication= */ false);

    KeyGenParameterSpec spec = getStoredSpec(CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS);
    assertThat(spec.isUserAuthenticationRequired()).isFalse();
  }

  @Test
  @Config(sdk = 34)
  public void generateKeyPair_whenDeviceHasNoSecureLockScreen_throwsCrumblesKeysException() {
    CrumblesLogsEncryptor contextAwareEncryptor = new CrumblesLogsEncryptor(getContext());
    setDeviceSecure(false);

    CrumblesKeysException e =
        assertThrows(CrumblesKeysException.class, contextAwareEncryptor::generateKeyPair);

    assertThat(e).hasMessageThat().contains("no biometric, PIN, pattern or password");
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesLogsEncryptor.KEY_ALIAS);
  }

  @Test
  @Config(sdk = 34)
  public void generateKeyPair_whenDeviceHasNoSecureLockScreen_keepsExistingKey() throws Exception {
    CrumblesLogsEncryptor contextAwareEncryptor = new CrumblesLogsEncryptor(getContext());
    setDeviceSecure(true);
    contextAwareEncryptor.generateKeyPair();

    setDeviceSecure(false);
    assertThrows(CrumblesKeysException.class, contextAwareEncryptor::generateKeyPair);

    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).containsKey(CrumblesLogsEncryptor.KEY_ALIAS);
  }

  @Test
  @Config(sdk = 34)
  public void generateKeyPair_whenDeviceIsSecure_generatesKey() throws Exception {
    CrumblesLogsEncryptor contextAwareEncryptor = new CrumblesLogsEncryptor(getContext());
    setDeviceSecure(true);

    KeyPair generatedKeyPair = contextAwareEncryptor.generateKeyPair();

    assertThat(generatedKeyPair).isNotNull();
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).containsKey(CrumblesLogsEncryptor.KEY_ALIAS);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void generateKeyPair_whenStrongBoxAvailable_generates2048BitKeyThereAndRecordsIt()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    resetPreferencesAndAuditLogger(context);
    setDeviceSecure(true);
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;

    new CrumblesLogsEncryptor(context).generateKeyPair();

    KeyGenParameterSpec spec =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS).getSpec();
    expect.that(spec.isStrongBoxBacked()).isTrue();
    expect.that(spec.getKeySize()).isEqualTo(2048);
    CrumblesAuditEvent event = latestAuditEvent(context);
    expect.that(event.getEventType()).isEqualTo("KEYSTORE_KEY_STORAGE");
    expect
        .that(event.getMessage())
        .isEqualTo("New decryption key pair generated in StrongBox (RSA-2048).");
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void generateKeyPair_whenStrongBoxUnavailable_generates3072BitTeeKeyAndRecordsIt()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    resetPreferencesAndAuditLogger(context);
    setDeviceSecure(true);
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = false;

    new CrumblesLogsEncryptor(context).generateKeyPair();

    KeyGenParameterSpec spec =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS).getSpec();
    expect.that(spec.isStrongBoxBacked()).isFalse();
    expect.that(spec.getKeySize()).isEqualTo(3072);
    expect
        .that(latestAuditEvent(context).getMessage())
        .isEqualTo(
            "New decryption key pair generated in the TEE (RSA-3072), as StrongBox could not"
                + " create it.");
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void generateKeyPair_whenStrongBoxRejectsParams_generates3072BitTeeKeyAndRecordsIt()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = true;

    new CrumblesLogsEncryptor(context).generateKeyPair();

    KeyGenParameterSpec spec =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS).getSpec();
    expect.that(spec.isStrongBoxBacked()).isFalse();
    expect.that(spec.getKeySize()).isEqualTo(3072);
    expect
        .that(latestAuditEvent(context).getMessage())
        .isEqualTo(
            "New decryption key pair generated in the TEE (RSA-3072), as StrongBox could not"
                + " create it.");
  }

  @Test
  public void generateKeyPair_withoutUserAuthentication_keepsTheKeyInTheTee() throws Exception {
    encryptor.generateKeyPair("custom_alias", /* requireUserAuthentication= */ false);

    KeyGenParameterSpec spec = FakeAndroidKeyStoreSpi.getPrivateKeyEntry("custom_alias").getSpec();
    expect.that(spec.isStrongBoxBacked()).isFalse();
    expect.that(spec.getKeySize()).isEqualTo(2048);
  }

  private static CrumblesAuditEvent latestAuditEvent(Context context) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().get(0);
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

  @Test
  public void generateKeyPair_replacesTheBatchUnwrapKeys() throws Exception {
    encryptor.generateKeyPair();
    ByteString previousKeyId = CrumblesBatchKeyStore.keyId();

    encryptor.generateKeyPair();

    assertThat(CrumblesBatchKeyStore.keyId()).isNotEqualTo(previousKeyId);
  }

  @Test
  public void generateKeyPair_forAnotherAlias_leavesTheBatchUnwrapKeysAlone() throws Exception {
    encryptor.generateKeyPair();
    ByteString keyId = CrumblesBatchKeyStore.keyId();

    encryptor.generateKeyPair(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS, /* requireUserAuthentication= */ false);

    assertThat(CrumblesBatchKeyStore.keyId()).isEqualTo(keyId);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void generateKeyPair_doesNotRecordInternalKeyFingerprintBeforeActivation()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    resetPreferencesAndAuditLogger(context);
    setDeviceSecure(true);
    CrumblesLogsEncryptor localEncryptor = new CrumblesLogsEncryptor(context);

    localEncryptor.generateKeyPair();

    assertThat(
            CrumblesDataStoreHolder.getInstance(context)
                .updateDataAsync(prefs -> prefs)
                .get()
                .getInternalKeyFingerprint())
        .isEmpty();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void generateKeyPair_whenBatchUnwrapKeysCannotBeImported_stillReturnsTheKeyPair()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    FakeAndroidKeyStoreSpi.isSecretKeyImportRefused = true;
    try {
      KeyPair keyPair = new CrumblesLogsEncryptor(context).generateKeyPair();

      expect.that(keyPair).isNotNull();
      expect.that(CrumblesBatchKeyStore.hasKeys()).isFalse();
      expect.that(auditEventTypes(context)).contains("BATCH_WRAP_FAILED");
    } finally {
      FakeAndroidKeyStoreSpi.isSecretKeyImportRefused = false;
    }
  }

  @Test
  public void deleteExistingKeyPair_deletesTheBatchUnwrapKeys() throws Exception {
    encryptor.generateKeyPair();

    encryptor.deleteExistingKeyPair();

    assertThat(CrumblesBatchKeyStore.hasKeys()).isFalse();
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

  @Test
  public void generateCandidateExternalKeyPair_doesNotMutateActiveKeyOrKeystore() throws Exception {
    // Given: An existing active external public key is set.
    PublicKey existingKey = generateTestExternalRsaKeyPair().getPublic();
    encryptor.setExternalEncryptionPublicKey(existingKey);

    // When: A candidate key pair is generated.
    KeyPair candidate = encryptor.generateCandidateExternalKeyPair();

    // Then: The candidate pair is valid and non-null.
    assertThat(candidate).isNotNull();
    assertThat(candidate.getPublic()).isNotNull();
    assertThat(candidate.getPrivate()).isNotNull();
    assertThat(candidate.getPublic().getAlgorithm()).isEqualTo("RSA");

    // And: The active encryption public key was NOT changed.
    assertThat(encryptor.getExternalEncryptionPublicKey()).isSameInstanceAs(existingKey);
  }

  @Test
  public void generateCandidateExternalKeyPair_generates3072BitKeyThatFitsInQrCode()
      throws Exception {
    KeyPair candidate = encryptor.generateCandidateExternalKeyPair();

    RSAPublicKey publicKey = (RSAPublicKey) candidate.getPublic();
    expect.that(publicKey.getModulus().bitLength()).isEqualTo(3072);
    expect.that(publicKey.getPublicExponent()).isEqualTo(RSAKeyGenParameterSpec.F4);
    // The key viewer hands the private key over as a QR code of its Base64 encoding.
    BitMatrix qrCode =
        new CrumblesBarcodeEncoder()
            .encode(
                Base64.getEncoder().encodeToString(candidate.getPrivate().getEncoded()),
                BarcodeFormat.QR_CODE,
                600,
                600);
    expect.that(qrCode.getWidth()).isEqualTo(600);
  }

  @Test
  public void commitExternalPublicKey_activatesKeyAndKeepsKeystoreKeyPair() throws Exception {
    PublicKey internalPublicKey = encryptor.generateKeyPair().getPublic();
    KeyPair candidate = encryptor.generateCandidateExternalKeyPair();

    encryptor.commitExternalPublicKey(candidate.getPublic());

    expect.that(encryptor.getExternalEncryptionPublicKey()).isEqualTo(candidate.getPublic());
    expect.that(encryptor.getPublicKey()).isEqualTo(internalPublicKey);
  }

  @Test
  public void commitExternalPublicKey_keepsBatchesEncryptedToKeystoreKeyDecryptable()
      throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] pendingLogs = "written before the key change".getBytes(UTF_8);
    LogBatch pendingBatch = encryptor.encryptLogs(pendingLogs, /* publicKey= */ null);

    encryptor.commitExternalPublicKey(encryptor.generateCandidateExternalKeyPair().getPublic());

    assertThat(decrypt(new CrumblesLogsEncryptor(), pendingBatch)).isEqualTo(pendingLogs);
  }

  @Test
  public void generateAndSetExternalKeyPair_keepsKeystoreKeyPair() throws Exception {
    PublicKey internalPublicKey = encryptor.generateKeyPair().getPublic();

    encryptor.generateAndSetExternalKeyPair(bytes -> {});

    expect.that(encryptor.getExternalEncryptionPublicKey()).isNotNull();
    expect.that(encryptor.getPublicKey()).isEqualTo(internalPublicKey);
  }

  @Test
  public void commitExternalPublicKey_withNullKey_throwsException() {
    assertThrows(CrumblesKeysException.class, () -> encryptor.commitExternalPublicKey(null));
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
    LogBatch batch1 = encryptor.encryptLogs(logData, encryptor.getExternalEncryptionPublicKey());
    LogBatch batch2 = encryptor.encryptLogs(logData, encryptor.getExternalEncryptionPublicKey());

    // Then: The Initialization Vectors (IVs) in each LogBatch must be different.
    byte[] iv1 = batch1.getKey().getIv().toByteArray();
    byte[] iv2 = batch2.getKey().getIv().toByteArray();
    assertThat(iv1).isNotNull();
    assertThat(iv2).isNotNull();
    assertThat(iv1).hasLength(12);
    assertThat(iv2).hasLength(12);
    assertThat(Arrays.equals(iv1, iv2)).isFalse();
    assertThat(batch1.getMetadata().getBlobSize())
        .isEqualTo(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES);
  }

  @Test
  public void encryptLogs_whenExternalPublicKeyIsSet_thenDoesNotInitializeKeystoreKeyIfNotPresent()
      throws Exception {
    // Given: A valid external PublicKey is set on the encryptor.
    encryptor.setExternalEncryptionPublicKey(generateTestExternalRsaKeyPair().getPublic());
    // And: The fake Keystore is empty.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();

    // When: encryptLogs is called.
    encryptor.encryptLogs(
        "test encryption with external key.".getBytes(UTF_8),
        encryptor.getExternalEncryptionPublicKey());

    // Then: The encryption proceeds without accessing or generating a Keystore key.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();
  }

  @Test
  public void encryptLogs_ciphertextHas128BitAuthenticationTag() throws Exception {
    // Given: An external public key and a known 100-byte plaintext log payload.
    KeyPair keyPair = generateTestExternalRsaKeyPair();
    byte[] plainText = new byte[100];
    Arrays.fill(plainText, (byte) 'a');

    // When: encryptLogs is called.
    LogBatch logBatch = encryptor.encryptLogs(plainText, keyPair.getPublic());

    // Then: The ciphertext is the 100 bytes padded to the 4096-byte bucket plus a 16-byte tag.
    assertThat(logBatch).isNotNull();
    byte[] cipherText = logBatch.getData().getLogBlob().toByteArray();
    assertThat(cipherText.length - 4096).isEqualTo(16);
  }

  @Test
  public void encryptLogs_padsTheSealedLogsToTheirSizeBucket(@TestParameter PaddingCase paddingCase)
      throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] logs = new byte[paddingCase.logsLength];
    Arrays.fill(logs, (byte) 'x');

    LogBatch logBatch = encryptor.encryptLogs(logs, /* publicKey= */ null);

    int expectedCiphertextLength =
        paddingCase.paddedLength + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES;
    expect
        .that(logBatch.getMetadata().getEncryptionType())
        .isEqualTo(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA);
    expect.that(logBatch.getData().getLogBlob().size()).isEqualTo(expectedCiphertextLength);
    expect.that(logBatch.getMetadata().getBlobSize()).isEqualTo(expectedCiphertextLength);
    expect.that(decrypt(encryptor, logBatch)).isEqualTo(logs);
  }

  @Test
  public void decryptLogs_whenBatchPredatesPadding_returnsItsPlaintextAsTheLogs() throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] logs = "logs written before batches were padded".getBytes(UTF_8);
    LogBatch unpaddedBatch =
        batchWithPlaintext(devicePublicKey, logs, LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM);

    byte[] decryptedLogs = decrypt(encryptor, unpaddedBatch);

    assertThat(decryptedLogs).isEqualTo(logs);
  }

  @Test
  public void decryptLogs_whenPaddedPlaintextIsMalformed_throws(
      @TestParameter MalformedPaddedPlaintext malformedPlaintext) throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch malformedBatch =
        batchWithPlaintext(
            devicePublicKey,
            malformedPlaintext.plaintext(),
            LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_PADDED);

    assertThrows(CrumblesLogsDecryptionException.class, () -> decrypt(encryptor, malformedBatch));
  }

  @Test
  public void decryptLogBatch_ofVersion2Batch_returnsTheSealedLogsAndMetadata() throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] logs = "logs sealed together with their metadata".getBytes(UTF_8);
    LogMetadata sealedMetadata =
        LogMetadata.newBuilder()
            .setTimestamp(Timestamp.newBuilder().setSeconds(1_700_000_000L))
            .setDevice(DeviceId.newBuilder().setDeviceId("sealed-device"))
            .build();
    SealedLogs sealedLogs =
        SealedLogs.newBuilder()
            .setMetadata(sealedMetadata)
            .setLogs(ByteString.copyFrom(logs))
            .build();
    LogBatch version2Batch =
        batchWithPlaintext(
            devicePublicKey,
            inSmallestPaddingBucket(sealedLogs.toByteArray()),
            LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA);

    DecryptedLogBatch decryptedBatch = decryptLogBatch(encryptor, version2Batch);

    expect.that(decryptedBatch.logs()).isEqualTo(logs);
    expect.that(decryptedBatch.metadata().getTimestamp()).isEqualTo(sealedMetadata.getTimestamp());
    expect.that(decryptedBatch.metadata().getDevice()).isEqualTo(sealedMetadata.getDevice());
    expect
        .that(decryptedBatch.metadata().getBlobSize())
        .isEqualTo(version2Batch.getMetadata().getBlobSize());
  }

  @Test
  public void decryptLogBatch_ofPaddedVersion1Batch_returnsItsCleartextMetadata() throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] logs = "logs written before metadata was sealed".getBytes(UTF_8);
    LogBatch paddedBatch =
        batchWithPlaintext(
            devicePublicKey,
            inSmallestPaddingBucket(logs),
            LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_PADDED);

    DecryptedLogBatch decryptedBatch = decryptLogBatch(encryptor, paddedBatch);

    expect.that(decryptedBatch.logs()).isEqualTo(logs);
    expect.that(decryptedBatch.metadata()).isEqualTo(paddedBatch.getMetadata());
  }

  @Test
  public void decryptLogs_whenVersion2BatchHoldsNoSealedLogs_throws() throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    // A tag whose varint never ends, which no serialized message can start with.
    byte[] notSealedLogs = new byte[] {(byte) 0xff, (byte) 0xff};
    LogBatch malformedBatch =
        batchWithPlaintext(
            devicePublicKey,
            inSmallestPaddingBucket(notSealedLogs),
            LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA);

    assertThrows(CrumblesLogsDecryptionException.class, () -> decrypt(encryptor, malformedBatch));
  }

  @Test
  public void computeAssociatedData_ofVersion2Metadata_startsWithTheFormatLabel() throws Exception {
    LogMetadata metadata =
        LogMetadata.newBuilder()
            .setBlobSize(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA)
            .build();
    byte[] label = "crumbles/v2/batch".getBytes(UTF_8);

    byte[] associatedData =
        CrumblesLogsEncryptor.computeAssociatedData(
            metadata,
            KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
            generateTestExternalRsaKeyPair().getPublic());

    assertThat(Arrays.copyOf(associatedData, label.length)).isEqualTo(label);
  }

  @Test
  public void computeAssociatedData_ofPaddedVersion1Metadata_hasNoFormatLabel() {
    LogMetadata metadata =
        LogMetadata.newBuilder()
            .setBlobSize(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_PADDED)
            .build();

    byte[] associatedData =
        CrumblesLogsEncryptor.computeAssociatedData(
            metadata, KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256, /* recipient= */ null);

    assertThat(new String(associatedData, UTF_8)).doesNotContain("crumbles/v2/batch");
  }

  @Test
  public void computeAssociatedData_ofVersion2Metadata_endsWithTheRecipientFingerprint()
      throws Exception {
    LogMetadata metadata =
        LogMetadata.newBuilder()
            .setBlobSize(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA)
            .build();
    KeyEncryptionType keyEncryptionType = KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256;
    PublicKey recipient = generateTestExternalRsaKeyPair().getPublic();

    byte[] associatedData =
        CrumblesLogsEncryptor.computeAssociatedData(metadata, keyEncryptionType, recipient);

    // The label, the serialized metadata, the key encryption type as a one-byte varint, then the
    // SHA-256 digest of the recipient's encoded public key.
    assertThat(associatedData)
        .isEqualTo(
            ByteString.copyFromUtf8("crumbles/v2/batch")
                .concat(metadata.toByteString())
                .concat(ByteString.copyFrom(new byte[] {(byte) keyEncryptionType.getNumber()}))
                .concat(
                    ByteString.copyFrom(
                        MessageDigest.getInstance("SHA-256").digest(recipient.getEncoded())))
                .toByteArray());
  }

  @Test
  public void computeAssociatedData_ofPaddedVersion1Metadata_bindsNoRecipient() throws Exception {
    LogMetadata metadata =
        LogMetadata.newBuilder()
            .setBlobSize(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_PADDED)
            .build();
    KeyEncryptionType keyEncryptionType = KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256;

    byte[] associatedData =
        CrumblesLogsEncryptor.computeAssociatedData(
            metadata, keyEncryptionType, generateTestExternalRsaKeyPair().getPublic());

    assertThat(associatedData)
        .isEqualTo(
            CrumblesLogsEncryptor.computeAssociatedData(
                metadata, keyEncryptionType, /* recipient= */ null));
  }

  /** Recipient keys that a format version 2 batch cannot be bound to. */
  private enum UnboundRecipient {
    MISSING {
      @Override
      @Nullable
      PublicKey recipient() {
        return null;
      }
    },
    WITHOUT_ENCODING {
      @Override
      PublicKey recipient() {
        return new PublicKey() {
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
        };
      }
    };

    @Nullable
    abstract PublicKey recipient();
  }

  @Test
  public void computeAssociatedData_ofVersion2MetadataWithoutAnEncodedRecipient_throws(
      @TestParameter UnboundRecipient unboundRecipient) {
    LogMetadata metadata =
        LogMetadata.newBuilder()
            .setBlobSize(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA)
            .build();

    assertThrows(
        IllegalArgumentException.class,
        () ->
            CrumblesLogsEncryptor.computeAssociatedData(
                metadata,
                KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
                unboundRecipient.recipient()));
  }

  @Test
  public void decryptLogs_whenVersion2BatchIsBoundToAnotherRecipient_throws() throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    SealedLogs sealedLogs =
        SealedLogs.newBuilder().setLogs(ByteString.copyFromUtf8("logs for another key")).build();
    LogBatch boundToAnotherRecipient =
        batchWithPlaintext(
            devicePublicKey,
            inSmallestPaddingBucket(sealedLogs.toByteArray()),
            LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA,
            generateTestExternalRsaKeyPair().getPublic());

    assertThrows(
        CrumblesLogsDecryptionException.class, () -> decrypt(encryptor, boundToAnotherRecipient));
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_sealsTheAttestationChainOfTheBatchSigningKey() throws Exception {
    Context context = getContext();
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();

    LogBatch logBatch =
        new CrumblesLogsEncryptor(context)
            .encryptLogs(
                context,
                "logs".getBytes(UTF_8),
                externalKeyPair.getPublic(),
                new CrumblesBatchSigner(context).attestationChainToSeal());

    ImmutableList<ByteString> batchSigningKeyChain = batchSigningKeyChain();
    assertThat(batchSigningKeyChain).isNotEmpty();
    assertThat(
            sealedLogsDecryptedWith(
                    externalKeyPair.getPrivate(), externalKeyPair.getPublic(), logBatch)
                .getAttestationChainList())
        .containsExactlyElementsIn(batchSigningKeyChain)
        .inOrder();
  }

  @Test
  public void encryptLogs_withoutContext_sealsNoAttestationChainAndCreatesNoSigningKey()
      throws Exception {
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();

    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), externalKeyPair.getPublic());

    expect
        .that(
            sealedLogsDecryptedWith(
                    externalKeyPair.getPrivate(), externalKeyPair.getPublic(), logBatch)
                .getAttestationChainList())
        .isEmpty();
    expect.that(FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesBatchSigningKey.ALIAS)).isNull();
  }

  /** Ways in which reading the attestation chain of the batch-signing key can fail. */
  private enum AttestationChainFailure {
    NO_CERTIFICATE_CHAIN {
      @Override
      void simulate() {
        FakeAndroidKeyStoreSpi.isCertificateChainNull = true;
      }
    },
    UNCHECKED_KEYSTORE_EXCEPTION {
      @Override
      void simulate() {
        FakeAndroidKeyStoreSpi.keystoreEntries.put(
            CrumblesBatchSigningKey.ALIAS,
            new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
                /* privateKey= */ null, /* certificateChain= */ null, /* spec= */ null) {
              @Override
              public Certificate[] getCertificateChain() {
                throw new IllegalStateException("Keystore failed");
              }
            });
      }
    };

    abstract void simulate();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_whenAttestationChainCannotBeRead_writesTheBatchWithoutIt(
      @TestParameter AttestationChainFailure failure) throws Exception {
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();
    byte[] plainLogs = "logs written without an attestation chain".getBytes(UTF_8);
    Context context = getContext();
    failure.simulate();

    LogBatch logBatch =
        new CrumblesLogsEncryptor(context)
            .encryptLogs(
                context,
                plainLogs,
                externalKeyPair.getPublic(),
                new CrumblesBatchSigner(context).attestationChainToSeal());

    SealedLogs sealedLogs =
        sealedLogsDecryptedWith(
            externalKeyPair.getPrivate(), externalKeyPair.getPublic(), logBatch);
    expect.that(sealedLogs.getLogs().toByteArray()).isEqualTo(plainLogs);
    expect.that(sealedLogs.getAttestationChainList()).isEmpty();
  }

  /** The metadata of a decrypted batch, written long before its logs are re-encrypted. */
  private static final LogMetadata ORIGINAL =
      recordedBy("original-device").toBuilder()
          .setTimestamp(Timestamp.newBuilder().setSeconds(1_600_000_000L))
          .build();

  /** Returns the metadata of a decrypted batch that records {@code deviceId} and no time. */
  private static LogMetadata recordedBy(String deviceId) {
    return LogMetadata.newBuilder().setDevice(DeviceId.newBuilder().setDeviceId(deviceId)).build();
  }

  /** Re-encryptions of the logs of another batch, which stay unsigned. */
  private enum UnsignedReEncryption {
    RE_ENCRYPT_LOG_BATCH {
      @Override
      LogBatch reEncrypt(CrumblesLogsEncryptor encryptor, byte[] plainLogs, PublicKey recipient)
          throws CrumblesKeysException {
        return encryptor.reEncryptLogBatch(plainLogs, recipient, ORIGINAL);
      }
    },
    ENCRYPT_LOGS_ATTRIBUTED_TO {
      @Override
      LogBatch reEncrypt(CrumblesLogsEncryptor encryptor, byte[] plainLogs, PublicKey recipient) {
        return encryptor.encryptLogsAttributedTo(ORIGINAL, plainLogs, recipient);
      }
    };

    abstract LogBatch reEncrypt(
        CrumblesLogsEncryptor encryptor, byte[] plainLogs, PublicKey recipient)
        throws CrumblesKeysException;
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void reEncryptingForAnotherDevice_sealsNoAttestationChainAndCreatesNoSigningKey(
      @TestParameter UnsignedReEncryption reEncryption) throws Exception {
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();

    LogBatch logBatch =
        reEncryption.reEncrypt(
            new CrumblesLogsEncryptor(getContext()),
            "logs of another batch".getBytes(UTF_8),
            externalKeyPair.getPublic());

    SealedLogs sealedLogs =
        sealedLogsDecryptedWith(
            externalKeyPair.getPrivate(), externalKeyPair.getPublic(), logBatch);
    expect.that(sealedLogs.getMetadata().getDevice().getDeviceId()).isEqualTo("original-device");
    expect.that(sealedLogs.getAttestationChainList()).isEmpty();
    expect.that(FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesBatchSigningKey.ALIAS)).isNull();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void reEncryptingForAnotherDevice_keepsTheTimeTheOriginalRecorded(
      @TestParameter UnsignedReEncryption reEncryption) throws Exception {
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();

    LogBatch logBatch =
        reEncryption.reEncrypt(
            new CrumblesLogsEncryptor(getContext()),
            "logs of another batch".getBytes(UTF_8),
            externalKeyPair.getPublic());

    assertThat(
            sealedLogsDecryptedWith(
                    externalKeyPair.getPrivate(), externalKeyPair.getPublic(), logBatch)
                .getMetadata()
                .getTimestamp())
        .isEqualTo(ORIGINAL.getTimestamp());
  }

  /** Re-encryptions of the logs of a batch that this installation signed, to sign them again. */
  private enum SignedReEncryption {
    RE_ENCRYPT_LOG_BATCH_FOR_SIGNING {
      @Override
      LogBatch reEncrypt(
          CrumblesLogsEncryptor encryptor,
          Context context,
          byte[] plainLogs,
          PublicKey recipient,
          List<ByteString> attestationChain)
          throws CrumblesKeysException {
        return encryptor.reEncryptLogBatchForSigning(
            context, plainLogs, recipient, ORIGINAL, attestationChain);
      }
    },
    ENCRYPT_LOGS_FOR_SIGNING_AGAIN {
      @Override
      LogBatch reEncrypt(
          CrumblesLogsEncryptor encryptor,
          Context context,
          byte[] plainLogs,
          PublicKey recipient,
          List<ByteString> attestationChain) {
        return encryptor.encryptLogsForSigningAgain(
            context, ORIGINAL, plainLogs, recipient, attestationChain);
      }
    };

    abstract LogBatch reEncrypt(
        CrumblesLogsEncryptor encryptor,
        Context context,
        byte[] plainLogs,
        PublicKey recipient,
        List<ByteString> attestationChain)
        throws CrumblesKeysException;
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void reEncryptingToSignAgain_keepsTheOriginalTimeAndSealsGivenChainAndThisDevicesId(
      @TestParameter SignedReEncryption reEncryption) throws Exception {
    Context context = getContext();
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();
    ImmutableList<ByteString> attestationChain =
        ImmutableList.of(ByteString.copyFromUtf8("leaf"), ByteString.copyFromUtf8("root"));

    LogBatch logBatch =
        reEncryption.reEncrypt(
            encryptor,
            context,
            "logs of this installation".getBytes(UTF_8),
            externalKeyPair.getPublic(),
            attestationChain);

    SealedLogs sealedLogs =
        sealedLogsDecryptedWith(
            externalKeyPair.getPrivate(), externalKeyPair.getPublic(), logBatch);
    expect.that(sealedLogs.getMetadata().getTimestamp()).isEqualTo(ORIGINAL.getTimestamp());
    expect
        .that(sealedLogs.getMetadata().getDevice().getDeviceId())
        .isEqualTo(CrumblesDeviceIdManager.getDeviceId(context));
    expect
        .that(sealedLogs.getAttestationChainList())
        .containsExactlyElementsIn(attestationChain)
        .inOrder();
  }

  @Test
  public void encryptData_ciphertextDecryptableWithSpecCompliant128BitReader() throws Exception {
    // Given: An external RSA key pair and a plaintext payload.
    KeyPair keyPair = generateTestExternalRsaKeyPair();
    byte[] plainText = "test payload for external 128-bit GCM reader".getBytes(UTF_8);
    CrumblesLogsEncryptor.EncryptedData encrypted =
        encryptor.encryptData(plainText, keyPair.getPublic());

    // When: An external reader unwraps the symmetric key and decrypts using a 128-bit GCM tag.
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsaCipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
    SecretKey aesKey =
        (SecretKey) rsaCipher.unwrap(encrypted.encryptedSymmetricKey, "AES", Cipher.SECRET_KEY);

    Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec spec128 = new GCMParameterSpec(128, encrypted.initializationVector);
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey, spec128);
    byte[] decrypted = aesCipher.doFinal(encrypted.ciphertext);

    // Then: Decryption succeeds and matches the original plaintext.
    assertThat(decrypted).isEqualTo(plainText);

    // And: Decrypting the same ciphertext with a 96-bit tag length fails authentication.
    GCMParameterSpec spec96 = new GCMParameterSpec(96, encrypted.initializationVector);
    aesCipher.init(Cipher.DECRYPT_MODE, aesKey, spec96);
    assertThrows(AEADBadTagException.class, () -> aesCipher.doFinal(encrypted.ciphertext));
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_toExternalKey_usesOaep() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();
    byte[] plainLogs = "logs for an external key".getBytes(UTF_8);

    LogBatch logBatch =
        new CrumblesLogsEncryptor(context).encryptLogs(plainLogs, externalKeyPair.getPublic());

    assertThat(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    assertThat(decryptWithOaepKeyPair(externalKeyPair, logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void encryptLogs_toLegacyPkcs1OnlyDeviceKey_keepsWrappingWithPkcs1() throws Exception {
    generateLegacyPkcs1OnlyDeviceKey();
    byte[] plainLogs = "logs for a PKCS#1 device key".getBytes(UTF_8);

    LogBatch logBatch = encryptor.encryptLogs(plainLogs, /* publicKey= */ null);

    expect
        .that(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC);
    expect.that(encryptor.decryptLogs(logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void isPrivateKeyPermanentlyInvalidated_withValidLegacyPkcs1Key_returnsFalse()
      throws Exception {
    generateLegacyPkcs1OnlyDeviceKey();

    assertThat(encryptor.isPrivateKeyPermanentlyInvalidated()).isFalse();
  }

  @Test
  public void isPrivateKeyPermanentlyInvalidated_withInvalidatedLegacyPkcs1Key_detectsInvalidation()
      throws Exception {
    generateLegacyPkcs1OnlyDeviceKey();
    FakeAndroidKeyStoreSpi.invalidateKey(CrumblesLogsEncryptor.KEY_ALIAS);

    assertThat(encryptor.isPrivateKeyPermanentlyInvalidated()).isTrue();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_toDeviceKey_usesOaep() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    CrumblesLogsEncryptor contextEncryptor = new CrumblesLogsEncryptor(context);
    contextEncryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs for an OAEP device key".getBytes(UTF_8);

    LogBatch logBatch = contextEncryptor.encryptLogs(plainLogs, /* publicKey= */ null);

    assertThat(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    assertThat(decrypt(contextEncryptor, logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void encryptLogs_whenDeviceKeyPaddingsAreUnreadable_usesOaep() throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry deviceEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    // Without the spec that the key was generated with, the fake reports no KeyInfo for it.
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            deviceEntry.getPrivateKey(), deviceEntry.getCertificateChain(), /* spec= */ null));
    byte[] plainLogs = "logs for a device key of unknown paddings".getBytes(UTF_8);

    LogBatch logBatch = encryptor.encryptLogs(plainLogs, /* publicKey= */ null);

    expect
        .that(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    expect.that(encryptor.decryptLogs(logBatch)).isEqualTo(plainLogs);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_afterRestartWhenOaepKeyPaddingsBecomeUnreadable_usesPersistedOaepCache()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    new CrumblesLogsEncryptor(context).generateKeyPair();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry deviceEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            deviceEntry.getPrivateKey(), deviceEntry.getCertificateChain(), /* spec= */ null));
    CrumblesLogsEncryptor.setApplicationContext(null);
    CrumblesLogsEncryptor.clearKeyPaddingCacheForTest();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs after restart for OAEP key".getBytes(UTF_8);

    LogBatch logBatch =
        new CrumblesLogsEncryptor()
            .encryptLogs(
                context,
                plainLogs,
                /* publicKey= */ null,
                /* attestationChain= */ ImmutableList.of());
    CrumblesLogsEncryptor.clearKeyPaddingCacheForTest();
    LogBatch nullContextBatch =
        new CrumblesLogsEncryptor()
            .encryptLogs(
                /* context= */ null,
                plainLogs,
                /* publicKey= */ null,
                /* attestationChain= */ ImmutableList.of());

    expect
        .that(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    expect
        .that(nullContextBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    expect.that(new CrumblesLogsEncryptor(context).decryptLogs(logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void encryptLogs_withoutContextWhenKeyInfoFailsAfterCaching_usesInMemoryPaddingCache()
      throws Exception {
    generateLegacyPkcs1OnlyDeviceKey();
    byte[] firstLogs = "first batch without context".getBytes(UTF_8);
    assertThat(encryptor.encryptLogs(firstLogs, /* publicKey= */ null)).isNotNull();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry legacyEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            legacyEntry.getPrivateKey(), legacyEntry.getCertificateChain(), /* spec= */ null) {
          @Override
          public Key getKey() {
            throw new ProviderException("OEM Keystore characteristics failure");
          }
        });

    LogBatch secondBatch =
        encryptor.encryptLogs("second batch".getBytes(UTF_8), /* publicKey= */ null);

    assertThat(secondBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC);
  }

  @Test
  public void encryptLogs_withoutContextWhenKeyInfoFailsAfterRestart_throwsEncryptionException()
      throws Exception {
    generateLegacyPkcs1OnlyDeviceKey();
    assertThat(encryptor.encryptLogs("first batch".getBytes(UTF_8), /* publicKey= */ null))
        .isNotNull();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry legacyEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            legacyEntry.getPrivateKey(), legacyEntry.getCertificateChain(), /* spec= */ null) {
          @Override
          public Key getKey() {
            throw new ProviderException("OEM Keystore characteristics failure");
          }
        });
    // A restart loses the padding cached in memory, and without a context nothing was persisted.
    CrumblesLogsEncryptor.clearKeyPaddingCacheForTest();

    assertThrows(
        CrumblesLogsEncryptionException.class,
        () -> encryptor.encryptLogs("second batch".getBytes(UTF_8), /* publicKey= */ null));
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_toLegacyPkcs1KeyAfterKeyInfoThrowsProviderException_usesPersistedPkcs1()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    generateLegacyPkcs1OnlyDeviceKey();
    CrumblesLogsEncryptor firstEncryptor = new CrumblesLogsEncryptor(context);
    byte[] firstLogs = "first batch while KeyInfo works".getBytes(UTF_8);
    assertThat(firstEncryptor.encryptLogs(firstLogs, /* publicKey= */ null)).isNotNull();

    FakeAndroidKeyStoreSpi.PrivateKeyEntry legacyEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            legacyEntry.getPrivateKey(), legacyEntry.getCertificateChain(), /* spec= */ null) {
          @Override
          public Key getKey() {
            throw new ProviderException("OEM Keystore characteristics failure");
          }
        });
    CrumblesLogsEncryptor.clearKeyPaddingCacheForTest();
    byte[] secondLogs = "second batch after restart with broken KeyInfo".getBytes(UTF_8);

    LogBatch logBatch =
        new CrumblesLogsEncryptor(context).encryptLogs(secondLogs, /* publicKey= */ null);

    FakeAndroidKeyStoreSpi.keystoreEntries.put(CrumblesLogsEncryptor.KEY_ALIAS, legacyEntry);
    expect
        .that(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC);
    expect.that(new CrumblesLogsEncryptor(context).decryptLogs(logBatch)).isEqualTo(secondLogs);
  }

  @Test
  public void encryptLogs_whenUncachedLegacyKeyPaddingsAreUnreadable_throwsEncryptionException()
      throws Exception {
    generateLegacyPkcs1OnlyDeviceKey();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry legacyEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            legacyEntry.getPrivateKey(), legacyEntry.getCertificateChain(), /* spec= */ null) {
          @Override
          public Key getKey() {
            throw new ProviderException("OEM Keystore characteristics failure");
          }
        });

    assertThrows(
        CrumblesLogsEncryptionException.class,
        () -> encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null));
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void
      encryptLogs_whenReplacedDeviceKeyHasDifferentFingerprint_doesNotReuseOldCachedPadding()
          throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    new CrumblesLogsEncryptor(context).generateKeyPair();
    generateLegacyPkcs1OnlyDeviceKey();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry legacyEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            legacyEntry.getPrivateKey(), legacyEntry.getCertificateChain(), /* spec= */ null));

    CrumblesLogsEncryptor crumblesLogsEncryptor = new CrumblesLogsEncryptor(context);
    assertThrows(
        CrumblesLogsEncryptionException.class,
        () -> crumblesLogsEncryptor.encryptLogs("logs".getBytes(UTF_8), null));
  }

  @Test
  public void encryptLogs_whenDeviceKeyLookupFailsWhileAliasExists_throwsInsteadOfTreatingExternal()
      throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.certificateLookupFailure =
        new ProviderException("Keystore certificate lookup failed");

    expect.that(encryptor.getPublicKey()).isNull();
    assertThrows(
        CrumblesLogsEncryptionException.class,
        () -> encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null));
    assertThrows(
        CrumblesLogsEncryptionException.class,
        () -> encryptor.encryptLogs("logs".getBytes(UTF_8), devicePublicKey));
    assertThrows(
        CrumblesKeysException.class,
        () -> encryptor.encryptData("data".getBytes(UTF_8), devicePublicKey));
  }

  @Test
  public void encryptLogs_toDeviceKey_addsTheBatchKeyWrappedWithTheBatchWrapKey() throws Exception {
    encryptor.generateKeyPair();
    byte[] plainLogs = "logs for the device key".getBytes(UTF_8);

    LogBatch logBatch = encryptor.encryptLogs(plainLogs, /* publicKey= */ null);

    expect.that(logBatch.getKey().getBatchWrapKeyId()).isEqualTo(CrumblesBatchKeyStore.keyId());
    expect.that(decryptWithBatchWrappedKey(logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void reEncryptLogBatch_toDeviceKey_addsTheBatchWrappedKey() throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    byte[] plainLogs = "re-encrypted logs".getBytes(UTF_8);

    LogBatch logBatch = encryptor.reEncryptLogBatch(plainLogs, devicePublicKey, ORIGINAL);

    assertThat(decryptWithBatchWrappedKey(logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void encryptLogs_toExternalKey_carriesNoBatchWrappedKey() throws Exception {
    encryptor.generateKeyPair();

    LogBatch logBatch =
        encryptor.encryptLogs(
            "logs for an external key".getBytes(UTF_8),
            generateTestExternalRsaKeyPair().getPublic());

    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect.that(logBatch.getKey().hasBatchWrapKeyId()).isFalse();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_withoutBatchUnwrapKeys_keepsOnlyTheRsaWrappedKey() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    setDeviceSecure(true);
    CrumblesLogsEncryptor contextEncryptor = new CrumblesLogsEncryptor(context);
    contextEncryptor.generateKeyPair();
    CrumblesBatchKeyStore.deleteKeys();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs without batch-unwrap keys".getBytes(UTF_8);

    LogBatch logBatch = contextEncryptor.encryptLogs(plainLogs, /* publicKey= */ null);

    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect.that(decrypt(contextEncryptor, logBatch)).isEqualTo(plainLogs);
    expect.that(auditEventTypes(context)).doesNotContain("BATCH_WRAP_FAILED");
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_whenBatchWrapFails_keepsTheRsaWrappedKeyAndAuditsTheFailure()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    setDeviceSecure(true);
    CrumblesLogsEncryptor contextEncryptor = new CrumblesLogsEncryptor(context);
    contextEncryptor.generateKeyPair();
    breakBatchWrapKey();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs whose batch wrap fails".getBytes(UTF_8);

    LogBatch logBatch = contextEncryptor.encryptLogs(plainLogs, /* publicKey= */ null);

    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect.that(decrypt(contextEncryptor, logBatch)).isEqualTo(plainLogs);
    expect.that(auditEventTypes(context)).contains("BATCH_WRAP_FAILED");
  }

  @Test
  public void encryptLogs_whenBatchWrapFailsWithoutContext_stillEncrypts() throws Exception {
    CrumblesLogsEncryptor.setApplicationContext(null);
    encryptor.generateKeyPair();
    breakBatchWrapKey();

    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);

    assertThat(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
  }

  @Test
  public void encryptLogsBeforeFirstUnlock_toDeviceKey_marksEmptyBatchWrapKeyId()
      throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs collected before the first unlock".getBytes(UTF_8);

    LogBatch logBatch =
        encryptor.encryptLogsBeforeFirstUnlock(
            plainLogs, devicePublicKey, "device-123", ImmutableList.of());

    expect.that(logBatch.getKey().hasBatchWrapKeyId()).isTrue();
    expect.that(logBatch.getKey().getBatchWrapKeyId()).isEmpty();
    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect
        .that(encryptor.partitionForBulkDecrypt(ImmutableList.of(logBatch)).rsaOnly())
        .containsExactly(logBatch);
    expect.that(decrypt(encryptor, logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void encryptLogsBeforeFirstUnlock_toExternalKey_carriesNoBatchWrapKeyId()
      throws Exception {
    encryptor.generateKeyPair();
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();
    byte[] plainLogs = "logs collected before the first unlock".getBytes(UTF_8);

    LogBatch logBatch =
        encryptor.encryptLogsBeforeFirstUnlock(
            plainLogs, externalKeyPair.getPublic(), "device-123", ImmutableList.of());

    expect.that(logBatch.getKey().hasBatchWrapKeyId()).isFalse();
    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect.that(decryptWithOaepKeyPair(externalKeyPair, logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void
      encryptLogsBeforeFirstUnlock_whenKeystoreCertificateLookupFails_returnsDecryptableBatch()
          throws Exception {
    PublicKey devicePublicKey = encryptor.generateKeyPair().getPublic();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs collected during Keystore fault".getBytes(UTF_8);

    LogBatch logBatch;
    FakeAndroidKeyStoreSpi.certificateLookupFailure =
        new ProviderException("Keystore certificate lookup failed");
    try {
      logBatch =
          encryptor.encryptLogsBeforeFirstUnlock(
              plainLogs, devicePublicKey, "device-123", ImmutableList.of());
    } finally {
      FakeAndroidKeyStoreSpi.certificateLookupFailure = null;
    }

    expect.that(logBatch.getKey().hasBatchWrapKeyId()).isFalse();
    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect.that(decrypt(encryptor, logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void unwrapBatchKeys_unwrapsTheKeyOfEachBatchWithOneCipher() throws Exception {
    encryptor.generateKeyPair();
    ImmutableList<LogBatch> logBatches =
        ImmutableList.of(
            encryptor.encryptLogs("first logs".getBytes(UTF_8), /* publicKey= */ null),
            encryptor.encryptLogs("second logs".getBytes(UTF_8), /* publicKey= */ null),
            encryptor.encryptLogs("third logs".getBytes(UTF_8), /* publicKey= */ null));
    ImmutableList<LogBatch> batchUnwrappable =
        encryptor.partitionForBulkDecrypt(logBatches).batchUnwrappable();
    Cipher batchUnwrapCipher = encryptor.createBatchUnwrapCipher();
    FakeAndroidKeyStoreSpi.authorizeOperation(batchUnwrapCipher);

    ImmutableList<SecretKey> symmetricKeys =
        encryptor.unwrapBatchKeys(batchUnwrapCipher, batchUnwrappable);
    ImmutableList.Builder<String> decryptedLogsBuilder = ImmutableList.builder();
    for (int i = 0; i < batchUnwrappable.size(); i++) {
      decryptedLogsBuilder.add(
          new String(
              encryptor
                  .decryptLogsWithSymmetricKey(batchUnwrappable.get(i), symmetricKeys.get(i))
                  .logs(),
              UTF_8));
    }
    ImmutableList<String> decryptedLogs = decryptedLogsBuilder.build();

    assertThat(decryptedLogs).containsExactly("first logs", "second logs", "third logs").inOrder();
  }

  @Test
  public void partitionForBulkDecrypt_groupsBatchesByTheKeysThatCanDecryptThem() throws Exception {
    encryptor.generateKeyPair();
    LogBatch earlierKeyPairBatch =
        encryptor.encryptLogs("earlier logs".getBytes(UTF_8), /* publicKey= */ null);
    encryptor.generateKeyPair();
    LogBatch firstBatch =
        encryptor.encryptLogs("first logs".getBytes(UTF_8), /* publicKey= */ null);
    LogBatch externalKeyBatch =
        encryptor.encryptLogs(
            "external logs".getBytes(UTF_8), generateTestExternalRsaKeyPair().getPublic());
    LogBatch secondBatch =
        encryptor.encryptLogs("second logs".getBytes(UTF_8), /* publicKey= */ null);

    BulkDecryptPartition partition =
        encryptor.partitionForBulkDecrypt(
            ImmutableList.of(firstBatch, earlierKeyPairBatch, externalKeyBatch, secondBatch));

    expect.that(partition.batchUnwrappable()).containsExactly(firstBatch, secondBatch).inOrder();
    expect.that(partition.rsaOnly()).containsExactly(externalKeyBatch);
    expect.that(partition.undecryptable()).containsExactly(earlierKeyPairBatch);
  }

  private enum UnknownBatchWrapKeyIdCause {
    NO_BATCH_UNWRAP_KEYS {
      @Override
      void apply() {
        CrumblesBatchKeyStore.deleteKeys();
      }
    },
    UNUSABLE_BATCH_WRAP_KEY {
      @Override
      void apply() {
        breakBatchWrapKey();
      }
    };

    abstract void apply();
  }

  @Test
  public void partitionForBulkDecrypt_withoutTheBatchWrapKeyId_leavesBatchesToTheRsaKey(
      @TestParameter UnknownBatchWrapKeyIdCause cause) throws Exception {
    encryptor.generateKeyPair();
    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);
    cause.apply();

    BulkDecryptPartition partition = encryptor.partitionForBulkDecrypt(ImmutableList.of(logBatch));

    assertThat(partition.rsaOnly()).containsExactly(logBatch);
  }

  @Test
  public void encryptLogs_toDeviceKeyWithoutABatchWrappedKey_marksItAsForTheDeviceKey(
      @TestParameter UnknownBatchWrapKeyIdCause cause) throws Exception {
    encryptor.generateKeyPair();
    cause.apply();

    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);

    expect.that(logBatch.getKey().hasBatchWrapKeyId()).isTrue();
    expect.that(logBatch.getKey().getBatchWrapKeyId()).isEqualTo(ByteString.EMPTY);
    expect.that(logBatch.getKey().hasBatchWrappedSymmetricKey()).isFalse();
    expect
        .that(
            encryptor
                .partitionForKeyChange(
                    ImmutableList.of(logBatch), /* mayBeForAnExternalKey= */ batch -> true)
                .rsaOnly())
        .containsExactly(logBatch);
  }

  private enum UnusableBatchWrappedKey {
    TRUNCATED {
      @Override
      LogKey apply(LogKey key) {
        return key.toBuilder()
            .setBatchWrappedSymmetricKey(key.getBatchWrappedSymmetricKey().substring(0, 32))
            .build();
      }
    },
    WITHOUT_KEY_ID {
      @Override
      LogKey apply(LogKey key) {
        return key.toBuilder().clearBatchWrapKeyId().build();
      }
    };

    abstract LogKey apply(LogKey key);
  }

  @Test
  public void partitionForBulkDecrypt_withAnUnusableBatchWrappedKey_leavesTheBatchToTheRsaKey(
      @TestParameter UnusableBatchWrappedKey unusableKey) throws Exception {
    encryptor.generateKeyPair();
    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);
    LogBatch modifiedBatch =
        logBatch.toBuilder().setKey(unusableKey.apply(logBatch.getKey())).build();

    BulkDecryptPartition partition =
        encryptor.partitionForBulkDecrypt(ImmutableList.of(modifiedBatch));

    assertThat(partition.rsaOnly()).containsExactly(modifiedBatch);
  }

  @Test
  public void partitionForKeyChange_whenBatchMayBeForExternalKey_findsItUndecryptable()
      throws Exception {
    encryptor.generateKeyPair();
    LogBatch keystoreKeyBatch =
        encryptor.encryptLogs("keystore logs".getBytes(UTF_8), /* publicKey= */ null);
    LogBatch externalKeyBatch =
        encryptor.encryptLogs(
            "external logs".getBytes(UTF_8), generateTestExternalRsaKeyPair().getPublic());
    LogBatch unmarkedBuiltInBatch =
        keystoreKeyBatch.toBuilder()
            .setKey(
                keystoreKeyBatch.getKey().toBuilder()
                    .clearBatchWrapKeyId()
                    .clearBatchWrappedSymmetricKey())
            .build();

    BulkDecryptPartition partition =
        encryptor.partitionForKeyChange(
            ImmutableList.of(keystoreKeyBatch, externalKeyBatch, unmarkedBuiltInBatch),
            /* mayBeForAnExternalKey= */ logBatch -> logBatch.equals(externalKeyBatch));

    expect.that(partition.batchUnwrappable()).containsExactly(keystoreKeyBatch);
    expect.that(partition.rsaOnly()).containsExactly(unmarkedBuiltInBatch);
    expect.that(partition.undecryptable()).containsExactly(externalKeyBatch);
  }

  @Test
  public void partitionForKeyChange_findsABatchForAKeyOfAnotherSizeUndecryptable()
      throws Exception {
    encryptor.generateKeyPair();
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
    LogBatch largerKeyBatch =
        encryptor.encryptLogs(
            "larger key logs".getBytes(UTF_8), keyPairGenerator.generateKeyPair().getPublic());
    LogBatch sameSizeKeyBatch =
        encryptor.encryptLogs(
            "same size key logs".getBytes(UTF_8), generateTestExternalRsaKeyPair().getPublic());

    BulkDecryptPartition partition =
        encryptor.partitionForKeyChange(
            ImmutableList.of(largerKeyBatch, sameSizeKeyBatch),
            /* mayBeForAnExternalKey= */ logBatch -> false);

    expect.that(partition.rsaOnly()).containsExactly(sameSizeKeyBatch);
    expect.that(partition.undecryptable()).containsExactly(largerKeyBatch);
  }

  @Test
  public void decryptLogsWithSymmetricKey_withAnotherKey_throws() throws Exception {
    encryptor.generateKeyPair();
    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);
    SecretKey anotherKey = new SecretKeySpec(new byte[32], "AES");

    assertThrows(
        CrumblesLogsDecryptionException.class,
        () -> encryptor.decryptLogsWithSymmetricKey(logBatch, anotherKey));
  }

  @Test
  public void decryptLogsWithSymmetricKey_withoutKeystorePublicKey_throws() throws Exception {
    encryptor.generateKeyPair();
    LogBatch logBatch = encryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);
    Cipher batchUnwrapCipher = encryptor.createBatchUnwrapCipher();
    FakeAndroidKeyStoreSpi.authorizeOperation(batchUnwrapCipher);
    SecretKey symmetricKey =
        encryptor.unwrapBatchKeys(batchUnwrapCipher, ImmutableList.of(logBatch)).get(0);
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogsEncryptor.KEY_ALIAS);

    assertThrows(
        CrumblesLogsDecryptionException.class,
        () -> encryptor.decryptLogsWithSymmetricKey(logBatch, symmetricKey));
  }

  @Test
  public void encryptDataStoreEntry_whenPrimaryKeyCannotUnwrap_replacesKeyAndStaysReadable()
      throws Exception {
    PublicKey stalePublicKey =
        encryptor
            .generateKeyPair(
                CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS,
                /* requireUserAuthentication= */ false)
            .getPublic();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry staleEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(
            CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            generateTestExternalRsaKeyPair().getPrivate(),
            staleEntry.getCertificateChain(),
            staleEntry.getSpec()));
    byte[] plaintext = "datastoreentry".getBytes(UTF_8);

    EncryptedPayload payload = encryptor.encryptDataStoreEntry(plaintext, "entry_id");

    assertThat(encryptor.getPublicKey(CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS))
        .isNotEqualTo(stalePublicKey);
    assertThat(encryptor.decryptDataStoreEntry(payload, "entry_id")).isEqualTo(plaintext);
  }

  @Test
  public void encryptDataStoreEntry_whenPrimaryKeyWorks_keepsEarlierEntriesReadable()
      throws Exception {
    byte[] earlierPlaintext = "earlier".getBytes(UTF_8);
    byte[] laterPlaintext = "later".getBytes(UTF_8);
    EncryptedPayload earlierPayload =
        encryptor.encryptDataStoreEntry(earlierPlaintext, "earlier_id");

    EncryptedPayload laterPayload = encryptor.encryptDataStoreEntry(laterPlaintext, "later_id");

    assertThat(encryptor.decryptDataStoreEntry(earlierPayload, "earlier_id"))
        .isEqualTo(earlierPlaintext);
    assertThat(encryptor.decryptDataStoreEntry(laterPayload, "later_id")).isEqualTo(laterPlaintext);
  }

  /** Primary private key lookups that fail without the Keystore refusing the key. */
  private enum FailingPrimaryKeyLookup {
    MISSING_PRIVATE_KEY {
      @Override
      @Nullable
      PrivateKey lookUp() {
        return null;
      }
    },
    USER_NOT_AUTHENTICATED {
      @Override
      PrivateKey lookUp() {
        throw new ProviderException(new UserNotAuthenticatedException());
      }
    },
    PROVIDER_EXCEPTION {
      @Override
      PrivateKey lookUp() {
        throw new ProviderException();
      }
    };

    @Nullable
    abstract PrivateKey lookUp();
  }

  @Test
  public void encryptDataStoreEntry_whenPrimaryKeyLookupFailsWithoutRefusal_keepsPrimaryKey(
      @TestParameter FailingPrimaryKeyLookup keyLookup) throws Exception {
    PublicKey primaryPublicKey =
        encryptor
            .generateKeyPair(
                CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS,
                /* requireUserAuthentication= */ false)
            .getPublic();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry primaryEntry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(
            CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            primaryEntry.getPrivateKey(),
            primaryEntry.getCertificateChain(),
            primaryEntry.getSpec()) {
          @Override
          @Nullable
          public PrivateKey getPrivateKey() {
            return keyLookup.lookUp();
          }
        });

    assertThat(encryptor.encryptDataStoreEntry("datastoreentry".getBytes(UTF_8), "entry_id"))
        .isNotNull();

    assertThat(encryptor.getPublicKey(CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS))
        .isEqualTo(primaryPublicKey);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void reEncryptLogBatch_toExternalKey_usesOaep() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    KeyPair externalKeyPair = generateTestExternalRsaKeyPair();
    byte[] plainLogs = "logs to re-encrypt".getBytes(UTF_8);

    LogBatch logBatch =
        new CrumblesLogsEncryptor(context)
            .reEncryptLogBatch(
                plainLogs, externalKeyPair.getPublic(), LogMetadata.getDefaultInstance());

    assertThat(logBatch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    assertThat(decryptWithOaepKeyPair(externalKeyPair, logBatch)).isEqualTo(plainLogs);
  }

  @Test
  public void encryptLogs_whenNoEncryptionKeyIsSet_logsIgnored() throws Exception {
    // Given: A valid external PublicKey is not set on the encryptor.
    // And: The fake Keystore is empty.
    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries).isEmpty();

    // When: encryptLogs is called.
    // Then: it returns null.
    assertThat(
            encryptor.encryptLogs(
                "test encryption with external key.".getBytes(UTF_8),
                encryptor.getExternalEncryptionPublicKey()))
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
    LogBatch logBatch =
        encryptor.encryptLogs(
            originalContent.getBytes(UTF_8), encryptor.getExternalEncryptionPublicKey());

    // And: A new CrumblesLogsEncryptor instance, simulating an app restart.
    CrumblesLogsEncryptor decryptingEncryptor = new CrumblesLogsEncryptor();
    // And: Auth state is still true.

    // When: decryptLogs is called on the new instance with an authorized per-operation cipher.
    byte[] decryptedBytes = decrypt(decryptingEncryptor, logBatch);

    // Then: The key is loaded from the fake Keystore and decryption succeeds.
    assertThat(new String(decryptedBytes, UTF_8)).isEqualTo(originalContent);
  }

  @Test
  public void decryptLogs_withoutAuthorizedCipher_throwsDecryptionException() throws Exception {
    encryptor.generateKeyPair();
    LogBatch logBatch = encryptor.encryptLogs("secret".getBytes(UTF_8), /* publicKey= */ null);

    CrumblesLogsDecryptionException thrown =
        assertThrows(CrumblesLogsDecryptionException.class, () -> encryptor.decryptLogs(logBatch));

    assertThat(thrown)
        .hasCauseThat()
        .hasCauseThat()
        .hasCauseThat()
        .isInstanceOf(IllegalBlockSizeException.class);
  }

  @Test
  public void decryptLogs_whenAuthorizedCipherReused_throwsDecryptionException() throws Exception {
    encryptor.generateKeyPair();
    LogBatch first = encryptor.encryptLogs("first".getBytes(UTF_8), /* publicKey= */ null);
    LogBatch second = encryptor.encryptLogs("second".getBytes(UTF_8), /* publicKey= */ null);
    Cipher cipher = encryptor.createUnwrapCipher(first);
    FakeAndroidKeyStoreSpi.authorizeOperation(cipher);
    assertThat(encryptor.decryptLogs(first, cipher)).isEqualTo("first".getBytes(UTF_8));

    assertThrows(
        CrumblesLogsDecryptionException.class, () -> encryptor.decryptLogs(second, cipher));
  }

  @Test
  public void decryptLogs_whenTimeWindowClosed_throwsUserNotAuthenticatedException()
      throws Exception {
    generateTimeWindowDeviceKey();
    LogBatch logBatch = encryptor.encryptLogs("windowed".getBytes(UTF_8), /* publicKey= */ null);
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);

    assertThrows(UserNotAuthenticatedException.class, () -> encryptor.decryptLogs(logBatch));
  }

  @Test
  public void decryptLogs_whenEncryptedWithExternalKey_thenFailsWithKeystoreKey() throws Exception {
    // Given: A LogBatch encrypted with an external key.
    encryptor.setExternalEncryptionPublicKey(generateTestExternalRsaKeyPair().getPublic());
    LogBatch logBatch =
        encryptor.encryptLogs(
            "encrypted with external key.".getBytes(UTF_8),
            encryptor.getExternalEncryptionPublicKey());

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
        CrumblesLogsDecryptionException.class, () -> decrypt(decryptorWithKeystore, logBatch));
  }

  @Test
  public void decryptLogs_withAuthorizedUnwrapCipher_succeeds() throws Exception {
    String originalContent = "test decryption bound to a single authorized operation.";
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch logBatch =
        encryptor.encryptLogs(
            originalContent.getBytes(UTF_8), encryptor.getExternalEncryptionPublicKey());

    Cipher unwrapCipher = encryptor.createUnwrapCipher(logBatch);
    FakeAndroidKeyStoreSpi.authorizeOperation(unwrapCipher);
    byte[] decryptedBytes = encryptor.decryptLogs(logBatch, unwrapCipher);

    assertThat(new String(decryptedBytes, UTF_8)).isEqualTo(originalContent);
  }

  @Test
  public void decryptLogs_withUnwrapCipherForAnotherKey_throwsDecryptionException()
      throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch logBatch =
        encryptor.encryptLogs(
            "encrypted with external key.".getBytes(UTF_8),
            generateTestExternalRsaKeyPair().getPublic());
    Cipher unwrapCipher = encryptor.createUnwrapCipher(logBatch);
    FakeAndroidKeyStoreSpi.authorizeOperation(unwrapCipher);

    assertThrows(
        CrumblesLogsDecryptionException.class, () -> encryptor.decryptLogs(logBatch, unwrapCipher));
  }

  @Test
  public void createUnwrapCipher_whenNoKeystoreKeyExists_throwsCrumblesKeysException()
      throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch logBatch =
        encryptor.encryptLogs(
            "no key to unwrap with.".getBytes(UTF_8), encryptor.getExternalEncryptionPublicKey());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();

    assertThrows(CrumblesKeysException.class, () -> encryptor.createUnwrapCipher(logBatch));
  }

  @Test
  public void isKeystoreKeyBoundToEachOperation_forAGeneratedKey_isTrue() throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);

    assertThat(encryptor.isKeystoreKeyBoundToEachOperation()).isTrue();
  }

  private static void generateTimeWindowDeviceKey() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA", FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    generator.initialize(
        new KeyGenParameterSpec.Builder(
                CrumblesLogsEncryptor.KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(2048)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                /* timeout= */ 30, KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .build());
    generator.generateKeyPair();
  }

  @Test
  public void isKeystoreKeyBoundToEachOperation_forAKeyWithATimeWindow_isFalse() throws Exception {
    generateTimeWindowDeviceKey();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);

    assertThat(encryptor.isKeystoreKeyBoundToEachOperation()).isFalse();
  }

  @Test
  public void isKeystoreKeyBoundToEachOperation_forAKeyWithoutAuthentication_isFalse()
      throws Exception {
    encryptor.generateKeyPair(
        CrumblesLogsEncryptor.KEY_ALIAS, /* requireUserAuthentication= */ false);

    assertThat(encryptor.isKeystoreKeyBoundToEachOperation()).isFalse();
  }

  @Test
  public void isKeystoreKeyBoundToEachOperation_withoutKey_isFalse() {
    assertThat(encryptor.isKeystoreKeyBoundToEachOperation()).isFalse();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void isKeystoreKeyBoundToEachOperation_whenKeyInfoCannotBeRead_isTrueAndAssumesOaep()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    CrumblesLogsEncryptor contextEncryptor = new CrumblesLogsEncryptor(context);
    contextEncryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.PrivateKeyEntry entry =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesLogsEncryptor.KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            entry.getPrivateKey(), entry.getCertificateChain(), /* spec= */ null));

    LogBatch batch = contextEncryptor.encryptLogs("logs".getBytes(UTF_8), /* publicKey= */ null);

    expect.that(contextEncryptor.isKeystoreKeyBoundToEachOperation()).isTrue();
    expect
        .that(batch.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
  }

  // --- Hashing and Helper Method Tests ---

  @Test
  public void getPublicKeyHash_whenKeyIsNotNull_returnsCorrectHash() throws Exception {
    PublicKey publicKey = generateTestExternalRsaKeyPair().getPublic();

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hashBytes = digest.digest(publicKey.getEncoded());
    String expectedHash = Base64.getEncoder().encodeToString(hashBytes);
    expectedHash = expectedHash.substring(0, Math.min(expectedHash.length(), 16));

    String actualHash = CrumblesLogsEncryptor.getPublicKeyHash(publicKey);
    assertThat(actualHash).isEqualTo(expectedHash);
  }

  @Test
  public void getPublicKeyHash_whenKeyIsNull_returnsUnknown() {
    String actualHash = CrumblesLogsEncryptor.getPublicKeyHash(null);
    assertThat(actualHash).isEqualTo("Unknown");
  }

  @Test
  public void getPublicKeyHash_isCryptographicDigest_notSuffix() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    PublicKey a = g.generateKeyPair().getPublic();
    PublicKey b = g.generateKeyPair().getPublic();
    assertThat(CrumblesLogsEncryptor.getPublicKeyHash(a))
        .isNotEqualTo(CrumblesLogsEncryptor.getPublicKeyHash(b));
  }

  @Test
  public void getPublicKeyFingerprint_coversWholeDigestInLinesOfEightBytes() throws Exception {
    PublicKey publicKey = generateTestExternalRsaKeyPair().getPublic();
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());

    String fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(publicKey);

    // Every digest byte appears exactly once, in order, as two uppercase hex characters: a
    // fingerprint that drops or reorders bytes would let a different key read as a match.
    String hex = fingerprint.replace(":", "").replace("\n", "");
    assertThat(hex).matches("[0-9A-F]+");
    assertThat(hex).hasLength(digest.length * 2);
    for (int i = 0; i < digest.length; i++) {
      assertThat(Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16)).isEqualTo(digest[i] & 0xFF);
    }
    // ... laid out as lines of eight colon-separated bytes, so that the user can compare it
    // against the value the recipient gave them out of band.
    String[] lines = fingerprint.split("\n", -1);
    assertThat(lines).hasLength(digest.length / 8);
    for (String line : lines) {
      assertThat(line.split(":", -1)).hasLength(8);
    }
  }

  @Test
  public void getPublicKeyFingerprint_whenKeyCannotBeEncoded_throws() {
    PublicKey unencodableKey =
        new PublicKey() {
          @Override
          public String getAlgorithm() {
            return "RSA";
          }

          @Override
          public String getFormat() {
            return null;
          }

          @Override
          public byte[] getEncoded() {
            return null;
          }
        };

    assertThrows(
        CrumblesKeysException.class,
        () -> CrumblesLogsEncryptor.getPublicKeyFingerprint(unencodableKey));
  }

  @Test
  public void publicKeyFromBase64_whenNull_returnsNull() throws Exception {
    PublicKey key = CrumblesLogsEncryptor.publicKeyFromBase64(null);

    assertThat(key).isNull();
  }

  @Test
  public void publicKeyFromBase64_whenEmpty_returnsNull() throws Exception {
    PublicKey key = CrumblesLogsEncryptor.publicKeyFromBase64("");

    assertThat(key).isNull();
  }

  @Test
  public void publicKeyFromBase64_whenInvalidBase64_throwsException() {
    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class,
            () -> CrumblesLogsEncryptor.publicKeyFromBase64("not-valid-base64!"));

    assertThat(thrown).hasMessageThat().contains("Failed to convert Base64 string to PublicKey.");
  }

  @Test
  public void publicKeyFromBase64_whenInvalidKeySpec_throwsException() {
    String invalidKeySpecB64 = Base64.getEncoder().encodeToString(new byte[] {0x30, 0x05, 0x00});

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class,
            () -> CrumblesLogsEncryptor.publicKeyFromBase64(invalidKeySpecB64));

    assertThat(thrown).hasMessageThat().contains("Failed to convert Base64 string to PublicKey.");
  }

  @Test
  public void publicKeyFromBase64_acceptsValidKey() throws Exception {
    KeyPair keyPair = generateTestExternalRsaKeyPair();
    String b64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

    PublicKey key = CrumblesLogsEncryptor.publicKeyFromBase64(b64);

    assertThat(key).isEqualTo(keyPair.getPublic());
  }

  @Test
  public void publicKeyFromBase64_rejectsSub2048Modulus() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(512);
    String b64 = Base64.getEncoder().encodeToString(g.generateKeyPair().getPublic().getEncoded());

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class, () -> CrumblesLogsEncryptor.publicKeyFromBase64(b64));

    assertThat(thrown).hasMessageThat().contains("modulus 512 bits");
  }

  @Test
  public void publicKeyFromBase64_rejectsOver4096Modulus() throws Exception {
    BigInteger modulus5120 = BigInteger.ONE.shiftLeft(5120).setBit(0);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus5120, BigInteger.valueOf(65537));
    KeyFactory kf = KeyFactory.getInstance("RSA");
    String b64 = Base64.getEncoder().encodeToString(kf.generatePublic(spec).getEncoded());

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class, () -> CrumblesLogsEncryptor.publicKeyFromBase64(b64));

    assertThat(thrown).hasMessageThat().contains("modulus 5121 bits");
  }

  @Test
  public void publicKeyFromBase64_rejectsExponent3() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    String b64 = Base64.getEncoder().encodeToString(g.generateKeyPair().getPublic().getEncoded());

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class, () -> CrumblesLogsEncryptor.publicKeyFromBase64(b64));

    assertThat(thrown).hasMessageThat().contains("public exponent must be 65537");
  }

  @Test
  public void assembleCipherText_createsValidLogBatchWithTimestamp() {
    // Given: Valid log components
    byte[] encryptedLogs = "encryptedLogs".getBytes(UTF_8);
    byte[] cipherSymKey = "cipherSymKey".getBytes(UTF_8);
    byte[] cipherIv = "cipherIv".getBytes(UTF_8);

    // When: LogBatch is assembled
    LogBatch logBatch =
        CrumblesLogsEncryptor.assembleCipherText(encryptedLogs, cipherSymKey, cipherIv);

    // Then: All components and timestamp metadata are correctly constructed
    assertThat(logBatch).isNotNull();
    assertThat(logBatch.getData().getLogBlob().toByteArray()).isEqualTo(encryptedLogs);
    assertThat(logBatch.getKey().getEncryptedSymmetricKey().toByteArray()).isEqualTo(cipherSymKey);
    assertThat(logBatch.getKey().getIv().toByteArray()).isEqualTo(cipherIv);
    assertThat(logBatch.getMetadata().getBlobSize()).isEqualTo(encryptedLogs.length);
    assertThat(logBatch.getMetadata().getTimestamp().getSeconds()).isGreaterThan(0L);
    assertThat(logBatch.getMetadata().getTimestamp().getNanos()).isAtLeast(0);
    assertThat(logBatch.getMetadata().getTimestamp().getNanos()).isLessThan(1_000_000_000);
    assertThat(logBatch.getMetadata().getDevice().getDeviceId()).isNotEmpty();
    assertThat(logBatch.getMetadata().getEncryptionType())
        .isEqualTo(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM);
  }

  @Test
  public void assembleCipherText_withExplicitDeviceId_setsDeviceIdInMetadata() {
    byte[] encryptedLogs = "encryptedLogs".getBytes(UTF_8);
    byte[] cipherSymKey = "cipherSymKey".getBytes(UTF_8);
    byte[] cipherIv = "cipherIv".getBytes(UTF_8);

    LogBatch logBatch =
        CrumblesLogsEncryptor.assembleCipherText(
            encryptedLogs, cipherSymKey, cipherIv, "device_pixel_9999");

    assertThat(logBatch.getMetadata().getDevice().getDeviceId()).isEqualTo("device_pixel_9999");
  }

  @Test
  public void encryptLogs_sealsTheTimestampAndDeviceIdAndKeepsTheRestInClear() throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    LogBatch logBatch = encryptor.encryptLogs("sample logs".getBytes(UTF_8), /* publicKey= */ null);

    LogMetadata metadata = decryptLogBatch(encryptor, logBatch).metadata();

    expect
        .that(metadata.getDevice().getDeviceId())
        .isEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
    expect.that(metadata.getTimestamp().getSeconds()).isGreaterThan(0L);
    expect
        .that(logBatch.getMetadata())
        .isEqualTo(
            LogMetadata.newBuilder()
                .setBlobSize(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES)
                .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA)
                .build());
  }

  @Test
  public void timestampFromMillis_correctlyComputesSecondsAndNanos() {
    long millis = 1700000123456L;
    Timestamp timestamp = CrumblesLogsEncryptor.timestampFromMillis(millis);

    assertThat(timestamp.getSeconds()).isEqualTo(1700000123L);
    assertThat(timestamp.getNanos()).isEqualTo(456_000_000);
  }

  @Test
  public void timestampFromMillis_withZeroFraction_returnsZeroNanos() {
    long millis = 1700000000000L;
    Timestamp timestamp = CrumblesLogsEncryptor.timestampFromMillis(millis);

    assertThat(timestamp.getSeconds()).isEqualTo(1700000000L);
    assertThat(timestamp.getNanos()).isEqualTo(0);
  }

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
    LogBatch originalLogBatch =
        encryptor.encryptLogs(
            originalContent.getBytes(UTF_8), encryptor.getExternalEncryptionPublicKey());

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
    byte[] decryptedData = decrypt(encryptor, deserializedLogBatch);
    assertThat(new String(decryptedData, UTF_8)).isEqualTo(originalContent);

    // Cleanup.
    Files.delete(filePath);
    Files.delete(tempDir);
  }

  @Test
  public void serializeBytes_whenTargetExists_replacesItAndLeavesNoTempFile() throws Exception {
    Path baseDir = Files.createTempDirectory("crumbles_test_");
    Path existingFile = Files.write(baseDir.resolve("batch.bin"), "stale batch".getBytes(UTF_8));
    LogBatch logBatch =
        CrumblesLogsEncryptor.assembleCipherText(
            new byte[] {1, 2, 3}, new byte[] {4, 5, 6}, new byte[12], "device-123");

    Path filePath = encryptor.serializeBytes(logBatch, baseDir.toFile(), "batch.bin");

    assertThat(filePath).isEqualTo(existingFile);
    assertThat(Files.readAllBytes(filePath)).isEqualTo(logBatch.toByteArray());
    assertThat(baseDir.toFile().list()).asList().containsExactly("batch.bin");
  }

  @Test
  public void serializeBytes_whenMoveFails_throwsAndDeletesTempFile() throws Exception {
    Path baseDir = Files.createTempDirectory("crumbles_test_");
    Path blockingDirectory = Files.createDirectory(baseDir.resolve("batch.bin"));
    Files.write(
        blockingDirectory.resolve("child"), "keeps the directory non-empty".getBytes(UTF_8));
    LogBatch logBatch =
        CrumblesLogsEncryptor.assembleCipherText(
            new byte[] {1, 2, 3}, new byte[] {4, 5, 6}, new byte[12], "device-123");

    assertThrows(
        CrumblesLogsEncryptionException.class,
        () -> encryptor.serializeBytes(logBatch, baseDir.toFile(), "batch.bin"));

    assertThat(baseDir.toFile().list()).asList().containsExactly("batch.bin");
  }

  // --- AAD Metadata and Key Integrity Tampering Tests ---

  /** Test cases representing single-field tampering in AAD (metadata or key encryption type). */
  private enum AadTamperingCase {
    METADATA_TIMESTAMP {
      @Override
      LogBatch tamper(LogBatch originalBatch) {
        Timestamp tamperedTimestamp =
            Timestamp.newBuilder()
                .setSeconds(originalBatch.getMetadata().getTimestamp().getSeconds() + 1000)
                .setNanos(originalBatch.getMetadata().getTimestamp().getNanos())
                .build();
        return originalBatch.toBuilder()
            .setMetadata(
                originalBatch.getMetadata().toBuilder().setTimestamp(tamperedTimestamp).build())
            .build();
      }
    },
    METADATA_DEVICE_ID {
      @Override
      LogBatch tamper(LogBatch originalBatch) {
        DeviceId tamperedDeviceId = DeviceId.newBuilder().setDeviceId("tampered-device-id").build();
        return originalBatch.toBuilder()
            .setMetadata(
                originalBatch.getMetadata().toBuilder().setDevice(tamperedDeviceId).build())
            .build();
      }
    },
    METADATA_BLOB_SIZE {
      @Override
      LogBatch tamper(LogBatch originalBatch) {
        return originalBatch.toBuilder()
            .setMetadata(
                originalBatch.getMetadata().toBuilder()
                    .setBlobSize(originalBatch.getMetadata().getBlobSize() + 1)
                    .build())
            .build();
      }
    },
    METADATA_ENCRYPTION_TYPE {
      @Override
      LogBatch tamper(LogBatch originalBatch) {
        return originalBatch.toBuilder()
            .setMetadata(
                originalBatch.getMetadata().toBuilder()
                    .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_UNSPECIFIED)
                    .build())
            .build();
      }
    },
    KEY_ENCRYPTION_TYPE {
      @Override
      LogBatch tamper(LogBatch originalBatch) {
        return originalBatch.toBuilder()
            .setKey(
                originalBatch.getKey().toBuilder()
                    .setKeyEncryptionType(KeyEncryptionType.KEY_ENCRYPTION_TYPE_UNSPECIFIED)
                    .build())
            .build();
      }
    };

    abstract LogBatch tamper(LogBatch batch);
  }

  @Test
  public void decryptLogs_whenAadFieldModified_throwsCrumblesLogsDecryptionException(
      @TestParameter AadTamperingCase tamperingCase) throws Exception {
    // Given: A valid LogBatch encrypted with a Keystore key.
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "test log content for AAD tampering".getBytes(UTF_8);
    LogBatch originalBatch =
        encryptor.encryptLogs(plainLogs, encryptor.getExternalEncryptionPublicKey());

    // And: An attacker modifies an AAD field (metadata or key encryption type).
    LogBatch tamperedBatch = tamperingCase.tamper(originalBatch);

    // When & Then: Decryption fails due to AAD authentication tag mismatch.
    assertThrows(CrumblesLogsDecryptionException.class, () -> decrypt(encryptor, tamperedBatch));
  }

  @Test
  public void reEncryptLogBatch_bindsAadAndCanBeDecryptedWithNewKey() throws Exception {
    // Given: A valid plain log payload and an initialized Keystore key.
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "test log content for re-encryption with AAD".getBytes(UTF_8);

    // When: The plain logs are re-encrypted for the recipient public key.
    LogBatch reEncryptedBatch =
        encryptor.reEncryptLogBatch(plainLogs, encryptor.getPublicKey(), ORIGINAL);

    // Then: The re-encrypted batch can be successfully decrypted and content matches.
    byte[] decryptedLogs = decrypt(encryptor, reEncryptedBatch);
    assertThat(decryptedLogs).isEqualTo(plainLogs);
    assertThat(reEncryptedBatch.getMetadata().getBlobSize())
        .isEqualTo(4096 + CrumblesLogsEncryptor.GCM_TAG_LEN_BYTES);

    // And: When metadata is tampered on the re-encrypted batch, decryption fails.
    LogBatch tamperedBatch =
        reEncryptedBatch.toBuilder()
            .setMetadata(
                reEncryptedBatch.getMetadata().toBuilder()
                    .setBlobSize(reEncryptedBatch.getMetadata().getBlobSize() + 10)
                    .build())
            .build();
    assertThrows(CrumblesLogsDecryptionException.class, () -> decrypt(encryptor, tamperedBatch));
  }

  @Test
  public void reEncryptLogBatch_sealsTheOriginalDeviceId() throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs collected on the original device".getBytes(UTF_8);

    LogBatch reEncryptedBatch =
        encryptor.reEncryptLogBatch(
            plainLogs, encryptor.getPublicKey(), recordedBy("original-device-42"));
    LogBatch fallbackDeviceBatch =
        reEncryptedBatch.toBuilder()
            .setMetadata(
                reEncryptedBatch.getMetadata().toBuilder()
                    .setDevice(
                        DeviceId.newBuilder()
                            .setDeviceId(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID)))
            .build();

    assertThat(decryptLogBatch(encryptor, reEncryptedBatch).metadata().getDevice().getDeviceId())
        .isEqualTo("original-device-42");
    assertThat(decrypt(encryptor, reEncryptedBatch)).isEqualTo(plainLogs);
    assertThrows(
        CrumblesLogsDecryptionException.class, () -> decrypt(encryptor, fallbackDeviceBatch));
  }

  @Test
  public void reEncryptLogBatch_withoutOriginalDeviceId_usesFallbackDeviceId() throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);

    LogBatch reEncryptedBatch =
        encryptor.reEncryptLogBatch(
            new byte[] {1, 2, 3}, encryptor.getPublicKey(), LogMetadata.getDefaultInstance());

    assertThat(decryptLogBatch(encryptor, reEncryptedBatch).metadata().getDevice().getDeviceId())
        .isEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
  }

  @Test
  public void encryptLogsAttributedTo_sealsTheGivenDeviceId() throws Exception {
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    byte[] plainLogs = "logs collected on the original device".getBytes(UTF_8);

    LogBatch batch =
        encryptor.encryptLogsAttributedTo(
            recordedBy("original-device-42"), plainLogs, encryptor.getPublicKey());

    DecryptedLogBatch decryptedBatch = decryptLogBatch(encryptor, batch);
    expect.that(batch.getMetadata().getDevice().getDeviceId()).isEmpty();
    expect
        .that(decryptedBatch.metadata().getDevice().getDeviceId())
        .isEqualTo("original-device-42");
    expect.that(decryptedBatch.logs()).isEqualTo(plainLogs);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void encryptLogs_twoArgOverload_usesContextForDeviceId() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    String expectedId = CrumblesDeviceIdManager.getDeviceId(context);
    encryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    PublicKey recipient = encryptor.getPublicKey();
    CrumblesLogsEncryptor.setApplicationContext(null);
    LogBatch fromInstance =
        new CrumblesLogsEncryptor(context).encryptLogs(new byte[] {1}, recipient);
    LogBatch fromCached = new CrumblesLogsEncryptor().encryptLogs(new byte[] {1}, recipient);
    expect.that(expectedId).isNotEqualTo(CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
    expect
        .that(decryptLogBatch(encryptor, fromInstance).metadata().getDevice().getDeviceId())
        .isEqualTo(expectedId);
    expect
        .that(decryptLogBatch(encryptor, fromCached).metadata().getDevice().getDeviceId())
        .isEqualTo(expectedId);
  }

  @Test
  public void computeAssociatedData_returnsDeterministicBytes() {
    LogMetadata metadata =
        LogMetadata.newBuilder()
            .setBlobSize(100)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM)
            .build();
    byte[] aad1 =
        CrumblesLogsEncryptor.computeAssociatedData(
            metadata, KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC, /* recipient= */ null);
    byte[] aad2 =
        CrumblesLogsEncryptor.computeAssociatedData(
            metadata, KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC, /* recipient= */ null);

    assertThat(aad1).isNotEmpty();
    assertThat(aad1).isEqualTo(aad2);
  }

  @Test
  public void decryptData_serializedPayload_supportsOaepAndLegacyPkcs1() throws Exception {
    byte[] plaintext = "legacydatastore".getBytes(UTF_8);
    encryptor.generateKeyPair(CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS, false);
    PublicKey primaryPubKey =
        encryptor.getPublicKey(CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS);
    byte[] iv = new byte[12];
    SecretKey symKey = KeyGenerator.getInstance("AES").generateKey();
    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    aes.init(Cipher.ENCRYPT_MODE, symKey, new GCMParameterSpec(128, iv));
    byte[] ct = aes.doFinal(plaintext);
    String ivB64 = Base64.getEncoder().encodeToString(iv);
    String ctB64 = Base64.getEncoder().encodeToString(ct);

    Cipher rsaOaep = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    rsaOaep.init(
        Cipher.WRAP_MODE,
        primaryPubKey,
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT));
    String oaepKeyB64 = Base64.getEncoder().encodeToString(rsaOaep.wrap(symKey));
    assertThat(encryptor.decryptData(ivB64 + ":" + oaepKeyB64 + ":" + ctB64)).isEqualTo(plaintext);

    Cipher rsaPkcs1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    rsaPkcs1.init(Cipher.WRAP_MODE, primaryPubKey);
    String pkcs1KeyB64 = Base64.getEncoder().encodeToString(rsaPkcs1.wrap(symKey));
    assertThat(encryptor.decryptData(ivB64 + ":" + pkcs1KeyB64 + ":" + ctB64)).isEqualTo(plaintext);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void assembleCipherText_withoutKeyEncryptionType_marksTheKeyAsOaepWrapped() {
    byte[] bytes = new byte[] {1};

    LogBatch withDeviceId = CrumblesLogsEncryptor.assembleCipherText(bytes, bytes, bytes, "device");
    LogBatch withContext =
        CrumblesLogsEncryptor.assembleCipherText(
            ApplicationProvider.getApplicationContext(), bytes, bytes, bytes);

    expect
        .that(withDeviceId.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    expect
        .that(withContext.getKey().getKeyEncryptionType())
        .isEqualTo(KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void decryptLogs_whenUnwrappingFails_keepsKey() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    CrumblesLogsEncryptor localEncryptor = new CrumblesLogsEncryptor(context);
    localEncryptor.generateKeyPair();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    PublicKey keyBeforeFailure = localEncryptor.getPublicKey();
    LogBatch validBatch =
        localEncryptor.encryptLogs(
            context, "secret".getBytes(UTF_8), null, /* attestationChain= */ ImmutableList.of());
    LogBatch corrupted =
        CrumblesLogsEncryptor.assembleCipherText(
            new byte[] {1, 2, 3}, new byte[] {9, 9, 9}, new byte[12], "device-123");

    assertThrows(CrumblesLogsDecryptionException.class, () -> decrypt(localEncryptor, corrupted));
    byte[] decryptedAfterFailure = decrypt(localEncryptor, validBatch);

    assertThat(localEncryptor.getPublicKey()).isEqualTo(keyBeforeFailure);
    assertThat(decryptedAfterFailure).isEqualTo("secret".getBytes(UTF_8));
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.VANILLA_ICE_CREAM})
  public void generateKeyPair_whereAnEarlierVersionHadDisabledOaep_createsOaepKey()
      throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    // The verdict that the faulty capability probe of earlier versions persisted.
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putBoolean("oaepProbedWithMgf1Sha256", true)
        .putBoolean("oaepPaddingDisabled", true)
        .commit();

    new CrumblesLogsEncryptor(context).generateKeyPair();

    KeyGenParameterSpec spec =
        FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS).getSpec();
    expect
        .that(spec.getEncryptionPaddings())
        .asList()
        .containsExactly(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
    expect.that(spec.getMgf1Digests()).containsExactly(KeyProperties.DIGEST_SHA256);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.VANILLA_ICE_CREAM})
  public void generateKeyPair_onAndroid15_authorizesMgf1Sha256ForOaepKeys() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    setDeviceSecure(true);
    CrumblesLogsEncryptor localEncryptor = new CrumblesLogsEncryptor(context);

    localEncryptor.generateKeyPair();
    localEncryptor.generateKeyPair("custom_alias", /* requireUserAuthentication= */ false);

    expect
        .that(
            FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS)
                .getSpec()
                .getMgf1Digests())
        .containsExactly(KeyProperties.DIGEST_SHA256);
    expect
        .that(FakeAndroidKeyStoreSpi.getPrivateKeyEntry("custom_alias").getSpec().getMgf1Digests())
        .containsExactly(KeyProperties.DIGEST_SHA256);
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.VANILLA_ICE_CREAM})
  public void generateKeyPair_onAndroid15_requiresUnlockedDevice() throws Exception {
    encryptor.generateKeyPair();

    assertThat(
            FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS)
                .getSpec()
                .isUnlockedDeviceRequired())
        .isTrue();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.UPSIDE_DOWN_CAKE})
  public void generateKeyPair_onAndroid14_doesNotRequireUnlockedDevice() throws Exception {
    encryptor.generateKeyPair();

    assertThat(
            FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesLogsEncryptor.KEY_ALIAS)
                .getSpec()
                .isUnlockedDeviceRequired())
        .isFalse();
  }

  @Test
  @Config(sdk = {Build.VERSION_CODES.VANILLA_ICE_CREAM})
  public void generateKeyPair_onAndroid15WithoutUserAuthentication_doesNotRequireUnlockedDevice()
      throws Exception {
    encryptor.generateKeyPair(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS, /* requireUserAuthentication= */ false);

    assertThat(
            FakeAndroidKeyStoreSpi.getPrivateKeyEntry(
                    CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS)
                .getSpec()
                .isUnlockedDeviceRequired())
        .isFalse();
  }

  @Test
  public void buildPromptInfo_usesConfiguredAuthenticatorsAndText() {
    PromptInfo lockInfo =
        CrumblesDeviceCredentialGate.buildPromptInfo(
            "Title", "Subtitle", Authenticators.DEVICE_CREDENTIAL);
    PromptInfo strongInfo =
        CrumblesDeviceCredentialGate.buildPromptInfo(
            "Title",
            /* subtitle= */ null,
            Authenticators.BIOMETRIC_STRONG | Authenticators.DEVICE_CREDENTIAL);

    expect.that(lockInfo.getAllowedAuthenticators()).isEqualTo(Authenticators.DEVICE_CREDENTIAL);
    expect.that(lockInfo.getTitle().toString()).isEqualTo("Title");
    expect.that(lockInfo.getSubtitle().toString()).isEqualTo("Subtitle");
    expect
        .that(strongInfo.getAllowedAuthenticators())
        .isEqualTo(Authenticators.BIOMETRIC_STRONG | Authenticators.DEVICE_CREDENTIAL);
    expect.that(strongInfo.getSubtitle()).isNull();
  }

  /**
   * Log lengths and the size buckets that their padded sealed logs fill. Sealing adds a few dozen
   * bytes of metadata to the logs.
   */
  private enum PaddingCase {
    NO_LOGS(0, 4096),
    ONE_BYTE(1, 4096),
    NEARLY_FILLS_THE_SMALLEST_BUCKET(4000, 4096),
    FILLS_THE_SMALLEST_BUCKET_ONLY_WITHOUT_METADATA(4080, 8192),
    NEARLY_FILLS_THE_NEXT_BUCKET(8100, 8192),
    OVER_THE_NEXT_BUCKET(8189, 16384);

    private final int logsLength;
    private final int paddedLength;

    PaddingCase(int logsLength, int paddedLength) {
      this.logsLength = logsLength;
      this.paddedLength = paddedLength;
    }
  }

  /** Padded plaintexts whose declared length does not fit what they hold. */
  private enum MalformedPaddedPlaintext {
    NEGATIVE_LENGTH {
      @Override
      byte[] plaintext() {
        return ByteBuffer.allocate(4096).putInt(-1).array();
      }
    },
    LENGTH_BEYOND_THE_PADDING {
      @Override
      byte[] plaintext() {
        return ByteBuffer.allocate(4096).putInt(4093).array();
      }
    },
    TOO_SHORT_FOR_A_LENGTH {
      @Override
      byte[] plaintext() {
        return new byte[Integer.BYTES - 1];
      }
    };

    abstract byte[] plaintext();
  }
}
