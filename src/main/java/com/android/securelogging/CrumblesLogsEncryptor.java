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

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.Math.min;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsDecryptionException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import com.google.common.time.TimeSource;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.Timestamp;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.KeyEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogKey;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CrumblesLogsEncryptor encrypts and decrypts Crumbles logs using a per-batch-of-logs AES-GCM
 * symmetric key. This symmetric key is wrapped by an RSA public key. The RSA key pair can either be
 * stored in the Android Keystore or an external public key can be provided for encryption.
 *
 * <p>Private keys generated in the Keystore are configured to require user authentication (e.g.,
 * fingerprint, PIN) for decryption operations.
 */
public class CrumblesLogsEncryptor {
  private static final String TAG = "CrumblesLogsEncryptor";

  private static final String SYM_ALGORITHM = "AES";
  private static final int AES_KEY_SIZE_BITS = 256;
  @VisibleForTesting static final int GCM_IV_LEN_BYTES = 12;
  @VisibleForTesting static final int GCM_TAG_LEN_BITS = 128;
  @VisibleForTesting static final int GCM_TAG_LEN_BYTES = GCM_TAG_LEN_BITS / 8;

  @VisibleForTesting static final String ASYM_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;
  private static final String CIPHER_MODE_ASYM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
  private static final int ASYM_BITS = 2048;
  private static final int MIN_RSA_MODULUS_BITS = 2048;
  private static final int MAX_RSA_MODULUS_BITS = 4096;
  private static final BigInteger EXPECTED_RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

  private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

  /** Default alias for the RSA key pair. */
  public static final String KEY_ALIAS = "com.android.securelogging.CrumblesRsaKeyAlias";

  /** Alias for the primary key used to encrypt preferences. */
  public static final String PREFERENCE_PRIMARY_KEY_ALIAS =
      "com.android.securelogging.CrumblesPreferencePrimaryKey";

  private static final String SERIALIZED_ENCRYPTED_DATA_DELIMITER = ":";

  private static final Duration AUTH_VALIDITY_DURATION = Duration.ofSeconds(30);

  @Nullable private final Context context;
  private PublicKey externalEncryptionPublicKey;

  public CrumblesLogsEncryptor() {
    this(null);
  }

  public CrumblesLogsEncryptor(@Nullable Context context) {
    this.context = context != null ? context.getApplicationContext() : null;
  }

  @VisibleForTesting
  static final class EncryptedData {
    final byte[] ciphertext;
    final byte[] encryptedSymmetricKey;
    final byte[] initializationVector;

    EncryptedData(byte[] ciphertext, byte[] encryptedSymmetricKey, byte[] initializationVector) {
      this.ciphertext = ciphertext;
      this.encryptedSymmetricKey = encryptedSymmetricKey;
      this.initializationVector = initializationVector;
    }
  }

  /** Consumer interface for private key bytes. */
  public interface PrivateKeyBytesConsumer {
    void accept(byte[] privateKeyBytes) throws CrumblesKeysException;
  }

  /** getPublicKey method. */
  @Nullable
  public PublicKey getPublicKey() {
    return getPublicKey(KEY_ALIAS);
  }

  /** getPublicKey method. */
  @Nullable
  public PublicKey getPublicKey(String keyAlias) {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      if (keyStore.containsAlias(keyAlias)) {
        return keyStore.getCertificate(keyAlias).getPublicKey();
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to load public key from Android Keystore for alias: " + keyAlias, e);
    }
    return null;
  }

  public boolean doesPrivateKeyExist() {
    return getPublicKey() != null;
  }

  /**
   * Sets the external encryption public key.
   *
   * @param publicKey the public key to be set for external encryption
   */
  public synchronized void setExternalEncryptionPublicKey(@Nullable PublicKey publicKey) {
    this.externalEncryptionPublicKey = publicKey;
    if (publicKey != null) {
      Log.d(TAG, "External public key has been set for encryption.");
    } else {
      Log.d(TAG, "Setting the external public key did not work.");
    }
  }

  @Nullable
  public synchronized PublicKey getExternalEncryptionPublicKey() {
    return this.externalEncryptionPublicKey;
  }

  /**
   * Generates a new key pair using the default alias and authentication settings.
   *
   * @return the generated {@link KeyPair}
   * @throws CrumblesKeysException if the key pair cannot be generated
   */
  @CanIgnoreReturnValue
  public synchronized KeyPair generateKeyPair() throws CrumblesKeysException {
    return generateKeyPair(KEY_ALIAS, true);
  }

  /**
   * Generates a new key pair and stores it in the Android Keystore.
   *
   * @param keyAlias the alias under which to store the key pair
   * @param requireUserAuthentication whether the key requires user authentication to be used
   * @return the generated {@link KeyPair}
   * @throws CrumblesKeysException if the key pair cannot be generated
   */
  @CanIgnoreReturnValue
  public synchronized KeyPair generateKeyPair(String keyAlias, boolean requireUserAuthentication)
      throws CrumblesKeysException {
    return generateKeyPair(keyAlias, requireUserAuthentication, AUTH_VALIDITY_DURATION);
  }

  /**
   * Generates a new key pair and stores it in the Android Keystore.
   *
   * @param keyAlias the alias under which to store the key pair
   * @param requireUserAuthentication whether the key requires user authentication to be used
   * @param authValidityDuration the duration for which the authentication remains valid
   * @return the generated {@link KeyPair}
   * @throws CrumblesKeysException if the key pair cannot be generated
   */
  @CanIgnoreReturnValue
  public synchronized KeyPair generateKeyPair(
      String keyAlias, boolean requireUserAuthentication, Duration authValidityDuration)
      throws CrumblesKeysException {
    deleteExistingKeyPair(keyAlias);
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      Log.d(TAG, "Generating new RSA key pair into Android Keystore with alias: " + keyAlias);
      KeyPairGenerator keyPairGenerator =
          KeyPairGenerator.getInstance(ASYM_ALGORITHM, ANDROID_KEYSTORE_PROVIDER);
      KeyGenParameterSpec.Builder specBuilder =
          new KeyGenParameterSpec.Builder(
                  keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setKeySize(ASYM_BITS)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
              .setDigests(KeyProperties.DIGEST_SHA256)
              .setUserAuthenticationRequired(requireUserAuthentication)
              .setUserAuthenticationValidityDurationSeconds((int) authValidityDuration.toSeconds());

      keyPairGenerator.initialize(specBuilder.build());
      return keyPairGenerator.generateKeyPair();
    } catch (Exception e) {
      throw new CrumblesKeysException(
          "Failed to generate or load key pair from Android Keystore for alias: " + keyAlias, e);
    }
  }

  @VisibleForTesting
  void deleteExistingKeyPair() {
    deleteExistingKeyPair(KEY_ALIAS);
  }

  private void deleteExistingKeyPair(String keyAlias) {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      if (keyStore.containsAlias(keyAlias)) {
        keyStore.deleteEntry(keyAlias);
        Log.d(TAG, "Existing key pair deleted from Android Keystore.");
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to delete existing key pair from Android Keystore.", e);
    }
  }

  /**
   * Generates a new candidate external RSA key pair without activating it or mutating current
   * state.
   *
   * @return the newly generated candidate KeyPair
   * @throws CrumblesKeysException if key pair generation fails
   */
  public KeyPair generateCandidateExternalKeyPair() throws CrumblesKeysException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYM_ALGORITHM);
      keyPairGenerator.initialize(ASYM_BITS);
      KeyPair generatedPair = keyPairGenerator.generateKeyPair();

      if (generatedPair == null
          || generatedPair.getPublic() == null
          || generatedPair.getPrivate() == null) {
        throw new CrumblesKeysException(
            "Generated external KeyPair or its components are null.", null);
      }
      return generatedPair;
    } catch (NoSuchAlgorithmException | RuntimeException e) {
      throw new CrumblesKeysException("Failed to generate external RSA key pair.", e);
    }
  }

  /**
   * Commits and activates a candidate external public key for encryption, and removes any existing
   * internal keystore key pair.
   *
   * @param candidatePublicKey the external public key to commit and activate
   * @throws CrumblesKeysException if the candidate public key is null
   */
  public synchronized void commitExternalPublicKey(PublicKey candidatePublicKey)
      throws CrumblesKeysException {
    if (candidatePublicKey == null) {
      throw new CrumblesKeysException("Candidate public key cannot be null.", null);
    }
    this.setExternalEncryptionPublicKey(candidatePublicKey);
    deleteExistingKeyPair();
    Log.d(TAG, "External public key committed and activated for encryption.");
  }

  /**
   * Generates a new external key pair, sets the public key for encryption, and passes the private
   * key to the provided consumer. Also deletes any existing keystore key pair.
   *
   * @param consumer a consumer that will receive the encoded private key bytes
   * @throws CrumblesKeysException if the key pair cannot be generated
   */
  public synchronized void generateAndSetExternalKeyPair(PrivateKeyBytesConsumer consumer)
      throws CrumblesKeysException {
    KeyPair generatedPair = generateCandidateExternalKeyPair();
    byte[] privateKeyBytes = generatedPair.getPrivate().getEncoded();
    consumer.accept(privateKeyBytes);
    commitExternalPublicKey(generatedPair.getPublic());
    Log.d(TAG, "New external key pair generated. Public key set for use.");
  }

  /**
   * Computes the Additional Authenticated Data (AAD) for binding a {@link LogBatch}'s metadata and
   * key encryption parameters to the AES-GCM cipher payload.
   *
   * @param metadata the {@link LogMetadata} to authenticate
   * @param keyEncryptionType the {@link KeyEncryptionType} to authenticate
   * @return deterministic bytes representing the bound associated data
   */
  public static byte[] computeAssociatedData(
      LogMetadata metadata, KeyEncryptionType keyEncryptionType) {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CodedOutputStream codedOutput = CodedOutputStream.newInstance(outputStream);
    // NOMUTANTS -- Scalar fields without maps serialize deterministically by default.
    codedOutput.useDeterministicSerialization();
    try {
      metadata.writeTo(codedOutput);
      codedOutput.writeEnumNoTag(keyEncryptionType.getNumber());
      codedOutput.flush();
    } catch (IOException e) {
      throw new AssertionError("In-memory serialization to ByteArrayOutputStream failed", e);
    }
    return outputStream.toByteArray();
  }

  public static LogMetadata assembleMetadata(int blobSize, String deviceId) {
    DeviceId deviceProto =
        DeviceId.newBuilder()
            .setDeviceId(
                isNullOrEmpty(deviceId) ? CrumblesDeviceIdManager.FALLBACK_DEVICE_ID : deviceId)
            .build();
    return LogMetadata.newBuilder()
        .setBlobSize(blobSize)
        .setTimestamp(timestampFromMillis(TimeSource.system().instant().toEpochMilli()))
        .setDevice(deviceProto)
        .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM)
        .build();
  }

  public static LogMetadata assembleMetadata(int blobSize) {
    return assembleMetadata(blobSize, CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
  }

  public EncryptedData encryptData(byte[] data, PublicKey encryptionKey)
      throws CrumblesKeysException {
    return encryptData(data, /* aad= */ null, encryptionKey);
  }

  /**
   * Encrypts data using a hybrid encryption scheme with Additional Authenticated Data (AAD).
   *
   * @param data the plaintext data to encrypt
   * @param aad the additional authenticated data to authenticate with AES-GCM, or null if none
   * @param encryptionKey the RSA public key to use for encrypting the symmetric key
   * @return an {@link EncryptedData} object containing the encrypted data, encrypted symmetric key,
   *     and IV
   * @throws CrumblesKeysException if an error occurs during encryption
   */
  public EncryptedData encryptData(byte[] data, @Nullable byte[] aad, PublicKey encryptionKey)
      throws CrumblesKeysException {
    SecretKey symKey = generateSecretKey();
    IvParameterSpec generatedIv = generateAesGcmInitializationVector();
    byte[] encryptedBytes = encryptDataWithSymKey(symKey, generatedIv, aad, data);
    byte[] encSymKey = wrapAesKey(encryptionKey, symKey);
    return new EncryptedData(encryptedBytes, encSymKey, generatedIv.getIV());
  }

  /**
   * Encrypts plain logs using the provided public key and context for device attribution.
   */
  @CanIgnoreReturnValue
  @Nullable
  public LogBatch encryptLogs(
      @Nullable Context context, byte[] plainLogsBytes, @Nullable PublicKey publicKey) {
    return encryptLogsInternal(
        plainLogsBytes, publicKey, CrumblesDeviceIdManager.getDeviceId(context));
  }

  /** Encrypts log data and packages it into a {@link LogBatch} protobuf message bound with AAD. */
  @CanIgnoreReturnValue
  @Nullable
  public LogBatch encryptLogs(byte[] plainLogsBytes, @Nullable PublicKey publicKey) {
    return encryptLogs(this.context, plainLogsBytes, publicKey);
  }

  @Nullable
  private LogBatch encryptLogsInternal(
      byte[] plainLogsBytes, @Nullable PublicKey publicKey, String deviceId) {
    try {
      String keySourceMessage;
      EncryptedData encryptedData;

      if (publicKey == null && !doesPrivateKeyExist()) {
        Log.e(TAG, "Encryption failed: No encryption key available.");
        return null;
      }

      LogMetadata logMetadata =
          assembleMetadata(plainLogsBytes.length + GCM_TAG_LEN_BYTES, deviceId);
      byte[] aad =
          computeAssociatedData(logMetadata, KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC);

      if (publicKey != null) {
        encryptedData = encryptData(plainLogsBytes, aad, publicKey);
        keySourceMessage = "Using provided public key for encryption.";
      } else {
        encryptedData = encryptData(plainLogsBytes, aad, getPublicKey());
        keySourceMessage = "Using Keystore public key for encryption.";
      }
      Log.d(TAG, keySourceMessage);

      return assembleCipherText(
          encryptedData.ciphertext,
          encryptedData.encryptedSymmetricKey,
          encryptedData.initializationVector,
          logMetadata);
    } catch (CrumblesKeysException | RuntimeException e) {
      Log.e(TAG, "Unexpected runtime error during encryption process.", e);
      throw new CrumblesLogsEncryptionException(
          "An unexpected error occurred during log encryption.", e);
    }
  }

  /**
   * Decrypts a {@link LogBatch} protobuf message using the Keystore private key and validates AAD.
   *
   * @param logBatch the {@link LogBatch} containing ciphertext, wrapped symmetric key, and metadata
   * @return the decrypted log bytes
   * @throws CrumblesKeysException if the private key cannot be accessed or loaded
   * @throws UserNotAuthenticatedException if user authentication is required
   */
  @CanIgnoreReturnValue
  public byte[] decryptLogs(LogBatch logBatch)
      throws CrumblesKeysException, UserNotAuthenticatedException {
    if (!doesPrivateKeyExist()) {
      throw new CrumblesKeysException(
          "Private key not available in Keystore for decryption.", null);
    }
    PrivateKey privateKey;
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
      if (privateKey == null) {
        throw new CrumblesKeysException("Failed to load private key from Keystore.", null);
      }
    } catch (Exception e) {
      throw new CrumblesKeysException(
          "Failed to load key pair from Android Keystore for decryption.", e);
    }

    try {
      byte[] encryptedLogsBytes = logBatch.getData().getLogBlob().toByteArray();
      byte[] cipherSymKeyBytes = logBatch.getKey().getEncryptedSymmetricKey().toByteArray();
      byte[] cipherIvBytes = logBatch.getKey().getIv().toByteArray();
      byte[] aad =
          computeAssociatedData(logBatch.getMetadata(), logBatch.getKey().getKeyEncryptionType());

      SecretKey decryptedSymKey = unwrapAesKey(privateKey, cipherSymKeyBytes);
      SecretKeySpec decryptedSymKeySpec =
          new SecretKeySpec(decryptedSymKey.getEncoded(), SYM_ALGORITHM);

      byte[] decryptedLogsBytes =
          decryptUsingAes256Gcm(
              decryptedSymKeySpec, new IvParameterSpec(cipherIvBytes), aad, encryptedLogsBytes);
      Log.d(TAG, "Log file decrypted successfully using Keystore private key.");
      return decryptedLogsBytes;
    } catch (CrumblesKeysException e) {
      // If the cause is UserNotAuthenticatedException, rethrow it so the OS can handle it.
      if (e.getCause() instanceof UserNotAuthenticatedException) {
        throw (UserNotAuthenticatedException) e.getCause();
      }
      throw new CrumblesLogsDecryptionException(
          "A cryptographic error occurred during log decryption.", e);
    } catch (RuntimeException e) {
      throw new CrumblesLogsDecryptionException(
          "An unexpected runtime error occurred during log decryption.", e);
    }
  }

  private static SecretKey generateSecretKey() throws CrumblesKeysException {
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGORITHM);
      keyGen.init(AES_KEY_SIZE_BITS);
      return keyGen.generateKey();
    } catch (NoSuchAlgorithmException e) {
      throw new CrumblesKeysException("Failed to generate symmetric key.", e);
    }
  }

  private static IvParameterSpec generateAesGcmInitializationVector() {
    byte[] ivBytes = new byte[GCM_IV_LEN_BYTES];
    new SecureRandom().nextBytes(ivBytes);
    return new IvParameterSpec(ivBytes);
  }

  private byte[] encryptDataWithSymKey(
      SecretKey symKey, IvParameterSpec generatedIv, @Nullable byte[] aad, byte[] plainBytes) {
    SecretKeySpec symKeySpec = new SecretKeySpec(symKey.getEncoded(), SYM_ALGORITHM);
    return encryptUsingAes256Gcm(symKeySpec, generatedIv, aad, plainBytes);
  }

  private static byte[] encryptUsingAes256Gcm(
      SecretKeySpec key, IvParameterSpec ivSpec, @Nullable byte[] aad, byte[] plainTextBytes) {
    try {
      Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec gcmParameterSpec =
          new GCMParameterSpec(GCM_TAG_LEN_BITS, ivSpec.getIV());
      aesCipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
      if (aad != null) {
        aesCipher.updateAAD(aad);
      }
      return aesCipher.doFinal(plainTextBytes);
    } catch (Exception e) {
      throw new CrumblesLogsEncryptionException("AES GCM encryption failed.", e);
    }
  }

  private static byte[] wrapAesKey(PublicKey publicKey, SecretKey symmetricKey)
      throws CrumblesKeysException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_MODE_ASYM);
      cipher.init(Cipher.WRAP_MODE, publicKey);
      return cipher.wrap(symmetricKey);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to wrap AES key with public key.", e);
    }
  }

  private static SecretKey unwrapAesKey(PrivateKey privateKey, byte[] wrappedAesKeyBytes)
      throws CrumblesKeysException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_MODE_ASYM);
      cipher.init(Cipher.UNWRAP_MODE, privateKey);
      return (SecretKey) cipher.unwrap(wrappedAesKeyBytes, SYM_ALGORITHM, Cipher.SECRET_KEY);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to unwrap AES key with private key.", e);
    }
  }

  private static byte[] decryptUsingAes256Gcm(
      SecretKeySpec key, IvParameterSpec ivSpec, @Nullable byte[] aad, byte[] cipherTextBytes) {
    try {
      Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec gcmParameterSpec =
          new GCMParameterSpec(GCM_TAG_LEN_BITS, ivSpec.getIV());
      aesCipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
      if (aad != null) {
        aesCipher.updateAAD(aad);
      }
      return aesCipher.doFinal(cipherTextBytes);
    } catch (Exception e) {
      throw new CrumblesLogsDecryptionException("AES GCM decryption failed.", e);
    }
  }

  /** serializeBytes method. */
  public Path serializeBytes(LogBatch toSerialize, File baseDir, String fileName) {
    try {
      byte[] serializedBytes = toSerialize.toByteArray();
      Path filePath = Path.of(baseDir.getAbsolutePath(), fileName);
      Files.write(filePath, serializedBytes);
      Log.d(TAG, "Bytes serialized to file: " + filePath);
      return filePath;
    } catch (IOException e) {
      throw new CrumblesLogsEncryptionException("Failed to serialize bytes to file.", e);
    }
  }

  public LogBatch deserializeFile(Path filePath) {
    try {
      byte[] serializedBytes = Files.readAllBytes(filePath);
      return LogBatch.parseFrom(serializedBytes, ExtensionRegistryLite.getGeneratedRegistry());
    } catch (IOException e) {
      throw new CrumblesLogsEncryptionException("Failed to deserialize bytes from file.", e);
    }
  }

  @VisibleForTesting
  static Timestamp timestampFromMillis(long millis) {
    return Timestamp.newBuilder()
        .setSeconds(Math.floorDiv(millis, 1000L))
        .setNanos((int) (Math.floorMod(millis, 1000L) * 1_000_000L))
        .build();
  }

  /**
   * Assembles a {@link LogBatch} protobuf message from ciphertext components and metadata.
   *
   * @param encryptedLogsBytes the encrypted log data blob
   * @param cipherSymKeyBytes the wrapped symmetric key bytes
   * @param cipherIvBytes the initialization vector bytes
   * @param logMetadata the metadata associated with the log batch
   * @return the assembled {@link LogBatch}
   */
  public static LogBatch assembleCipherText(
      byte[] encryptedLogsBytes,
      byte[] cipherSymKeyBytes,
      byte[] cipherIvBytes,
      LogMetadata logMetadata) {
    LogData logData =
        LogData.newBuilder().setLogBlob(ByteString.copyFrom(encryptedLogsBytes)).build();
    LogKey logKey =
        LogKey.newBuilder()
            .setKeyEncryptionType(KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC)
            .setEncryptedSymmetricKey(ByteString.copyFrom(cipherSymKeyBytes))
            .setIv(ByteString.copyFrom(cipherIvBytes))
            .build();
    return LogBatch.newBuilder().setData(logData).setKey(logKey).setMetadata(logMetadata).build();
  }

  /**
   * Assembles a {@link LogBatch} protobuf message from ciphertext components with generated
   * metadata.
   *
   * @param encryptedLogsBytes the encrypted log data blob
   * @param cipherSymKeyBytes the wrapped symmetric key bytes
   * @param cipherIvBytes the initialization vector bytes
   * @return the assembled {@link LogBatch}
   */
  public static LogBatch assembleCipherText(
      byte[] encryptedLogsBytes, byte[] cipherSymKeyBytes, byte[] cipherIvBytes, String deviceId) {
    return assembleCipherText(
        encryptedLogsBytes,
        cipherSymKeyBytes,
        cipherIvBytes,
        assembleMetadata(encryptedLogsBytes.length, deviceId));
  }

  public static LogBatch assembleCipherText(
      @Nullable Context context,
      byte[] encryptedLogsBytes,
      byte[] cipherSymKeyBytes,
      byte[] cipherIvBytes) {
    return assembleCipherText(
        encryptedLogsBytes,
        cipherSymKeyBytes,
        cipherIvBytes,
        CrumblesDeviceIdManager.getDeviceId(context));
  }

  public static LogBatch assembleCipherText(
      byte[] encryptedLogsBytes, byte[] cipherSymKeyBytes, byte[] cipherIvBytes) {
    return assembleCipherText(
        /* context= */ null, encryptedLogsBytes, cipherSymKeyBytes, cipherIvBytes);
  }

  @CanIgnoreReturnValue
  public String encryptDataStoreEntry(byte[] plaintext) throws CrumblesKeysException {
    PublicKey publicKey = getPublicKey(PREFERENCE_PRIMARY_KEY_ALIAS);
    if (publicKey == null) {
      publicKey = generateKeyPair(PREFERENCE_PRIMARY_KEY_ALIAS, false).getPublic();
    }
    EncryptedData encData = encryptData(plaintext, publicKey);

    String ivString = Base64.getEncoder().encodeToString(encData.initializationVector);
    String keyString = Base64.getEncoder().encodeToString(encData.encryptedSymmetricKey);
    String ciphertextString = Base64.getEncoder().encodeToString(encData.ciphertext);

    return ivString
        + SERIALIZED_ENCRYPTED_DATA_DELIMITER
        + keyString
        + SERIALIZED_ENCRYPTED_DATA_DELIMITER
        + ciphertextString;
  }

  public byte[] decryptData(String serializedPayload) throws CrumblesKeysException {
    String[] parts = serializedPayload.split(SERIALIZED_ENCRYPTED_DATA_DELIMITER, 3);
    if (parts.length != 3) {
      throw new CrumblesKeysException("Invalid encrypted payload format.", null);
    }
    try {
      byte[] ivBytes = Base64.getDecoder().decode(parts[0]);
      byte[] wrappedKeyBytes = Base64.getDecoder().decode(parts[1]);
      byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      PrivateKey primaryPrivateKey =
          (PrivateKey) keyStore.getKey(PREFERENCE_PRIMARY_KEY_ALIAS, null);
      if (primaryPrivateKey == null) {
        throw new CrumblesKeysException("Failed to load primary private key from Keystore.");
      }

      SecretKey aesKey = unwrapAesKey(primaryPrivateKey, wrappedKeyBytes);
      SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), SYM_ALGORITHM);

      return decryptUsingAes256Gcm(
          aesKeySpec, new IvParameterSpec(ivBytes), /* aad= */ null, ciphertext);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to perform AES-GCM decryption.", e);
    }
  }

  @Nullable
  public static String publicKeyToBase64(@Nullable PublicKey publicKey) {
    if (publicKey == null) {
      return null;
    }
    return Base64.getEncoder().encodeToString(publicKey.getEncoded());
  }

  @Nullable
  public static String privateKeyToBase64(@Nullable PrivateKey privateKey) {
    if (privateKey == null) {
      return null;
    }
    return Base64.getEncoder().encodeToString(privateKey.getEncoded());
  }

  public static String getPublicKeyHash(PublicKey key) {
    if (key == null) {
      return "Unknown";
    }
    String keyHash = "Unknown";
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hashBytes = digest.digest(key.getEncoded());
      String base64Hash = Base64.getEncoder().encodeToString(hashBytes);
      keyHash = base64Hash.substring(0, min(base64Hash.length(), 16));
    } catch (NoSuchAlgorithmException | RuntimeException e) {
      Log.w(TAG, "Could not generate preview for external key", e);
    }
    return keyHash;
  }

  @Nullable
  public static PublicKey publicKeyFromBase64(@Nullable String base64PublicKey)
      throws CrumblesKeysException {
    if (isNullOrEmpty(base64PublicKey)) {
      return null;
    }
    RSAPublicKey rsa;
    try {
      byte[] decodedKey = Base64.getDecoder().decode(base64PublicKey);
      KeyFactory keyFactory = KeyFactory.getInstance(ASYM_ALGORITHM);
      rsa = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CrumblesKeysException("Failed to convert Base64 string to PublicKey.", e);
    }
    int bits = rsa.getModulus().bitLength();
    if (bits < MIN_RSA_MODULUS_BITS || bits > MAX_RSA_MODULUS_BITS) {
      throw new CrumblesKeysException(
          "Rejected RSA key: modulus " + bits + " bits (require 2048-4096).");
    }
    if (!Objects.equals(rsa.getPublicExponent(), EXPECTED_RSA_PUBLIC_EXPONENT)) {
      throw new CrumblesKeysException(
          "Rejected RSA key: public exponent must be " + EXPECTED_RSA_PUBLIC_EXPONENT + ".");
    }
    return rsa;
  }

  /**
   * Re-encrypts plain log bytes under a new public key and packages the result into a {@link
   * LogBatch}.
   *
   * @param plainLogsBytes the plain log bytes to re-encrypt
   * @param reEncryptionKey the public key to wrap the per-batch symmetric key with
   * @return a newly assembled {@link LogBatch} bound with AAD
   * @throws CrumblesKeysException if key wrapping fails
   */
  public LogBatch reEncryptLogBatch(byte[] plainLogsBytes, PublicKey reEncryptionKey)
      throws CrumblesKeysException {
    LogMetadata logMetadata = assembleMetadata(plainLogsBytes.length + GCM_TAG_LEN_BYTES);
    byte[] aad =
        computeAssociatedData(logMetadata, KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC);
    EncryptedData encryptedData = encryptData(plainLogsBytes, aad, reEncryptionKey);
    return assembleCipherText(
        encryptedData.ciphertext,
        encryptedData.encryptedSymmetricKey,
        encryptedData.initializationVector,
        logMetadata);
  }
}
