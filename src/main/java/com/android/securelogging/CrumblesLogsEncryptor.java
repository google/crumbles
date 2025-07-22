package com.android.securelogging;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.lang.Math.min;

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
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.util.Timestamps;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.KeyEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogKey;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
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
  private static final int GCM_IV_LEN_BYTES = 12;

  @VisibleForTesting static final String ASYM_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;
  private static final String CIPHER_MODE_ASYM = "RSA/ECB/PKCS1Padding";
  private static final int ASYM_BITS = 2048;

  private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
  public static final String KEY_ALIAS = "com.android.securelogging.CrumblesRsaKeyAlias";
  public static final String PREFERENCE_MASTER_KEY_ALIAS =
      "com.android.securelogging.CrumblesPreferenceMasterKey";
  public static final String RE_ENCRYPT_KEY_ALIAS_PREFIX = "re_encrypt_";
  private static final String SERIALIZED_ENCRYPTED_DATA_DELIMITER = ":";

  private static final int AUTH_VALIDITY_SECONDS = 30;

  private PublicKey externalEncryptionPublicKey;

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

  @Nullable
  public PublicKey getPublicKey() {
    return getPublicKey(KEY_ALIAS);
  }

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

  public synchronized void setExternalEncryptionPublicKey(@Nullable PublicKey publicKey) {
    this.externalEncryptionPublicKey = publicKey;
    if (publicKey != null) {
      Log.d(TAG, "External public key has been set for encryption.");
      deleteExistingKeyPair();
    } else {
      Log.d(TAG, "Setting the external public key did not work.");
    }
  }

  @Nullable
  public synchronized PublicKey getExternalEncryptionPublicKey() {
    return this.externalEncryptionPublicKey;
  }

  @CanIgnoreReturnValue
  public synchronized KeyPair generateKeyPair() throws CrumblesKeysException {
    return generateKeyPair(KEY_ALIAS, true);
  }

  @CanIgnoreReturnValue
  public synchronized KeyPair generateKeyPair(String keyAlias, boolean requireUserAuthentication)
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
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
              .setUserAuthenticationRequired(requireUserAuthentication)
              .setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS);

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

  public synchronized void generateAndSetExternalKeyPair(PrivateKeyBytesConsumer consumer)
      throws CrumblesKeysException {
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

      this.setExternalEncryptionPublicKey(generatedPair.getPublic());
      deleteExistingKeyPair();
      Log.d(TAG, "New external key pair generated. Public key set for use.");

      byte[] privateKeyBytes = generatedPair.getPrivate().getEncoded();
      consumer.accept(privateKeyBytes);

    } catch (NoSuchAlgorithmException | RuntimeException e) {
      throw new CrumblesKeysException("Failed to generate external RSA key pair.", e);
    }
  }

  public EncryptedData encryptData(byte[] data, PublicKey encryptionKey)
      throws CrumblesKeysException {
    SecretKey symKey = generateSecretKey();
    IvParameterSpec generatedIv = generateAesGcmInitializationVector();
    byte[] encryptedBytes = encryptDataWithSymKey(symKey, generatedIv, data);
    byte[] encSymKey = wrapAesKey(encryptionKey, symKey);
    return new EncryptedData(encryptedBytes, encSymKey, generatedIv.getIV());
  }

  @CanIgnoreReturnValue
  @Nullable
  public LogBatch encryptLogs(byte[] plainLogsBytes) {
    try {
      String keySourceMessage;
      EncryptedData encryptedData;

      if (this.externalEncryptionPublicKey == null && !doesPrivateKeyExist()) {
        Log.e(TAG, "Encryption failed: No encryption key available.");
        return null;
      }

      if (this.externalEncryptionPublicKey != null) {
        encryptedData = encryptData(plainLogsBytes, this.externalEncryptionPublicKey);
        keySourceMessage = "Using external public key for encryption.";
      } else {
        encryptedData = encryptData(plainLogsBytes, getPublicKey());
        keySourceMessage = "Using Keystore public key for encryption.";
      }
      Log.d(TAG, keySourceMessage);

      return assembleCipherText(
          encryptedData.ciphertext,
          encryptedData.encryptedSymmetricKey,
          encryptedData.initializationVector);
    } catch (CrumblesKeysException | RuntimeException e) {
      Log.e(TAG, "Unexpected runtime error during encryption process.", e);
      throw new CrumblesLogsEncryptionException(
          "An unexpected error occurred during log encryption.", e);
    }
  }

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

      SecretKey decryptedSymKey = unwrapAesKey(privateKey, cipherSymKeyBytes);
      SecretKeySpec decryptedSymKeySpec =
          new SecretKeySpec(decryptedSymKey.getEncoded(), SYM_ALGORITHM);

      byte[] decryptedLogsBytes =
          decryptUsingAes256Gcm(
              decryptedSymKeySpec, new IvParameterSpec(cipherIvBytes), encryptedLogsBytes);
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
      SecretKey symKey, IvParameterSpec generatedIv, byte[] plainBytes) {
    SecretKeySpec symKeySpec = new SecretKeySpec(symKey.getEncoded(), SYM_ALGORITHM);
    return encryptUsingAes256Gcm(symKeySpec, generatedIv, plainBytes);
  }

  private static byte[] encryptUsingAes256Gcm(
      SecretKeySpec key, IvParameterSpec ivSpec, byte[] plainTextBytes) {
    try {
      Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec gcmParameterSpec =
          new GCMParameterSpec(GCM_IV_LEN_BYTES * 8, ivSpec.getIV());
      aesCipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
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
      SecretKeySpec key, IvParameterSpec ivSpec, byte[] cipherTextBytes) {
    try {
      Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec gcmParameterSpec =
          new GCMParameterSpec(GCM_IV_LEN_BYTES * 8, ivSpec.getIV());
      aesCipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
      return aesCipher.doFinal(cipherTextBytes);
    } catch (Exception e) {
      throw new CrumblesLogsDecryptionException("AES GCM decryption failed.", e);
    }
  }

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

  public static LogBatch assembleCipherText(
      byte[] encryptedLogsBytes, byte[] cipherSymKeyBytes, byte[] cipherIvBytes) {
    LogData logData =
        LogData.newBuilder().setLogBlob(ByteString.copyFrom(encryptedLogsBytes)).build();
    LogKey logKey =
        LogKey.newBuilder()
            .setKeyEncryptionType(KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC)
            .setEncryptedSymmetricKey(ByteString.copyFrom(cipherSymKeyBytes))
            .setIv(ByteString.copyFrom(cipherIvBytes))
            .build();
    DeviceId deviceId =
        DeviceId.newBuilder()
            .setDeviceId("123456789") // Placeholder
            .build();
    LogMetadata logMetadata =
        LogMetadata.newBuilder()
            .setBlobSize(encryptedLogsBytes.length)
            .setTimestamp(Timestamps.fromMillis(TimeSource.system().instant().toEpochMilli()))
            .setDevice(deviceId)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM)
            .build();
    return LogBatch.newBuilder().setData(logData).setKey(logKey).setMetadata(logMetadata).build();
  }

  @CanIgnoreReturnValue
  public String encryptDataStoreEntry(byte[] plaintext) throws CrumblesKeysException {
    PublicKey publicKey = getPublicKey(PREFERENCE_MASTER_KEY_ALIAS);
    if (publicKey == null) {
      publicKey = generateKeyPair(PREFERENCE_MASTER_KEY_ALIAS, false).getPublic();
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
      PrivateKey masterPrivateKey = (PrivateKey) keyStore.getKey(PREFERENCE_MASTER_KEY_ALIAS, null);
      if (masterPrivateKey == null) {
        throw new CrumblesKeysException("Failed to load master private key from Keystore.");
      }

      SecretKey aesKey = unwrapAesKey(masterPrivateKey, wrappedKeyBytes);
      SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), SYM_ALGORITHM);

      return decryptUsingAes256Gcm(aesKeySpec, new IvParameterSpec(ivBytes), ciphertext);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to perform AES-GCM decryption.", e);
    }
  }

  public List<PublicKey> getInternalReEncryptPublicKeys() {
    List<PublicKey> keys = new ArrayList<>();
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      Enumeration<String> aliases = keyStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (alias.startsWith(RE_ENCRYPT_KEY_ALIAS_PREFIX)) {
          PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
          if (publicKey != null) {
            keys.add(publicKey);
          }
        }
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to retrieve re-encryption keys from Keystore.", e);
    }
    return Collections.unmodifiableList(keys);
  }

  @Nullable
  public static String getPublicKeyAlias(PublicKey publicKey) {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      Enumeration<String> aliases = keyStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        Certificate cert = keyStore.getCertificate(alias);
        if (cert != null && cert.getPublicKey().equals(publicKey)) {
          return alias;
        }
      }
    } catch (Exception e) {
      Log.e(TAG, "Failed to get alias for public key.", e);
    }
    return null;
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
      String base64Key = CrumblesLogsEncryptor.publicKeyToBase64(key);
      if (base64Key != null && !base64Key.isEmpty()) {
        if (base64Key.length() > 20) {
          keyHash = "..." + base64Key.substring(base64Key.length() - 10);
        } else {
          keyHash = base64Key.substring(0, min(base64Key.length(), 10)) + "...";
        }
      }
    } catch (RuntimeException e) {
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
    try {
      byte[] decodedKey = Base64.getDecoder().decode(base64PublicKey);
      KeyFactory keyFactory = KeyFactory.getInstance(ASYM_ALGORITHM);
      return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to convert Base64 string to PublicKey.", e);
    }
  }

  public LogBatch reEncryptLogBatch(byte[] plainLogsBytes, PublicKey reEncryptionKey)
      throws CrumblesKeysException {
    EncryptedData encryptedData = encryptData(plainLogsBytes, reEncryptionKey);
    return assembleCipherText(
        encryptedData.ciphertext,
        encryptedData.encryptedSymmetricKey,
        encryptedData.initializationVector);
  }
}
