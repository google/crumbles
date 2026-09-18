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
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
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
import java.security.GeneralSecurityException;
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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
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
  private static final OAEPParameterSpec OAEP_SPEC =
      new OAEPParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
  private static final String CIPHER_MODE_ASYM_PKCS1 = "RSA/ECB/PKCS1Padding";

  private static final String PROBE_KEY_ALIAS = "_oaep_probe_key_";
  private static final String OAEP_UNSUPPORTED_MESSAGE =
      "OAEP padding is not supported on this device. Defaulting to standard PKCS#1 padding.";
  private static volatile boolean isOaepPaddingDisabledInMemory = false;
  private static volatile Context applicationContext = null;

  /** Caches the application {@link Context}, or clears it when {@code context} is {@code null}. */
  public static void setApplicationContext(@Nullable Context context) {
    applicationContext = context != null ? context.getApplicationContext() : null;
  }

  @Nullable
  private static Context cacheAndResolveContext(@Nullable Context context) {
    if (context != null) {
      setApplicationContext(context);
    }
    return applicationContext;
  }

  private static boolean probeOaepSupport() {
    try {
      KeyPairGenerator keyPairGenerator =
          KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_PROVIDER);
      keyPairGenerator.initialize(
          new KeyGenParameterSpec.Builder(
                  PROBE_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setKeySize(ASYM_BITS)
              .setDigests(KeyProperties.DIGEST_SHA256)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
              .build());
      KeyPair probeKeyPair = keyPairGenerator.generateKeyPair();
      SecretKey probeKey = generateSecretKey();
      byte[] wrapped = wrapAesKey(probeKeyPair.getPublic(), probeKey, /* oaepDisabled= */ false);
      SecretKey unwrapped = unwrapAesKey(probeKeyPair.getPrivate(), wrapped);
      return Arrays.equals(probeKey.getEncoded(), unwrapped.getEncoded());
    } catch (GeneralSecurityException | CrumblesKeysException | RuntimeException e) {
      Log.w(TAG, "OAEP probe failed on this device.", e);
      return false;
    } finally {
      deleteExistingKeyPair(PROBE_KEY_ALIAS);
    }
  }

  private static void communicateOaepUnsupported(@Nullable Context context) {
    if (context == null) {
      return;
    }
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent("OAEP_UNSUPPORTED", "OAEP unsupported on this device; defaulted to PKCS#1.");
    new Handler(Looper.getMainLooper())
        .post(() -> Toast.makeText(context, OAEP_UNSUPPORTED_MESSAGE, Toast.LENGTH_LONG).show());
  }

  /**
   * Returns whether RSA-OAEP padding is disabled on the current device.
   *
   * <p>"Unsupported" means the Keystore lacks functional OAEP unwrapping, verified once via {@link
   * #probeOaepSupport()}. When unsupported, or when decryption fails, OAEP becomes "disabled" in
   * {@link SharedPreferences}, permanently falling back to {@code RSA/ECB/PKCS1Padding}.
   *
   * @param context the Android context to access preferences, or {@code null} for cached context
   * @return {@code true} if OAEP padding is disabled on this device; {@code false} if enabled
   */
  @CanIgnoreReturnValue
  public static boolean isOaepPaddingDisabled(@Nullable Context context) {
    Context resolvedContext = cacheAndResolveContext(context);
    if (resolvedContext == null) {
      return isOaepPaddingDisabledInMemory;
    }
    SharedPreferences preferences =
        resolvedContext.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
    if (!preferences.getBoolean(CrumblesConstants.PREF_OAEP_PROBED, false)) {
      probeAndEnableOaepPadding(resolvedContext);
      return isOaepPaddingDisabledInMemory;
    }
    isOaepPaddingDisabledInMemory =
        preferences.getBoolean(CrumblesConstants.PREF_OAEP_PADDING_DISABLED, false);
    return isOaepPaddingDisabledInMemory;
  }

  private static KeyEncryptionType getKeyEncryptionType(@Nullable Context context) {
    return isOaepPaddingDisabled(context)
        ? KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC
        : KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256;
  }

  /**
   * Enables RSA-OAEP padding if this device supports it, notifying the user via a toast and an
   * audit log entry otherwise, and persists the outcome.
   *
   * @param context the Android context to persist preferences, or {@code null} for cached context
   */
  public static void probeAndEnableOaepPadding(@Nullable Context context) {
    Context resolvedContext = cacheAndResolveContext(context);
    boolean supported = probeOaepSupport();
    if (!supported) {
      communicateOaepUnsupported(resolvedContext);
    }
    persistOaepPaddingDisabled(resolvedContext, !supported);
  }

  /** Disables RSA-OAEP padding on this device, permanently falling back to PKCS#1 v1.5 padding. */
  public static void disableOaepPadding(@Nullable Context context) {
    persistOaepPaddingDisabled(cacheAndResolveContext(context), /* disabled= */ true);
  }

  private static void persistOaepPaddingDisabled(@Nullable Context context, boolean disabled) {
    isOaepPaddingDisabledInMemory = disabled;
    if (context == null) {
      return;
    }
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(CrumblesConstants.PREF_OAEP_PROBED, true)
        .putBoolean(CrumblesConstants.PREF_OAEP_PADDING_DISABLED, disabled)
        .apply();
  }

  private void fallBackToPkcs1PaddingOnDevice() {
    Log.w(TAG, "OAEP decryption failed; falling back to PKCS#1 v1.5 padding on device.");
    disableOaepPadding(this.context);
    try {
      generateKeyPair(KEY_ALIAS, /* requireUserAuthentication= */ true);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to re-generate Keystore key pair with PKCS#1 padding.", e);
    }
  }

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
      boolean oaepDisabled = keyAlias.equals(KEY_ALIAS) && isOaepPaddingDisabled(this.context);
      KeyGenParameterSpec.Builder specBuilder =
          new KeyGenParameterSpec.Builder(
                  keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setKeySize(ASYM_BITS)
              .setEncryptionPaddings(
                  oaepDisabled
                      ? KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
                      : KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
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

  private static void deleteExistingKeyPair(String keyAlias) {
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

  /**
   * Encrypts data using a hybrid encryption scheme without Additional Authenticated Data.
   *
   * @param data the plaintext data to encrypt
   * @param encryptionKey the RSA public key to wrap the symmetric key
   * @return an {@link EncryptedData} object containing ciphertext, wrapped key, and IV
   * @throws CrumblesKeysException if an error occurs during encryption
   */
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
    byte[] encSymKey = wrapAesKey(encryptionKey, symKey, isOaepPaddingDisabled(this.context));
    return new EncryptedData(encryptedBytes, encSymKey, generatedIv.getIV());
  }

  /**
   * Encrypts plain logs using the provided public key and context for device attribution.
   *
   * @param context the Android context to resolve device ID from, or {@code null}
   * @param plainLogsBytes the plain log data
   * @param publicKey the specific public key to use for encryption
   * @return a {@link LogBatch} containing encrypted logs, or {@code null} if no key is available
   */
  @CanIgnoreReturnValue
  @Nullable
  public LogBatch encryptLogs(
      @Nullable Context context, byte[] plainLogsBytes, @Nullable PublicKey publicKey) {
    return encryptLogsInternal(
        plainLogsBytes, publicKey, CrumblesDeviceIdManager.getDeviceId(context));
  }

  /**
   * Encrypts log data and packages it into a {@link LogBatch} protobuf message bound with AAD.
   *
   * @param plainLogsBytes the plain log data to encrypt
   * @param publicKey the public key to use for encryption, or {@code null} to use Keystore
   * @return a {@link LogBatch} containing encrypted logs, or {@code null} if no key exists
   */
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
      KeyEncryptionType keyEncryptionType = getKeyEncryptionType(context);
      byte[] aad = computeAssociatedData(logMetadata, keyEncryptionType);

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
          logMetadata,
          keyEncryptionType);
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
    return decryptLogsBytes(logBatch);
  }

  /**
   * Decrypts an encrypted {@link LogBatch}, disabling OAEP on this device if unwrapping fails.
   *
   * @param context the Android context used to persist fallback state and notify the user
   * @param logBatch the encrypted log batch to decrypt
   * @return the decrypted plaintext log bytes
   * @throws CrumblesKeysException if the Keystore key cannot be loaded or decryption fails
   * @throws UserNotAuthenticatedException if the user must first authenticate
   */
  @CanIgnoreReturnValue
  public byte[] decryptLogs(Context context, LogBatch logBatch)
      throws CrumblesKeysException, UserNotAuthenticatedException {
    setApplicationContext(context);
    return decryptLogsBytes(logBatch);
  }

  private byte[] decryptLogsBytes(LogBatch logBatch)
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

      KeyEncryptionType keyEncryptionType = logBatch.getKey().getKeyEncryptionType();
      SecretKey decryptedSymKey =
          switch (keyEncryptionType) {
            case KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256 -> unwrapAesKey(privateKey, cipherSymKeyBytes);
            case KEY_ENCRYPTION_TYPE_ASYMMETRIC -> unwrapAesKeyPkcs1(privateKey, cipherSymKeyBytes);
            default ->
                throw new CrumblesLogsDecryptionException(
                    "A cryptographic error occurred during log decryption.", null);
          };
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
      if (logBatch.getKey().getKeyEncryptionType()
          == KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256) {
        fallBackToPkcs1PaddingOnDevice();
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
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LEN_BITS, ivSpec.getIV());
      aesCipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
      if (aad != null) {
        aesCipher.updateAAD(aad);
      }
      return aesCipher.doFinal(plainTextBytes);
    } catch (Exception e) {
      throw new CrumblesLogsEncryptionException("AES GCM encryption failed.", e);
    }
  }

  private static byte[] wrapAesKey(
      PublicKey publicKey, SecretKey symmetricKey, boolean oaepDisabled)
      throws CrumblesKeysException {
    try {
      Cipher cipher;
      if (oaepDisabled) {
        cipher = Cipher.getInstance(CIPHER_MODE_ASYM_PKCS1);
        cipher.init(Cipher.WRAP_MODE, publicKey);
      } else {
        cipher = Cipher.getInstance(CIPHER_MODE_ASYM);
        cipher.init(Cipher.WRAP_MODE, publicKey, OAEP_SPEC);
      }
      return cipher.wrap(symmetricKey);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to wrap AES key with public key.", e);
    }
  }

  private static SecretKey unwrapAesKey(PrivateKey privateKey, byte[] wrappedAesKeyBytes)
      throws CrumblesKeysException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_MODE_ASYM);
      cipher.init(Cipher.UNWRAP_MODE, privateKey, OAEP_SPEC);
      return (SecretKey) cipher.unwrap(wrappedAesKeyBytes, SYM_ALGORITHM, Cipher.SECRET_KEY);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to unwrap AES key with private key.", e);
    }
  }

  private static SecretKey unwrapAesKeyPkcs1(PrivateKey privateKey, byte[] wrappedAesKeyBytes)
      throws CrumblesKeysException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_MODE_ASYM_PKCS1);
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
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LEN_BITS, ivSpec.getIV());
      aesCipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
      if (aad != null) {
        aesCipher.updateAAD(aad);
      }
      return aesCipher.doFinal(cipherTextBytes);
    } catch (Exception e) {
      throw new CrumblesLogsDecryptionException("AES GCM decryption failed.", e);
    }
  }

  /**
   * Serializes a {@link LogBatch} protocol buffer to a file in the specified directory.
   *
   * @param toSerialize the {@link LogBatch} to write
   * @param baseDir the destination directory
   * @param fileName the target file name
   * @return the {@link Path} to the written file
   */
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

  /**
   * Deserializes a {@link LogBatch} protocol buffer from the specified file path.
   *
   * @param filePath the file path to read
   * @return the parsed {@link LogBatch}
   */
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
   * Assembles a {@link LogBatch} protobuf message with an explicit {@link KeyEncryptionType}.
   *
   * @param encryptedLogsBytes the encrypted log data blob
   * @param cipherSymKeyBytes the wrapped symmetric key bytes
   * @param cipherIvBytes the initialization vector bytes
   * @param logMetadata the metadata associated with the log batch
   * @param keyEncryptionType the key encryption type used to wrap the symmetric key
   * @return the assembled {@link LogBatch}
   */
  public static LogBatch assembleCipherText(
      byte[] encryptedLogsBytes,
      byte[] cipherSymKeyBytes,
      byte[] cipherIvBytes,
      LogMetadata logMetadata,
      KeyEncryptionType keyEncryptionType) {
    LogData logData =
        LogData.newBuilder().setLogBlob(ByteString.copyFrom(encryptedLogsBytes)).build();
    LogKey logKey =
        LogKey.newBuilder()
            .setKeyEncryptionType(keyEncryptionType)
            .setEncryptedSymmetricKey(ByteString.copyFrom(cipherSymKeyBytes))
            .setIv(ByteString.copyFrom(cipherIvBytes))
            .build();
    return LogBatch.newBuilder().setData(logData).setKey(logKey).setMetadata(logMetadata).build();
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
    return assembleCipherText(
        encryptedLogsBytes,
        cipherSymKeyBytes,
        cipherIvBytes,
        logMetadata,
        getKeyEncryptionType(/* context= */ null));
  }

  /**
   * Assembles a {@link LogBatch} protobuf message from ciphertext components with generated
   * metadata.
   *
   * @param encryptedLogsBytes the encrypted log data blob
   * @param cipherSymKeyBytes the wrapped symmetric key bytes
   * @param cipherIvBytes the initialization vector bytes
   * @param deviceId the device attribution identifier
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

  /**
   * Assembles a {@link LogBatch} protobuf message using the provided Android {@link Context} to
   * resolve device attribution and OAEP fallback configuration.
   *
   * @param context the Android context used for device ID attribution and preferences, or {@code
   *     null}
   * @param encryptedLogsBytes the encrypted log data blob
   * @param cipherSymKeyBytes the wrapped symmetric key bytes
   * @param cipherIvBytes the initialization vector bytes
   * @return the assembled {@link LogBatch}
   */
  public static LogBatch assembleCipherText(
      @Nullable Context context,
      byte[] encryptedLogsBytes,
      byte[] cipherSymKeyBytes,
      byte[] cipherIvBytes) {
    return assembleCipherText(
        encryptedLogsBytes,
        cipherSymKeyBytes,
        cipherIvBytes,
        assembleMetadata(encryptedLogsBytes.length, CrumblesDeviceIdManager.getDeviceId(context)),
        getKeyEncryptionType(context));
  }

  /**
   * Assembles a {@link LogBatch} protobuf message without an Android {@link Context}.
   *
   * <p><b>Note:</b> Calling this overload without a {@link Context} means {@link
   * CrumblesDeviceIdManager} cannot fall back to Android ID or a persisted UUID in {@link
   * SharedPreferences} if the hardware serial is inaccessible. Prefer {@link
   * #assembleCipherText(Context, byte[], byte[], byte[])}.
   *
   * @param encryptedLogsBytes the encrypted log data blob
   * @param cipherSymKeyBytes the wrapped symmetric key bytes
   * @param cipherIvBytes the initialization vector bytes
   * @return the assembled {@link LogBatch}
   */
  public static LogBatch assembleCipherText(
      byte[] encryptedLogsBytes, byte[] cipherSymKeyBytes, byte[] cipherIvBytes) {
    return assembleCipherText(
        /* context= */ null, encryptedLogsBytes, cipherSymKeyBytes, cipherIvBytes);
  }

  /**
   * Encrypts a plaintext byte array (a data store entry) using AES-GCM + RSA and returns the
   * encrypted payload.
   *
   * @param plaintext The plaintext byte array to encrypt.
   * @return The encrypted payload.
   * @throws CrumblesKeysException If encryption fails.
   */
  public EncryptedPayload encryptDataStoreEntry(byte[] plaintext) throws CrumblesKeysException {
    return encryptDataStoreEntry(plaintext, /* entryId= */ null);
  }

  /**
   * Encrypts a data store entry and binds it to the entry it is stored under.
   *
   * <p>The entry identifier is supplied as AES-GCM associated data. Without it, sealed entries are
   * interchangeable: anyone able to write the preferences file could move the payload of one entry
   * into another and the app would accept it, which would let an attacker substitute the key that
   * future log batches are encrypted to.
   *
   * @param plaintext the plaintext byte array to encrypt
   * @param entryId identifier of the entry this payload belongs to, or {@code null} to seal without
   *     binding
   * @return the encrypted payload
   * @throws CrumblesKeysException if encryption fails
   */
  public EncryptedPayload encryptDataStoreEntry(byte[] plaintext, @Nullable String entryId)
      throws CrumblesKeysException {
    PublicKey publicKey = getPublicKey(PREFERENCE_PRIMARY_KEY_ALIAS);
    if (publicKey == null) {
      publicKey = generateKeyPair(PREFERENCE_PRIMARY_KEY_ALIAS, false).getPublic();
    }
    EncryptedData encData = encryptData(plaintext, entryIdAsAssociatedData(entryId), publicKey);
    return EncryptedPayload.newBuilder()
        .setCiphertext(ByteString.copyFrom(encData.ciphertext))
        .setWrappedEncryptionKey(ByteString.copyFrom(encData.encryptedSymmetricKey))
        .setInitializationVector(ByteString.copyFrom(encData.initializationVector))
        .build();
  }

  /**
   * Decrypts an EncryptedPayload. It unwraps the AES key using the primary key from the Android
   * Keystore and then performs AES-GCM decryption.
   *
   * @param payload The encrypted payload to decrypt.
   * @return The original plaintext data.
   * @throws CrumblesKeysException If decryption fails due to key errors or data tampering.
   */
  public byte[] decryptData(EncryptedPayload payload) throws CrumblesKeysException {
    return decryptDataStoreEntryWithAad(payload, /* aad= */ null);
  }

  /**
   * Decrypts a data store entry that was sealed for {@code entryId}.
   *
   * <p>Entries written before entry binding was introduced carry no associated data. Those are
   * still accepted so that existing installations keep working, but they offer no guarantee that
   * the payload belongs to the entry it was read from.
   *
   * @param payload the encrypted payload to decrypt
   * @param entryId identifier of the entry the payload was read from
   * @return the original plaintext data
   * @throws CrumblesKeysException if decryption fails with and without the binding
   */
  public byte[] decryptDataStoreEntry(EncryptedPayload payload, String entryId)
      throws CrumblesKeysException {
    try {
      return decryptDataStoreEntryWithAad(payload, entryIdAsAssociatedData(entryId));
    } catch (CrumblesKeysException e) {
      Log.w(
          TAG,
          "Entry is not bound to its identifier; assuming it predates entry binding.");
      return decryptDataStoreEntryWithAad(payload, /* aad= */ null);
    }
  }

  @Nullable
  private static byte[] entryIdAsAssociatedData(@Nullable String entryId) {
    return entryId == null ? null : entryId.getBytes(UTF_8);
  }

  private byte[] decryptDataStoreEntryWithAad(EncryptedPayload payload, @Nullable byte[] aad)
      throws CrumblesKeysException {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      PrivateKey primaryPrivateKey =
          (PrivateKey) keyStore.getKey(PREFERENCE_PRIMARY_KEY_ALIAS, null);
      if (primaryPrivateKey == null) {
        throw new CrumblesKeysException("Failed to load primary private key from Keystore.");
      }

      SecretKey aesKey =
          unwrapAesKey(primaryPrivateKey, payload.getWrappedEncryptionKey().toByteArray());
      SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey.getEncoded(), SYM_ALGORITHM);

      byte[] ciphertext = payload.getCiphertext().toByteArray();
      IvParameterSpec iv = new IvParameterSpec(payload.getInitializationVector().toByteArray());

      return decryptUsingAes256Gcm(aesKeySpec, iv, aad, ciphertext);
    } catch (Exception e) {
      throw new CrumblesKeysException("Failed to perform AES-GCM decryption.", e);
    }
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

      SecretKey aesKey;
      try {
        aesKey = unwrapAesKey(primaryPrivateKey, wrappedKeyBytes);
      } catch (CrumblesKeysException e) {
        aesKey = unwrapAesKeyPkcs1(primaryPrivateKey, wrappedKeyBytes);
      }
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
        computeAssociatedData(logMetadata, KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
    EncryptedData encryptedData = encryptData(plainLogsBytes, aad, reEncryptionKey);
    return assembleCipherText(
        encryptedData.ciphertext,
        encryptedData.encryptedSymmetricKey,
        encryptedData.initializationVector,
        logMetadata);
  }
}
