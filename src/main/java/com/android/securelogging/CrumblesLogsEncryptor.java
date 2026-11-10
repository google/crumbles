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
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.lang.Math.min;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyStoreException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsDecryptionException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.time.TimeSource;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Timestamp;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.DeviceId;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.KeyEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogKey;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.SealedLogs;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
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
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.BadPaddingException;
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
 * fingerprint, PIN) for decryption operations. Authentication is bound to a single operation: the
 * user has to approve every individual decryption through a {@code BiometricPrompt} carrying a
 * {@code CryptoObject} that wraps the {@link Cipher} being authorized. On Android 15 and higher,
 * such keys can also only be used while the device is unlocked. Encryption only needs the public
 * key, so log batches are still encrypted while the device is locked.
 */
public class CrumblesLogsEncryptor {
  private static final String TAG = "CrumblesLogsEncryptor";

  private static final String SYM_ALGORITHM = "AES";
  private static final int AES_KEY_SIZE_BITS = 256;
  @VisibleForTesting static final int GCM_IV_LEN_BYTES = 12;
  @VisibleForTesting static final int GCM_TAG_LEN_BITS = 128;
  @VisibleForTesting static final int GCM_TAG_LEN_BYTES = GCM_TAG_LEN_BITS / 8;

  /** Smallest padded size of the logs in a batch, so that small batches all look alike. */
  private static final int MIN_PADDED_LOGS_BYTES = 4096;

  /** Label at the start of the associated data of a format version 2 batch. */
  private static final String V2_ASSOCIATED_DATA_LABEL = "crumbles/v2/batch";

  @VisibleForTesting static final String ASYM_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;
  private static final String CIPHER_MODE_ASYM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
  private static final int ASYM_BITS = 2048;

  /**
   * Size of the key pairs generated for export, as CR-04.2 asks for 3072 or 4096 bits. Their
   * private key is handed over as a QR code of its Base64 encoding, which a 4096-bit key exceeds.
   */
  private static final int EXPORTABLE_KEY_BITS = 3072;

  private static final int MIN_RSA_MODULUS_BITS = 2048;
  private static final int FINGERPRINT_BYTES_PER_LINE = 8;
  private static final int MAX_RSA_MODULUS_BITS = 4096;
  private static final BigInteger EXPECTED_RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;
  private static final OAEPParameterSpec OAEP_SPEC =
      new OAEPParameterSpec(
          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
  private static final String CIPHER_MODE_ASYM_PKCS1 = "RSA/ECB/PKCS1Padding";

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

  /**
   * Authorizes MGF1 with SHA-256 for an RSA-OAEP key, as required by {@link #OAEP_SPEC}.
   *
   * <p>Since Android 15, Keystore only authorizes the MGF1 digests requested at key generation
   * (SHA-1 by default), so unwrapping with {@link #OAEP_SPEC} otherwise fails.
   */
  private static KeyGenParameterSpec.Builder authorizeOaepMgf1Sha256(
      KeyGenParameterSpec.Builder specBuilder) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
      return specBuilder;
    }
    return specBuilder.setMgf1Digests(KeyProperties.DIGEST_SHA256);
  }

  /**
   * Allows private key operations only while the device is unlocked, on Android 15 and higher.
   *
   * <p>Android 12 to 14 don't re-authorize these keys after an unlock with a non-strong biometric,
   * such as face unlock, or with a biometric in a profile that shares its parent's lock, which can
   * leave the key unusable.
   */
  private static KeyGenParameterSpec.Builder requireUnlockedDevice(
      KeyGenParameterSpec.Builder specBuilder) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
      return specBuilder;
    }
    return specBuilder.setUnlockedDeviceRequired(true);
  }

  private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

  /** Default alias for the RSA key pair. */
  public static final String KEY_ALIAS = "com.android.securelogging.CrumblesRsaKeyAlias";

  /** Alias for the primary key used to encrypt preferences. */
  public static final String PREFERENCE_PRIMARY_KEY_ALIAS =
      "com.android.securelogging.CrumblesPreferencePrimaryKey";

  private static final String SERIALIZED_ENCRYPTED_DATA_DELIMITER = ":";

  private static final Duration PER_OPERATION_AUTH_TIMEOUT = Duration.ZERO;
  private static final int ALLOWED_AUTHENTICATORS =
      KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL;

  /** Size of the authentication-bound keys in StrongBox, which only guarantees RSA-2048. */
  private static final int STRONGBOX_KEY_BITS = 2048;

  /** Size of the authentication-bound keys in the TEE, as CR-04.2 asks for 3072 bits. */
  private static final int TEE_KEY_BITS = 3072;

  private static final String AUDIT_EVENT_DECRYPTION_KEY_STORAGE = "KEYSTORE_KEY_STORAGE";
  private static final String PREF_KEY_PADDING_CACHE = "keystore_key_authorized_padding";
  private static final String CACHED_PADDING_OAEP_SUFFIX = ":OAEP";
  private static final String CACHED_PADDING_PKCS1_SUFFIX = ":PKCS1";

  private static final ConcurrentHashMap<String, Boolean> cachedKeyOaepSupport =
      new ConcurrentHashMap<>();

  @VisibleForTesting
  static void clearKeyPaddingCacheForTest() {
    cachedKeyOaepSupport.clear();
  }

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

  /**
   * Log batches grouped by the keys that can decrypt them, see {@link #partitionForBulkDecrypt}.
   *
   * @param batchUnwrappable batches whose symmetric keys {@link #unwrapBatchKeys} unwraps together,
   *     with one authorized {@link #createBatchUnwrapCipher() cipher}
   * @param rsaOnly batches without a usable batch-wrapped key, which only the Keystore RSA key may
   *     decrypt, one operation each: batches written before the batch-unwrap keys existed, or
   *     encrypted to an external key
   * @param undecryptable batches whose batch-unwrap keys were replaced after they were written.
   *     Those keys are only replaced together with the Keystore RSA key, so no key on this device
   *     can decrypt these batches.
   */
  record BulkDecryptPartition(
      ImmutableList<LogBatch> batchUnwrappable,
      ImmutableList<LogBatch> rsaOnly,
      ImmutableList<LogBatch> undecryptable) {}

  /**
   * The logs of a decrypted {@link LogBatch}.
   *
   * @param metadata the metadata of the batch, which for a format version 2 batch includes the
   *     timestamp and the device identifier sealed inside it
   */
  @SuppressWarnings("ArrayRecordComponent") // Callers wipe the logs in place.
  record DecryptedLogBatch(LogMetadata metadata, byte[] logs) {}

  /** getPublicKey method. */
  @Nullable
  public PublicKey getPublicKey() {
    return getPublicKey(KEY_ALIAS);
  }

  /** getPublicKey method. */
  @Nullable
  public PublicKey getPublicKey(String keyAlias) {
    try {
      return loadKeystorePublicKey(keyAlias).orElse(null);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to load public key from Android Keystore for alias: " + keyAlias, e);
      return null;
    }
  }

  private static Optional<PublicKey> loadKeystorePublicKey(String keyAlias)
      throws CrumblesKeysException {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      if (!keyStore.containsAlias(keyAlias)) {
        return Optional.empty();
      }
      return Optional.of(keyStore.getCertificate(keyAlias).getPublicKey());
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      throw new CrumblesKeysException(
          "Failed to load public key from Android Keystore for alias: " + keyAlias, e);
    }
  }

  public boolean doesPrivateKeyExist() {
    return getPublicKey() != null;
  }

  /**
   * Returns whether the Keystore permanently invalidated the private key of {@link #KEY_ALIAS} (for
   * example, after the secure lock screen is removed).
   */
  public boolean isPrivateKeyPermanentlyInvalidated() {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      if (keyStore.getKey(KEY_ALIAS, null) instanceof PrivateKey privateKey) {
        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        if (!keystoreKeySupportsOaep(KEY_ALIAS, publicKey)) {
          Cipher.getInstance(CIPHER_MODE_ASYM_PKCS1).init(Cipher.UNWRAP_MODE, privateKey);
        } else {
          Cipher.getInstance(CIPHER_MODE_ASYM).init(Cipher.UNWRAP_MODE, privateKey, OAEP_SPEC);
        }
      }
    } catch (KeyPermanentlyInvalidatedException e) {
      Log.e(TAG, "The Keystore permanently invalidated the private key. Deleting it.", e);
      deleteExistingKeyPair();
      return true;
    } catch (GeneralSecurityException | IOException | RuntimeException | CrumblesKeysException e) {
      Log.d(TAG, "The private key is not known to be invalidated.", e);
    }
    return false;
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
   * <p>If {@code requireUserAuthentication} is true, on Android 15 and higher the private key can
   * also only be used while the device is unlocked. Public key operations are not restricted.
   *
   * <p>A new {@link #KEY_ALIAS} key pair also gets new batch-unwrap keys, see {@link
   * CrumblesBatchKeyStore}.
   *
   * @param keyAlias the alias under which to store the key pair
   * @param requireUserAuthentication whether the key requires per-operation user authentication
   * @return the generated {@link KeyPair}
   * @throws CrumblesKeysException if the device has no screen lock or key generation fails
   */
  @CanIgnoreReturnValue
  public synchronized KeyPair generateKeyPair(String keyAlias, boolean requireUserAuthentication)
      throws CrumblesKeysException {
    if (requireUserAuthentication) {
      requireSecureLockScreen();
    }
    deleteExistingKeyPair(keyAlias);
    KeyPair keyPair;
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      Log.d(TAG, "Generating new RSA key pair into Android Keystore with alias: " + keyAlias);
      KeyGenParameterSpec.Builder specBuilder =
          new KeyGenParameterSpec.Builder(
                  keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setKeySize(ASYM_BITS)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
              .setDigests(KeyProperties.DIGEST_SHA256)
              .setUserAuthenticationRequired(requireUserAuthentication);
      if (requireUserAuthentication) {
        specBuilder
            .setUserAuthenticationParameters(
                (int) PER_OPERATION_AUTH_TIMEOUT.toSeconds(), ALLOWED_AUTHENTICATORS)
            // Device credentials remain valid across biometric enrollments, so Android Keystore
            // ignores biometric-enrollment invalidation when AUTH_DEVICE_CREDENTIAL is authorized.
            .setInvalidatedByBiometricEnrollment(false);
      }
      specBuilder = authorizeOaepMgf1Sha256(specBuilder);
      if (requireUserAuthentication) {
        specBuilder = requireUnlockedDevice(specBuilder);
        keyPair = generateDecryptionKeyPair(specBuilder);
      } else {
        keyPair = generateWithSpec(specBuilder);
      }
    } catch (Exception e) {
      throw new CrumblesKeysException(
          "Failed to generate or load key pair from Android Keystore for alias: " + keyAlias, e);
    }
    if (keyAlias.equals(KEY_ALIAS)) {
      cacheKeyOaepSupport(keyPair.getPublic(), /* supportsOaep= */ true);
      createBatchUnwrapKeys();
    }
    return keyPair;
  }

  /**
   * Generates an authentication-bound key pair in StrongBox as an RSA-2048 key or, if StrongBox
   * cannot create it, in the TEE as an RSA-3072 key, and records which in the activity log.
   */
  private KeyPair generateDecryptionKeyPair(KeyGenParameterSpec.Builder specBuilder)
      throws GeneralSecurityException {
    try {
      KeyPair keyPair =
          generateWithSpec(specBuilder.setKeySize(STRONGBOX_KEY_BITS).setIsStrongBoxBacked(true));
      recordDecryptionKeyStorage("in StrongBox (RSA-2048)");
      return keyPair;
    } catch (GeneralSecurityException | ProviderException e) {
      // StrongBoxUnavailableException without StrongBox, or any StrongBox failure when TEE works.
      Log.i(TAG, "StrongBox could not create the key pair; creating it in the TEE instead.", e);
    }
    KeyPair keyPair =
        generateWithSpec(specBuilder.setKeySize(TEE_KEY_BITS).setIsStrongBoxBacked(false));
    recordDecryptionKeyStorage("in the TEE (RSA-3072), as StrongBox could not create it");
    return keyPair;
  }

  private static KeyPair generateWithSpec(KeyGenParameterSpec.Builder specBuilder)
      throws GeneralSecurityException {
    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance(ASYM_ALGORITHM, ANDROID_KEYSTORE_PROVIDER);
    keyPairGenerator.initialize(specBuilder.build());
    return keyPairGenerator.generateKeyPair();
  }

  /** Records in the activity log where a new decryption key pair is kept. */
  private void recordDecryptionKeyStorage(String storage) {
    Context resolvedContext = cacheAndResolveContext(this.context);
    if (resolvedContext != null) {
      CrumblesAppAuditLogger.getInstance(resolvedContext)
          .logEvent(
              AUDIT_EVENT_DECRYPTION_KEY_STORAGE,
              "New decryption key pair generated " + storage + ".");
    }
  }

  /**
   * Creates the batch-unwrap keys of a new {@link #KEY_ALIAS} key pair. Batches are still written
   * without them, but each one then needs its own authentication to be read.
   */
  private void createBatchUnwrapKeys() {
    try {
      CrumblesBatchKeyStore.createKeys();
    } catch (CrumblesKeysException e) {
      Log.w(TAG, "Failed to create the batch-unwrap keys.", e);
      logBatchWrapFailure(
          "Batch-unwrap keys could not be created; each new log batch needs its own"
              + " authentication to be read.");
    }
  }

  private void requireSecureLockScreen() throws CrumblesKeysException {
    Context resolvedContext = cacheAndResolveContext(this.context);
    if (resolvedContext == null) {
      return;
    }
    KeyguardManager keyguardManager = resolvedContext.getSystemService(KeyguardManager.class);
    if (keyguardManager == null || !keyguardManager.isDeviceSecure()) {
      throw new CrumblesKeysException(
          "Cannot generate an authentication bound key: this device has no biometric, PIN, pattern"
              + " or password set up. Configure a screen lock and try again.");
    }
  }

  @VisibleForTesting
  void deleteExistingKeyPair() {
    deleteExistingKeyPair(KEY_ALIAS);
  }

  private static void deleteExistingKeyPair(String keyAlias) {
    if (keyAlias.equals(KEY_ALIAS)) {
      CrumblesBatchKeyStore.deleteKeys();
    }
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
   * Generates a new candidate external 3072-bit RSA key pair without activating it or mutating
   * current state.
   *
   * @return the newly generated candidate KeyPair
   * @throws CrumblesKeysException if key pair generation fails
   */
  public KeyPair generateCandidateExternalKeyPair() throws CrumblesKeysException {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYM_ALGORITHM);
      // The public exponent that publicKeyFromBase64() requires of imported keys.
      keyPairGenerator.initialize(
          new RSAKeyGenParameterSpec(EXPORTABLE_KEY_BITS, EXPECTED_RSA_PUBLIC_EXPONENT));
      KeyPair generatedPair = keyPairGenerator.generateKeyPair();

      if (generatedPair == null
          || generatedPair.getPublic() == null
          || generatedPair.getPrivate() == null) {
        throw new CrumblesKeysException(
            "Generated external KeyPair or its components are null.", null);
      }
      return generatedPair;
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | RuntimeException e) {
      throw new CrumblesKeysException("Failed to generate external RSA key pair.", e);
    }
  }

  /**
   * Commits and activates a candidate external public key for encryption.
   *
   * <p>The internal Keystore key pair, if any, is kept: batches already encrypted to it, including
   * any written while the candidate key waited for confirmation, must stay decryptable. It is only
   * replaced when a new internal key pair is generated.
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
    Log.d(TAG, "External public key committed and activated for encryption.");
  }

  /**
   * Generates a new external key pair, sets the public key for encryption, and passes the private
   * key to the provided consumer. Any internal Keystore key pair is kept, as in {@link
   * #commitExternalPublicKey}.
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
   * Computes the Additional Authenticated Data (AAD) for binding a {@link LogBatch}'s metadata, key
   * encryption parameters and recipient to the AES-GCM cipher payload.
   *
   * <p>For a format version 2 batch, the AAD starts with a label that no version 1 batch has, so
   * that associated data cannot be carried over from one format to the other. It ends with the
   * SHA-256 digest of the encoded {@code recipient}, the fingerprint that {@link
   * #getPublicKeyFingerprint} formats, so that the batch only decrypts as one encrypted to that
   * key: its symmetric key cannot be wrapped for another recipient without decryption failing.
   *
   * @param metadata the {@link LogMetadata} to authenticate
   * @param keyEncryptionType the {@link KeyEncryptionType} to authenticate
   * @param recipient the public key that wraps the symmetric key of the batch. Only format version
   *     2 batches bind it, so it may be {@code null} for the batches of earlier formats.
   * @return deterministic bytes representing the bound associated data
   * @throws IllegalArgumentException if {@code metadata} is that of a format version 2 batch and
   *     {@code recipient} is {@code null} or has no encoding
   */
  public static byte[] computeAssociatedData(
      LogMetadata metadata, KeyEncryptionType keyEncryptionType, @Nullable PublicKey recipient) {
    boolean isVersion2 =
        metadata
            .getEncryptionType()
            .equals(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA);
    byte[] recipientFingerprint = isVersion2 ? recipientFingerprint(recipient) : new byte[0];
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CodedOutputStream codedOutput = CodedOutputStream.newInstance(outputStream);
    // NOMUTANTS -- Scalar fields without maps serialize deterministically by default.
    codedOutput.useDeterministicSerialization();
    try {
      if (isVersion2) {
        codedOutput.writeRawBytes(V2_ASSOCIATED_DATA_LABEL.getBytes(UTF_8));
      }
      metadata.writeTo(codedOutput);
      codedOutput.writeEnumNoTag(keyEncryptionType.getNumber());
      codedOutput.writeRawBytes(recipientFingerprint);
      codedOutput.flush();
    } catch (IOException e) {
      throw new AssertionError("In-memory serialization to ByteArrayOutputStream failed", e);
    }
    return outputStream.toByteArray();
  }

  /**
   * Returns the SHA-256 digest of the encoded {@code recipient}, which a format version 2 batch
   * binds.
   *
   * @throws IllegalArgumentException if {@code recipient} is {@code null} or has no encoding, as a
   *     format version 2 batch without it would bind no recipient at all
   */
  private static byte[] recipientFingerprint(@Nullable PublicKey recipient) {
    byte[] encodedRecipient = recipient == null ? null : recipient.getEncoded();
    if (encodedRecipient == null) {
      throw new IllegalArgumentException(
          "A format version 2 batch is bound to its recipient, but no encoded recipient key was"
              + " given.");
    }
    try {
      return MessageDigest.getInstance("SHA-256").digest(encodedRecipient);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError("Every Java platform supports SHA-256.", e);
    }
  }

  public static LogMetadata assembleMetadata(int blobSize, String deviceId) {
    return sealedMetadata(deviceId).toBuilder()
        .setBlobSize(blobSize)
        .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM)
        .build();
  }

  public static LogMetadata assembleMetadata(int blobSize) {
    return assembleMetadata(blobSize, CrumblesDeviceIdManager.FALLBACK_DEVICE_ID);
  }

  /**
   * Returns the metadata that a format version 2 batch seals: the current time and {@code
   * deviceId}, or the fallback device identifier if {@code deviceId} is empty.
   */
  private static LogMetadata sealedMetadata(@Nullable String deviceId) {
    DeviceId deviceProto =
        DeviceId.newBuilder()
            .setDeviceId(
                isNullOrEmpty(deviceId) ? CrumblesDeviceIdManager.FALLBACK_DEVICE_ID : deviceId)
            .build();
    return LogMetadata.newBuilder()
        .setTimestamp(timestampFromMillis(TimeSource.system().instant().toEpochMilli()))
        .setDevice(deviceProto)
        .build();
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
   * <p>The symmetric key is wrapped with RSA-OAEP, unless {@code encryptionKey} is a device
   * Keystore key that an earlier version of the app created for PKCS#1 v1.5 padding only.
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
    return encryptData(
        generateSecretKey(), data, aad, encryptionKey, wrapsWithPkcs1(encryptionKey));
  }

  private EncryptedData encryptData(
      SecretKey symKey,
      byte[] data,
      @Nullable byte[] aad,
      PublicKey encryptionKey,
      boolean oaepDisabled)
      throws CrumblesKeysException {
    IvParameterSpec generatedIv = generateAesGcmInitializationVector();
    byte[] encryptedBytes = encryptDataWithSymKey(symKey, generatedIv, aad, data);
    byte[] encSymKey = wrapAesKey(encryptionKey, symKey, oaepDisabled);
    return new EncryptedData(encryptedBytes, encSymKey, generatedIv.getIV());
  }

  /**
   * Returns whether symmetric keys wrapped for {@code recipient} must use PKCS#1 v1.5 padding.
   *
   * <p>Every key pair this version generates is authorized for RSA-OAEP only. Earlier versions
   * created the device key for PKCS#1 v1.5 padding when a faulty capability probe reported that
   * OAEP was unsupported. Such a key keeps receiving PKCS#1 v1.5 wraps, the only ones it can
   * unwrap, until a new device key replaces it. Every other recipient is wrapped with RSA-OAEP.
   */
  private boolean wrapsWithPkcs1(PublicKey recipient) throws CrumblesKeysException {
    return isDeviceKey(recipient) && !keystoreKeySupportsOaep(KEY_ALIAS, recipient);
  }

  /** Returns whether {@code recipient} is the public key of the device Keystore key. */
  private static boolean isDeviceKey(PublicKey recipient) throws CrumblesKeysException {
    Optional<PublicKey> deviceKey = loadKeystorePublicKey(KEY_ALIAS);
    return deviceKey.isPresent()
        && Arrays.equals(recipient.getEncoded(), deviceKey.get().getEncoded());
  }

  /**
   * Returns whether the Keystore key needs its own authentication for each operation, as the keys
   * that {@link #generateKeyPair()} creates do, rather than opening a time window. Returns false if
   * there is no such key. Returns true if its authorizations cannot be read, as on some OEM builds,
   * because only a prompt of its own authorizes a key that {@link #generateKeyPair()} created.
   */
  public boolean isKeystoreKeyBoundToEachOperation() {
    if (!doesPrivateKeyExist()) {
      return false;
    }
    KeyInfo keyInfo = readKeystoreKeyInfo(KEY_ALIAS);
    return keyInfo == null
        || (keyInfo.isUserAuthenticationRequired()
            && keyInfo.getUserAuthenticationValidityDurationSeconds() <= 0);
  }

  /** Returns the authorizations of the Keystore key under {@code alias}, or null if unavailable. */
  @Nullable
  private static KeyInfo readKeystoreKeyInfo(String alias) {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      Key key = keyStore.getKey(alias, null);
      return key == null
          ? null
          : KeyFactory.getInstance(ASYM_ALGORITHM, ANDROID_KEYSTORE_PROVIDER)
              .getKeySpec(key, KeyInfo.class);
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      // Keystore implementations on some OEM builds throw unchecked exceptions (such as
      // ProviderException) when reading key characteristics.
      Log.w(TAG, "Failed to read the authorizations of a Keystore key.", e);
      return null;
    }
  }

  /**
   * Returns whether the Keystore key under {@code alias} with {@code publicKey} is authorized for
   * RSA-OAEP padding, consulting the fingerprint-keyed padding cache before reading {@link
   * KeyInfo}.
   *
   * @throws CrumblesKeysException if neither the cache nor {@link KeyInfo} can determine the key's
   *     authorized padding
   */
  private boolean keystoreKeySupportsOaep(String alias, PublicKey publicKey)
      throws CrumblesKeysException {
    String fingerprint = getPublicKeyFingerprint(publicKey);
    Boolean cached = lookupCachedKeyOaepSupport(fingerprint);
    if (cached != null) {
      return cached;
    }
    KeyInfo keyInfo = readKeystoreKeyInfo(alias);
    if (keyInfo == null) {
      throw new CrumblesKeysException(
          "Failed to read the paddings authorized for Keystore alias: " + alias);
    }
    boolean supportsOaep =
        Arrays.asList(keyInfo.getEncryptionPaddings())
            .contains(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
    cacheKeyOaepSupport(publicKey, supportsOaep);
    return supportsOaep;
  }

  private void cacheKeyOaepSupport(PublicKey publicKey, boolean supportsOaep)
      throws CrumblesKeysException {
    String fingerprint = getPublicKeyFingerprint(publicKey);
    cachedKeyOaepSupport.put(fingerprint, supportsOaep);
    Context resolvedContext = cacheAndResolveContext(this.context);
    if (resolvedContext != null) {
      String encodedVerdict =
          fingerprint + (supportsOaep ? CACHED_PADDING_OAEP_SUFFIX : CACHED_PADDING_PKCS1_SUFFIX);
      resolvedContext
          .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
          .edit()
          .putString(PREF_KEY_PADDING_CACHE, encodedVerdict)
          .apply();
    }
  }

  @Nullable
  private Boolean lookupCachedKeyOaepSupport(String fingerprint) {
    Boolean inMemory = cachedKeyOaepSupport.get(fingerprint);
    if (inMemory != null) {
      return inMemory;
    }
    Context resolvedContext = cacheAndResolveContext(this.context);
    if (resolvedContext == null) {
      return null;
    }
    String stored =
        resolvedContext
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(PREF_KEY_PADDING_CACHE, /* defValue= */ null);
    if ((fingerprint + CACHED_PADDING_OAEP_SUFFIX).equals(stored)) {
      return true;
    }
    if ((fingerprint + CACHED_PADDING_PKCS1_SUFFIX).equals(stored)) {
      return false;
    }
    return null;
  }

  /**
   * Encrypts plain logs of this installation using the provided public key and context for device
   * attribution. The batch seals the attestation chain of this installation's batch-signing key,
   * creating that key if there is none, for {@link CrumblesBatchSigner} to sign the batch.
   *
   * @param context the Android context to resolve the device ID and the batch-signing key from, or
   *     {@code null} to seal no attestation chain
   * @param plainLogsBytes the plain log data
   * @param publicKey the specific public key to use for encryption
   * @return a {@link LogBatch} containing encrypted logs, or {@code null} if no key is available
   */
  @CanIgnoreReturnValue
  @Nullable
  public LogBatch encryptLogs(
      @Nullable Context context, byte[] plainLogsBytes, @Nullable PublicKey publicKey) {
    if (context != null) {
      setApplicationContext(context);
    }
    return encryptLogsInternal(
        plainLogsBytes, publicKey, CrumblesDeviceIdManager.getDeviceId(context), context);
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
    return encryptLogs(cacheAndResolveContext(this.context), plainLogsBytes, publicKey);
  }

  /**
   * As {@link #encryptLogs(byte[], PublicKey)}, but seals {@code deviceId} in the batch instead of
   * this device's ID, such as the ID of the device that wrote the batch the logs were decrypted
   * from. The batch stays unsigned, so it seals no attestation chain and creates no batch-signing
   * key.
   */
  @Nullable
  LogBatch encryptLogsAttributedTo(
      String deviceId, byte[] plainLogsBytes, @Nullable PublicKey publicKey) {
    return encryptLogsInternal(plainLogsBytes, publicKey, deviceId, /* signingContext= */ null);
  }

  /**
   * Encrypts {@code plainLogsBytes} for {@code publicKey}, or the Keystore key when it is null.
   *
   * @param signingContext the context of the installation that will sign the batch, whose
   *     batch-signing key's attestation chain the batch seals, or {@code null} for a batch that
   *     stays unsigned
   * @return the batch, or {@code null} if there is no key to encrypt to
   */
  @Nullable
  private LogBatch encryptLogsInternal(
      byte[] plainLogsBytes,
      @Nullable PublicKey publicKey,
      String deviceId,
      @Nullable Context signingContext) {
    try {
      PublicKey recipient =
          publicKey != null ? publicKey : loadKeystorePublicKey(KEY_ALIAS).orElse(null);
      if (recipient == null) {
        Log.e(TAG, "Encryption failed: No encryption key available.");
        return null;
      }
      Log.d(
          TAG,
          publicKey != null
              ? "Using provided public key for encryption."
              : "Using Keystore public key for encryption.");

      KeyEncryptionType keyEncryptionType =
          wrapsWithPkcs1(recipient)
              ? KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC
              : KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256;
      return encryptLogBatch(
          plainLogsBytes,
          recipient,
          deviceId,
          keyEncryptionType,
          batchSigningKeyAttestationChain(signingContext));
    } catch (CrumblesKeysException | RuntimeException e) {
      Log.e(TAG, "Unexpected runtime error during encryption process.", e);
      throw new CrumblesLogsEncryptionException(
          "An unexpected error occurred during log encryption.", e);
    }
  }

  /**
   * Encrypts {@code plainLogsBytes} into a format version 2 {@link LogBatch} for {@code recipient}:
   * a {@link SealedLogs} that holds the logs, the current time, {@code deviceId} and {@code
   * attestationChain}, padded to its size bucket and bound to {@code recipient} by its associated
   * data. A batch for the device Keystore key also carries its symmetric key wrapped with the
   * batch-wrap key.
   *
   * @param attestationChain the attestation chain of this installation's batch-signing key for a
   *     batch that it will sign, or an empty list for a batch that stays unsigned
   */
  private LogBatch encryptLogBatch(
      byte[] plainLogsBytes,
      PublicKey recipient,
      @Nullable String deviceId,
      KeyEncryptionType keyEncryptionType,
      ImmutableList<ByteString> attestationChain)
      throws CrumblesKeysException {
    SealedLogs sealedLogs =
        SealedLogs.newBuilder()
            .setMetadata(sealedMetadata(deviceId))
            .setLogs(ByteString.copyFrom(plainLogsBytes))
            .addAllAttestationChain(attestationChain)
            .build();
    byte[] paddedLogs = padToSizeBucket(sealedLogs.toByteArray());
    LogMetadata logMetadata =
        LogMetadata.newBuilder()
            .setBlobSize(paddedLogs.length + GCM_TAG_LEN_BYTES)
            .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA)
            .build();
    SecretKey symKey = generateSecretKey();
    EncryptedData encryptedData =
        encryptData(
            symKey,
            paddedLogs,
            computeAssociatedData(logMetadata, keyEncryptionType, recipient),
            recipient,
            keyEncryptionType == KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC);
    LogBatch logBatch =
        assembleCipherText(
            encryptedData.ciphertext,
            encryptedData.encryptedSymmetricKey,
            encryptedData.initializationVector,
            logMetadata,
            keyEncryptionType);
    return isDeviceKey(recipient) ? addBatchWrappedKey(logBatch, symKey) : logBatch;
  }

  /**
   * Returns the attestation chain of the batch-signing key of the installation that {@code
   * signingContext} belongs to, for a format version 2 batch that it will sign to seal, as {@link
   * CrumblesBatchSigner} leaves the chain out of the cleartext signature. Reading the chain creates
   * the key if the installation has none.
   *
   * <p>Returns an empty list without a context, so that a batch that stays unsigned neither seals a
   * chain nor creates a key, and if the chain cannot be read, as on devices without key
   * attestation: the batch is then still written, without the chain that its recipient needs to
   * check a signature.
   */
  private static ImmutableList<ByteString> batchSigningKeyAttestationChain(
      @Nullable Context signingContext) {
    if (signingContext == null) {
      return ImmutableList.of();
    }
    try {
      return new CrumblesBatchSigningKey(signingContext).attestationChain();
    } catch (CrumblesKeysException | RuntimeException e) {
      // Sealing the chain must never keep the logs from being written, and Keystore on some OEM
      // builds throws unchecked exceptions other than the ProviderException that
      // attestationChain() reports as CrumblesKeysException.
      Log.w(TAG, "Failed to read the attestation chain of the batch-signing key.", e);
      return ImmutableList.of();
    }
  }

  /**
   * Adds {@code symKey}, wrapped with the batch-wrap key, to {@code logBatch}, so that one
   * authentication can unwrap it together with the keys of other batches. Without batch-unwrap
   * keys, or if wrapping fails, the batch keeps only its RSA-wrapped key.
   */
  private LogBatch addBatchWrappedKey(LogBatch logBatch, SecretKey symKey) {
    if (!CrumblesBatchKeyStore.hasKeys()) {
      return logBatch;
    }
    CrumblesBatchKeyStore.WrappedKey wrappedKey;
    try {
      wrappedKey = CrumblesBatchKeyStore.wrap(symKey);
    } catch (CrumblesKeysException e) {
      Log.w(TAG, "Failed to wrap a batch key with the batch-wrap key.", e);
      logBatchWrapFailure(
          "A log batch was written without its batch-wrapped key; reading it needs its own"
              + " authentication.");
      return logBatch;
    }
    return logBatch.toBuilder()
        .setKey(
            logBatch.getKey().toBuilder()
                .setBatchWrappedSymmetricKey(wrappedKey.wrappedKey())
                .setBatchWrapKeyId(wrappedKey.keyId()))
        .build();
  }

  private void logBatchWrapFailure(String message) {
    Context resolvedContext = cacheAndResolveContext(this.context);
    if (resolvedContext != null) {
      CrumblesAppAuditLogger.getInstance(resolvedContext).logEvent("BATCH_WRAP_FAILED", message);
    }
  }

  /**
   * Creates an initialized {@link Cipher} to unwrap the symmetric key of {@code logBatch} via a
   * {@code BiometricPrompt.CryptoObject}.
   */
  public Cipher createUnwrapCipher(LogBatch logBatch) throws CrumblesKeysException {
    PrivateKey privateKey = loadKeystorePrivateKey();
    boolean usesPkcs1Padding =
        logBatch.getKey().getKeyEncryptionType()
            == KeyEncryptionType.KEY_ENCRYPTION_TYPE_ASYMMETRIC;
    Cipher cipher;
    try {
      if (usesPkcs1Padding) {
        cipher = Cipher.getInstance(CIPHER_MODE_ASYM_PKCS1);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
      } else {
        cipher = Cipher.getInstance(CIPHER_MODE_ASYM);
        cipher.init(Cipher.UNWRAP_MODE, privateKey, OAEP_SPEC);
      }
    } catch (GeneralSecurityException e) {
      throw new CrumblesKeysException("Failed to initialize the unwrap cipher.", e);
    }
    return cipher;
  }

  private static PrivateKey loadKeystorePrivateKey() throws CrumblesKeysException {
    PrivateKey privateKey;
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
    } catch (GeneralSecurityException | IOException e) {
      throw new CrumblesKeysException(
          "Failed to load key pair from Android Keystore for decryption.", e);
    }
    if (privateKey == null) {
      throw new CrumblesKeysException(
          "Failed to load key pair from Android Keystore for decryption.", null);
    }
    return privateKey;
  }

  /**
   * Decrypts a {@link LogBatch} protobuf message using the Keystore private key and validates AAD.
   *
   * <p>A batch that cannot be unwrapped (wrong key or corrupt file) fails with a decryption error
   * and never changes the Keystore key.
   *
   * @param logBatch the {@link LogBatch} containing ciphertext, wrapped symmetric key, and metadata
   * @return the decrypted log bytes
   * @throws CrumblesKeysException if the private key cannot be accessed or loaded
   * @throws UserNotAuthenticatedException if user authentication is required
   */
  @CanIgnoreReturnValue
  public byte[] decryptLogs(LogBatch logBatch)
      throws CrumblesKeysException, UserNotAuthenticatedException {
    return decryptLogBatch(logBatch).logs();
  }

  /**
   * Decrypts a {@link LogBatch} protobuf message and validates AAD, unwrapping the symmetric key
   * with {@code authorizedUnwrapCipher} (or the Keystore private key if {@code null}).
   */
  @CanIgnoreReturnValue
  public byte[] decryptLogs(LogBatch logBatch, @Nullable Cipher authorizedUnwrapCipher)
      throws CrumblesKeysException, UserNotAuthenticatedException {
    return decryptLogBatch(logBatch, authorizedUnwrapCipher).logs();
  }

  /**
   * Decrypts {@code logBatch} as {@link #decryptLogs} does and returns its logs with its metadata,
   * which for a format version 2 batch includes the timestamp and the device identifier sealed
   * inside it.
   */
  DecryptedLogBatch decryptLogBatch(LogBatch logBatch)
      throws CrumblesKeysException, UserNotAuthenticatedException {
    return decryptLogBatch(logBatch, /* authorizedUnwrapCipher= */ null);
  }

  /**
   * Decrypts {@code logBatch} as {@link #decryptLogs(LogBatch, Cipher)} does and returns its logs
   * with its metadata, as {@link #decryptLogBatch(LogBatch)} does. A format version 2 batch must be
   * bound to the Keystore public key by its associated data.
   */
  DecryptedLogBatch decryptLogBatch(LogBatch logBatch, @Nullable Cipher authorizedUnwrapCipher)
      throws CrumblesKeysException, UserNotAuthenticatedException {
    PublicKey recipient = getPublicKey();
    if (recipient == null) {
      throw new CrumblesKeysException(
          "Private key not available in Keystore for decryption.", null);
    }
    PrivateKey privateKey = authorizedUnwrapCipher == null ? loadKeystorePrivateKey() : null;

    try {
      byte[] encryptedLogsBytes = logBatch.getData().getLogBlob().toByteArray();
      byte[] cipherSymKeyBytes = logBatch.getKey().getEncryptedSymmetricKey().toByteArray();
      byte[] cipherIvBytes = logBatch.getKey().getIv().toByteArray();
      byte[] aad =
          computeAssociatedData(
              logBatch.getMetadata(), logBatch.getKey().getKeyEncryptionType(), recipient);

      KeyEncryptionType keyEncryptionType = logBatch.getKey().getKeyEncryptionType();
      SecretKey decryptedSymKey =
          switch (keyEncryptionType) {
            case KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256 ->
                authorizedUnwrapCipher == null
                    ? unwrapAesKey(privateKey, cipherSymKeyBytes)
                    : unwrapAesKey(authorizedUnwrapCipher, cipherSymKeyBytes);
            case KEY_ENCRYPTION_TYPE_ASYMMETRIC ->
                authorizedUnwrapCipher == null
                    ? unwrapAesKeyPkcs1(privateKey, cipherSymKeyBytes)
                    : unwrapAesKey(authorizedUnwrapCipher, cipherSymKeyBytes);
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
      return decryptedLogBatch(logBatch.getMetadata(), decryptedLogsBytes);
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

  /**
   * Groups {@code logBatches} by the keys that can decrypt them, so that one authentication covers
   * every batch whose key the current batch-unwrap key can unwrap. Each group keeps the order of
   * {@code logBatches}.
   */
  BulkDecryptPartition partitionForBulkDecrypt(List<LogBatch> logBatches) {
    Optional<ByteString> batchWrapKeyId = currentBatchWrapKeyId();
    ImmutableList.Builder<LogBatch> batchUnwrappable = ImmutableList.builder();
    ImmutableList.Builder<LogBatch> rsaOnly = ImmutableList.builder();
    ImmutableList.Builder<LogBatch> undecryptable = ImmutableList.builder();
    for (LogBatch logBatch : logBatches) {
      LogKey key = logBatch.getKey();
      if (!carriesBatchWrappedKey(key) || batchWrapKeyId.isEmpty()) {
        rsaOnly.add(logBatch);
      } else if (key.getBatchWrapKeyId().equals(batchWrapKeyId.get())) {
        batchUnwrappable.add(logBatch);
      } else {
        undecryptable.add(logBatch);
      }
    }
    return new BulkDecryptPartition(
        batchUnwrappable.build(), rsaOnly.build(), undecryptable.build());
  }

  /**
   * Returns the id of the current batch-wrap key, or empty if the batch-unwrap keys are missing or
   * unusable. Batches are then left to the RSA key rather than reported as undecryptable.
   */
  private static Optional<ByteString> currentBatchWrapKeyId() {
    if (!CrumblesBatchKeyStore.hasKeys()) {
      return Optional.empty();
    }
    try {
      return Optional.of(CrumblesBatchKeyStore.keyId());
    } catch (CrumblesKeysException e) {
      Log.w(TAG, "Failed to compute the id of the batch-wrap key.", e);
      return Optional.empty();
    }
  }

  /**
   * Returns whether {@code key} carries a key id and a batch-wrapped key in the format that {@link
   * #unwrapBatchKeys} takes.
   */
  private static boolean carriesBatchWrappedKey(LogKey key) {
    return key.hasBatchWrapKeyId()
        && key.getBatchWrappedSymmetricKey().size() == CrumblesBatchKeyStore.WRAPPED_KEY_SIZE_BYTES;
  }

  /**
   * Returns the cipher that {@link #unwrapBatchKeys} needs, for a {@code BiometricPrompt} to
   * authorize through a {@code CryptoObject}.
   *
   * @throws CrumblesKeysException if the cipher cannot be initialized
   */
  Cipher createBatchUnwrapCipher() throws CrumblesKeysException {
    return CrumblesBatchKeyStore.createUnwrapCipher();
  }

  /**
   * Unwraps the symmetric keys of {@code batchUnwrappable}, in order, in the one operation of
   * {@code authorizedCipher} that the user authorized.
   *
   * @param authorizedCipher a cipher from {@link #createBatchUnwrapCipher}, used up by this call
   * @param batchUnwrappable batches from {@link BulkDecryptPartition#batchUnwrappable}
   * @throws CrumblesKeysException if the operation fails, as when it was not authorized
   */
  ImmutableList<SecretKey> unwrapBatchKeys(Cipher authorizedCipher, List<LogBatch> batchUnwrappable)
      throws CrumblesKeysException {
    return CrumblesBatchKeyStore.unwrap(
        authorizedCipher,
        batchUnwrappable.stream()
            .map(logBatch -> logBatch.getKey().getBatchWrappedSymmetricKey())
            .collect(toImmutableList()));
  }

  /**
   * Decrypts {@code logBatch} with its symmetric key from {@link #unwrapBatchKeys}, validates its
   * AAD and returns its logs with its metadata, as {@link #decryptLogBatch} does. Batch-wrapped
   * keys only go with batches for the Keystore key, so a format version 2 batch must be bound to
   * the Keystore public key by its associated data.
   *
   * @throws CrumblesLogsDecryptionException if the key does not decrypt the batch, as when the
   *     batch or its batch-wrapped key was modified, or if the Keystore public key that the batch
   *     is bound to is not available. Its RSA-wrapped key may still decrypt it.
   */
  DecryptedLogBatch decryptLogsWithSymmetricKey(LogBatch logBatch, SecretKey symmetricKey) {
    PublicKey recipient = getPublicKey();
    if (recipient == null) {
      throw new CrumblesLogsDecryptionException(
          "The Keystore public key that log batches are bound to is not available.", null);
    }
    LogKey key = logBatch.getKey();
    return decryptedLogBatch(
        logBatch.getMetadata(),
        decryptUsingAes256Gcm(
            symmetricKey,
            new IvParameterSpec(key.getIv().toByteArray()),
            computeAssociatedData(logBatch.getMetadata(), key.getKeyEncryptionType(), recipient),
            logBatch.getData().getLogBlob().toByteArray()));
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

  private static SecretKey unwrapAesKey(Cipher authorizedUnwrapCipher, byte[] wrappedAesKeyBytes)
      throws CrumblesKeysException {
    try {
      return (SecretKey)
          authorizedUnwrapCipher.unwrap(wrappedAesKeyBytes, SYM_ALGORITHM, Cipher.SECRET_KEY);
    } catch (GeneralSecurityException e) {
      throw new CrumblesKeysException("Failed to unwrap AES key with private key.", e);
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
      SecretKey key, IvParameterSpec ivSpec, @Nullable byte[] aad, byte[] cipherTextBytes) {
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
   * Atomically serializes a {@link LogBatch} protocol buffer to a file in the specified directory.
   *
   * <p>The batch is written and synced to a uniquely named {@link
   * CrumblesConstants#TEMP_FILE_SUFFIX} sibling, which is then atomically moved to {@code
   * fileName}. Readers therefore never observe a partially written batch, and an existing file of
   * that name is only replaced once the new content is durable.
   *
   * @param toSerialize the {@link LogBatch} to write
   * @param baseDir the destination directory
   * @param fileName the target file name
   * @return the {@link Path} to the written file
   */
  public Path serializeBytes(LogBatch toSerialize, File baseDir, String fileName) {
    Path filePath = Path.of(baseDir.getAbsolutePath(), fileName);
    Path tempFilePath =
        filePath.resolveSibling(
            fileName + "." + UUID.randomUUID() + CrumblesConstants.TEMP_FILE_SUFFIX);
    try {
      writeAndSync(toSerialize, tempFilePath);
      moveAtomically(tempFilePath, filePath);
    } catch (IOException e) {
      throw new CrumblesLogsEncryptionException("Failed to serialize bytes to file.", e);
    } finally {
      deleteTempFileIfPresent(tempFilePath);
    }
    Log.d(TAG, "Bytes serialized to file: " + filePath);
    return filePath;
  }

  private static void writeAndSync(LogBatch toSerialize, Path tempFilePath) throws IOException {
    try (FileChannel channel =
        FileChannel.open(tempFilePath, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
      toSerialize.writeTo(Channels.newOutputStream(channel));
      channel.force(/* metaData= */ true);
    }
  }

  private static void moveAtomically(Path source, Path target) throws IOException {
    try {
      Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException e) {
      Log.w(TAG, "Atomic move unsupported; replacing " + target + " non-atomically.", e);
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static void deleteTempFileIfPresent(Path tempFilePath) {
    try {
      Files.deleteIfExists(tempFilePath);
    } catch (IOException e) {
      Log.e(TAG, "Failed to delete temporary file: " + tempFilePath, e);
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
        KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
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
   * resolve device attribution.
   *
   * @param context the Android context used for device ID attribution, or {@code null}
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
        KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256);
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
    } else if (isPrimaryKeyPermanentlyUnusable(publicKey)) {
      publicKey = replaceUnusablePrimaryKey();
    }
    EncryptedData encData = encryptData(plaintext, entryIdAsAssociatedData(entryId), publicKey);
    return EncryptedPayload.newBuilder()
        .setCiphertext(ByteString.copyFrom(encData.ciphertext))
        .setWrappedEncryptionKey(ByteString.copyFrom(encData.encryptedSymmetricKey))
        .setInitializationVector(ByteString.copyFrom(encData.initializationVector))
        .build();
  }

  /**
   * Returns whether the primary key can no longer unwrap a key wrapped with its own public key.
   *
   * <p>On Android 15 and later, the Keystore refuses RSA-OAEP unwrapping with keys created without
   * an MGF1-SHA-256 authorization, so every entry sealed to such a key is unreadable. Transient
   * failures do not count: replacing the key then would destroy entries that are still readable.
   */
  private static boolean isPrimaryKeyPermanentlyUnusable(PublicKey primaryPublicKey) {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
      keyStore.load(null);
      if (!(keyStore.getKey(PREFERENCE_PRIMARY_KEY_ALIAS, null) instanceof PrivateKey privateKey)) {
        return false;
      }
      SecretKey probeKey = generateSecretKey();
      byte[] wrapped = wrapAesKey(primaryPublicKey, probeKey, /* oaepDisabled= */ false);
      return !Arrays.equals(probeKey.getEncoded(), unwrapAesKey(privateKey, wrapped).getEncoded());
    } catch (GeneralSecurityException | IOException | CrumblesKeysException | RuntimeException e) {
      Log.w(TAG, "Primary key self-test failed.", e);
      return isPermanentKeyRefusal(e);
    }
  }

  /**
   * Returns whether {@code failure} shows that the Keystore refuses the key itself, as opposed to a
   * transient or authentication failure that may succeed on a later attempt.
   */
  private static boolean isPermanentKeyRefusal(Throwable failure) {
    boolean refused = false;
    for (Throwable cause : Throwables.getCausalChain(failure)) {
      if (cause instanceof UserNotAuthenticatedException
          || (cause instanceof KeyStoreException keyStoreException
              && keyStoreException.isTransientFailure())) {
        return false;
      }
      refused |= cause instanceof InvalidKeyException || cause instanceof BadPaddingException;
    }
    return refused;
  }

  /**
   * Replaces a primary key that the Keystore permanently refuses and records the replacement.
   *
   * <p>Entries sealed to the old key were already unreadable, so nothing readable is lost; the user
   * has to save those settings again.
   */
  private PublicKey replaceUnusablePrimaryKey() throws CrumblesKeysException {
    Log.w(TAG, "Primary key can no longer decrypt; replacing it.");
    PublicKey publicKey =
        generateKeyPair(PREFERENCE_PRIMARY_KEY_ALIAS, /* requireUserAuthentication= */ false)
            .getPublic();
    Context resolvedContext = cacheAndResolveContext(this.context);
    if (resolvedContext != null) {
      CrumblesAppAuditLogger.getInstance(resolvedContext)
          .logEvent(
              "PRIMARY_KEY_REPLACED",
              "Settings storage key could not decrypt and was replaced; saved settings may need to"
                  + " be entered again.");
    }
    return publicKey;
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

  /**
   * Returns the complete SHA-256 fingerprint of a public key, formatted for a person to compare
   * against a value they obtained out of band.
   *
   * <p>{@link #getPublicKeyHash} truncates its digest and is only suitable as a short label or map
   * key. Use this method instead wherever the user is being asked to decide whether to trust a key.
   *
   * @param key the public key to fingerprint
   * @return colon-separated uppercase hex in lines of {@value #FINGERPRINT_BYTES_PER_LINE} bytes
   * @throws CrumblesKeysException if the key cannot be encoded and digested
   */
  public static String getPublicKeyFingerprint(PublicKey key) throws CrumblesKeysException {
    byte[] hashBytes;
    try {
      hashBytes = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
    } catch (NoSuchAlgorithmException | RuntimeException e) {
      throw new CrumblesKeysException("Could not compute the fingerprint of a public key.", e);
    }
    // The digest is wrapped into short colon-separated groups because the user is expected to read
    // it against a value the recipient gave them out of band, digit by digit: an unbroken run of 64
    // hex characters is impractical to compare that way, which is how a wrong key gets accepted.
    StringBuilder fingerprint = new StringBuilder();
    for (int i = 0; i < hashBytes.length; i++) {
      if (i > 0) {
        fingerprint.append(i % FINGERPRINT_BYTES_PER_LINE == 0 ? '\n' : ':');
      }
      fingerprint.append(String.format(Locale.ROOT, "%02X", hashBytes[i]));
    }
    return fingerprint.toString();
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
   * <p>The new batch is attributed to {@code originalDeviceId}, the device that produced the batch
   * the logs were decrypted from, in the metadata that it seals. It stays unsigned, so it seals no
   * attestation chain and creates no batch-signing key; see {@link #reEncryptLogBatchForSigning}
   * for a batch that this installation signed.
   *
   * @param plainLogsBytes the plain log bytes to re-encrypt
   * @param reEncryptionKey the public key to wrap the per-batch symmetric key with
   * @param originalDeviceId the device id from the original batch's {@link LogMetadata}, or {@code
   *     null} if unknown
   * @return a newly assembled {@link LogBatch} bound with AAD
   * @throws CrumblesKeysException if key wrapping fails
   */
  public LogBatch reEncryptLogBatch(
      byte[] plainLogsBytes, PublicKey reEncryptionKey, @Nullable String originalDeviceId)
      throws CrumblesKeysException {
    return encryptLogBatch(
        plainLogsBytes,
        reEncryptionKey,
        originalDeviceId,
        KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
        /* attestationChain= */ ImmutableList.of());
  }

  /**
   * As {@link #reEncryptLogBatch}, but for the logs of a batch that this installation signed, for
   * {@link CrumblesBatchSigner#signAgain} to sign the new batch: it is attributed to this device
   * and seals the attestation chain of this installation's batch-signing key, read with {@code
   * context}.
   *
   * <p>Reading the chain creates the batch-signing key if the installation has none, so only call
   * this once {@link CrumblesBatchSigner#isSignedByThisInstallation} confirmed that the original
   * batch is this installation's.
   *
   * @throws CrumblesKeysException if key wrapping fails
   */
  LogBatch reEncryptLogBatchForSigning(
      Context context, byte[] plainLogsBytes, PublicKey reEncryptionKey)
      throws CrumblesKeysException {
    return encryptLogBatch(
        plainLogsBytes,
        reEncryptionKey,
        CrumblesDeviceIdManager.getDeviceId(context),
        KeyEncryptionType.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
        batchSigningKeyAttestationChain(context));
  }

  /**
   * Returns {@code logs} laid out for {@link LogEncryptionType#LOG_ENCRYPTION_TYPE_AES_GCM_PADDED}:
   * their length as a 4-byte big-endian integer, the logs, then zero bytes up to the next power of
   * two of at least {@value #MIN_PADDED_LOGS_BYTES} bytes.
   */
  private static byte[] padToSizeBucket(byte[] logs) {
    int paddedLength = MIN_PADDED_LOGS_BYTES;
    while (paddedLength < Integer.BYTES + logs.length) {
      paddedLength = Math.multiplyExact(paddedLength, 2);
    }
    return ByteBuffer.allocate(paddedLength).putInt(logs.length).put(logs).array();
  }

  /**
   * Returns the logs in {@code plaintext}, decrypted from a batch with {@code metadata}, with the
   * metadata of the batch. The padding of a padded batch is removed. A format version 2 batch holds
   * its logs in a {@link SealedLogs}, together with the timestamp and the device identifier that
   * its cleartext metadata leaves out; older batches hold the logs alone.
   *
   * @throws CrumblesLogsDecryptionException if the plaintext does not have the layout that the
   *     encryption type of the batch announces
   */
  private static DecryptedLogBatch decryptedLogBatch(LogMetadata metadata, byte[] plaintext) {
    return switch (metadata.getEncryptionType()) {
      case LOG_ENCRYPTION_TYPE_AES_GCM_PADDED ->
          new DecryptedLogBatch(metadata, stripPadding(plaintext));
      case LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA -> {
        SealedLogs sealedLogs = parseSealedLogs(stripPadding(plaintext));
        LogMetadata sealedMetadata = sealedLogs.getMetadata();
        yield new DecryptedLogBatch(
            metadata.toBuilder()
                .setTimestamp(sealedMetadata.getTimestamp())
                .setDevice(sealedMetadata.getDevice())
                .build(),
            sealedLogs.getLogs().toByteArray());
      }
      default -> new DecryptedLogBatch(metadata, plaintext);
    };
  }

  /**
   * Reverses {@link #padToSizeBucket}.
   *
   * @throws CrumblesLogsDecryptionException if {@code paddedLogs} declares more logs than it holds
   */
  private static byte[] stripPadding(byte[] paddedLogs) {
    ByteBuffer buffer = ByteBuffer.wrap(paddedLogs);
    int logsLength = buffer.remaining() >= Integer.BYTES ? buffer.getInt() : -1;
    if (logsLength < 0 || logsLength > buffer.remaining()) {
      throw new CrumblesLogsDecryptionException(
          "A padded log batch declares more logs than it holds.", null);
    }
    byte[] logs = new byte[logsLength];
    buffer.get(logs);
    return logs;
  }

  private static SealedLogs parseSealedLogs(byte[] serializedSealedLogs) {
    try {
      return SealedLogs.parseFrom(serializedSealedLogs, ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new CrumblesLogsDecryptionException(
          "A format version 2 log batch holds malformed sealed logs.", e);
    }
  }
}
