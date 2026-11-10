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

import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Log;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * One AES-256 key imported into the Android Keystore under two aliases, so that one user
 * authentication can unwrap the symmetric keys of many log batches.
 *
 * <ul>
 *   <li>{@link #WRAP_KEY_ALIAS} can only encrypt and needs no authentication, so that the logger
 *       can wrap the key of every batch it writes, even while the device is locked.
 *   <li>{@link #UNWRAP_KEY_ALIAS} can only decrypt, on an unlocked device and after an
 *       authentication for each operation, so that one {@code BiometricPrompt} authorizes one
 *       operation that unwraps the keys of many batches.
 * </ul>
 *
 * <p>Both use AES/CBC/NoPadding, and the Keystore picks the IV of every encryption. A batch key is
 * two random blocks, and the AES-GCM tag of its batch rejects a wrong or tampered key. Unlike CTR
 * or GCM, CBC gives the encrypt-only alias no way to decrypt.
 */
final class CrumblesBatchKeyStore {
  private static final String TAG = "CrumblesBatchKeyStore";

  /** Alias of the encrypt-only key. */
  static final String WRAP_KEY_ALIAS = "com.android.securelogging.CrumblesBatchWrapKey";

  /** Alias of the decrypt-only key. */
  static final String UNWRAP_KEY_ALIAS = "com.android.securelogging.CrumblesBatchUnwrapKey";

  /** Size of the id of the batch-wrap key, see {@link WrappedKey}. */
  static final int KEY_ID_SIZE_BYTES = 8;

  private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";
  private static final String CIPHER_TRANSFORMATION = "AES/CBC/NoPadding";
  private static final int AES_BLOCK_SIZE_BYTES = 16;
  private static final int KEY_SIZE_BYTES = 32;

  /** Size of a wrapped batch key: the IV, then the two encrypted blocks of the batch key. */
  static final int WRAPPED_KEY_SIZE_BYTES = AES_BLOCK_SIZE_BYTES + KEY_SIZE_BYTES;

  private static final Duration PER_OPERATION_AUTH_TIMEOUT = Duration.ZERO;
  private static final int ALLOWED_AUTHENTICATORS =
      KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL;
  private static final SecureRandom secureRandom = new SecureRandom();

  /**
   * A batch key wrapped with {@link #WRAP_KEY_ALIAS}, and the id of that key: the first {@link
   * #KEY_ID_SIZE_BYTES} bytes of its encryption of a zero block.
   */
  record WrappedKey(ByteString wrappedKey, ByteString keyId) {}

  private CrumblesBatchKeyStore() {}

  /**
   * Imports new random key material under both aliases, replacing the previous key. The material is
   * in app memory only during the import, and the copy made here is zeroed afterwards.
   *
   * @throws CrumblesKeysException if an import fails
   */
  static void createKeys() throws CrumblesKeysException {
    // Deleting first means that a failed import cannot leave two aliases with different keys.
    deleteKeys();
    byte[] keyBytes = new byte[KEY_SIZE_BYTES];
    secureRandom.nextBytes(keyBytes);
    try {
      KeyStore.SecretKeyEntry entry =
          new KeyStore.SecretKeyEntry(new SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES));
      KeyStore keyStore = loadKeyStore();
      keyStore.setEntry(WRAP_KEY_ALIAS, entry, wrapKeyProtection());
      try {
        keyStore.setEntry(UNWRAP_KEY_ALIAS, entry, unwrapKeyProtection());
      } catch (GeneralSecurityException | RuntimeException e) {
        try {
          keyStore.deleteEntry(WRAP_KEY_ALIAS);
        } catch (GeneralSecurityException | RuntimeException suppressed) {
          e.addSuppressed(suppressed);
        }
        throw e;
      }
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      throw new CrumblesKeysException("Failed to import the batch keys.", e);
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /** Deletes both aliases. */
  static void deleteKeys() {
    try {
      KeyStore keyStore = loadKeyStore();
      keyStore.deleteEntry(WRAP_KEY_ALIAS);
      keyStore.deleteEntry(UNWRAP_KEY_ALIAS);
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      Log.e(TAG, "Failed to delete the batch keys.", e);
    }
  }

  /** Returns whether both aliases exist, so that a batch key wrapped now can also be unwrapped. */
  static boolean hasKeys() {
    try {
      KeyStore keyStore = loadKeyStore();
      return keyStore.containsAlias(WRAP_KEY_ALIAS) && keyStore.containsAlias(UNWRAP_KEY_ALIAS);
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      Log.e(TAG, "Failed to look up the batch keys.", e);
      return false;
    }
  }

  /**
   * Wraps the AES-256 {@code batchKey} with {@link #WRAP_KEY_ALIAS}, under a random IV that the
   * Keystore picks. The wrapped key is that IV followed by the encrypted batch key.
   */
  static WrappedKey wrap(SecretKey batchKey) throws CrumblesKeysException {
    byte[] keyBytes = batchKey.getEncoded();
    if (keyBytes == null) {
      throw new CrumblesKeysException("Batch keys must support encoding.");
    }
    try {
      checkArgument(keyBytes.length == KEY_SIZE_BYTES, "Batch keys are AES-256 keys.");
      return new WrappedKey(encrypt(iv -> keyBytes), keyId());
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
  }

  /**
   * Returns the id of the current key: the first bytes of its encryption of a zero block. In CBC
   * mode, a block equal to the IV is encrypted as a zero block.
   */
  static ByteString keyId() throws CrumblesKeysException {
    return encrypt(iv -> iv)
        .substring(AES_BLOCK_SIZE_BYTES, AES_BLOCK_SIZE_BYTES + KEY_ID_SIZE_BYTES);
  }

  /**
   * Returns a cipher of {@link #UNWRAP_KEY_ALIAS} for {@link #unwrap}, which a {@code
   * BiometricPrompt} has to authorize through a {@code CryptoObject} first.
   *
   * @throws CrumblesKeysException if the cipher cannot be initialized, as when there are no keys
   */
  static Cipher createUnwrapCipher() throws CrumblesKeysException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
      // unwrap() drops the output block of each IV, so the IV of the operation is never used.
      cipher.init(
          Cipher.DECRYPT_MODE,
          loadKey(UNWRAP_KEY_ALIAS),
          new IvParameterSpec(new byte[AES_BLOCK_SIZE_BYTES]));
      return cipher;
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      throw new CrumblesKeysException("Failed to initialize the batch-unwrap cipher.", e);
    }
  }

  /**
   * Unwraps {@code wrappedKeys}, in order, in one operation of {@code authorizedCipher}.
   *
   * <p>The wrapped keys are decrypted as one CBC stream. Each one starts with its IV, so the block
   * before the first encrypted block of each batch key is its IV, as when the key is decrypted on
   * its own. The output block of each IV is dropped.
   *
   * @param authorizedCipher a cipher from {@link #createUnwrapCipher}, authorized by the user
   * @param wrappedKeys wrapped keys of {@link #WRAPPED_KEY_SIZE_BYTES} each
   * @throws CrumblesKeysException if the operation fails, as when it was not authorized
   */
  static ImmutableList<SecretKey> unwrap(Cipher authorizedCipher, List<ByteString> wrappedKeys)
      throws CrumblesKeysException {
    for (ByteString wrappedKey : wrappedKeys) {
      checkArgument(wrappedKey.size() == WRAPPED_KEY_SIZE_BYTES, "Malformed wrapped batch key.");
    }
    byte[] plaintext;
    try {
      plaintext = authorizedCipher.doFinal(ByteString.copyFrom(wrappedKeys).toByteArray());
    } catch (GeneralSecurityException | ProviderException e) {
      throw new CrumblesKeysException("Failed to unwrap the batch keys.", e);
    }
    try {
      ImmutableList.Builder<SecretKey> batchKeys = ImmutableList.builder();
      for (int offset = 0; offset < plaintext.length; offset += WRAPPED_KEY_SIZE_BYTES) {
        batchKeys.add(
            new SecretKeySpec(
                plaintext,
                offset + AES_BLOCK_SIZE_BYTES,
                KEY_SIZE_BYTES,
                KeyProperties.KEY_ALGORITHM_AES));
      }
      return batchKeys.build();
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  /**
   * Encrypts what {@code plaintextForIv} returns for the random IV of a new {@link #WRAP_KEY_ALIAS}
   * operation, and returns that IV followed by the ciphertext.
   */
  private static ByteString encrypt(UnaryOperator<byte[]> plaintextForIv)
      throws CrumblesKeysException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, loadKey(WRAP_KEY_ALIAS));
      byte[] iv = cipher.getIV();
      return ByteString.copyFrom(iv)
          .concat(ByteString.copyFrom(cipher.doFinal(plaintextForIv.apply(iv))));
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      throw new CrumblesKeysException("Failed to encrypt with the batch-wrap key.", e);
    }
  }

  private static Key loadKey(String alias) throws GeneralSecurityException, IOException {
    Key key = loadKeyStore().getKey(alias, /* password= */ null);
    if (key == null) {
      throw new KeyStoreException("No batch key under " + alias);
    }
    return key;
  }

  private static KeyStore loadKeyStore() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
    keyStore.load(/* param= */ null);
    return keyStore;
  }

  private static KeyProtection wrapKeyProtection() {
    return new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build();
  }

  private static KeyProtection unwrapKeyProtection() {
    return new KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(
            (int) PER_OPERATION_AUTH_TIMEOUT.toSeconds(), ALLOWED_AUTHENTICATORS)
        // Device credentials remain valid across biometric enrollments, so Android Keystore
        // ignores biometric-enrollment invalidation when AUTH_DEVICE_CREDENTIAL is authorized.
        .setInvalidatedByBiometricEnrollment(false)
        .setUnlockedDeviceRequired(true)
        .build();
  }
}
