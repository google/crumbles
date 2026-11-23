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

import static java.nio.charset.StandardCharsets.UTF_8;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.VisibleForTesting;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Optional;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Seals log batches that wait for a recipient key to a Keystore key that never leaves this device.
 *
 * <p>Each batch is sealed in software with AES-256-GCM under its own random data key, which the
 * batch carries in its header, wrapped by the Keystore key. Sealing or unsealing a batch thus costs
 * one Keystore operation on 32 bytes however large the batch is, which StrongBox can afford. A
 * sealed batch is bound to its name, so it cannot be passed off as another batch.
 */
final class CrumblesLogStagingSealer {
  @VisibleForTesting static final String WRAPPING_KEY_ALIAS = "crumbles_log_staging_wrapping_key";

  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final byte VERSION = 1;
  private static final int KEY_SIZE_BYTES = 32;
  private static final int IV_SIZE_BYTES = 12;
  private static final int TAG_SIZE_BYTES = 16;
  // A sealed batch is: version, wrapping IV, wrapped data key, data IV, then the ciphertext.
  private static final int WRAPPED_KEY_OFFSET = 1 + IV_SIZE_BYTES;
  private static final int DATA_IV_OFFSET = WRAPPED_KEY_OFFSET + KEY_SIZE_BYTES + TAG_SIZE_BYTES;
  private static final int HEADER_SIZE_BYTES = DATA_IV_OFFSET + IV_SIZE_BYTES;

  /** The number of bytes that sealing adds to a batch. */
  static final int OVERHEAD_BYTES = HEADER_SIZE_BYTES + TAG_SIZE_BYTES;

  private static final SecureRandom random = new SecureRandom();

  private CrumblesLogStagingSealer() {}

  /**
   * Returns {@code logs} sealed under a fresh data key and bound to {@code name}.
   *
   * @throws GeneralSecurityException if the Keystore fails
   * @throws IOException if the Keystore cannot be loaded
   */
  static byte[] seal(byte[] logs, String name) throws GeneralSecurityException, IOException {
    byte[] dataKey = new byte[KEY_SIZE_BYTES];
    random.nextBytes(dataKey);
    Cipher wrapCipher = Cipher.getInstance(TRANSFORMATION);
    byte[] wrappedKey;
    try {
      // The Keystore picks the IV, as it requires for encryption.
      wrapCipher.init(Cipher.ENCRYPT_MODE, loadOrCreateWrappingKey());
      wrappedKey = wrapCipher.doFinal(dataKey);
    } catch (RuntimeException e) {
      // Keystore reports some failures, such as losing its connection to the Keystore service, as
      // ProviderException, and on some OEM builds throws other unchecked exceptions. Callers handle
      // them as any other Keystore failure.
      throw new GeneralSecurityException("Keystore failed to wrap the data key.", e);
    }
    byte[] dataIv = new byte[IV_SIZE_BYTES];
    random.nextBytes(dataIv);
    Cipher dataCipher = Cipher.getInstance(TRANSFORMATION);
    dataCipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(dataKey, KeyProperties.KEY_ALGORITHM_AES),
        new GCMParameterSpec(TAG_SIZE_BYTES * 8, dataIv));
    dataCipher.updateAAD(associatedData(name));
    byte[] ciphertext = dataCipher.doFinal(logs);
    return ByteBuffer.allocate(HEADER_SIZE_BYTES + ciphertext.length)
        .put(VERSION)
        .put(wrapCipher.getIV())
        .put(wrappedKey)
        .put(dataIv)
        .put(ciphertext)
        .array();
  }

  /**
   * Returns the logs in {@code sealed}, a batch sealed under {@code name}.
   *
   * @throws AEADBadTagException if the batch can never be unsealed: it was altered or renamed, or
   *     the Keystore key that wrapped its data key is gone
   * @throws GeneralSecurityException if the Keystore fails
   * @throws IOException if the Keystore cannot be loaded
   */
  static byte[] unseal(byte[] sealed, String name) throws GeneralSecurityException, IOException {
    if (sealed.length < OVERHEAD_BYTES || sealed[0] != VERSION) {
      throw new AEADBadTagException("Staged batch is truncated or in an unknown format.");
    }
    byte[] dataKey;
    try {
      Optional<SecretKey> wrappingKey = loadWrappingKey();
      if (wrappingKey.isEmpty()) {
        throw new AEADBadTagException("The key that wrapped the staged batch is gone.");
      }
      Cipher unwrapCipher = Cipher.getInstance(TRANSFORMATION);
      unwrapCipher.init(
          Cipher.DECRYPT_MODE,
          wrappingKey.get(),
          new GCMParameterSpec(TAG_SIZE_BYTES * 8, sealed, 1, IV_SIZE_BYTES));
      dataKey =
          unwrapCipher.doFinal(sealed, WRAPPED_KEY_OFFSET, DATA_IV_OFFSET - WRAPPED_KEY_OFFSET);
    } catch (RuntimeException e) {
      // As in seal. Not an AEADBadTagException, which would get the batch deleted as unreadable.
      // The AEADBadTagException of a batch that can never be unsealed is checked, so it still
      // propagates.
      throw new GeneralSecurityException("Keystore failed to unwrap the data key.", e);
    }
    Cipher dataCipher = Cipher.getInstance(TRANSFORMATION);
    dataCipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(dataKey, KeyProperties.KEY_ALGORITHM_AES),
        new GCMParameterSpec(TAG_SIZE_BYTES * 8, sealed, DATA_IV_OFFSET, IV_SIZE_BYTES));
    dataCipher.updateAAD(associatedData(name));
    return dataCipher.doFinal(sealed, HEADER_SIZE_BYTES, sealed.length - HEADER_SIZE_BYTES);
  }

  /** Binds a sealed batch to the format version and to its name. */
  private static byte[] associatedData(String name) {
    byte[] nameBytes = name.getBytes(UTF_8);
    return ByteBuffer.allocate(1 + nameBytes.length).put(VERSION).put(nameBytes).array();
  }

  private static Optional<SecretKey> loadWrappingKey()
      throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);
    return keyStore.getKey(WRAPPING_KEY_ALIAS, /* password= */ null) instanceof SecretKey key
        ? Optional.of(key)
        : Optional.empty();
  }

  private static SecretKey loadOrCreateWrappingKey() throws GeneralSecurityException, IOException {
    Optional<SecretKey> wrappingKey = loadWrappingKey();
    if (wrappingKey.isPresent()) {
      return wrappingKey.get();
    }
    try {
      return generateWrappingKey(/* strongBoxBacked= */ true);
    } catch (GeneralSecurityException | RuntimeException e) {
      // StrongBox can be missing, or fail with ProviderException or, on some OEM builds, with other
      // unchecked exceptions, while the TEE works.
      return generateWrappingKey(/* strongBoxBacked= */ false);
    }
  }

  // Logs arrive while the device is locked, so the key needs neither user authentication nor an
  // unlocked device.
  private static SecretKey generateWrappingKey(boolean strongBoxBacked)
      throws GeneralSecurityException {
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
    keyGenerator.init(
        new KeyGenParameterSpec.Builder(
                WRAPPING_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(KEY_SIZE_BYTES * 8)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strongBoxBacked)
            .build());
    return keyGenerator.generateKey();
  }
}
