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

package com.android.securelogging.audit;

import static java.util.Objects.requireNonNull;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The AES-256 key that seals app audit log records at rest, stored wrapped by a non-exportable
 * Keystore key. Records are sealed in software, so that reading the whole trail costs one Keystore
 * operation instead of one per record.
 */
final class CrumblesAuditDataKey {
  static final String WRAPPING_KEY_ALIAS = "crumbles_audit_log_wrapping_key";
  private static final String TAG = "CrumblesAuditDataKey";
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int KEY_SIZE_BYTES = 32;
  private static final int IV_SIZE_BYTES = 12;
  private static final int GCM_TAG_SIZE_BYTES = 16;

  private final File wrappedKeyFile;
  @Nullable private SecretKey key;
  private boolean replacedStoredKey;

  /** Creates a data key that is stored, wrapped, in {@code wrappedKeyFile}. */
  CrumblesAuditDataKey(File wrappedKeyFile) {
    this.wrappedKeyFile = wrappedKeyFile;
  }

  /**
   * Returns the data key, loading it unless already loaded, or creating it on first use. A stored
   * data key that can never be unwrapped again is replaced, as the records sealed under it are lost
   * either way, and {@link #takeStoredKeyReplacement} then reports the replacement.
   *
   * @throws GeneralSecurityException if the Keystore fails
   * @throws IOException if the data key cannot be read or stored
   */
  @CanIgnoreReturnValue
  synchronized SecretKey load() throws GeneralSecurityException, IOException {
    if (key == null) {
      try {
        key = loadOrCreate();
      } catch (ProviderException e) {
        // AndroidKeyStore reports some failed operations unchecked, as when StrongBox and then the
        // TEE fail to generate the wrapping key. Callers handle them as any other Keystore failure.
        throw new KeyStoreException("Keystore operation failed", e);
      }
    }
    return requireNonNull(key);
  }

  /**
   * Destroys the data key and its wrapping key, so that the records sealed under them can never be
   * unsealed again, not even from copies left on flash. The next {@link #load} creates new keys.
   *
   * @throws GeneralSecurityException if the Keystore fails to delete the wrapping key
   * @throws IOException if the stored data key cannot be deleted
   */
  synchronized void destroy() throws GeneralSecurityException, IOException {
    key = null;
    replacedStoredKey = false;
    Files.deleteIfExists(wrappedKeyFile.toPath());
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
      keyStore.load(null);
      // Unlike the deleted file, the deleted wrapping key leaves nothing on flash to recover.
      keyStore.deleteEntry(WRAPPING_KEY_ALIAS);
    } catch (ProviderException e) {
      throw new KeyStoreException("Keystore operation failed", e);
    }
  }

  /**
   * Returns whether {@link #load} replaced a stored data key since the last call. The records
   * sealed under the replaced key can no longer be unsealed.
   */
  synchronized boolean takeStoredKeyReplacement() {
    boolean replaced = replacedStoredKey;
    replacedStoredKey = false;
    return replaced;
  }

  private SecretKey loadOrCreate() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);
    if (keyStore.getKey(WRAPPING_KEY_ALIAS, /* password= */ null)
        instanceof SecretKey wrappingKey) {
      if (wrappedKeyFile.exists()) {
        try {
          return unwrap(wrappingKey, Files.readAllBytes(wrappedKeyFile.toPath()));
        } catch (AEADBadTagException e) {
          // The stored key was altered, truncated, or wrapped by an earlier wrapping key.
          Log.e(TAG, "Replacing an audit log data key that fails authentication.", e);
        }
      }
      // A wrapping key is only generated along with a data key, which is now lost.
      return replace(wrappingKey);
    }
    // Without its wrapping key, a stored data key can never be unwrapped again.
    SecretKey newWrappingKey = generateWrappingKey();
    return wrappedKeyFile.exists() ? replace(newWrappingKey) : create(newWrappingKey);
  }

  /** Creates a data key in place of a stored one that can never be unwrapped again. */
  private SecretKey replace(SecretKey wrappingKey) throws GeneralSecurityException, IOException {
    SecretKey newKey = create(wrappingKey);
    replacedStoredKey = true;
    return newKey;
  }

  private SecretKey create(SecretKey wrappingKey) throws GeneralSecurityException, IOException {
    byte[] keyBytes = new byte[KEY_SIZE_BYTES];
    new SecureRandom().nextBytes(keyBytes);
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    // The Keystore picks the IV, as it requires for encryption.
    cipher.init(Cipher.ENCRYPT_MODE, wrappingKey);
    byte[] iv = cipher.getIV();
    byte[] wrappedKey = cipher.doFinal(keyBytes);
    try (FileOutputStream output = new FileOutputStream(wrappedKeyFile)) {
      output.write(iv);
      output.write(wrappedKey);
      // The data key must be durable before any record is sealed under it.
      output.getFD().sync();
    }
    return new SecretKeySpec(keyBytes, KeyProperties.KEY_ALGORITHM_AES);
  }

  private static SecretKey unwrap(SecretKey wrappingKey, byte[] wrappedKey)
      throws GeneralSecurityException {
    if (wrappedKey.length != IV_SIZE_BYTES + KEY_SIZE_BYTES + GCM_TAG_SIZE_BYTES) {
      // The Keystore reports a short input as a generic error, which must not replace the key.
      throw new AEADBadTagException("Wrapped audit log data key has the wrong size.");
    }
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(
        Cipher.DECRYPT_MODE,
        wrappingKey,
        new GCMParameterSpec(GCM_TAG_SIZE_BYTES * 8, wrappedKey, 0, IV_SIZE_BYTES));
    return new SecretKeySpec(
        cipher.doFinal(wrappedKey, IV_SIZE_BYTES, wrappedKey.length - IV_SIZE_BYTES),
        KeyProperties.KEY_ALGORITHM_AES);
  }

  private static SecretKey generateWrappingKey() throws GeneralSecurityException {
    try {
      return generateWrappingKey(/* strongBoxBacked= */ true);
    } catch (GeneralSecurityException | ProviderException e) {
      return generateWrappingKey(/* strongBoxBacked= */ false);
    }
  }

  // Like the chain key, the wrapping key needs no authentication or unlocked device, because
  // events are also logged while the device is locked.
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
