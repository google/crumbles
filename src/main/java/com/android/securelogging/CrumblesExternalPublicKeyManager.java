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

import android.content.Context;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.datastore.guava.GuavaDataStore;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.UncheckedExecutionException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Manages the storage and retrieval of external public keys using encrypted GuavaDataStore.
 *
 * <p>Keys are stored under their full SHA-256. Older releases stored them under the 16-character
 * prefix that {@link CrumblesLogsEncryptor#getPublicKeyHash} shows; such entries move to the full
 * ID when they are read.
 */
public class CrumblesExternalPublicKeyManager {
  private static final String TAG = "CrumblesExternalPubKeyManager";

  // Prefixes that bind a stored payload to the map it belongs to as well as to its key, so that an
  // entry cannot be moved between the two maps or between keys within one map.
  private static final String EXTERNAL_KEY_ENTRY_PREFIX = "external_public_keys/";
  private static final String RE_ENCRYPT_KEY_ENTRY_PREFIX = "re_encrypt_public_keys/";

  private final GuavaDataStore<UserKeyPreferences> dataStore;
  private final CrumblesLogsEncryptor cryptoManager;
  private final InstantSource clock;
  private static volatile CrumblesExternalPublicKeyManager instance;

  /** A saved re-encryption public key alongside its DataStore entry ID and import timestamp. */
  public static final class SavedReEncryptKey {
    private final String keyId;
    private final PublicKey publicKey;
    private final Optional<Instant> importedAt;

    public SavedReEncryptKey(String keyId, PublicKey publicKey, Optional<Instant> importedAt) {
      this.keyId = keyId;
      this.publicKey = publicKey;
      this.importedAt = importedAt;
    }

    public String keyId() {
      return keyId;
    }

    public PublicKey publicKey() {
      return publicKey;
    }

    public Optional<Instant> importedAt() {
      return importedAt;
    }
  }

  private CrumblesExternalPublicKeyManager(Context context) {
    this(
        CrumblesDataStoreHolder.getInstance(context.getApplicationContext()),
        CrumblesMain.getLogsEncryptorInstance(),
        InstantSource.system());
  }

  @VisibleForTesting
  CrumblesExternalPublicKeyManager(
      GuavaDataStore<UserKeyPreferences> testDataStore, CrumblesLogsEncryptor testCryptoManager) {
    this(testDataStore, testCryptoManager, InstantSource.system());
  }

  @VisibleForTesting
  CrumblesExternalPublicKeyManager(
      GuavaDataStore<UserKeyPreferences> testDataStore,
      CrumblesLogsEncryptor testCryptoManager,
      InstantSource clock) {
    this.dataStore = testDataStore;
    this.cryptoManager = testCryptoManager;
    this.clock = clock;
  }

  public static CrumblesExternalPublicKeyManager getInstance(Context context) {
    if (instance == null) {
      synchronized (CrumblesExternalPublicKeyManager.class) {
        if (instance == null) {
          instance = new CrumblesExternalPublicKeyManager(context.getApplicationContext());
        }
      }
    }
    return instance;
  }

  /**
   * Deactivates the currently active key by clearing the active key ID pointer. The key itself
   * remains in storage.
   */
  public void clearActiveExternalPublicKey() throws CrumblesKeysException {
    Log.i(TAG, "Deactivating current external key.");
    try {
      Futures.getChecked(
          dataStore.updateDataAsync(prefs -> prefs.toBuilder().clearActiveKeyId().build()),
          CrumblesKeysException.class);
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.e(TAG, "Failed to clear active external public key.", e);
      if (e instanceof CrumblesKeysException keysException) {
        throw keysException;
      }
      throw new CrumblesKeysException("Failed to clear active external public key", e);
    }
  }

  /**
   * Saves the provided public key to the DataStore after encrypting it and sets it as active.
   *
   * @param publicKey the external public key to save
   */
  public void saveActiveExternalPublicKey(@Nullable PublicKey publicKey)
      throws CrumblesKeysException {
    if (publicKey == null) {
      clearActiveExternalPublicKey();
      return;
    }
    try {
      String keyId = entryIdOf(publicKey);
      EncryptedPayload payload =
          cryptoManager.encryptDataStoreEntry(
              publicKey.getEncoded(), EXTERNAL_KEY_ENTRY_PREFIX + keyId);

      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs ->
                  prefs.toBuilder()
                      .putExternalPublicKeys(keyId, payload)
                      .setActiveKeyId(keyId)
                      .build()),
          CrumblesKeysException.class);
      Log.i(TAG, "Successfully saved and set active public key with ID: " + keyId);
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.e(TAG, "Failed to save and encrypt public key.", e);
      if (e instanceof CrumblesKeysException keysException) {
        throw keysException;
      }
      throw new CrumblesKeysException("Failed to save and encrypt public key", e);
    }
  }

  /**
   * Returns whether the user has selected an external public key as the encryption key, regardless
   * of whether that key can currently be read.
   *
   * <p>If the preferences themselves cannot be read, the selection is unknown and this returns
   * true, so that callers fail closed instead of encrypting to a key the user did not choose.
   */
  public boolean isExternalKeySelected() {
    try {
      return !Futures.getChecked(dataStore.getDataAsync(), CrumblesKeysException.class)
          .getActiveKeyId()
          .isEmpty();
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.e(TAG, "Failed to read the external key selection; assuming one is selected.", e);
      return true;
    }
  }

  /** Returns the ID of the active external key, or an empty string if none is selected. */
  public String getActiveKeyId() {
    try {
      return Futures.getChecked(dataStore.getDataAsync(), CrumblesKeysException.class)
          .getActiveKeyId();
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      return "";
    }
  }

  /**
   * Retrieves and decrypts the active external public key from the DataStore.
   *
   * @return the deserialized PublicKey, or null if not found or invalid
   */
  @Nullable
  public PublicKey getActiveExternalPublicKey() {
    try {
      UserKeyPreferences prefs =
          Futures.getChecked(dataStore.getDataAsync(), CrumblesKeysException.class);
      String activeKeyId = prefs.getActiveKeyId();
      if (activeKeyId.isEmpty()) {
        return null;
      }

      EncryptedPayload payload = prefs.getExternalPublicKeysOrDefault(activeKeyId, null);
      if (payload == null) {
        Log.e(TAG, "Active key ID '" + activeKeyId + "' not found in key map.");
        return null;
      }

      byte[] decryptedBytes =
          cryptoManager.decryptDataStoreEntry(payload, EXTERNAL_KEY_ENTRY_PREFIX + activeKeyId);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(decryptedBytes));
      String keyId = entryIdOf(publicKey);
      if (!activeKeyId.equals(keyId)) {
        moveActiveKey(activeKeyId, keyId, publicKey);
      }
      return publicKey;
    } catch (Exception e) {
      Log.e(TAG, "Failed to retrieve and decrypt active public key.", e);
      return null;
    }
  }

  /** Re-saves an active key found under an older ID under {@code keyId}, if it can. */
  private void moveActiveKey(String olderId, String keyId, PublicKey publicKey) {
    try {
      EncryptedPayload payload =
          cryptoManager.encryptDataStoreEntry(
              publicKey.getEncoded(), EXTERNAL_KEY_ENTRY_PREFIX + keyId);
      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs ->
                  prefs.toBuilder()
                      .removeExternalPublicKeys(olderId)
                      .putExternalPublicKeys(keyId, payload)
                      .setActiveKeyId(keyId)
                      .build()),
          CrumblesKeysException.class);
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.w(TAG, "Could not move the active key to its full ID; it stays under the older one.", e);
    }
  }

  /**
   * Saves a re-encryption public key to the DataStore after encrypting it.
   *
   * @param publicKey the re-encryption public key to save
   */
  public void saveReEncryptPublicKey(PublicKey publicKey) throws CrumblesKeysException {
    try {
      String keyId = entryIdOf(publicKey);
      long importedAtMillis = clock.instant().toEpochMilli();
      EncryptedPayload payload =
          cryptoManager.encryptDataStoreEntry(
              publicKey.getEncoded(), RE_ENCRYPT_KEY_ENTRY_PREFIX + keyId);

      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs ->
                  prefs.toBuilder()
                      .putReEncryptPublicKeys(keyId, payload)
                      .putReEncryptKeyImportedAtMillis(keyId, importedAtMillis)
                      .build()),
          CrumblesKeysException.class);
      Log.i(TAG, "Successfully saved re-encryption key with ID: " + keyId);
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.e(TAG, "Failed to save re-encryption key.", e);
      if (e instanceof CrumblesKeysException keysException) {
        throw keysException;
      }
      throw new CrumblesKeysException("Failed to save re-encryption key", e);
    }
  }

  /**
   * Removes the re-encryption public key with {@code keyId} and its import timestamp from the
   * DataStore.
   */
  public void removeExternalPublicKey(String keyId) throws CrumblesKeysException {
    try {
      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs ->
                  prefs.toBuilder()
                      .removeReEncryptPublicKeys(keyId)
                      .removeReEncryptKeyImportedAtMillis(keyId)
                      .build()),
          CrumblesKeysException.class);
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.e(TAG, "Failed to remove re-encryption key.", e);
      throw new CrumblesKeysException("Failed to remove re-encryption key.", e);
    }
  }

  /**
   * Retrieves and decrypts all saved re-encryption public keys and their import timestamps from the
   * DataStore.
   */
  public List<SavedReEncryptKey> getSavedReEncryptPublicKeys() {
    ImmutableList.Builder<SavedReEncryptKey> savedKeys = ImmutableList.builder();
    ImmutableMap.Builder<String, PublicKey> keysUnderOlderIds = ImmutableMap.builder();
    try {
      UserKeyPreferences prefs =
          Futures.getChecked(dataStore.getDataAsync(), CrumblesKeysException.class);
      Map<String, Long> importedAtMap = prefs.getReEncryptKeyImportedAtMillisMap();
      for (Map.Entry<String, EncryptedPayload> entry :
          prefs.getReEncryptPublicKeysMap().entrySet()) {
        try {
          byte[] decryptedBytes =
              cryptoManager.decryptDataStoreEntry(
                  entry.getValue(), RE_ENCRYPT_KEY_ENTRY_PREFIX + entry.getKey());
          KeyFactory kf = KeyFactory.getInstance("RSA");
          PublicKey key = kf.generatePublic(new X509EncodedKeySpec(decryptedBytes));
          String fullKeyId = entryIdOf(key);
          Optional<Instant> importedAt =
              Optional.ofNullable(importedAtMap.get(entry.getKey())).map(Instant::ofEpochMilli);
          savedKeys.add(new SavedReEncryptKey(fullKeyId, key, importedAt));
          if (!entry.getKey().equals(fullKeyId)) {
            keysUnderOlderIds.put(entry.getKey(), key);
          }
        } catch (Exception e) {
          Log.w(TAG, "Could not decrypt a re-encryption key from DataStore. Skipping.", e);
        }
      }
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.e(TAG, "Failed to load re-encryption keys from DataStore.", e);
    }
    moveReEncryptKeysToFullIds(keysUnderOlderIds.buildOrThrow());
    return savedKeys.build();
  }

  /**
   * Retrieves and decrypts all external re-encryption public keys from the DataStore.
   *
   * @return a list of deserialized re-encryption PublicKeys
   */
  public List<PublicKey> getExternalReEncryptPublicKeys() {
    List<PublicKey> keys = new ArrayList<>();
    for (SavedReEncryptKey savedKey : getSavedReEncryptPublicKeys()) {
      keys.add(savedKey.publicKey());
    }
    return keys;
  }

  /** Re-saves re-encryption keys found under older IDs under their full IDs, if there are any. */
  private void moveReEncryptKeysToFullIds(ImmutableMap<String, PublicKey> keysByOlderId) {
    if (keysByOlderId.isEmpty()) {
      return;
    }
    try {
      ImmutableMap.Builder<String, EncryptedPayload> payloads = ImmutableMap.builder();
      ImmutableMap.Builder<String, String> fullIds = ImmutableMap.builder();
      for (Map.Entry<String, PublicKey> entry : keysByOlderId.entrySet()) {
        String keyId = entryIdOf(entry.getValue());
        fullIds.put(entry.getKey(), keyId);
        payloads.put(
            keyId,
            cryptoManager.encryptDataStoreEntry(
                entry.getValue().getEncoded(), RE_ENCRYPT_KEY_ENTRY_PREFIX + keyId));
      }
      ImmutableMap<String, EncryptedPayload> payloadsById = payloads.buildKeepingLast();
      ImmutableMap<String, String> fullIdsByOlderId = fullIds.buildOrThrow();
      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs -> {
                UserKeyPreferences.Builder builder = prefs.toBuilder();
                for (Map.Entry<String, String> idEntry : fullIdsByOlderId.entrySet()) {
                  String olderId = idEntry.getKey();
                  builder.removeReEncryptPublicKeys(olderId);
                  if (prefs.containsReEncryptKeyImportedAtMillis(olderId)) {
                    builder
                        .removeReEncryptKeyImportedAtMillis(olderId)
                        .putReEncryptKeyImportedAtMillis(
                            idEntry.getValue(),
                            prefs.getReEncryptKeyImportedAtMillisOrThrow(olderId));
                  }
                }
                return builder.putAllReEncryptPublicKeys(payloadsById).build();
              }),
          CrumblesKeysException.class);
    } catch (CrumblesKeysException | UncheckedExecutionException e) {
      Log.w(TAG, "Could not move re-encryption keys to their full IDs; they stay readable.", e);
    }
  }

  /**
   * Returns the ID that {@code publicKey} is stored under: its full SHA-256 fingerprint, without
   * separators.
   */
  private static String entryIdOf(PublicKey publicKey) throws CrumblesKeysException {
    return CrumblesLogsEncryptor.getPublicKeyFingerprint(publicKey)
        .replace(":", "")
        .replace("\n", "");
  }
}
