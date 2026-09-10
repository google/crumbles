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
import com.google.common.util.concurrent.Futures;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/** Manages the storage and retrieval of external public keys using encrypted GuavaDataStore. */
public class CrumblesExternalPublicKeyManager {
  private static final String TAG = "CrumblesExternalPubKeyManager";

  private final GuavaDataStore<UserKeyPreferences> dataStore;
  private final CrumblesLogsEncryptor cryptoManager;
  private static volatile CrumblesExternalPublicKeyManager instance;

  private CrumblesExternalPublicKeyManager(Context context) {
    this(
        CrumblesDataStoreHolder.getInstance(context.getApplicationContext()),
        CrumblesMain.getLogsEncryptorInstance());
  }

  @VisibleForTesting
  CrumblesExternalPublicKeyManager(
      GuavaDataStore<UserKeyPreferences> testDataStore, CrumblesLogsEncryptor testCryptoManager) {
    this.dataStore = testDataStore;
    this.cryptoManager = testCryptoManager;
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
  public void clearActiveExternalPublicKey() {
    Log.i(TAG, "Deactivating current external key.");
    try {
      Futures.getChecked(
          dataStore.updateDataAsync(prefs -> prefs.toBuilder().clearActiveKeyId().build()),
          CrumblesKeysException.class);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to clear active external public key.", e);
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
      String keyId = CrumblesLogsEncryptor.getPublicKeyHash(publicKey);
      EncryptedPayload payload = cryptoManager.encryptDataStoreEntry(publicKey.getEncoded());

      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs ->
                  prefs.toBuilder()
                      .putExternalPublicKeys(keyId, payload)
                      .setActiveKeyId(keyId)
                      .build()),
          CrumblesKeysException.class);
      Log.i(TAG, "Successfully saved and set active public key with ID: " + keyId);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to save and encrypt public key.", e);
      throw e;
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

      byte[] decryptedBytes = cryptoManager.decryptData(payload);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePublic(new X509EncodedKeySpec(decryptedBytes));
    } catch (Exception e) {
      Log.e(TAG, "Failed to retrieve and decrypt active public key.", e);
      return null;
    }
  }

  /**
   * Saves a re-encryption public key to the DataStore after encrypting it.
   *
   * @param publicKey the re-encryption public key to save
   */
  public void saveReEncryptPublicKey(PublicKey publicKey) throws CrumblesKeysException {
    try {
      String keyId = CrumblesLogsEncryptor.getPublicKeyHash(publicKey);
      EncryptedPayload payload = cryptoManager.encryptDataStoreEntry(publicKey.getEncoded());

      Futures.getChecked(
          dataStore.updateDataAsync(
              prefs -> prefs.toBuilder().putReEncryptPublicKeys(keyId, payload).build()),
          CrumblesKeysException.class);
      Log.i(TAG, "Successfully saved re-encryption key with ID: " + keyId);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to save re-encryption key.", e);
      throw e;
    }
  }

  /**
   * Retrieves and decrypts all external re-encryption public keys from the DataStore.
   *
   * @return a list of deserialized re-encryption PublicKeys
   */
  public List<PublicKey> getExternalReEncryptPublicKeys() {
    List<PublicKey> keys = new ArrayList<>();
    try {
      UserKeyPreferences prefs =
          Futures.getChecked(dataStore.getDataAsync(), CrumblesKeysException.class);
      for (EncryptedPayload payload : prefs.getReEncryptPublicKeysMap().values()) {
        try {
          byte[] decryptedBytes = cryptoManager.decryptData(payload);
          KeyFactory kf = KeyFactory.getInstance("RSA");
          keys.add(kf.generatePublic(new X509EncodedKeySpec(decryptedBytes)));
        } catch (Exception e) {
          Log.w(TAG, "Could not decrypt a re-encryption key from DataStore. Skipping.", e);
        }
      }
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Failed to load re-encryption keys from DataStore.", e);
    }
    return keys;
  }
}
