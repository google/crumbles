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
import android.content.SharedPreferences;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableSet;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Manages the storage and retrieval of external public keys using EncryptedSharedPreferences. */
public class CrumblesExternalPublicKeyManager {
  private static final String TAG = "CrumblesExternalPubKeyManager";
  private static final String PREFS_FILE_NAME = "crumbles_external_keys";
  private static final String KEY_VALUE_DELIMITER = "|";

  private static final String PREF_ACTIVE_KEY_ID = "active_external_key_id";
  private static final String PREF_PRIMARY_KEYS = "primary_external_public_keys";
  private static final String PREF_RE_ENCRYPT_KEYS = "re_encrypt_external_public_keys";

  private final SharedPreferences prefs;
  private final CrumblesLogsEncryptor cryptoManager;
  private static volatile CrumblesExternalPublicKeyManager instance;

  private CrumblesExternalPublicKeyManager(Context context) {
    this.cryptoManager = CrumblesMain.getLogsEncryptorInstance();
    // Use standard SharedPreferences. Security is handled by encrypting the values.
    this.prefs = context.getSharedPreferences(PREFS_FILE_NAME, Context.MODE_PRIVATE);
  }

  @VisibleForTesting
  CrumblesExternalPublicKeyManager(
      SharedPreferences testPrefs, CrumblesLogsEncryptor testCryptoManager) {
    this.prefs = testPrefs;
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

  public void clearActiveExternalPublicKey() {
    Log.i(TAG, "Deactivating current external key.");
    prefs.edit().remove(PREF_ACTIVE_KEY_ID).apply();
  }

  public void saveActiveExternalPublicKey(@Nullable PublicKey publicKey)
      throws CrumblesKeysException {
    if (publicKey == null) {
      clearActiveExternalPublicKey();
      return;
    }
    String keyId = CrumblesLogsEncryptor.getPublicKeyHash(publicKey);
    String encryptedValue = cryptoManager.encryptDataStoreEntry(publicKey.getEncoded());
    String entry = keyId + KEY_VALUE_DELIMITER + encryptedValue;

    Set<String> currentKeys =
        new HashSet<>(prefs.getStringSet(PREF_PRIMARY_KEYS, ImmutableSet.of()));
    currentKeys.removeIf(s -> s.startsWith(keyId + KEY_VALUE_DELIMITER));
    currentKeys.add(entry);

    prefs
        .edit()
        .putStringSet(PREF_PRIMARY_KEYS, currentKeys)
        .putString(PREF_ACTIVE_KEY_ID, keyId)
        .apply();
    Log.i(TAG, "Successfully saved and set active public key with ID: " + keyId);
  }

  @Nullable
  public PublicKey getActiveExternalPublicKey() {
    String activeKeyId = prefs.getString(PREF_ACTIVE_KEY_ID, null);
    if (activeKeyId == null) {
      return null;
    }
    Set<String> allKeys = prefs.getStringSet(PREF_PRIMARY_KEYS, Collections.emptySet());
    for (String entry : allKeys) {
      String[] parts = entry.split("\\" + KEY_VALUE_DELIMITER, 2);
      if (parts.length == 2 && parts[0].equals(activeKeyId)) {
        try {
          byte[] decryptedBytes = cryptoManager.decryptData(parts[1]);
          KeyFactory kf = KeyFactory.getInstance("RSA");
          return kf.generatePublic(new X509EncodedKeySpec(decryptedBytes));
        } catch (Exception e) {
          Log.e(TAG, "Failed to decrypt active key with ID: " + activeKeyId, e);
          return null; // Don't clear here, might be a temporary issue.
        }
      }
    }
    Log.e(TAG, "Active key ID '" + activeKeyId + "' not found in key set.");
    return null;
  }

  public void saveReEncryptPublicKey(PublicKey publicKey) throws CrumblesKeysException {
    String keyId = CrumblesLogsEncryptor.getPublicKeyHash(publicKey);
    String encryptedValue = cryptoManager.encryptDataStoreEntry(publicKey.getEncoded());
    String entry = keyId + KEY_VALUE_DELIMITER + encryptedValue;

    Set<String> currentKeys =
        new HashSet<>(prefs.getStringSet(PREF_RE_ENCRYPT_KEYS, Collections.emptySet()));
    currentKeys.removeIf(s -> s.startsWith(keyId + KEY_VALUE_DELIMITER));
    currentKeys.add(entry);

    prefs.edit().putStringSet(PREF_RE_ENCRYPT_KEYS, currentKeys).apply();
    Log.i(TAG, "Successfully saved re-encryption key with ID: " + keyId);
  }

  public List<PublicKey> getExternalReEncryptPublicKeys() {
    List<PublicKey> keys = new ArrayList<>();
    Set<String> allEntries = prefs.getStringSet(PREF_RE_ENCRYPT_KEYS, Collections.emptySet());
    for (String entry : allEntries) {
      try {
        String[] parts = entry.split("\\" + KEY_VALUE_DELIMITER, 2);
        if (parts.length == 2) {
          byte[] decryptedBytes = cryptoManager.decryptData(parts[1]);
          KeyFactory kf = KeyFactory.getInstance("RSA");
          keys.add(kf.generatePublic(new X509EncodedKeySpec(decryptedBytes)));
        }
      } catch (Exception e) {
        Log.w(TAG, "Could not decrypt a re-encryption key from SharedPreferences. Skipping.", e);
      }
    }
    return keys;
  }
}
