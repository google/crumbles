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
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.Serializer;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.ProviderException;
import java.util.Optional;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import kotlin.Unit;
import kotlin.coroutines.Continuation;

/**
 * Reads and writes the key preferences store, authenticated with an HMAC-SHA256 Keystore key.
 *
 * <p>Each write stores, in {@code store_mac}, an HMAC over the preferences without that field. A
 * read is reported as corruption if the HMAC is missing or does not match when the key exists; a
 * pre-update store without an HMAC is accepted until the startup write of {@link
 * CrumblesDataStoreHolder#getInstance}, which creates the key, has migrated it.
 */
class CrumblesPreferencesSerializer implements Serializer<UserKeyPreferences> {

  @Nullable private final File file;
  @Nullable private final Context context;

  CrumblesPreferencesSerializer() {
    this(/* file= */ null, /* context= */ null);
  }

  CrumblesPreferencesSerializer(@Nullable File file, @Nullable Context context) {
    this.file = file;
    this.context = context;
  }

  /** Alias of the Keystore key that authenticates the key preferences store. */
  static final String MAC_KEY_ALIAS = "crumbles_preferences_mac_key";

  private static final String TAG = "CrumblesPreferencesSerializer";
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

  /** Cause of the corruption reported for a store that fails its HMAC check. */
  static final class IntegrityCheckFailedException extends Exception {
    IntegrityCheckFailedException() {
      super("The key preferences failed their HMAC check.");
    }
  }

  @Override
  public UserKeyPreferences getDefaultValue() {
    if (CrumblesDataStoreHolder.isFirstMacWriteInFlight()) {
      return UserKeyPreferences.getDefaultInstance(); // Not written yet, rather than deleted.
    }
    try {
      if (macKeyExists()) {
        if (context != null && file != null) {
          CrumblesDataStoreHolder.reportDeletedStore(file, context);
        }
        return CrumblesDataStoreHolder.UNREADABLE_STORE_REPLACEMENT;
      }
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      // Handled when reading or writing the store.
    }
    return UserKeyPreferences.getDefaultInstance();
  }

  @Override
  public Object readFrom(InputStream input, Continuation<? super UserKeyPreferences> continuation) {
    UserKeyPreferences preferences;
    try {
      preferences =
          UserKeyPreferences.parseFrom(input, ExtensionRegistryLite.getGeneratedRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw sneakyThrow(new CorruptionException("Cannot read the key preferences.", e));
    } catch (IOException e) {
      throw sneakyThrow(e);
    }
    if (CrumblesDataStoreHolder.isFirstMacWriteInFlight() && preferences.getStoreMac().isEmpty()) {
      return preferences; // The pre-update store being migrated, rather than an altered one.
    }
    boolean authentic;
    try {
      authentic = isAuthentic(preferences, loadMacKey());
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      // A Keystore failure says nothing about the file, so it fails the read instead of being
      // reported as corruption, which would discard the store.
      throw sneakyThrow(new IOException("Cannot check the key preferences HMAC.", e));
    }
    if (!authentic) {
      Exception cause = new IntegrityCheckFailedException();
      throw sneakyThrow(new CorruptionException("The key preferences were altered.", cause));
    }
    return preferences;
  }

  @Override
  public Object writeTo(
      UserKeyPreferences preferences,
      OutputStream output,
      Continuation<? super Unit> continuation) {
    boolean keyExistedBefore;
    try {
      keyExistedBefore = macKeyExists();
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      keyExistedBefore = true;
    }
    try {
      withMac(preferences).writeTo(output);
    } catch (IOException e) {
      if (!keyExistedBefore) {
        try {
          deleteMacKey();
        } catch (GeneralSecurityException | IOException | ProviderException deleteEx) {
          // Best-effort cleanup of a newly generated key when the initial store write fails.
        }
      }
      throw sneakyThrow(new IOException("Cannot write the key preferences.", e));
    }
    return Unit.INSTANCE;
  }

  /**
   * Returns {@code preferences} with its {@code store_mac} set to the HMAC computed under the
   * Keystore key, creating the key if it does not exist yet.
   */
  static UserKeyPreferences withMac(UserKeyPreferences preferences) {
    try {
      byte[] mac = computeMac(preferences, loadOrCreateMacKey());
      return preferences.toBuilder().setStoreMac(ByteString.copyFrom(mac)).build();
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      throw sneakyThrow(new IOException("Cannot write the key preferences.", e));
    }
  }

  private static boolean isAuthentic(UserKeyPreferences preferences, Optional<SecretKey> macKey)
      throws GeneralSecurityException {
    if (macKey.isEmpty()) {
      // Until the first write after the update, there is no key and the store has no HMAC.
      return preferences.getStoreMac().isEmpty();
    }
    return MessageDigest.isEqual(
        preferences.getStoreMac().toByteArray(), computeMac(preferences, macKey.get()));
  }

  private static byte[] computeMac(UserKeyPreferences preferences, SecretKey macKey)
      throws GeneralSecurityException {
    Mac mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256);
    mac.init(macKey);
    return mac.doFinal(preferences.toBuilder().clearStoreMac().build().toByteArray());
  }

  /** Returns whether the HMAC key exists; the first write of the store creates it. */
  static boolean macKeyExists() throws GeneralSecurityException, IOException {
    return loadMacKey().isPresent();
  }

  private static Optional<SecretKey> loadMacKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);
    return keyStore.getKey(MAC_KEY_ALIAS, /* password= */ null) instanceof SecretKey macKey
        ? Optional.of(macKey)
        : Optional.empty();
  }

  private static SecretKey loadOrCreateMacKey() throws GeneralSecurityException, IOException {
    Optional<SecretKey> macKey = loadMacKey();
    if (macKey.isPresent()) {
      return macKey.get();
    }
    try {
      return generateMacKey(/* strongBoxBacked= */ true);
    } catch (GeneralSecurityException | ProviderException e) {
      Log.w(TAG, "StrongBox could not create the preferences MAC key; creating it in the TEE.", e);
      return generateMacKey(/* strongBoxBacked= */ false);
    }
  }

  private static SecretKey generateMacKey(boolean strongBoxBacked) throws GeneralSecurityException {
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE);
    // Usable without authentication and while locked: the receiver reads the store then.
    keyGenerator.init(
        new KeyGenParameterSpec.Builder(
                MAC_KEY_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBoxBacked)
            .build());
    return keyGenerator.generateKey();
  }

  static void deleteMacKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);
    keyStore.deleteEntry(MAC_KEY_ALIAS);
  }

  /** Throws {@code exception} without declaring it, as required by Kotlin's {@link Serializer}. */
  // Suppress "unchecked" because the cast only makes the compiler treat a checked exception as
  // unchecked; the exception itself is thrown unchanged.
  @SuppressWarnings("unchecked")
  private static <E extends Throwable> RuntimeException sneakyThrow(Throwable exception) throws E {
    throw (E) exception;
  }
}
