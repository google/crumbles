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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import androidx.datastore.guava.GuavaDataStore;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesExternalPublicKeyManager.SavedReEncryptKey;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.time.Instant;
import java.time.InstantSource;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

/** Unit tests for the {@link CrumblesExternalPublicKeyManager} class. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesExternalPublicKeyManagerTest {

  private static Provider fakeProviderInstance;

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  @Rule public final Expect expect = Expect.create();

  private CrumblesLogsEncryptor cryptoManager;
  private GuavaDataStore<UserKeyPreferences> testDataStore;
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private PublicKey testPublicKey;
  private EncryptedPayload testPayload;

  @BeforeClass
  public static void setUpClass() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    fakeProviderInstance = new FakeAndroidKeyStoreProvider();
    Security.insertProviderAt(fakeProviderInstance, 1);
  }

  @AfterClass
  public static void tearDownClass() {
    if (fakeProviderInstance != null) {
      Security.removeProvider(fakeProviderInstance.getName());
      fakeProviderInstance = null;
    }
  }

  @Before
  public void setUp() throws Exception {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    cryptoManager = new CrumblesLogsEncryptor();

    File testFile = new File(tempFolder.getRoot(), "test_user_key_prefs.pb");
    testDataStore = CrumblesDataStoreHolder.createDataStore(testFile);

    KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    testPublicKey = kp.getPublic();
    testPayload = cryptoManager.encryptDataStoreEntry(testPublicKey.getEncoded());

    publicKeyManager = new CrumblesExternalPublicKeyManager(testDataStore, cryptoManager);
  }

  @Test
  public void saveAndGetActiveExternalPublicKey_successfulRoundtrip() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    PublicKey retrievedKey = publicKeyManager.getActiveExternalPublicKey();

    assertThat(retrievedKey).isNotNull();
    assertThat(retrievedKey.getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }

  @Test
  public void getActiveExternalPublicKey_whenNoActiveKey_returnsNull() {
    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void isExternalKeySelected_whenNoActiveKey_returnsFalse() {
    assertThat(publicKeyManager.isExternalKeySelected()).isFalse();
  }

  @Test
  public void isExternalKeySelected_whenActiveKeySaved_returnsTrue() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);

    assertThat(publicKeyManager.isExternalKeySelected()).isTrue();
  }

  @Test
  public void isExternalKeySelected_whenActiveKeyUnreadable_returnsTrue() throws Exception {
    testDataStore
        .updateDataAsync(prefs -> prefs.toBuilder().setActiveKeyId("unknown-key-id").build())
        .get();

    assertThat(publicKeyManager.isExternalKeySelected()).isTrue();
  }

  @Test
  public void clearActiveExternalPublicKey_clearsActiveKey() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNotNull();

    publicKeyManager.clearActiveExternalPublicKey();

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void clearActiveExternalPublicKey_whenStoreNotWritable_throwsException() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    try {
      assertThrows(
          CrumblesKeysException.class,
          () -> publicKeyManager.clearActiveExternalPublicKey());
    } finally {
      tempFolder.getRoot().setWritable(true);
    }

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNotNull();
  }

  @Test
  public void saveActiveExternalPublicKey_nullKey_clearsActiveKey() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNotNull();

    publicKeyManager.saveActiveExternalPublicKey(null);

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void saveActiveExternalPublicKey_nullKeyWhenStoreNotWritable_throwsException()
      throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    try {
      assertThrows(
          CrumblesKeysException.class, () -> publicKeyManager.saveActiveExternalPublicKey(null));
    } finally {
      tempFolder.getRoot().setWritable(true);
    }

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNotNull();
  }

  @Test
  public void saveActiveExternalPublicKey_nonNullKeyWhenStoreNotWritable_throwsException() {
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    try {
      assertThrows(
          CrumblesKeysException.class,
          () -> publicKeyManager.saveActiveExternalPublicKey(testPublicKey));
    } finally {
      tempFolder.getRoot().setWritable(true);
    }

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void saveReEncryptPublicKey_whenStoreNotWritable_throwsException() {
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    try {
      assertThrows(
          CrumblesKeysException.class,
          () -> publicKeyManager.saveReEncryptPublicKey(testPublicKey));
    } finally {
      tempFolder.getRoot().setWritable(true);
    }

    assertThat(publicKeyManager.getExternalReEncryptPublicKeys()).isEmpty();
  }

  @Test
  public void saveReEncryptPublicKey_andGet_successfulRoundtrip() throws Exception {
    publicKeyManager.saveReEncryptPublicKey(testPublicKey);
    List<PublicKey> retrievedKeys = publicKeyManager.getExternalReEncryptPublicKeys();

    assertThat(retrievedKeys).hasSize(1);
    assertThat(retrievedKeys.get(0).getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }

  @Test
  public void getExternalReEncryptPublicKeys_whenNoneSaved_returnsEmpty() {
    assertThat(publicKeyManager.getExternalReEncryptPublicKeys()).isEmpty();
  }

  @Test
  public void getActiveExternalPublicKey_whenActiveKeyIdEmptyEvenIfBlankEntryInMap_returnsNull()
      throws Exception {
    testDataStore
        .updateDataAsync(prefs -> prefs.toBuilder().putExternalPublicKeys("", testPayload).build())
        .get();

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void getActiveExternalPublicKey_whenActiveKeyIdNotInMap_returnsNull() throws Exception {
    testDataStore
        .updateDataAsync(prefs -> prefs.toBuilder().setActiveKeyId("unknown-key-id").build())
        .get();

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void getActiveExternalPublicKey_whenDecryptionFails_returnsNull() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(
        CrumblesLogsEncryptor.PREFERENCE_PRIMARY_KEY_ALIAS);

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void getSavedExternalPublicKeys_returnsTheActiveKeyAndTheClearedOnes() throws Exception {
    PublicKey clearedKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    publicKeyManager.saveActiveExternalPublicKey(clearedKey);
    publicKeyManager.clearActiveExternalPublicKey();
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);

    ImmutableList<PublicKey> savedKeys = publicKeyManager.getSavedExternalPublicKeys();

    assertThat(savedKeys.stream().map(key -> ByteString.copyFrom(key.getEncoded())).toList())
        .containsExactly(
            ByteString.copyFrom(clearedKey.getEncoded()),
            ByteString.copyFrom(testPublicKey.getEncoded()));
  }

  @Test
  public void getSavedExternalPublicKeys_whenNoneSaved_returnsEmpty() throws Exception {
    assertThat(publicKeyManager.getSavedExternalPublicKeys()).isEmpty();
  }

  @Test
  public void getSavedExternalPublicKeys_whenActiveKeyIdNotInMap_throws() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    testDataStore
        .updateDataAsync(prefs -> prefs.toBuilder().setActiveKeyId("unknown-key-id").build())
        .get();

    assertThrows(CrumblesKeysException.class, () -> publicKeyManager.getSavedExternalPublicKeys());
  }

  @Test
  public void getSavedExternalPublicKeys_whenASavedKeyCannotBeDecrypted_throws() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    EncryptedPayload badPayload =
        EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("bad")).build();
    testDataStore
        .updateDataAsync(
            prefs -> prefs.toBuilder().putExternalPublicKeys("bad_key", badPayload).build())
        .get();

    assertThrows(CrumblesKeysException.class, () -> publicKeyManager.getSavedExternalPublicKeys());
  }

  @Test
  public void getExternalReEncryptPublicKeys_whenDecryptionFailsForOneKey_skipsFailedKey()
      throws Exception {
    EncryptedPayload badPayload =
        EncryptedPayload.newBuilder().setCiphertext(ByteString.copyFromUtf8("bad")).build();
    testDataStore
        .updateDataAsync(
            prefs ->
                prefs.toBuilder()
                    .putReEncryptPublicKeys("bad_key", badPayload)
                    .putReEncryptPublicKeys("good_key", testPayload)
                    .build())
        .get();

    List<PublicKey> keys = publicKeyManager.getExternalReEncryptPublicKeys();

    assertThat(keys).hasSize(1);
    assertThat(keys.get(0).getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }

  @Test
  public void saveKeys_whenEncryptionFails_throwsCrumblesKeysException() throws Exception {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    try {
      assertThrows(
          CrumblesKeysException.class,
          () -> publicKeyManager.saveActiveExternalPublicKey(testPublicKey));
      assertThrows(
          CrumblesKeysException.class,
          () -> publicKeyManager.saveReEncryptPublicKey(testPublicKey));
    } finally {
      Security.insertProviderAt(fakeProviderInstance, 1);
    }
  }
  @Test
  public void getActiveExternalPublicKey_whenPayloadCopiedToAnotherEntry_returnsNull()
      throws Exception {
    // Given: a legitimately saved active key.
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    EncryptedPayload savedPayload =
        prefs.getExternalPublicKeysOrThrow(prefs.getActiveKeyId());

    // When: someone with file access copies that payload under a different entry and repoints the
    // active key at it.
    testDataStore
        .updateDataAsync(
            p ->
                p.toBuilder()
                    .putExternalPublicKeys("substituted-entry", savedPayload)
                    .setActiveKeyId("substituted-entry")
                    .build())
        .get();

    // Then: the payload no longer matches the entry it was read from, so it is rejected.
    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void getExternalReEncryptPublicKeys_whenPayloadCameFromTheOtherMap_skipsIt()
      throws Exception {
    // Given: a key saved as the active external key.
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    String keyId = prefs.getActiveKeyId();
    EncryptedPayload savedPayload = prefs.getExternalPublicKeysOrThrow(keyId);

    // When: its payload is copied into the re-encryption key map under the same key id.
    testDataStore
        .updateDataAsync(p -> p.toBuilder().putReEncryptPublicKeys(keyId, savedPayload).build())
        .get();

    // Then: the binding distinguishes the two maps, so the moved entry is not accepted.
    assertThat(publicKeyManager.getExternalReEncryptPublicKeys()).isEmpty();
  }

  @Test
  public void getActiveExternalPublicKey_whenEntryPredatesBinding_isStillReadable()
      throws Exception {
    // Given: an entry sealed the way older releases sealed it, with no binding to its entry id.
    EncryptedPayload legacyPayload =
        cryptoManager.encryptDataStoreEntry(testPublicKey.getEncoded());
    String keyId = CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey);
    testDataStore
        .updateDataAsync(
            p ->
                p.toBuilder()
                    .putExternalPublicKeys(keyId, legacyPayload)
                    .setActiveKeyId(keyId)
                    .build())
        .get();

    // Then: an existing installation keeps working after the upgrade.
    PublicKey retrievedKey = publicKeyManager.getActiveExternalPublicKey();
    assertThat(retrievedKey).isNotNull();
    assertThat(retrievedKey.getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }

  @Test
  public void saveActiveExternalPublicKey_storesKeyUnderItsFullSha256() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);

    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    expect.that(prefs.getActiveKeyId()).isEqualTo(fullSha256Of(testPublicKey));
    expect
        .that(prefs.getExternalPublicKeysMap().keySet())
        .containsExactly(fullSha256Of(testPublicKey));
  }

  @Test
  public void saveReEncryptPublicKey_storesKeyUnderItsFullSha256() throws Exception {
    publicKeyManager.saveReEncryptPublicKey(testPublicKey);

    assertThat(testDataStore.getDataAsync().get().getReEncryptPublicKeysMap().keySet())
        .containsExactly(fullSha256Of(testPublicKey));
  }

  @Test
  public void getActiveExternalPublicKey_whenStoredUnderShortId_movesItToItsFullId()
      throws Exception {
    String shortId = CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey);
    EncryptedPayload payload =
        cryptoManager.encryptDataStoreEntry(
            testPublicKey.getEncoded(), "external_public_keys/" + shortId);
    testDataStore
        .updateDataAsync(
            p ->
                p.toBuilder()
                    .putExternalPublicKeys(shortId, payload)
                    .setActiveKeyId(shortId)
                    .build())
        .get();

    PublicKey retrievedKey = publicKeyManager.getActiveExternalPublicKey();

    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    expect.that(retrievedKey.getEncoded()).isEqualTo(testPublicKey.getEncoded());
    expect.that(prefs.getActiveKeyId()).isEqualTo(fullSha256Of(testPublicKey));
    expect
        .that(prefs.getExternalPublicKeysMap().keySet())
        .containsExactly(fullSha256Of(testPublicKey));
  }

  @Test
  public void getActiveExternalPublicKey_whenMovingToFullIdFails_stillReturnsKey()
      throws Exception {
    String shortId = CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey);
    EncryptedPayload payload =
        cryptoManager.encryptDataStoreEntry(
            testPublicKey.getEncoded(), "external_public_keys/" + shortId);
    testDataStore
        .updateDataAsync(
            p ->
                p.toBuilder()
                    .putExternalPublicKeys(shortId, payload)
                    .setActiveKeyId(shortId)
                    .build())
        .get();
    // The store can't be rewritten, so the entry can't move.
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    PublicKey retrievedKey;
    try {
      retrievedKey = publicKeyManager.getActiveExternalPublicKey();
    } finally {
      tempFolder.getRoot().setWritable(true);
    }

    assertThat(retrievedKey.getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }

  @Test
  public void getExternalReEncryptPublicKeys_whenStoredUnderShortId_movesItToItsFullId()
      throws Exception {
    String shortId = CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey);
    EncryptedPayload payload =
        cryptoManager.encryptDataStoreEntry(
            testPublicKey.getEncoded(), "re_encrypt_public_keys/" + shortId);
    testDataStore
        .updateDataAsync(p -> p.toBuilder().putReEncryptPublicKeys(shortId, payload).build())
        .get();

    List<PublicKey> keys = publicKeyManager.getExternalReEncryptPublicKeys();

    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    expect.that(keys).hasSize(1);
    expect
        .that(prefs.getReEncryptPublicKeysMap().keySet())
        .containsExactly(fullSha256Of(testPublicKey));
    expect.that(prefs.getReEncryptKeyImportedAtMillisMap()).isEmpty();
  }

  @Test
  public void saveReEncryptPublicKey_recordsImportTimestampAndReturnsSavedMetadata()
      throws Exception {
    Instant fixedNow = Instant.ofEpochMilli(1700000000123L);
    CrumblesExternalPublicKeyManager managerWithClock =
        new CrumblesExternalPublicKeyManager(
            testDataStore, cryptoManager, InstantSource.fixed(fixedNow));

    managerWithClock.saveReEncryptPublicKey(testPublicKey);
    List<SavedReEncryptKey> savedKeys = managerWithClock.getSavedReEncryptPublicKeys();

    assertThat(savedKeys).hasSize(1);
    expect.that(savedKeys.get(0).keyId()).isEqualTo(fullSha256Of(testPublicKey));
    expect.that(savedKeys.get(0).publicKey().getEncoded()).isEqualTo(testPublicKey.getEncoded());
    expect.that(savedKeys.get(0).importedAt()).isEqualTo(Optional.of(fixedNow));
  }

  @Test
  public void getSavedReEncryptPublicKeys_whenNoTimestampRecorded_returnsEmptyImportedAt()
      throws Exception {
    String fullId = fullSha256Of(testPublicKey);
    EncryptedPayload payload =
        cryptoManager.encryptDataStoreEntry(
            testPublicKey.getEncoded(), "re_encrypt_public_keys/" + fullId);
    testDataStore
        .updateDataAsync(p -> p.toBuilder().putReEncryptPublicKeys(fullId, payload).build())
        .get();

    List<SavedReEncryptKey> savedKeys = publicKeyManager.getSavedReEncryptPublicKeys();

    assertThat(savedKeys).hasSize(1);
    expect.that(savedKeys.get(0).keyId()).isEqualTo(fullId);
    expect.that(savedKeys.get(0).importedAt()).isEmpty();
  }

  @Test
  public void getSavedReEncryptPublicKeys_whenStoredUnderShortIdWithTimestamp_migratesBoth()
      throws Exception {
    String shortId = CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey);
    long importedMillis = 1700000000456L;
    EncryptedPayload payload =
        cryptoManager.encryptDataStoreEntry(
            testPublicKey.getEncoded(), "re_encrypt_public_keys/" + shortId);
    testDataStore
        .updateDataAsync(
            p ->
                p.toBuilder()
                    .putReEncryptPublicKeys(shortId, payload)
                    .putReEncryptKeyImportedAtMillis(shortId, importedMillis)
                    .build())
        .get();

    List<SavedReEncryptKey> savedKeys = publicKeyManager.getSavedReEncryptPublicKeys();

    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    String fullId = fullSha256Of(testPublicKey);
    assertThat(savedKeys).hasSize(1);
    expect.that(savedKeys.get(0).keyId()).isEqualTo(fullId);
    expect
        .that(savedKeys.get(0).importedAt())
        .isEqualTo(Optional.of(Instant.ofEpochMilli(importedMillis)));
    expect.that(prefs.getReEncryptPublicKeysMap().keySet()).containsExactly(fullId);
    expect.that(prefs.getReEncryptKeyImportedAtMillisMap()).containsExactly(fullId, importedMillis);
  }

  @Test
  public void getSavedReEncryptPublicKeys_whenMovingToFullIdFails_stillReturnsSavedKey()
      throws Exception {
    String shortId = CrumblesLogsEncryptor.getPublicKeyHash(testPublicKey);
    EncryptedPayload payload =
        cryptoManager.encryptDataStoreEntry(
            testPublicKey.getEncoded(), "re_encrypt_public_keys/" + shortId);
    testDataStore
        .updateDataAsync(p -> p.toBuilder().putReEncryptPublicKeys(shortId, payload).build())
        .get();
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    List<SavedReEncryptKey> savedKeys;
    try {
      savedKeys = publicKeyManager.getSavedReEncryptPublicKeys();
    } finally {
      tempFolder.getRoot().setWritable(true);
    }

    assertThat(savedKeys).hasSize(1);
    assertThat(savedKeys.get(0).publicKey().getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }

  @Test
  public void removeExternalPublicKey_removesTargetKeyAndTimestampOnly() throws Exception {
    PublicKey otherKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    publicKeyManager.saveReEncryptPublicKey(testPublicKey);
    publicKeyManager.saveReEncryptPublicKey(otherKey);

    publicKeyManager.removeExternalPublicKey(fullSha256Of(testPublicKey));

    UserKeyPreferences prefs = testDataStore.getDataAsync().get();
    String remainingId = fullSha256Of(otherKey);
    expect.that(prefs.getReEncryptPublicKeysMap().keySet()).containsExactly(remainingId);
    expect.that(prefs.getReEncryptKeyImportedAtMillisMap().keySet()).containsExactly(remainingId);
  }

  @Test
  public void removeExternalPublicKey_whenStoreNotWritable_throwsCrumblesKeysException()
      throws Exception {
    publicKeyManager.saveReEncryptPublicKey(testPublicKey);
    String keyId = fullSha256Of(testPublicKey);
    assertThat(tempFolder.getRoot().setWritable(false)).isTrue();

    try {
      assertThrows(
          CrumblesKeysException.class, () -> publicKeyManager.removeExternalPublicKey(keyId));
    } finally {
      tempFolder.getRoot().setWritable(true);
    }
  }

  /** Returns the SHA-256 of {@code key}'s encoding as 64 uppercase hexadecimal digits. */
  private static String fullSha256Of(PublicKey key) throws Exception {
    StringBuilder hex = new StringBuilder();
    for (byte digestByte : MessageDigest.getInstance("SHA-256").digest(key.getEncoded())) {
      hex.append(String.format(Locale.ROOT, "%02X", digestByte));
    }
    return hex.toString();
  }
}
