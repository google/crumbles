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
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.protobuf.ByteString;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;
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
  public void clearActiveExternalPublicKey_clearsActiveKey() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNotNull();

    publicKeyManager.clearActiveExternalPublicKey();

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
  }

  @Test
  public void saveActiveExternalPublicKey_nullKey_clearsActiveKey() throws Exception {
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNotNull();

    publicKeyManager.saveActiveExternalPublicKey(null);

    assertThat(publicKeyManager.getActiveExternalPublicKey()).isNull();
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
}
