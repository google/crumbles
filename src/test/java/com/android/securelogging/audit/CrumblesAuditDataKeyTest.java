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

import static com.android.securelogging.audit.CrumblesAuditDataKey.WRAPPING_KEY_ALIAS;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.Security;
import javax.crypto.SecretKey;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/** Unit tests for the {@link CrumblesAuditDataKey} class. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesAuditDataKeyTest {

  @Rule public final Expect expect = Expect.create();
  @Rule public final TemporaryFolder temporaryFolder = new TemporaryFolder();

  private File wrappedKeyFile;

  @Before
  public void setUp() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = false;
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = false;
    wrappedKeyFile = new File(temporaryFolder.getRoot(), "app_audit_log.key");
  }

  @After
  public void tearDown() {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Test
  public void load_withNewInstance_returnsStoredKey() throws Exception {
    SecretKey key = new CrumblesAuditDataKey(wrappedKeyFile).load();

    SecretKey reloadedKey = new CrumblesAuditDataKey(wrappedKeyFile).load();

    assertThat(reloadedKey).isEqualTo(key);
  }

  @Test
  public void load_whenAlreadyLoaded_returnsKeyWithoutKeystore() throws Exception {
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    SecretKey key = dataKey.load();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);

    assertThat(dataKey.load()).isEqualTo(key);
  }

  @Test
  public void load_generatesWrappingKeyThatWorksWhileLocked() throws Exception {
    new CrumblesAuditDataKey(wrappedKeyFile).load();

    KeyGenParameterSpec spec = FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec();
    expect.that(spec.getKeystoreAlias()).isEqualTo(WRAPPING_KEY_ALIAS);
    expect
        .that(spec.getPurposes())
        .isEqualTo(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
    expect.that(spec.getKeySize()).isEqualTo(256);
    expect.that(spec.getBlockModes()).asList().containsExactly(KeyProperties.BLOCK_MODE_GCM);
    expect.that(spec.isUserAuthenticationRequired()).isFalse();
    expect.that(spec.isUnlockedDeviceRequired()).isFalse();
    expect.that(spec.isStrongBoxBacked()).isTrue();
  }

  @Test
  public void load_whenStrongBoxUnavailable_generatesTeeWrappingKey() throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = false;

    new CrumblesAuditDataKey(wrappedKeyFile).load();

    assertThat(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
  }

  @Test
  public void load_whenStrongBoxFails_generatesTeeWrappingKey() throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = true;

    new CrumblesAuditDataKey(wrappedKeyFile).load();

    assertThat(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
  }

  @Test
  public void load_whenStrongBoxThrowsGeneralSecurityException_generatesTeeWrappingKey()
      throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = true;

    new CrumblesAuditDataKey(wrappedKeyFile).load();

    assertThat(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
  }

  @Test
  public void load_whenWrappingKeyLost_storesNewKey() throws Exception {
    SecretKey lostKey = new CrumblesAuditDataKey(wrappedKeyFile).load();
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(WRAPPING_KEY_ALIAS);

    SecretKey newKey = new CrumblesAuditDataKey(wrappedKeyFile).load();

    expect.that(newKey).isNotEqualTo(lostKey);
    expect.that(new CrumblesAuditDataKey(wrappedKeyFile).load()).isEqualTo(newKey);
  }

  @Test
  public void load_whenStoredKeyAltered_storesNewKey() throws Exception {
    SecretKey alteredKey = new CrumblesAuditDataKey(wrappedKeyFile).load();
    Files.write(wrappedKeyFile.toPath(), new byte[(int) wrappedKeyFile.length()]);

    SecretKey newKey = new CrumblesAuditDataKey(wrappedKeyFile).load();

    expect.that(newKey).isNotEqualTo(alteredKey);
    expect.that(new CrumblesAuditDataKey(wrappedKeyFile).load()).isEqualTo(newKey);
  }

  @Test
  public void load_whenStoredKeyTruncated_storesNewKey() throws Exception {
    SecretKey truncatedKey = new CrumblesAuditDataKey(wrappedKeyFile).load();
    Files.write(wrappedKeyFile.toPath(), new byte[4]);

    SecretKey newKey = new CrumblesAuditDataKey(wrappedKeyFile).load();

    expect.that(newKey).isNotEqualTo(truncatedKey);
    expect.that(new CrumblesAuditDataKey(wrappedKeyFile).load()).isEqualTo(newKey);
  }

  @Test
  public void load_whenKeystoreUnavailable_throwsAndKeepsStoredKey() throws Exception {
    new CrumblesAuditDataKey(wrappedKeyFile).load();
    byte[] storedKey = Files.readAllBytes(wrappedKeyFile.toPath());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);

    assertThrows(KeyStoreException.class, () -> new CrumblesAuditDataKey(wrappedKeyFile).load());
    assertThat(Files.readAllBytes(wrappedKeyFile.toPath())).isEqualTo(storedKey);
  }

  @Test
  public void load_whenKeystoreThrowsProviderException_throwsAndKeepsStoredKey() throws Exception {
    new CrumblesAuditDataKey(wrappedKeyFile).load();
    byte[] storedKey = Files.readAllBytes(wrappedKeyFile.toPath());
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        WRAPPING_KEY_ALIAS,
        () -> {
          throw new ProviderException("Keystore operation failed");
        });

    assertThrows(KeyStoreException.class, () -> new CrumblesAuditDataKey(wrappedKeyFile).load());
    assertThat(Files.readAllBytes(wrappedKeyFile.toPath())).isEqualTo(storedKey);
  }

  @Test
  public void destroy_deletesStoredKeyAndWrappingKey() throws Exception {
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    dataKey.load();

    dataKey.destroy();

    expect.that(wrappedKeyFile.exists()).isFalse();
    expect.that(FakeAndroidKeyStoreSpi.keystoreEntries).doesNotContainKey(WRAPPING_KEY_ALIAS);
  }

  @Test
  public void destroy_whenKeystoreThrowsProviderException_throwsAndDeletesStoredKey()
      throws Exception {
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    dataKey.load();
    FakeAndroidKeyStoreSpi.isDeleteFailing = true;
    try {
      assertThrows(KeyStoreException.class, dataKey::destroy);
    } finally {
      FakeAndroidKeyStoreSpi.isDeleteFailing = false;
    }

    expect.that(wrappedKeyFile.exists()).isFalse();
  }

  @Test
  public void load_afterDestroy_returnsNewKey() throws Exception {
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    SecretKey destroyedKey = dataKey.load();
    dataKey.destroy();

    SecretKey newKey = dataKey.load();

    expect.that(newKey).isNotEqualTo(destroyedKey);
    expect.that(new CrumblesAuditDataKey(wrappedKeyFile).load()).isEqualTo(newKey);
  }

  @Test
  public void load_afterDestroy_cannotUnwrapCopyOfDestroyedKey() throws Exception {
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    SecretKey destroyedKey = dataKey.load();
    byte[] storedKey = Files.readAllBytes(wrappedKeyFile.toPath());
    dataKey.destroy();
    Files.write(wrappedKeyFile.toPath(), storedKey);

    SecretKey newKey = new CrumblesAuditDataKey(wrappedKeyFile).load();

    assertThat(newKey).isNotEqualTo(destroyedKey);
  }

  @Test
  public void takeStoredKeyReplacement_afterLoadReplacedStoredKey_returnsTrue() throws Exception {
    new CrumblesAuditDataKey(wrappedKeyFile).load();
    Files.write(wrappedKeyFile.toPath(), new byte[(int) wrappedKeyFile.length()]);
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    dataKey.load();

    assertThat(dataKey.takeStoredKeyReplacement()).isTrue();
  }

  @Test
  public void takeStoredKeyReplacement_whenAlreadyTaken_returnsFalse() throws Exception {
    new CrumblesAuditDataKey(wrappedKeyFile).load();
    Files.write(wrappedKeyFile.toPath(), new byte[(int) wrappedKeyFile.length()]);
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    dataKey.load();
    var unused = dataKey.takeStoredKeyReplacement();

    assertThat(dataKey.takeStoredKeyReplacement()).isFalse();
  }

  @Test
  public void takeStoredKeyReplacement_afterLoadCreatedFirstKey_returnsFalse() throws Exception {
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    dataKey.load();

    assertThat(dataKey.takeStoredKeyReplacement()).isFalse();
  }

  @Test
  public void takeStoredKeyReplacement_afterDestroy_returnsFalse() throws Exception {
    new CrumblesAuditDataKey(wrappedKeyFile).load();
    Files.write(wrappedKeyFile.toPath(), new byte[(int) wrappedKeyFile.length()]);
    CrumblesAuditDataKey dataKey = new CrumblesAuditDataKey(wrappedKeyFile);
    dataKey.load();
    dataKey.destroy();

    assertThat(dataKey.takeStoredKeyReplacement()).isFalse();
  }
}
