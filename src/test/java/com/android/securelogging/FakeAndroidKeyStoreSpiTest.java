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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.security.keystore.UserNotAuthenticatedException;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Tests for the secret keys and the per-alias authentication of {@link FakeAndroidKeyStoreSpi}. */
@RunWith(AndroidJUnit4.class)
public final class FakeAndroidKeyStoreSpiTest {
  private static final String ALIAS = "alias";
  private static final SecretKey secretKey = new SecretKeySpec(new byte[32], "AES");
  private static final FakeAndroidKeyStoreSpi keyStoreSpi = new FakeAndroidKeyStoreSpi();

  @Before
  public void setUp() throws KeyStoreException {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
    keyStoreSpi.engineSetEntry(
        ALIAS,
        new KeyStore.SecretKeyEntry(secretKey),
        new KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                /* timeout= */ 30, KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .build());
  }

  private static void initDecryptCipher() throws Exception {
    Key key = keyStoreSpi.engineGetKey(ALIAS, /* password= */ null);
    Cipher.getInstance("AES/CBC/NoPadding", new FakeAndroidKeyStoreProvider())
        .init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
  }

  @Test
  public void setEntry_withKeyProtection_storesKeyWithThatProtection() throws KeyStoreException {
    KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT).build();

    keyStoreSpi.engineSetEntry(ALIAS, new KeyStore.SecretKeyEntry(secretKey), protection);

    assertThat(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsExactly(ALIAS, new FakeAndroidKeyStoreSpi.SecretKeyEntry(secretKey, protection));
  }

  @Test
  public void setEntry_withoutKeyProtection_throws() {
    assertThrows(
        KeyStoreException.class,
        () ->
            keyStoreSpi.engineSetEntry(
                ALIAS, new KeyStore.SecretKeyEntry(secretKey), /* protParam= */ null));
  }

  @Test
  public void cipherInit_whenUserAuthenticatedForThatAliasAlone_succeeds() throws Exception {
    FakeAndroidKeyStoreSpi.setUserAuthenticated(ALIAS, true);

    initDecryptCipher();
  }

  @Test
  public void cipherInit_withAnotherProvider_refusesKeyThatRequiresAuthentication()
      throws Exception {
    Key key = keyStoreSpi.engineGetKey(ALIAS, /* password= */ null);
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");

    assertThrows(
        InvalidKeyException.class,
        () -> cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16])));
  }

  @Test
  public void cipherInit_whenAliasStateOverridesGlobalAuthentication_throws() {
    FakeAndroidKeyStoreSpi.setUserAuthenticated(true);
    FakeAndroidKeyStoreSpi.setUserAuthenticated(ALIAS, false);

    assertThrows(
        UserNotAuthenticatedException.class, FakeAndroidKeyStoreSpiTest::initDecryptCipher);
  }

  @Test
  public void setUserAuthenticated_forEveryKey_clearsAliasStates() {
    FakeAndroidKeyStoreSpi.setUserAuthenticated(ALIAS, true);

    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);

    assertThrows(
        UserNotAuthenticatedException.class, FakeAndroidKeyStoreSpiTest::initDecryptCipher);
  }

  @Test
  public void isKeyEntry_withStoredSecretKey_returnsTrue() {
    assertThat(keyStoreSpi.engineIsKeyEntry(ALIAS)).isTrue();
  }

  @Test
  public void isKeyEntry_withUnknownAlias_returnsFalse() {
    assertThat(keyStoreSpi.engineIsKeyEntry("unknown")).isFalse();
  }
}
