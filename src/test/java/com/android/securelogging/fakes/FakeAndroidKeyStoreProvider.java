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

package com.android.securelogging.fakes;

import java.security.Provider;

/** A fake provider to register a fake KeyStore and KeyPairGenerator for testing purposes. */
public class FakeAndroidKeyStoreProvider extends Provider {
  public static final String PROVIDER_NAME =
      "AndroidKeyStore"; // Match what CrumblesLogsEncryptor expects.

  public FakeAndroidKeyStoreProvider() {
    super(PROVIDER_NAME, "1.0", "Fake AndroidKeyStore Provider for Testing");

    // Register the KeyStoreSpi.
    put("KeyStore." + PROVIDER_NAME, FakeAndroidKeyStoreSpi.class.getName());

    // CrumblesLogsEncryptor calls: KeyPairGenerator.getInstance("RSA", "AndroidKeyStore").
    // So, our provider (named "AndroidKeyStore") needs to offer an "RSA" KeyPairGenerator.
    put("KeyPairGenerator.RSA", FakeAndroidKeyPairGeneratorSpi.class.getName());
    put("KeyPairGenerator.EC", FakeAndroidKeyPairGeneratorSpi.Ec.class.getName());
    put("KeyGenerator.HmacSHA256", FakeAndroidKeyStoreSpi.HmacKeyGeneratorSpi.class.getName());
    put("KeyGenerator.AES", FakeAndroidKeyStoreSpi.AesKeyGeneratorSpi.class.getName());
    put("KeyFactory.RSA", FakeAndroidKeyFactorySpi.class.getName());
    // Only offered for keys that FakeAndroidKeyStoreSpi.invalidateKey() invalidated, which no other
    // provider accepts.
    put("Cipher.RSA", FakeAndroidKeyStoreSpi.InvalidatedKeyCipherSpi.class.getName());
    put(
        "Cipher.RSA SupportedKeyClasses",
        FakeAndroidKeyStoreSpi.InvalidatedPrivateKey.class.getName());
    for (String transformation :
        new String[] {
          "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA/ECB/PKCS1Padding", "AES/CBC/NoPadding"
        }) {
      putService(
          new Service(this, "Cipher", transformation, "Spi", null, null) {
            @Override
            public boolean supportsParameter(Object key) {
              return FakeAndroidKeyStoreSpi.holdsKey(key);
            }

            @Override
            public Object newInstance(Object parameter) {
              return new FakeAndroidKeyStoreSpi.FakeCipherSpi(transformation);
            }
          });
    }
  }
}
