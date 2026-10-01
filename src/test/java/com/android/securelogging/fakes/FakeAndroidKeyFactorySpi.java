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

package com.android.securelogging.fakes;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.security.keystore.KeyInfo;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Fake AndroidKeyStore {@link KeyFactorySpi} that only exposes the {@link KeyInfo} of private keys
 * held by {@link FakeAndroidKeyStoreSpi}, reporting the encryption paddings they were generated
 * with.
 */
public class FakeAndroidKeyFactorySpi extends KeyFactorySpi {

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    FakeAndroidKeyStoreSpi.PrivateKeyEntry entry = FakeAndroidKeyStoreSpi.findPrivateKeyEntry(key);
    if (!keySpec.equals(KeyInfo.class) || entry == null || entry.getSpec() == null) {
      throw new InvalidKeySpecException("Only the KeyInfo of fake Keystore keys is supported.");
    }
    KeyInfo keyInfo = mock(KeyInfo.class);
    when(keyInfo.getEncryptionPaddings()).thenReturn(entry.getSpec().getEncryptionPaddings());
    return keySpec.cast(keyInfo);
  }

  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) {
    throw new UnsupportedOperationException("Not supported by this fake.");
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) {
    throw new UnsupportedOperationException("Not supported by this fake.");
  }

  @Override
  protected Key engineTranslateKey(Key key) {
    throw new UnsupportedOperationException("Not supported by this fake.");
  }
}
