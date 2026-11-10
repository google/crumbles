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

import com.android.securelogging.exceptions.CrumblesKeysException;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class CrumblesScannedKeyVerifierTest {

  @Test
  public void parseScannedKey_withBase64PublicKey_returnsTheKey() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    PublicKey publicKey = generator.generateKeyPair().getPublic();

    PublicKey parsedKey =
        CrumblesScannedKeyVerifier.parseScannedKey(
            Base64.getEncoder().encodeToString(publicKey.getEncoded()));

    assertThat(parsedKey).isEqualTo(publicKey);
  }

  @Test
  public void parseScannedKey_whenLongerThanTheLimit_rejectsItWithoutDecoding() {
    String scannedText = "A".repeat(CrumblesScannedKeyVerifier.MAX_SCANNED_KEY_LENGTH + 1);

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class,
            () -> CrumblesScannedKeyVerifier.parseScannedKey(scannedText));

    assertThat(thrown).hasMessageThat().isEqualTo("Scanned text is longer than 4096 characters.");
  }

  @Test
  public void parseScannedKey_atTheLimit_decodesIt() {
    // Valid Base64 of zero bytes, which is not a key.
    String scannedText = "A".repeat(CrumblesScannedKeyVerifier.MAX_SCANNED_KEY_LENGTH);

    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class,
            () -> CrumblesScannedKeyVerifier.parseScannedKey(scannedText));

    assertThat(thrown).hasMessageThat().isEqualTo("Failed to convert Base64 string to PublicKey.");
  }

  @Test
  public void parseScannedKey_whenEmpty_throws() {
    CrumblesKeysException thrown =
        assertThrows(
            CrumblesKeysException.class, () -> CrumblesScannedKeyVerifier.parseScannedKey(""));

    assertThat(thrown).hasMessageThat().isEqualTo("Scanned text is empty.");
  }
}
