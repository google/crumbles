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

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import com.google.testing.junit.testparameterinjector.TestParameter;
import java.security.GeneralSecurityException;
import java.security.ProviderException;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;

@RunWith(RobolectricTestParameterInjector.class)
public final class CrumblesLogStagingSealerTest {
  private static final String NAME = "0000000000000000001.sealed";
  private static final String OTHER_NAME = "0000000000000000002.sealed";
  private static final byte[] logs = "Security log ID: 1".getBytes(UTF_8);

  @Rule public final Expect expect = Expect.create();

  @Before
  public void setUp() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = false;
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = false;
    FakeAndroidKeyStoreSpi.strongBoxFailure = null;
  }

  @After
  public void tearDown() {
    FakeAndroidKeyStoreSpi.strongBoxFailure = null;
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Test
  public void unseal_returnsEachBatchSealedUnderTheWrappingKey() throws Exception {
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);
    byte[] sealedEmpty = CrumblesLogStagingSealer.seal(new byte[0], OTHER_NAME);

    byte[] unsealed = CrumblesLogStagingSealer.unseal(sealed, NAME);
    byte[] unsealedEmpty = CrumblesLogStagingSealer.unseal(sealedEmpty, OTHER_NAME);

    expect.that(unsealed).isEqualTo(logs);
    expect.that(unsealedEmpty).isEmpty();
  }

  @Test
  public void seal_hidesTheLogsAndAddsTheOverhead() throws Exception {
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);

    expect.that(new String(sealed, ISO_8859_1)).doesNotContain("Security log");
    expect.that(sealed).hasLength(logs.length + CrumblesLogStagingSealer.OVERHEAD_BYTES);
    // The version, the wrapping IV, the wrapped key and its tag, the data IV and the data tag.
    expect.that(CrumblesLogStagingSealer.OVERHEAD_BYTES).isEqualTo(1 + 12 + 32 + 16 + 12 + 16);
  }

  @Test
  public void seal_usesAFreshDataKeyAndDataIvForEachBatch() throws Exception {
    byte[] first = CrumblesLogStagingSealer.seal(logs, NAME);
    byte[] second = CrumblesLogStagingSealer.seal(logs, NAME);

    expect.that(unwrapDataKey(first)).isNotEqualTo(unwrapDataKey(second));
    expect.that(Arrays.copyOfRange(first, 61, 73)).isNotEqualTo(Arrays.copyOfRange(second, 61, 73));
  }

  @Test
  public void seal_createsAStrongBoxWrappingKeyUsableWhileLocked() throws Exception {
    var unused = CrumblesLogStagingSealer.seal(logs, NAME);

    KeyGenParameterSpec spec = FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec();
    expect.that(spec.getKeystoreAlias()).isEqualTo(CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS);
    expect
        .that(spec.getPurposes())
        .isEqualTo(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
    expect.that(spec.getKeySize()).isEqualTo(256);
    expect.that(spec.getBlockModes()).asList().containsExactly(KeyProperties.BLOCK_MODE_GCM);
    expect
        .that(spec.getEncryptionPaddings())
        .asList()
        .containsExactly(KeyProperties.ENCRYPTION_PADDING_NONE);
    expect.that(spec.isUserAuthenticationRequired()).isFalse();
    expect.that(spec.isUnlockedDeviceRequired()).isFalse();
    expect.that(spec.isStrongBoxBacked()).isTrue();
  }

  @Test
  public void seal_withoutStrongBox_createsATeeWrappingKey() throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = false;

    var unused = CrumblesLogStagingSealer.seal(logs, NAME);

    expect
        .that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked())
        .isFalse();
  }

  @Test
  public void seal_whenStrongBoxFails_createsATeeWrappingKey() throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = true;

    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);

    expect
        .that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked())
        .isFalse();
    expect.that(CrumblesLogStagingSealer.unseal(sealed, NAME)).isEqualTo(logs);
  }

  @Test
  public void seal_whenStrongBoxThrowsGeneralSecurityException_createsATeeWrappingKey()
      throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = true;

    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);

    expect
        .that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked())
        .isFalse();
    expect.that(CrumblesLogStagingSealer.unseal(sealed, NAME)).isEqualTo(logs);
  }

  @Test
  public void seal_whenStrongBoxThrowsOtherUncheckedException_createsATeeWrappingKey()
      throws Exception {
    FakeAndroidKeyStoreSpi.strongBoxFailure = new IllegalStateException("StrongBox failed");

    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);

    expect
        .that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked())
        .isFalse();
    expect.that(CrumblesLogStagingSealer.unseal(sealed, NAME)).isEqualTo(logs);
  }

  /** Unchecked exceptions that Keystore throws on some devices. */
  private enum UncheckedKeystoreFailure {
    PROVIDER_EXCEPTION {
      @Override
      RuntimeException create() {
        return new ProviderException("Keystore cannot be reached.");
      }
    },
    OTHER_UNCHECKED_EXCEPTION {
      @Override
      RuntimeException create() {
        return new IllegalStateException("Keystore failed.");
      }
    };

    abstract RuntimeException create();
  }

  @Test
  public void seal_whenKeystoreThrowsUncheckedException_throwsGeneralSecurityException(
      @TestParameter UncheckedKeystoreFailure keystoreFailure) {
    RuntimeException failure = keystoreFailure.create();
    FakeAndroidKeyStoreSpi.failKeyLookup(CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS, failure);

    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class, () -> CrumblesLogStagingSealer.seal(logs, NAME));

    expect.that(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  @Test
  public void unseal_whenKeystoreThrowsUnchecked_throwsGeneralSecurityExceptionNotBadTag(
      @TestParameter UncheckedKeystoreFailure keystoreFailure) throws Exception {
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);
    RuntimeException failure = keystoreFailure.create();
    FakeAndroidKeyStoreSpi.failKeyLookup(CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS, failure);

    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class, () -> CrumblesLogStagingSealer.unseal(sealed, NAME));

    // An AEADBadTagException would get the staged batch deleted as unreadable.
    expect.that(thrown).isNotInstanceOf(AEADBadTagException.class);
    expect.that(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  /** Bytes of a sealed batch, by offset. */
  private enum SealedByte {
    VERSION(0),
    WRAPPING_IV(1),
    WRAPPED_KEY(13),
    DATA_IV(61),
    CIPHERTEXT(73);

    final int offset;

    SealedByte(int offset) {
      this.offset = offset;
    }
  }

  @Test
  public void unseal_whenAByteIsAltered_throwsAeadBadTag(@TestParameter SealedByte alteredByte)
      throws Exception {
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);
    sealed[alteredByte.offset] = (byte) (sealed[alteredByte.offset] ^ 1);

    assertThrows(AEADBadTagException.class, () -> CrumblesLogStagingSealer.unseal(sealed, NAME));
  }

  @Test
  public void unseal_whenTruncated_throwsAeadBadTag() throws Exception {
    byte[] truncated = Arrays.copyOf(CrumblesLogStagingSealer.seal(logs, NAME), 40);

    assertThrows(AEADBadTagException.class, () -> CrumblesLogStagingSealer.unseal(truncated, NAME));
  }

  @Test
  public void unseal_underAnotherName_throwsAeadBadTag() throws Exception {
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);

    assertThrows(
        AEADBadTagException.class, () -> CrumblesLogStagingSealer.unseal(sealed, OTHER_NAME));
  }

  @Test
  public void unseal_whenWrappingKeyIsGone_throwsAeadBadTag() throws Exception {
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, NAME);
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS);

    assertThrows(AEADBadTagException.class, () -> CrumblesLogStagingSealer.unseal(sealed, NAME));
  }

  /** Returns the data key in {@code sealed}, unwrapped with the fake Keystore's wrapping key. */
  private static byte[] unwrapDataKey(byte[] sealed) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        FakeAndroidKeyStoreSpi.keystoreEntries
            .get(CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS)
            .getKey(),
        new GCMParameterSpec(128, sealed, 1, 12));
    return cipher.doFinal(sealed, 13, 48);
  }
}
