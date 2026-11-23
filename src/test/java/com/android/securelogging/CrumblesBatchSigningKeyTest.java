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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import android.content.Context;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.test.core.app.ApplicationProvider;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.BatchSignature;
import com.google.testing.junit.testparameterinjector.TestParameter;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import javax.crypto.KeyGenerator;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;
import org.robolectric.shadows.ShadowBuild;

/** Tests for {@link CrumblesBatchSigningKey} with a fake AndroidKeyStore provider. */
@RunWith(RobolectricTestParameterInjector.class)
public final class CrumblesBatchSigningKeyTest {
  private static final String DATA = "serialized log batch";
  private static final String SERIAL = "hardware_serial_12345";

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private CrumblesBatchSigningKey signingKey;

  @BeforeClass
  public static void installFakeKeystore() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
  }

  @AfterClass
  public static void removeFakeKeystore() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Before
  public void setUp() {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = false;
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = false;
    FakeAndroidKeyStoreSpi.strongBoxFailure = null;
    FakeAndroidKeyStoreSpi.isCertificateChainNull = false;
    FakeAndroidKeyStoreSpi.certificateLookupFailure = null;
    FakeAndroidKeyStoreSpi.isDeleteFailing = false;
    FakeAndroidKeyStoreSpi.deleteFailure = null;
    context = ApplicationProvider.getApplicationContext();
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    signingKey = new CrumblesBatchSigningKey(context);
  }

  @Test
  public void sign_returnsSignatureByTheKeyAndItsAttestationChain() throws Exception {
    BatchSignature signature = signingKey.sign(DATA.getBytes(UTF_8));

    expect.that(verifies(signature, keystorePublicKey())).isTrue();
    expect.that(signature.getAttestationChainList()).containsExactlyElementsIn(keystoreChain());
  }

  @Test
  public void sign_createsAttestedP256KeyInStrongBox() throws Exception {
    var unused = signingKey.sign(DATA.getBytes(UTF_8));

    KeyGenParameterSpec spec = keystoreSpec();
    expect.that(spec.isStrongBoxBacked()).isTrue();
    expect.that(spec.getPurposes()).isEqualTo(KeyProperties.PURPOSE_SIGN);
    expect.that(spec.getDigests()).asList().containsExactly(KeyProperties.DIGEST_SHA256);
    expect.that(spec.isUserAuthenticationRequired()).isFalse();
    expect
        .that(spec.getAttestationChallenge())
        .isEqualTo(CrumblesDeviceIdManager.getDeviceId(context).getBytes(UTF_8));
    expect
        .that(((ECPublicKey) keystorePublicKey()).getParams().getCurve().getField().getFieldSize())
        .isEqualTo(256);
  }

  /** Ways in which StrongBox can fail to create the key. */
  private enum StrongBoxFailure {
    UNAVAILABLE {
      @Override
      void simulate() {
        FakeAndroidKeyStoreSpi.isStrongBoxSupported = false;
      }
    },
    OTHER_PROVIDER_EXCEPTION {
      @Override
      void simulate() {
        FakeAndroidKeyStoreSpi.isStrongBoxFailing = true;
      }
    },
    GENERAL_SECURITY_EXCEPTION {
      @Override
      void simulate() {
        FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = true;
      }
    },
    OTHER_UNCHECKED_EXCEPTION {
      @Override
      void simulate() {
        FakeAndroidKeyStoreSpi.strongBoxFailure = new IllegalStateException("StrongBox failed");
      }
    };

    abstract void simulate();
  }

  @Test
  public void sign_whenStrongBoxCannotCreateTheKey_createsKeyInTee(
      @TestParameter StrongBoxFailure strongBoxFailure) throws Exception {
    strongBoxFailure.simulate();

    BatchSignature signature = signingKey.sign(DATA.getBytes(UTF_8));

    expect.that(verifies(signature, keystorePublicKey())).isTrue();
    expect.that(keystoreSpec().isStrongBoxBacked()).isFalse();
  }

  @Test
  public void sign_again_keepsTheKey() throws Exception {
    BatchSignature first = signingKey.sign(DATA.getBytes(UTF_8));

    @SuppressWarnings("unused")
    var unusedSignature = new CrumblesBatchSigningKey(context).sign(DATA.getBytes(UTF_8));

    assertThat(verifies(first, keystorePublicKey())).isTrue();
  }

  @Test
  public void sign_afterHardwareAttributionIsEnabled_createsKeyAttestedToTheNewDeviceId()
      throws Exception {
    ShadowBuild.setSerial(SERIAL);
    @SuppressWarnings("unused")
    var unusedInitialSignature = signingKey.sign(DATA.getBytes(UTF_8));

    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);
    @SuppressWarnings("unused")
    var unusedRotatedSignature = signingKey.sign(DATA.getBytes(UTF_8));

    expect.that(keystoreSpec().getAttestationChallenge()).isEqualTo(SERIAL.getBytes(UTF_8));
    expect.that(CrumblesDeviceIdManager.getDeviceId(context)).isEqualTo(SERIAL);
    expect.that(countAuditEvents("BATCH_SIGNING_KEY_ROTATED")).isEqualTo(1);
  }

  @Test
  public void sign_afterHardwareAttributionIsSetToTheSameValue_keepsTheKey() throws Exception {
    ShadowBuild.setSerial(SERIAL);
    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);
    BatchSignature first = signingKey.sign(DATA.getBytes(UTF_8));

    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);
    @SuppressWarnings("unused")
    var unusedKeptSignature = signingKey.sign(DATA.getBytes(UTF_8));

    expect.that(verifies(first, keystorePublicKey())).isTrue();
    expect.that(countAuditEvents("BATCH_SIGNING_KEY_ROTATED")).isEqualTo(1);
  }

  @Test
  public void sign_afterHardwareAttributionIsEnabledWithoutHardwareIds_keepsTheKey()
      throws Exception {
    Settings.Secure.putString(context.getContentResolver(), Settings.Secure.ANDROID_ID, "");
    BatchSignature first = signingKey.sign(DATA.getBytes(UTF_8));

    CrumblesDeviceIdManager.setHardwareAttributionEnabled(context, /* enabled= */ true);
    @SuppressWarnings("unused")
    var unusedKeptSignature = signingKey.sign(DATA.getBytes(UTF_8));

    expect.that(verifies(first, keystorePublicKey())).isTrue();
    expect.that(countAuditEvents("BATCH_SIGNING_KEY_ROTATED")).isEqualTo(0);
    expect.that(countAuditEvents("BATCH_SIGNING_KEY_KEPT")).isEqualTo(1);
  }

  @Test
  public void sign_whenAliasHoldsSecretKey_throws() throws Exception {
    KeyGenerator generator =
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256, FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    generator.init(
        new KeyGenParameterSpec.Builder(CrumblesBatchSigningKey.ALIAS, KeyProperties.PURPOSE_SIGN)
            .build());
    generator.generateKey();

    assertThrows(CrumblesKeysException.class, () -> signingKey.sign(DATA.getBytes(UTF_8)));
  }

  @Test
  public void sign_whenAliasHoldsRsaKey_throws() throws Exception {
    KeyPairGenerator generator =
        KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    generator.initialize(
        new KeyGenParameterSpec.Builder(
                CrumblesBatchSigningKey.ALIAS, KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(2048)
            .build());
    generator.generateKeyPair();

    CrumblesKeysException thrown =
        assertThrows(CrumblesKeysException.class, () -> signingKey.sign(DATA.getBytes(UTF_8)));

    assertThat(thrown).hasCauseThat().isInstanceOf(InvalidKeyException.class);
  }

  @Test
  public void sign_whenCertificateChainIsNull_throwsCrumblesKeysException() throws Exception {
    FakeAndroidKeyStoreSpi.isCertificateChainNull = true;

    assertThrows(CrumblesKeysException.class, () -> signingKey.sign(DATA.getBytes(UTF_8)));
  }

  @Test
  public void attestationChain_isTheChainOfTheKeyThatThenSigns() throws Exception {
    ImmutableList<ByteString> chain = signingKey.attestationChain();

    BatchSignature signature = new CrumblesBatchSigningKey(context).sign(DATA.getBytes(UTF_8));

    expect.that(chain).containsExactlyElementsIn(keystoreChain()).inOrder();
    expect.that(signature.getAttestationChainList()).containsExactlyElementsIn(chain).inOrder();
    expect.that(verifies(signature, keystorePublicKey())).isTrue();
  }

  @Test
  public void attestationChain_createsAttestedKeyForTheDeviceId() throws Exception {
    var unused = signingKey.attestationChain();

    expect.that(keystoreSpec().getPurposes()).isEqualTo(KeyProperties.PURPOSE_SIGN);
    expect
        .that(keystoreSpec().getAttestationChallenge())
        .isEqualTo(CrumblesDeviceIdManager.getDeviceId(context).getBytes(UTF_8));
  }

  @Test
  public void attestationChain_whenCertificateChainIsNull_throwsCrumblesKeysException() {
    FakeAndroidKeyStoreSpi.isCertificateChainNull = true;

    assertThrows(CrumblesKeysException.class, signingKey::attestationChain);
  }

  /** Unchecked exceptions that Keystore throws on some devices. */
  private enum UncheckedKeystoreFailure {
    PROVIDER_EXCEPTION {
      @Override
      RuntimeException create() {
        return new ProviderException("Keystore failed");
      }
    },
    OTHER_UNCHECKED_EXCEPTION {
      @Override
      RuntimeException create() {
        return new IllegalStateException("Keystore failed");
      }
    };

    abstract RuntimeException create();
  }

  @Test
  public void sign_whenKeystoreThrowsUncheckedException_throwsCrumblesKeysException(
      @TestParameter UncheckedKeystoreFailure keystoreFailure) {
    RuntimeException failure = keystoreFailure.create();
    FakeAndroidKeyStoreSpi.failKeyLookup(CrumblesBatchSigningKey.ALIAS, failure);

    CrumblesKeysException thrown =
        assertThrows(CrumblesKeysException.class, () -> signingKey.sign(DATA.getBytes(UTF_8)));

    assertThat(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  @Test
  public void attestationChain_whenKeystoreThrowsUncheckedException_throwsCrumblesKeysException(
      @TestParameter UncheckedKeystoreFailure keystoreFailure) {
    RuntimeException failure = keystoreFailure.create();
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesBatchSigningKey.ALIAS,
        new FakeAndroidKeyStoreSpi.PrivateKeyEntry(
            /* privateKey= */ null, /* certificateChain= */ null, /* spec= */ null) {
          @Override
          public Certificate[] getCertificateChain() {
            throw failure;
          }
        });

    CrumblesKeysException thrown =
        assertThrows(CrumblesKeysException.class, signingKey::attestationChain);

    assertThat(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  @Test
  public void verifies_whenKeystoreThrowsUncheckedException_throwsCrumblesKeysException(
      @TestParameter UncheckedKeystoreFailure keystoreFailure) throws Exception {
    BatchSignature signature = signingKey.sign(DATA.getBytes(UTF_8));
    RuntimeException failure = keystoreFailure.create();
    FakeAndroidKeyStoreSpi.certificateLookupFailure = failure;

    CrumblesKeysException thrown;
    try {
      thrown =
          assertThrows(
              CrumblesKeysException.class,
              () ->
                  signingKey.verifies(
                      DATA.getBytes(UTF_8), signature.getSignature().toByteArray()));
    } finally {
      FakeAndroidKeyStoreSpi.certificateLookupFailure = null;
    }

    assertThat(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  @Test
  public void delete_whenKeystoreThrowsUncheckedException_throwsCrumblesKeysException(
      @TestParameter UncheckedKeystoreFailure keystoreFailure) throws Exception {
    @SuppressWarnings("unused")
    var unusedSignature = signingKey.sign(DATA.getBytes(UTF_8));
    RuntimeException failure = keystoreFailure.create();
    FakeAndroidKeyStoreSpi.deleteFailure = failure;

    CrumblesKeysException thrown = assertThrows(CrumblesKeysException.class, signingKey::delete);

    assertThat(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  private static boolean verifies(BatchSignature signature, PublicKey publicKey) throws Exception {
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(publicKey);
    verifier.update(DATA.getBytes(UTF_8));
    return verifier.verify(signature.getSignature().toByteArray());
  }

  private static KeyStore loadKeystore() throws Exception {
    KeyStore keyStore = KeyStore.getInstance(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    keyStore.load(/* param= */ null);
    return keyStore;
  }

  private static PublicKey keystorePublicKey() throws Exception {
    return loadKeystore().getCertificate(CrumblesBatchSigningKey.ALIAS).getPublicKey();
  }

  private static ImmutableList<ByteString> keystoreChain() throws Exception {
    Certificate[] certificates = loadKeystore().getCertificateChain(CrumblesBatchSigningKey.ALIAS);
    ImmutableList.Builder<ByteString> chain = ImmutableList.builder();
    for (Certificate certificate : certificates) {
      chain.add(ByteString.copyFrom(certificate.getEncoded()));
    }
    return chain.build();
  }

  private static KeyGenParameterSpec keystoreSpec() {
    return FakeAndroidKeyStoreSpi.getPrivateKeyEntry(CrumblesBatchSigningKey.ALIAS).getSpec();
  }

  private long countAuditEvents(String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .filter(event -> event.getEventType().equals(eventType))
        .count();
  }
}
