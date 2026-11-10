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

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.WireFormat;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogData;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.ProviderException;
import java.security.Security;
import java.security.Signature;
import javax.crypto.KeyGenerator;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Tests for {@link CrumblesBatchSigner} with a fake AndroidKeyStore provider. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesBatchSignerTest {
  private static final LogBatch BATCH =
      LogBatch.newBuilder()
          .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("ciphertext")))
          .build();
  private static final LogBatch RE_ENCRYPTED_BATCH =
      LogBatch.newBuilder()
          .setData(LogData.newBuilder().setLogBlob(ByteString.copyFromUtf8("new ciphertext")))
          .build();
  private static final LogMetadata VERSION_2_METADATA =
      LogMetadata.newBuilder()
          .setEncryptionType(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA)
          .build();
  private static final LogBatch VERSION_2_BATCH =
      BATCH.toBuilder().setMetadata(VERSION_2_METADATA).build();

  @Rule public final Expect expect = Expect.create();

  private Context context;

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
    FakeAndroidKeyStoreSpi.certificateLookupFailure = null;
    context = ApplicationProvider.getApplicationContext();
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit();
  }

  @Test
  public void sign_numbersBatchesFromOne() throws Exception {
    LogBatch first = new CrumblesBatchSigner(context).sign(BATCH);
    LogBatch second = new CrumblesBatchSigner(context).sign(BATCH);

    expect.that(first.getSequenceNumber()).isEqualTo(1);
    expect.that(second.getSequenceNumber()).isEqualTo(2);
  }

  @Test
  public void sign_signsBatchFileWithoutSignatureField() throws Exception {
    LogBatch signed = new CrumblesBatchSigner(context).sign(BATCH);

    expect.that(verifies(signed)).isTrue();
    expect.that(signed.getData()).isEqualTo(BATCH.getData());
  }

  @Test
  public void sign_replacesExistingSignature() throws Exception {
    LogBatch signedOnce = new CrumblesBatchSigner(context).sign(BATCH);

    LogBatch signedTwice = new CrumblesBatchSigner(context).sign(signedOnce);

    expect.that(verifies(signedTwice)).isTrue();
    expect.that(signedTwice.getSequenceNumber()).isEqualTo(2);
  }

  @Test
  public void sign_ofVersion1Batch_keepsTheAttestationChainInTheSignature() throws Exception {
    LogBatch signed = new CrumblesBatchSigner(context).sign(BATCH);

    assertThat(signed.getSignature().getAttestationChainList()).isNotEmpty();
  }

  @Test
  public void sign_ofVersion2Batch_leavesTheSealedAttestationChainOutOfTheSignature()
      throws Exception {
    LogBatch signed = new CrumblesBatchSigner(context).sign(VERSION_2_BATCH);

    expect.that(signed.getSignature().getAttestationChainList()).isEmpty();
    expect.that(verifies(signed)).isTrue();
  }

  @Test
  public void sign_afterFailedSignature_reusesSequenceNumber() throws Exception {
    KeyGenerator generator =
        KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256, FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    generator.init(
        new KeyGenParameterSpec.Builder(CrumblesBatchSigningKey.ALIAS, KeyProperties.PURPOSE_SIGN)
            .build());
    generator.generateKey();
    assertThrows(CrumblesKeysException.class, () -> new CrumblesBatchSigner(context).sign(BATCH));
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();

    LogBatch signed = new CrumblesBatchSigner(context).sign(BATCH);

    assertThat(signed.getSequenceNumber()).isEqualTo(1);
  }

  @Test
  public void sign_whenSequenceNumberCannotBeStored_throws() {
    File preferencesDirectory = new File(context.getDataDir(), "shared_prefs");
    assertThat(preferencesDirectory.setWritable(false)).isTrue();
    try {
      assertThrows(
          CrumblesKeysException.class, () -> new CrumblesBatchSigner(context).sign(BATCH));
    } finally {
      preferencesDirectory.setWritable(true);
    }
  }

  @Test
  public void signAgain_signsReEncryptedBatchUnderOriginalSequenceNumber() throws Exception {
    var unused = new CrumblesBatchSigner(context).sign(BATCH);
    LogBatch original = new CrumblesBatchSigner(context).sign(BATCH);
    LogBatch reEncrypted =
        RE_ENCRYPTED_BATCH.toBuilder().setSignature(original.getSignature()).build();

    LogBatch signedAgain = new CrumblesBatchSigner(context).signAgain(original, reEncrypted);

    expect.that(signedAgain.getSequenceNumber()).isEqualTo(2);
    expect.that(signedAgain.getData()).isEqualTo(RE_ENCRYPTED_BATCH.getData());
    expect.that(verifies(signedAgain)).isTrue();
  }

  @Test
  public void signAgain_usesNoNewSequenceNumber() throws Exception {
    LogBatch original = new CrumblesBatchSigner(context).sign(BATCH);
    var unused = new CrumblesBatchSigner(context).signAgain(original, RE_ENCRYPTED_BATCH);

    LogBatch next = new CrumblesBatchSigner(context).sign(BATCH);

    assertThat(next.getSequenceNumber()).isEqualTo(2);
  }

  @Test
  public void signAgain_ofVersion2Batch_leavesTheSealedAttestationChainOutOfTheSignature()
      throws Exception {
    LogBatch original = new CrumblesBatchSigner(context).sign(VERSION_2_BATCH);
    LogBatch reEncrypted = RE_ENCRYPTED_BATCH.toBuilder().setMetadata(VERSION_2_METADATA).build();

    LogBatch signedAgain = new CrumblesBatchSigner(context).signAgain(original, reEncrypted);

    expect.that(signedAgain.getSignature().getAttestationChainList()).isEmpty();
    expect.that(verifies(signedAgain)).isTrue();
  }

  @Test
  public void signAgain_whenOriginalWasAltered_throws() throws Exception {
    LogBatch original = new CrumblesBatchSigner(context).sign(BATCH);
    LogBatch altered = original.toBuilder().setData(RE_ENCRYPTED_BATCH.getData()).build();

    assertThrows(
        CrumblesKeysException.class,
        () -> new CrumblesBatchSigner(context).signAgain(altered, RE_ENCRYPTED_BATCH));
  }

  @Test
  public void signAgain_whenOriginalIsUnsigned_throws() throws Exception {
    var unused = new CrumblesBatchSigner(context).sign(BATCH);

    assertThrows(
        CrumblesKeysException.class,
        () -> new CrumblesBatchSigner(context).signAgain(BATCH, RE_ENCRYPTED_BATCH));
  }

  @Test
  public void signAgain_whenInstallationHasNoSigningKey_throws() throws Exception {
    LogBatch original = new CrumblesBatchSigner(context).sign(BATCH);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();

    assertThrows(
        CrumblesKeysException.class,
        () -> new CrumblesBatchSigner(context).signAgain(original, RE_ENCRYPTED_BATCH));
  }

  @Test
  public void isSignedByThisInstallation_ofBatchItSigned_isTrue() throws Exception {
    LogBatch signed = new CrumblesBatchSigner(context).sign(BATCH);

    assertThat(new CrumblesBatchSigner(context).isSignedByThisInstallation(signed)).isTrue();
  }

  @Test
  public void isSignedByThisInstallation_ofUnsignedBatch_isFalse() throws Exception {
    var unused = new CrumblesBatchSigner(context).sign(BATCH);

    assertThat(new CrumblesBatchSigner(context).isSignedByThisInstallation(BATCH)).isFalse();
  }

  @Test
  public void isSignedByThisInstallation_ofBatchSignedWithAnotherKey_isFalse() throws Exception {
    LogBatch signedWithEarlierKey = new CrumblesBatchSigner(context).sign(BATCH);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    var unused = new CrumblesBatchSigner(context).sign(BATCH);

    assertThat(new CrumblesBatchSigner(context).isSignedByThisInstallation(signedWithEarlierKey))
        .isFalse();
  }

  @Test
  public void isSignedByThisInstallation_whenInstallationHasNoSigningKey_isFalseAndCreatesNone()
      throws Exception {
    LogBatch signed = new CrumblesBatchSigner(context).sign(BATCH);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();

    boolean signedByThisInstallation =
        new CrumblesBatchSigner(context).isSignedByThisInstallation(signed);

    expect.that(signedByThisInstallation).isFalse();
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesBatchSigningKey.ALIAS);
  }

  @Test
  public void isSignedByThisInstallation_whenTheKeyCannotBeRead_isFalse() throws Exception {
    LogBatch signed = new CrumblesBatchSigner(context).sign(BATCH);
    FakeAndroidKeyStoreSpi.certificateLookupFailure = new ProviderException("Keystore failed");

    assertThat(new CrumblesBatchSigner(context).isSignedByThisInstallation(signed)).isFalse();
  }

  /** Verifies {@code batch} as its recipient does, on the file bytes without field 5. */
  private static boolean verifies(LogBatch batch) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    keyStore.load(/* param= */ null);
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(keyStore.getCertificate(CrumblesBatchSigningKey.ALIAS).getPublicKey());
    verifier.update(withoutSignatureField(batch.toByteArray()));
    return verifier.verify(batch.getSignature().getSignature().toByteArray());
  }

  private static byte[] withoutSignatureField(byte[] batchFile) throws IOException {
    CodedInputStream input = CodedInputStream.newInstance(batchFile);
    ByteString.Output output = ByteString.newOutput();
    while (!input.isAtEnd()) {
      int fieldStart = input.getTotalBytesRead();
      int tag = input.readTag();
      input.skipField(tag);
      if (WireFormat.getTagFieldNumber(tag) != LogBatch.SIGNATURE_FIELD_NUMBER) {
        output.write(batchFile, fieldStart, input.getTotalBytesRead() - fieldStart);
      }
    }
    return output.toByteString().toByteArray();
  }
}
