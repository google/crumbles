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

import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.BatchSignature;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * The installation's batch-signing key: an attested EC P-256 Android Keystore key that signs log
 * batches, so that their recipient can check which installation wrote them.
 *
 * <p>The key is created on first use, in StrongBox when the device has one that can create it and
 * in the TEE otherwise. It cannot leave the device and needs no user authentication, because
 * batches are written while the device is locked. Its attestation chain goes with every signed
 * batch, sealed inside the ciphertext of a format version 2 batch: the chain shows that the key is
 * hardware-backed and was created by this app, and its attestation challenge is the device ID that
 * {@link CrumblesDeviceIdManager} stamps into every batch.
 *
 * <p>{@link CrumblesDeviceIdManager} deletes the key when it changes the device ID, so that the
 * next batch is signed with a new key whose attestation challenge is the new ID.
 */
public final class CrumblesBatchSigningKey {
  private static final String TAG = "CrumblesBatchSigningKey";
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
  private static final String CURVE = "secp256r1";

  /** Keystore alias of the batch-signing key. */
  static final String ALIAS = "com.android.securelogging.CrumblesBatchSigningKey";

  private final Context context;

  public CrumblesBatchSigningKey(Context context) {
    this.context = context;
  }

  /**
   * Signs {@code data} with SHA256withECDSA, creating the key first if this installation has none.
   *
   * @return the DER-encoded signature and the key's attestation chain, leaf first
   * @throws CrumblesKeysException if the key cannot be created or cannot sign
   */
  public BatchSignature sign(byte[] data) throws CrumblesKeysException {
    try {
      KeyStore keyStore = loadKeyStoreCreatingKey();
      if (!(keyStore.getKey(ALIAS, /* password= */ null) instanceof PrivateKey privateKey)) {
        throw new CrumblesKeysException("The batch-signing key alias holds no private key.");
      }
      Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
      signer.initSign(privateKey);
      signer.update(data);
      return BatchSignature.newBuilder()
          .setSignature(ByteString.copyFrom(signer.sign()))
          .addAllAttestationChain(encodedCertificateChain(keyStore))
          .build();
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      // Keystore reports some failures, such as having no attestation key, as ProviderException,
      // and on some OEM builds throws other unchecked exceptions.
      throw new CrumblesKeysException("Failed to sign with the batch-signing key.", e);
    }
  }

  /**
   * Returns the attestation chain of the key, leaf first, creating the key first if this
   * installation has none, so that a format version 2 batch can seal the chain of the key that
   * signs it.
   *
   * @throws CrumblesKeysException if the key cannot be created or its chain cannot be read
   */
  ImmutableList<ByteString> attestationChain() throws CrumblesKeysException {
    try {
      return encodedCertificateChain(loadKeyStoreCreatingKey());
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      // Keystore reports some failures, such as having no attestation key, as ProviderException,
      // and on some OEM builds throws other unchecked exceptions.
      throw new CrumblesKeysException(
          "Failed to read the attestation chain of the batch-signing key.", e);
    }
  }

  /**
   * Returns whether {@code signature} is this installation's SHA256withECDSA signature of {@code
   * data}. Returns false if the installation has no batch-signing key yet.
   *
   * @throws CrumblesKeysException if the key cannot be read or {@code signature} is malformed
   */
  public boolean verifies(byte[] data, byte[] signature) throws CrumblesKeysException {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
      keyStore.load(/* param= */ null);
      Certificate certificate = keyStore.getCertificate(ALIAS);
      if (certificate == null) {
        return false;
      }
      Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
      verifier.initVerify(certificate);
      verifier.update(data);
      return verifier.verify(signature);
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      // Keystore reports some failures as ProviderException, and on some OEM builds throws other
      // unchecked exceptions.
      throw new CrumblesKeysException("Failed to verify with the batch-signing key.", e);
    }
  }

  /**
   * Deletes the key, so that the next {@link #sign} call creates a new one whose attestation
   * challenge is the device ID at that time.
   *
   * @throws CrumblesKeysException if the key cannot be deleted
   */
  void delete() throws CrumblesKeysException {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
      keyStore.load(/* param= */ null);
      if (keyStore.containsAlias(ALIAS)) {
        keyStore.deleteEntry(ALIAS);
      }
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      // As in verifies.
      throw new CrumblesKeysException("Failed to delete the batch-signing key.", e);
    }
  }

  /** Returns the loaded Android Keystore, after creating the key if this installation has none. */
  private KeyStore loadKeyStoreCreatingKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(/* param= */ null);
    if (!keyStore.containsAlias(ALIAS)) {
      create();
    }
    return keyStore;
  }

  /**
   * Returns the DER encodings of the key's certificate chain in {@code keyStore}, leaf first.
   *
   * @throws CrumblesKeysException if {@code keyStore} has no certificate chain for the key
   */
  private static ImmutableList<ByteString> encodedCertificateChain(KeyStore keyStore)
      throws GeneralSecurityException, CrumblesKeysException {
    Certificate[] chain = keyStore.getCertificateChain(ALIAS);
    if (chain == null) {
      throw new CrumblesKeysException("No certificate chain for the batch-signing key.");
    }
    ImmutableList.Builder<ByteString> encodedChain = ImmutableList.builder();
    for (Certificate certificate : chain) {
      encodedChain.add(ByteString.copyFrom(certificate.getEncoded()));
    }
    return encodedChain.build();
  }

  private void create() throws GeneralSecurityException {
    try {
      create(/* strongBoxBacked= */ true);
    } catch (GeneralSecurityException | RuntimeException e) {
      // StrongBoxUnavailableException only means that the device has no StrongBox. A StrongBox can
      // also fail in other ways while the TEE works: when it has no attestation key, it throws
      // ProviderException, and on some OEM builds it throws other unchecked exceptions.
      Log.w(TAG, "StrongBox could not create the batch-signing key; creating it in the TEE.", e);
      create(/* strongBoxBacked= */ false);
    }
  }

  private void create(boolean strongBoxBacked) throws GeneralSecurityException {
    KeyPairGenerator generator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
    generator.initialize(
        new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(new ECGenParameterSpec(CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(CrumblesDeviceIdManager.getDeviceId(context).getBytes(UTF_8))
            .setIsStrongBoxBacked(strongBoxBacked)
            .build());
    generator.generateKeyPair();
  }
}
