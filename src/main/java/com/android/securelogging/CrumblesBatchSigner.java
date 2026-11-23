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

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.BatchSignature;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import java.time.Instant;
import java.time.InstantSource;
import java.util.List;
import java.util.Optional;

/**
 * Numbers and signs log batches, so that their recipient can check that each batch was written by
 * this installation and that none is missing.
 *
 * <p>Sequence numbers start at 1 and grow by one with each signed batch. A number is only used once
 * its batch has been signed, so a gap means that a signed batch is missing. The signature, made
 * with {@link CrumblesBatchSigningKey}, covers the serialized batch without its {@code signature}
 * field: the ciphertext, the wrapped key, the metadata and the sequence number.
 */
public final class CrumblesBatchSigner {
  private static final String TAG = "CrumblesBatchSigner";

  /** Preference holding the sequence number of the last signed batch. */
  static final String PREF_LAST_SEQUENCE_NUMBER = "lastBatchSequenceNumber";

  /** Preference holding when the last batch was signed, in milliseconds since the epoch. */
  static final String PREF_LAST_SIGNED_AT_MILLIS = "lastBatchSignedAtMillis";

  /**
   * Keeps two batches from getting the same sequence number, and the batch-signing key from being
   * deleted between checking the signature of a batch and signing its re-encrypted copy.
   */
  private static final Object signingLock = new Object();

  private final Context context;

  public CrumblesBatchSigner(Context context) {
    this.context = context;
  }

  /**
   * Returns the attestation chain of this installation's batch-signing key, creating the key if
   * there is none, for a format version 2 batch to seal before {@link #sign(LogBatch, List)} or
   * {@link #signAgain(LogBatch, LogBatch, List)} signs it, as its cleartext signature leaves the
   * chain out. Returns an empty list if the chain cannot be read, as on devices without key
   * attestation: the batch is then written unsigned.
   */
  public ImmutableList<ByteString> attestationChainToSeal() {
    try {
      return new CrumblesBatchSigningKey(context).attestationChain();
    } catch (CrumblesKeysException | RuntimeException e) {
      // Keystore on some OEM builds throws unchecked exceptions other than the ProviderException
      // that attestationChain() reports as CrumblesKeysException.
      Log.w(TAG, "Failed to read the attestation chain of the batch-signing key.", e);
      return ImmutableList.of();
    }
  }

  /**
   * As {@link #sign(LogBatch, List)} for a batch that seals no attestation chain, such as one of an
   * older format. Crumbles writes only format version 2 batches, which must seal one, so this only
   * serves tests.
   */
  @VisibleForTesting
  LogBatch sign(LogBatch batch) throws CrumblesKeysException {
    return sign(batch, /* sealedChain= */ ImmutableList.of());
  }

  /**
   * Returns {@code batch} with the next sequence number and a signature, replacing any signature it
   * already has. The signature of a format version 2 batch leaves out the attestation chain, which
   * the batch seals with its logs, so such a batch is only signed if {@code sealedChain}, the chain
   * it seals, is the chain of the key that signs it.
   *
   * @throws CrumblesKeysException if the batch cannot be signed, does not seal the chain of the
   *     signing key, or its sequence number cannot be stored; the sequence number is then not used
   */
  public LogBatch sign(LogBatch batch, List<ByteString> sealedChain) throws CrumblesKeysException {
    synchronized (signingLock) {
      SharedPreferences preferences = getPreferences();
      long sequenceNumber = preferences.getLong(PREF_LAST_SEQUENCE_NUMBER, /* defValue= */ 0) + 1;
      LogBatch numberedBatch =
          batch.toBuilder().clearSignature().setSequenceNumber(sequenceNumber).build();
      BatchSignature signature =
          new CrumblesBatchSigningKey(context).sign(numberedBatch.toByteArray());
      checkSealsTheSigningKeysChain(numberedBatch, sealedChain, signature);
      boolean stored =
          preferences
              .edit()
              .putLong(PREF_LAST_SEQUENCE_NUMBER, sequenceNumber)
              .putLong(PREF_LAST_SIGNED_AT_MILLIS, InstantSource.system().millis())
              .commit();
      if (!stored) {
        throw new CrumblesKeysException("Failed to store the batch sequence number.");
      }
      return withSignature(numberedBatch, signature);
    }
  }

  /**
   * As {@link #signAgain(LogBatch, LogBatch, List)} for a re-encrypted batch that seals no
   * attestation chain. Crumbles writes only format version 2 batches, which must seal one, so this
   * only serves tests.
   */
  @VisibleForTesting
  LogBatch signAgain(LogBatch originalBatch, LogBatch reEncryptedBatch)
      throws CrumblesKeysException {
    return signAgain(originalBatch, reEncryptedBatch, /* sealedChain= */ ImmutableList.of());
  }

  /**
   * Returns {@code reEncryptedBatch}, which holds the logs of {@code originalBatch} encrypted to
   * another key, signed under the original's sequence number without using a new one, so that the
   * recipient sees no gap. As in {@link #sign(LogBatch, List)}, a format version 2 batch must seal
   * the chain of the signing key, {@code sealedChain}, which its signature leaves out.
   *
   * <p>Only a batch whose signature verifies with this installation's key is signed again, so that
   * re-encryption cannot turn a batch written by anyone else into one signed by this installation.
   * The key that verifies the original signs the copy: {@link #deleteSigningKey} waits meanwhile.
   *
   * @throws CrumblesKeysException if the original's signature does not verify with this
   *     installation's key, or the re-encrypted batch cannot be signed or does not seal the chain
   *     of the signing key
   */
  public LogBatch signAgain(
      LogBatch originalBatch, LogBatch reEncryptedBatch, List<ByteString> sealedChain)
      throws CrumblesKeysException {
    synchronized (signingLock) {
      if (!verifiesWithThisInstallationsKey(originalBatch)) {
        throw new CrumblesKeysException("The original batch is not signed by this installation.");
      }
      LogBatch numberedBatch =
          reEncryptedBatch.toBuilder()
              .clearSignature()
              .setSequenceNumber(originalBatch.getSequenceNumber())
              .build();
      BatchSignature signature =
          new CrumblesBatchSigningKey(context).sign(numberedBatch.toByteArray());
      checkSealsTheSigningKeysChain(numberedBatch, sealedChain, signature);
      return withSignature(numberedBatch, signature);
    }
  }

  /**
   * Deletes this installation's batch-signing key, so that the next batch is signed with a new key
   * attested to the device ID at that time. No batch is signed, or signed again, meanwhile.
   *
   * @throws CrumblesKeysException if the key cannot be deleted
   */
  static void deleteSigningKey(Context context) throws CrumblesKeysException {
    synchronized (signingLock) {
      new CrumblesBatchSigningKey(context).delete();
    }
  }

  /**
   * Returns whether {@code batch} carries a signature that this installation's batch-signing key
   * verifies, as {@link #signAgain} requires, without creating that key if the installation has
   * none. Returns false if the key cannot be read or the signature is malformed, as such a batch
   * cannot be signed again either.
   */
  public boolean isSignedByThisInstallation(LogBatch batch) {
    try {
      return verifiesWithThisInstallationsKey(batch);
    } catch (CrumblesKeysException e) {
      Log.w(TAG, "Failed to check whether this installation signed a log batch.", e);
      return false;
    }
  }

  /**
   * Returns whether {@code batch} carries a signature that this installation's key verifies, or
   * false if the installation has no key.
   *
   * @throws CrumblesKeysException if the key cannot be read or the signature is malformed
   */
  private boolean verifiesWithThisInstallationsKey(LogBatch batch) throws CrumblesKeysException {
    return batch.hasSignature()
        && new CrumblesBatchSigningKey(context)
            .verifies(
                batch.toBuilder().clearSignature().build().toByteArray(),
                batch.getSignature().getSignature().toByteArray());
  }

  /**
   * Throws unless {@code numberedBatch}, if it is a format version 2 batch, seals the attestation
   * chain that {@code signature} comes with, as its recipient checks the signature with the chain
   * that the batch seals. A chain that could not be read when the batch was encrypted, or that a
   * new key has replaced since, leaves the batch unsigned rather than unverifiable.
   */
  private static void checkSealsTheSigningKeysChain(
      LogBatch numberedBatch, List<ByteString> sealedChain, BatchSignature signature)
      throws CrumblesKeysException {
    if (sealsAttestationChain(numberedBatch)
        && (sealedChain.isEmpty() || !sealedChain.equals(signature.getAttestationChainList()))) {
      throw new CrumblesKeysException(
          "The batch does not seal the attestation chain of the key that signs it.");
    }
  }

  /**
   * Returns {@code numberedBatch} with {@code signature}. A format version 2 batch seals the
   * attestation chain of the signing key with its logs, so that the chain's device ID, verified
   * boot key and patch level stay hidden from whoever stores the batch; its cleartext signature
   * then keeps only the signature itself.
   */
  private static LogBatch withSignature(LogBatch numberedBatch, BatchSignature signature) {
    return numberedBatch.toBuilder()
        .setSignature(
            sealsAttestationChain(numberedBatch)
                ? signature.toBuilder().clearAttestationChain().build()
                : signature)
        .build();
  }

  /** Returns whether {@code batch} seals the attestation chain of its signing key. */
  private static boolean sealsAttestationChain(LogBatch batch) {
    return batch
        .getMetadata()
        .getEncryptionType()
        .equals(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA);
  }

  /** Returns when this installation last signed a batch, or empty if it never has. */
  public Optional<Instant> lastSignedAt() {
    return Optional.ofNullable((Long) getPreferences().getAll().get(PREF_LAST_SIGNED_AT_MILLIS))
        .map(Instant::ofEpochMilli);
  }

  private SharedPreferences getPreferences() {
    return context.getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE);
  }
}
