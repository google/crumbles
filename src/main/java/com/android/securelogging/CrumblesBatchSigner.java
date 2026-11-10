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
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.BatchSignature;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogEncryptionType;
import java.time.Instant;
import java.time.InstantSource;
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

  /** Keeps two batches from getting the same sequence number. */
  private static final Object sequenceLock = new Object();

  private final Context context;

  public CrumblesBatchSigner(Context context) {
    this.context = context;
  }

  /**
   * Returns {@code batch} with the next sequence number and a signature, replacing any signature it
   * already has. The signature of a format version 2 batch leaves out the attestation chain, which
   * the batch seals with its logs.
   *
   * @throws CrumblesKeysException if the batch cannot be signed or its sequence number cannot be
   *     stored; the sequence number is then not used
   */
  public LogBatch sign(LogBatch batch) throws CrumblesKeysException {
    synchronized (sequenceLock) {
      SharedPreferences preferences = getPreferences();
      long sequenceNumber = preferences.getLong(PREF_LAST_SEQUENCE_NUMBER, /* defValue= */ 0) + 1;
      LogBatch numberedBatch =
          batch.toBuilder().clearSignature().setSequenceNumber(sequenceNumber).build();
      BatchSignature signature =
          new CrumblesBatchSigningKey(context).sign(numberedBatch.toByteArray());
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
   * Returns {@code reEncryptedBatch}, which holds the logs of {@code originalBatch} encrypted to
   * another key, signed under the original's sequence number without using a new one, so that the
   * recipient sees no gap. As in {@link #sign}, the signature of a format version 2 batch leaves
   * out the attestation chain.
   *
   * <p>Only a batch whose signature verifies with this installation's key is signed again, so that
   * re-encryption cannot turn a batch written by anyone else into one signed by this installation.
   *
   * @throws CrumblesKeysException if the original's signature does not verify with this
   *     installation's key, or the re-encrypted batch cannot be signed
   */
  public LogBatch signAgain(LogBatch originalBatch, LogBatch reEncryptedBatch)
      throws CrumblesKeysException {
    if (!verifiesWithThisInstallationsKey(originalBatch)) {
      throw new CrumblesKeysException("The original batch is not signed by this installation.");
    }
    LogBatch numberedBatch =
        reEncryptedBatch.toBuilder()
            .clearSignature()
            .setSequenceNumber(originalBatch.getSequenceNumber())
            .build();
    return withSignature(
        numberedBatch, new CrumblesBatchSigningKey(context).sign(numberedBatch.toByteArray()));
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
   * Returns {@code numberedBatch} with {@code signature}. A format version 2 batch seals the
   * attestation chain of the signing key with its logs, so that the chain's device ID, verified
   * boot key and patch level stay hidden from whoever stores the batch; its cleartext signature
   * then keeps only the signature itself.
   */
  private static LogBatch withSignature(LogBatch numberedBatch, BatchSignature signature) {
    boolean sealsAttestationChain =
        numberedBatch
            .getMetadata()
            .getEncryptionType()
            .equals(LogEncryptionType.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA);
    return numberedBatch.toBuilder()
        .setSignature(
            sealsAttestationChain
                ? signature.toBuilder().clearAttestationChain().build()
                : signature)
        .build();
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
