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

import android.icu.text.MessageFormat;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricManager.Authenticators;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;
import com.android.securelogging.CrumblesLogsEncryptor.BulkDecryptPartition;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsDecryptionException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

/**
 * Decrypts a selection of log batches with the internal Keystore keys, asking the user to authorize
 * it through {@link BiometricPrompt}.
 *
 * <p>One prompt covers all the batches that the batch-unwrap key covers: its {@code CryptoObject}
 * authorizes the one Keystore operation that unwraps all their keys. Without that prompt, a prompt
 * opens the time window of the Keystore RSA key before its first batch, even if the window is
 * already open, as after a biometric unlock of the phone. Whenever that window is closed, another
 * prompt opens it for the other batches. If that key needs an authentication for each operation
 * instead, each of the other batches gets its own prompt, and cancelling one stops the decryption,
 * or skips the batches left for a key change, see {@link #forKeyChange}. Batches that no key on
 * this device can decrypt fail without a prompt.
 */
final class CrumblesAuthorizedLogDecryptor {
  private static final String TAG = "CrumblesAuthorizedLogDecryptor";

  /**
   * Receives the outcome of {@link #decrypt}, always asynchronously on the main thread. Each
   * decryption ends with either {@link #onFinished} or {@link #onNotAuthorized}.
   */
  interface Callback {
    /**
     * Called with the logs of one log batch of the selection and its metadata, which for a format
     * version 2 batch include the device identifier sealed inside it.
     */
    void onDecrypted(LogBatch logBatch, DecryptedLogBatch decryptedBatch);

    /** Called when one log batch of the selection cannot be decrypted. */
    void onDecryptionFailed(LogBatch logBatch, Exception exception);

    /**
     * Called when the user did not authorize the decryption, with the {@link BiometricPrompt} error
     * code (such as {@link BiometricPrompt#ERROR_USER_CANCELED}) and its message. The batches not
     * reported yet stay encrypted.
     */
    void onNotAuthorized(int errorCode, CharSequence errorMessage);

    /** Called once every log batch of the selection is decrypted or failed. */
    void onFinished();
  }

  /** Handles a prompt that closed without an authentication, given its error code and message. */
  private interface RefusalHandler {
    void onRefused(int errorCode, CharSequence errorMessage);
  }

  private final FragmentActivity activity;
  private final CrumblesLogsEncryptor logsEncryptor;
  private final boolean forKeyChange;
  private final Predicate<LogBatch> mayBeForAnExternalKey;
  private boolean cancelled;

  CrumblesAuthorizedLogDecryptor(FragmentActivity activity, CrumblesLogsEncryptor logsEncryptor) {
    this(
        activity,
        logsEncryptor,
        /* forKeyChange= */ false,
        /* mayBeForAnExternalKey= */ logBatch -> false);
  }

  private CrumblesAuthorizedLogDecryptor(
      FragmentActivity activity,
      CrumblesLogsEncryptor logsEncryptor,
      boolean forKeyChange,
      Predicate<LogBatch> mayBeForAnExternalKey) {
    this.activity = activity;
    this.logsEncryptor = logsEncryptor;
    this.forKeyChange = forKeyChange;
    this.mayBeForAnExternalKey = mayBeForAnExternalKey;
  }

  /**
   * Returns a decryptor for the pending logs of a key change, right after the change asked for the
   * device credential, which opened the time window of the Keystore RSA key: the batches that this
   * key decrypts need no prompt of their own while that window stays open. The batches that {@link
   * CrumblesLogsEncryptor#partitionForKeyChange} takes to be for another key, including those that
   * {@code mayBeForAnExternalKey} accepts, fail without a prompt. Cancelling the prompt that a
   * batch needs of its own skips it and the batches left, as that prompt says, instead of stopping
   * the change, which then asks what to do with them.
   */
  static CrumblesAuthorizedLogDecryptor forKeyChange(
      FragmentActivity activity,
      CrumblesLogsEncryptor logsEncryptor,
      Predicate<LogBatch> mayBeForAnExternalKey) {
    return new CrumblesAuthorizedLogDecryptor(
        activity, logsEncryptor, /* forKeyChange= */ true, mayBeForAnExternalKey);
  }

  void cancel() {
    cancelled = true;
  }

  /** Decrypts {@code logBatches}, asking the user to authorize it as few times as possible. */
  void decrypt(List<LogBatch> logBatches, Callback callback) {
    BulkDecryptPartition partition =
        forKeyChange
            ? logsEncryptor.partitionForKeyChange(logBatches, mayBeForAnExternalKey)
            : logsEncryptor.partitionForBulkDecrypt(logBatches);
    CrumblesLogsDecryptionException noKey =
        new CrumblesLogsDecryptionException("No key on this device can decrypt this log batch.");
    for (LogBatch logBatch : partition.undecryptable()) {
      postToCallback(() -> callback.onDecryptionFailed(logBatch, noKey));
    }
    Optional<Cipher> unwrapCipher = createBatchUnwrapCipher(partition.batchUnwrappable());
    if (unwrapCipher.isPresent()) {
      int batchCount = partition.batchUnwrappable().size();
      if (!logsEncryptor.isKeystoreKeyBoundToEachOperation()) {
        batchCount += partition.rsaOnly().size();
      }
      authenticate(
          batchCount,
          /* description= */ null,
          unwrapCipher.get(),
          () -> decryptBatchUnwrappable(partition, unwrapCipher.get(), callback),
          callback::onNotAuthorized);
      return;
    }
    // Without a batch-unwrap cipher, the RSA-wrapped keys still decrypt every batch.
    ImmutableList<LogBatch> rsaBatches =
        ImmutableList.copyOf(Iterables.concat(partition.batchUnwrappable(), partition.rsaOnly()));
    if (forKeyChange || rsaBatches.isEmpty() || logsEncryptor.isKeystoreKeyBoundToEachOperation()) {
      postToCallback(() -> decryptAllWithRsaKey(rsaBatches, callback));
      return;
    }
    // The device credential reopens the time window of the RSA key first: a biometric that someone
    // can force onto the sensor may have opened it.
    authenticate(
        rsaBatches.size(),
        /* description= */ null,
        /* cipher= */ null,
        () -> decryptWithRsaKey(rsaBatches, /* windowJustOpened= */ true, callback),
        callback::onNotAuthorized);
  }

  /** Returns a cipher for {@code batchUnwrappable}, or empty if there are none or it fails. */
  private Optional<Cipher> createBatchUnwrapCipher(List<LogBatch> batchUnwrappable) {
    if (batchUnwrappable.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(logsEncryptor.createBatchUnwrapCipher());
    } catch (CrumblesKeysException e) {
      Log.w(TAG, "Failed to create the batch-unwrap cipher.", e);
      return Optional.empty();
    }
  }

  /**
   * Decrypts the batchUnwrappable batches of {@code partition} with the keys that {@code
   * authorizedCipher} unwraps, then the other batches, and any batch that its unwrapped key does
   * not decrypt, with the RSA key.
   */
  private void decryptBatchUnwrappable(
      BulkDecryptPartition partition, Cipher authorizedCipher, Callback callback) {
    ImmutableList<LogBatch> batchUnwrappable = partition.batchUnwrappable();
    ImmutableList.Builder<LogBatch> rsaBatches = ImmutableList.builder();
    ImmutableList<SecretKey> symmetricKeys;
    try {
      symmetricKeys = logsEncryptor.unwrapBatchKeys(authorizedCipher, batchUnwrappable);
    } catch (CrumblesKeysException e) {
      // As when the Keystore pruned the operation while the prompt was showing.
      Log.w(TAG, "Failed to unwrap the batch keys.", e);
      symmetricKeys = ImmutableList.of();
      rsaBatches.addAll(batchUnwrappable);
    }
    for (int i = 0; i < symmetricKeys.size(); i++) {
      LogBatch logBatch = batchUnwrappable.get(i);
      SecretKey key = symmetricKeys.get(i);
      try {
        callback.onDecrypted(logBatch, logsEncryptor.decryptLogsWithSymmetricKey(logBatch, key));
      } catch (CrumblesLogsDecryptionException e) {
        rsaBatches.add(logBatch);
      } finally {
        destroyKey(key);
      }
    }
    decryptAllWithRsaKey(rsaBatches.addAll(partition.rsaOnly()).build(), callback);
  }

  private static void destroyKey(SecretKey key) {
    try {
      key.destroy();
    } catch (DestroyFailedException e) {
      // SecretKeySpec throws DestroyFailedException when destroy() is unsupported.
    }
  }

  /**
   * Decrypts {@code rsaBatches} with the RSA key: each after its own prompt if that key needs an
   * authentication for each operation, or else within its time window.
   */
  private void decryptAllWithRsaKey(List<LogBatch> rsaBatches, Callback callback) {
    if (logsEncryptor.isKeystoreKeyBoundToEachOperation()) {
      decryptEachAfterItsOwnPrompt(rsaBatches, callback);
    } else {
      decryptWithRsaKey(rsaBatches, /* windowJustOpened= */ false, callback);
    }
  }

  /**
   * Decrypts each of {@code rsaBatches} after its own prompt, whose {@code CryptoObject} authorizes
   * the one RSA operation that unwraps its key. Cancelling a prompt stops the decryption, or skips
   * the batches left for a key change. If the key turns out to have a time window, which is closed,
   * the batches left are decrypted within its time window instead.
   */
  private void decryptEachAfterItsOwnPrompt(List<LogBatch> rsaBatches, Callback callback) {
    for (int i = 0; i < rsaBatches.size(); i++) {
      LogBatch logBatch = rsaBatches.get(i);
      Cipher unwrapCipher;
      try {
        unwrapCipher = logsEncryptor.createUnwrapCipher(logBatch);
      } catch (CrumblesKeysException e) {
        // Only a key with a closed time window refuses to start an operation before the user
        // authenticates. A key bound to each operation asks for the authentication afterwards.
        if (e.getCause() instanceof UserNotAuthenticatedException) {
          decryptWithRsaKey(
              rsaBatches.subList(i, rsaBatches.size()), /* windowJustOpened= */ false, callback);
          return;
        }
        callback.onDecryptionFailed(logBatch, e);
        continue;
      }
      List<LogBatch> batchesLeft = rsaBatches.subList(i, rsaBatches.size());
      List<LogBatch> later = rsaBatches.subList(i + 1, rsaBatches.size());
      authenticate(
          /* batchCount= */ 1,
          MessageFormat.format(
              activity.getString(R.string.decrypt_logs_own_prompt_description),
              ImmutableMap.of("count", later.size())),
          unwrapCipher,
          () -> {
            try {
              callback.onDecrypted(logBatch, logsEncryptor.decryptLogBatch(logBatch, unwrapCipher));
            } catch (CrumblesKeysException
                | CrumblesLogsDecryptionException
                | UserNotAuthenticatedException e) {
              callback.onDecryptionFailed(logBatch, e);
            }
            decryptEachAfterItsOwnPrompt(later, callback);
          },
          (errorCode, errorMessage) ->
              onOwnPromptRefused(batchesLeft, errorCode, errorMessage, callback));
      return;
    }
    callback.onFinished();
  }

  /**
   * Handles the refusal of the prompt that the first of {@code batchesLeft} needs of its own, which
   * says that cancelling it skips them all: a key change then goes on without them. Any other
   * refusal stops the decryption.
   */
  private void onOwnPromptRefused(
      List<LogBatch> batchesLeft, int errorCode, CharSequence errorMessage, Callback callback) {
    if (!forKeyChange || errorCode != BiometricPrompt.ERROR_USER_CANCELED) {
      callback.onNotAuthorized(errorCode, errorMessage);
      return;
    }
    CrumblesLogsDecryptionException skipped =
        new CrumblesLogsDecryptionException("Not decrypted: " + errorMessage);
    for (LogBatch logBatch : batchesLeft) {
      callback.onDecryptionFailed(logBatch, skipped);
    }
    callback.onFinished();
  }

  /**
   * Decrypts {@code rsaBatches} with the RSA key. Whenever its time window is closed, a prompt
   * opens it and decryption resumes. If it is still closed right after that prompt, as for a key
   * bound to one operation per authentication, the remaining batches fail.
   */
  private void decryptWithRsaKey(
      List<LogBatch> rsaBatches, boolean windowJustOpened, Callback callback) {
    for (int i = 0; i < rsaBatches.size(); i++) {
      LogBatch logBatch = rsaBatches.get(i);
      try {
        callback.onDecrypted(logBatch, logsEncryptor.decryptLogBatch(logBatch));
      } catch (UserNotAuthenticatedException e) {
        List<LogBatch> remaining = rsaBatches.subList(i, rsaBatches.size());
        if (windowJustOpened && i == 0) {
          remaining.forEach(failedBatch -> callback.onDecryptionFailed(failedBatch, e));
          break;
        }
        authenticate(
            remaining.size(),
            /* description= */ null,
            /* cipher= */ null,
            () -> decryptWithRsaKey(remaining, /* windowJustOpened= */ true, callback),
            callback::onNotAuthorized);
        return;
      } catch (CrumblesKeysException | CrumblesLogsDecryptionException e) {
        callback.onDecryptionFailed(logBatch, e);
      }
    }
    callback.onFinished();
  }

  /**
   * Shows a prompt for {@code batchCount} log batches, with {@code description} if not null, and
   * runs {@code onAuthorized} once the user authenticates, or {@code onRefused} if the prompt
   * closes without an authentication. The prompt authorizes {@code cipher}, or opens the time
   * window of the RSA key if it is {@code null}.
   *
   * <p>The prompt asks for the device credential only, like {@link CrumblesDeviceCredentialGate}
   * before every setting change: the keys also accept a strong biometric, but a finger or face that
   * someone can force onto the sensor must not unlock every batch the phone holds.
   */
  private void authenticate(
      int batchCount,
      @Nullable String description,
      @Nullable Cipher cipher,
      Runnable onAuthorized,
      RefusalHandler onRefused) {
    BiometricPrompt.PromptInfo.Builder promptInfo =
        new BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.decrypt_logs_prompt_title))
            .setSubtitle(
                MessageFormat.format(
                    activity.getString(R.string.decrypt_logs_prompt_subtitle),
                    ImmutableMap.of("count", batchCount)))
            .setDescription(description)
            .setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL);
    BiometricPrompt prompt =
        new BiometricPrompt(
            activity,
            new BiometricPrompt.AuthenticationCallback() {
              @Override
              public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                postToCallback(onAuthorized);
              }

              @Override
              public void onAuthenticationError(int errorCode, CharSequence errorMessage) {
                postToCallback(() -> onRefused.onRefused(errorCode, errorMessage));
              }
            });
    if (cipher == null) {
      promptInfo.setDescription(
          activity.getString(R.string.decrypt_logs_separate_prompt_description));
      prompt.authenticate(promptInfo.build());
    } else {
      prompt.authenticate(promptInfo.build(), new BiometricPrompt.CryptoObject(cipher));
    }
  }

  /**
   * Runs {@code callbackInvocation} once the prompt has closed, unless the activity is gone.
   *
   * <p>The prompt reports its result before it removes its fragment. Waiting for that removal lets
   * the next prompt open: opened earlier, it would reuse the closing fragment and lose its result.
   */
  private void postToCallback(Runnable callbackInvocation) {
    activity
        .getMainExecutor()
        .execute(() -> {
          if (!cancelled && !activity.isFinishing() && !activity.isDestroyed()) {
            callbackInvocation.run();
          }
        });
  }
}
