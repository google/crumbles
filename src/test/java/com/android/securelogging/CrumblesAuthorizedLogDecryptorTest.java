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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.os.Build;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v4.app.FragmentActivity;
import androidx.biometric.BiometricPrompt;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesLogsEncryptor.BulkDecryptPartition;
import com.android.securelogging.CrumblesLogsEncryptor.DecryptedLogBatch;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsDecryptionException;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogKey;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogMetadata;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowBiometricPrompt;
import org.robolectric.shadows.ShadowLooper;

/**
 * Tests for {@link CrumblesAuthorizedLogDecryptor}. Most tests mock the encryptor to isolate prompt
 * sequencing, while an integration test exercises real per-operation RSA authorization.
 */
@RunWith(AndroidJUnit4.class)
@Config(sdk = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
public final class CrumblesAuthorizedLogDecryptorTest {
  private static final LogBatch FIRST_BATCH = logBatch("first");
  private static final LogBatch SECOND_BATCH = logBatch("second");
  private static final ImmutableList<LogBatch> BOTH_BATCHES =
      ImmutableList.of(FIRST_BATCH, SECOND_BATCH);
  private static final ImmutableList<LogBatch> NO_BATCHES = ImmutableList.of();
  private static final SecretKey firstKey = new SecretKeySpec(new byte[] {1}, "AES");
  private static final SecretKey secondKey = new SecretKeySpec(new byte[] {2}, "AES");
  private final DecryptedLogBatch firstLogs = decrypted("first logs");
  private final DecryptedLogBatch secondLogs = decrypted("second logs");

  private final CrumblesLogsEncryptor mockLogsEncryptor = mock(CrumblesLogsEncryptor.class);
  private final CrumblesAuthorizedLogDecryptor.Callback mockCallback =
      mock(CrumblesAuthorizedLogDecryptor.Callback.class);

  private ActivityController<FragmentActivity> activityController;
  private CrumblesAuthorizedLogDecryptor decryptor;
  private Cipher unwrapCipher;

  @Before
  public void setUp() throws Exception {
    activityController = Robolectric.buildActivity(FragmentActivity.class).setup();
    decryptor = new CrumblesAuthorizedLogDecryptor(activityController.get(), mockLogsEncryptor);
    // The shadowed prompt never uses the cipher it authorizes, so any cipher works.
    unwrapCipher = Cipher.getInstance("AES/CBC/NoPadding");
  }

  private static LogBatch logBatch(String name) {
    return LogBatch.newBuilder()
        .setKey(LogKey.newBuilder().setIv(ByteString.copyFromUtf8(name)))
        .build();
  }

  private static DecryptedLogBatch decrypted(String logs) {
    return new DecryptedLogBatch(LogMetadata.getDefaultInstance(), logs.getBytes(UTF_8));
  }

  private void partition(
      ImmutableList<LogBatch> batchUnwrappable,
      ImmutableList<LogBatch> rsaOnly,
      ImmutableList<LogBatch> undecryptable) {
    when(mockLogsEncryptor.partitionForBulkDecrypt(BOTH_BATCHES))
        .thenReturn(new BulkDecryptPartition(batchUnwrappable, rsaOnly, undecryptable));
  }

  @Test
  public void decrypt_decryptsEveryBatchUnwrappableBatchAfterOnePrompt() throws Exception {
    partition(BOTH_BATCHES, NO_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.createBatchUnwrapCipher()).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.unwrapBatchKeys(unwrapCipher, BOTH_BATCHES))
        .thenReturn(ImmutableList.of(firstKey, secondKey));
    when(mockLogsEncryptor.decryptLogsWithSymmetricKey(FIRST_BATCH, firstKey))
        .thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogsWithSymmetricKey(SECOND_BATCH, secondKey))
        .thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("2 log files");
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
  }

  @Test
  public void decrypt_whenAnUnwrappedKeyFails_decryptsItsBatchWithTheRsaKey() throws Exception {
    partition(ImmutableList.of(FIRST_BATCH), ImmutableList.of(SECOND_BATCH), NO_BATCHES);
    when(mockLogsEncryptor.createBatchUnwrapCipher()).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.unwrapBatchKeys(unwrapCipher, ImmutableList.of(FIRST_BATCH)))
        .thenReturn(ImmutableList.of(firstKey));
    when(mockLogsEncryptor.decryptLogsWithSymmetricKey(FIRST_BATCH, firstKey))
        .thenThrow(new CrumblesLogsDecryptionException("AES GCM decryption failed."));
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH)).thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("2 log files");
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_whenUnwrappingFails_decryptsTheBatchesWithTheRsaKey() throws Exception {
    partition(BOTH_BATCHES, NO_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.createBatchUnwrapCipher()).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.unwrapBatchKeys(unwrapCipher, BOTH_BATCHES))
        .thenThrow(new CrumblesKeysException("Operation pruned."));
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH)).thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("2 log files");
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_withoutBatchUnwrapCipher_decryptsWithTheRsaKeyWithoutPrompt()
      throws Exception {
    partition(ImmutableList.of(FIRST_BATCH), ImmutableList.of(SECOND_BATCH), NO_BATCHES);
    when(mockLogsEncryptor.createBatchUnwrapCipher())
        .thenThrow(new CrumblesKeysException("No batch-unwrap keys."));
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH)).thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
  }

  @Test
  public void decrypt_whileTheRsaKeyWindowIsOpen_decryptsEveryBatchWithoutPrompt()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH)).thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
  }

  @Test
  public void decrypt_whenTheRsaKeyWindowCloses_promptsForTheBatchesLeft() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    UserNotAuthenticatedException windowClosed = new UserNotAuthenticatedException();
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH))
        .thenThrow(windowClosed)
        .thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenThrow(windowClosed);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback, never()).onFinished();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("1 log file");
    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getDescription().toString())
        .isEqualTo("These log files need their own authentication.");
  }

  @Test
  public void decrypt_whenTheRsaKeyStaysLockedAfterThePrompt_failsTheBatchesLeft()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    UserNotAuthenticatedException locked = new UserNotAuthenticatedException();
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class))).thenThrow(locked);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecryptionFailed(FIRST_BATCH, locked);
    verify(mockCallback).onDecryptionFailed(SECOND_BATCH, locked);
    verify(mockCallback).onFinished();
    assertThat(ShadowBiometricPrompt.getCurrentPrompt()).isNull();
  }

  @Test
  public void decrypt_whenTheRsaKeyFailsForABatch_reportsItAndGoesOn() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    CrumblesLogsDecryptionException wrongKey =
        new CrumblesLogsDecryptionException("A cryptographic error occurred.");
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH)).thenThrow(wrongKey);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecryptionFailed(FIRST_BATCH, wrongKey);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_failsUndecryptableBatchesWithoutPrompt() throws Exception {
    partition(NO_BATCHES, NO_BATCHES, BOTH_BATCHES);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();

    verify(mockCallback)
        .onDecryptionFailed(same(FIRST_BATCH), any(CrumblesLogsDecryptionException.class));
    verify(mockCallback)
        .onDecryptionFailed(same(SECOND_BATCH), any(CrumblesLogsDecryptionException.class));
    verify(mockCallback).onFinished();
    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void decrypt_whenTheUserCancels_reportsItAndDecryptsNothingMore() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.decryptLogBatch(any(LogBatch.class)))
        .thenThrow(new UserNotAuthenticatedException());

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.ERROR_USER_CANCELED, "Authentication canceled");
    ShadowLooper.idleMainLooper();

    verify(mockCallback)
        .onNotAuthorized(BiometricPrompt.ERROR_USER_CANCELED, "Authentication canceled");
    verify(mockLogsEncryptor).decryptLogBatch(any(LogBatch.class));
    verify(mockCallback, never()).onFinished();
  }

  @Test
  public void decrypt_destroysUnwrappedKeysEvenWhenDecryptionFails() throws Exception {
    SecretKey mockFirstKey = mock(SecretKey.class);
    SecretKey mockSecondKey = mock(SecretKey.class);
    partition(BOTH_BATCHES, NO_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.createBatchUnwrapCipher()).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.unwrapBatchKeys(unwrapCipher, BOTH_BATCHES))
        .thenReturn(ImmutableList.of(mockFirstKey, mockSecondKey));
    when(mockLogsEncryptor.decryptLogsWithSymmetricKey(FIRST_BATCH, mockFirstKey))
        .thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogsWithSymmetricKey(SECOND_BATCH, mockSecondKey))
        .thenThrow(new CrumblesLogsDecryptionException("AES GCM decryption failed."));
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockFirstKey).destroy();
    verify(mockSecondKey).destroy();
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_whenActivityIsFinishing_doesNotInvokeCallback() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    activityController.get().finish();
    ShadowLooper.idleMainLooper();

    verify(mockCallback, never()).onFinished();
    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void decrypt_whenActivityIsDestroyed_doesNotInvokeCallback() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    activityController.destroy();
    ShadowLooper.idleMainLooper();

    verify(mockCallback, never()).onFinished();
    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void decrypt_whenCancelledWhileAPromptIsOpen_decryptsNothingMore() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    // The time window of the RSA key closes before the second batch, so it waits for a prompt.
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH)).thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH))
        .thenThrow(new UserNotAuthenticatedException())
        .thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    decryptor.cancel();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockLogsEncryptor).decryptLogBatch(SECOND_BATCH);
    verify(mockCallback, never()).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback, never()).onFinished();
  }

  @Test
  public void decrypt_withAKeyBoundToEachOperation_batchPromptCountsOnlyBatchUnwrappableFiles()
      throws Exception {
    partition(ImmutableList.of(FIRST_BATCH), ImmutableList.of(SECOND_BATCH), NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    when(mockLogsEncryptor.createBatchUnwrapCipher()).thenReturn(unwrapCipher);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);

    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getSubtitle().toString())
        .isEqualTo("1 log file");
  }

  @Test
  public void decrypt_withAKeyBoundToEachOperation_decryptsEachRsaBatchAfterItsOwnPrompt()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    Cipher secondCipher = Cipher.getInstance("AES/CBC/NoPadding");
    when(mockLogsEncryptor.createUnwrapCipher(FIRST_BATCH)).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.createUnwrapCipher(SECOND_BATCH)).thenReturn(secondCipher);
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH, unwrapCipher)).thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH, secondCipher)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
    verify(mockLogsEncryptor, never()).decryptLogBatch(any(LogBatch.class));
  }

  @Test
  public void decrypt_withAKeyBoundToEachOperation_saysHowManyBatchesCancellingSkips()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    when(mockLogsEncryptor.createUnwrapCipher(any(LogBatch.class))).thenReturn(unwrapCipher);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();

    assertThat(ShadowBiometricPrompt.getCurrentPrompt().getDescription().toString())
        .isEqualTo(
            "This log file needs its own authentication. Cancel to skip it and 1 more file.");
  }

  @Test
  public void decrypt_whenAPromptOfItsOwnIsCancelled_reportsItAndDecryptsNothingMore()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    when(mockLogsEncryptor.createUnwrapCipher(FIRST_BATCH)).thenReturn(unwrapCipher);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionWithError(
        BiometricPrompt.ERROR_USER_CANCELED, "Authentication canceled");
    ShadowLooper.idleMainLooper();

    verify(mockCallback)
        .onNotAuthorized(BiometricPrompt.ERROR_USER_CANCELED, "Authentication canceled");
    verify(mockCallback, never()).onFinished();
    verify(mockLogsEncryptor, never()).createUnwrapCipher(SECOND_BATCH);
  }

  @Test
  public void decrypt_whenAnRsaUnwrapCipherCannotBeCreated_failsItsBatchAndGoesOn()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    CrumblesKeysException noKey = new CrumblesKeysException("No Keystore key.");
    when(mockLogsEncryptor.createUnwrapCipher(FIRST_BATCH)).thenThrow(noKey);
    when(mockLogsEncryptor.createUnwrapCipher(SECOND_BATCH)).thenReturn(unwrapCipher);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH, unwrapCipher)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecryptionFailed(FIRST_BATCH, noKey);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_whenTheKeyTurnsOutToHaveAClosedTimeWindow_opensItForTheBatchesLeft()
      throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    UserNotAuthenticatedException windowClosed = new UserNotAuthenticatedException();
    when(mockLogsEncryptor.createUnwrapCipher(any(LogBatch.class)))
        .thenThrow(new CrumblesKeysException("Failed to initialize the cipher.", windowClosed));
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH))
        .thenThrow(windowClosed)
        .thenReturn(firstLogs);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecrypted(FIRST_BATCH, firstLogs);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_whenAnAuthorizedRsaCipherFails_reportsItsBatchAndGoesOn() throws Exception {
    partition(NO_BATCHES, BOTH_BATCHES, NO_BATCHES);
    when(mockLogsEncryptor.isKeystoreKeyBoundToEachOperation()).thenReturn(true);
    when(mockLogsEncryptor.createUnwrapCipher(any(LogBatch.class))).thenReturn(unwrapCipher);
    CrumblesLogsDecryptionException wrongKey =
        new CrumblesLogsDecryptionException("A cryptographic error occurred.");
    when(mockLogsEncryptor.decryptLogBatch(FIRST_BATCH, unwrapCipher)).thenThrow(wrongKey);
    when(mockLogsEncryptor.decryptLogBatch(SECOND_BATCH, unwrapCipher)).thenReturn(secondLogs);

    decryptor.decrypt(BOTH_BATCHES, mockCallback);
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();
    ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
    ShadowLooper.idleMainLooper();

    verify(mockCallback).onDecryptionFailed(FIRST_BATCH, wrongKey);
    verify(mockCallback).onDecrypted(SECOND_BATCH, secondLogs);
    verify(mockCallback).onFinished();
  }

  @Test
  public void decrypt_withRealPerOperationRsaKey_authorizesEachCipher() throws Exception {
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    try {
      CrumblesLogsEncryptor realEncryptor = new CrumblesLogsEncryptor();
      realEncryptor.generateKeyPair();
      CrumblesBatchKeyStore.deleteKeys();
      LogBatch first = realEncryptor.encryptLogs(firstLogs.logs(), /* publicKey= */ null);
      LogBatch second = realEncryptor.encryptLogs(secondLogs.logs(), /* publicKey= */ null);

      new CrumblesAuthorizedLogDecryptor(activityController.get(), realEncryptor)
          .decrypt(ImmutableList.of(first, second), mockCallback);
      for (int i = 0; i < 2; i++) {
        ShadowLooper.idleMainLooper();
        FakeAndroidKeyStoreSpi.authorizeLatestPendingCipher();
        ShadowBiometricPrompt.authenticateCurrentSessionSuccessfully();
      }
      ShadowLooper.idleMainLooper();

      verify(mockCallback)
          .onDecrypted(eq(first), argThat(d -> Arrays.equals(d.logs(), firstLogs.logs())));
      verify(mockCallback)
          .onDecrypted(eq(second), argThat(d -> Arrays.equals(d.logs(), secondLogs.logs())));
      verify(mockCallback).onFinished();
    } finally {
      FakeAndroidKeyStoreSpi.keystoreEntries.clear();
      Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    }
  }
}
