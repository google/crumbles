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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Keeps in device-encrypted storage what Crumbles needs to collect security logs before the first
 * unlock after a restart, while the Keystore and credential-encrypted storage are unavailable: the
 * recipient of the last batch saved while unlocked, the batches collected for it since, and the
 * losses to report once the user unlocks the device.
 *
 * <p>A change of the encryption key forgets the recipient, so that no logs are encrypted to a key
 * that the user replaced. Until a batch is saved for the new key, logs wait with the platform.
 *
 * <p>The recipient's public key, the device ID and the attestation chain are kept unencrypted, so
 * that the batches saved before the unlock seal them in format version 2 like every other batch.
 * Device-encrypted storage is readable before the first unlock, so anyone who can extract the app's
 * data then learns that collection is set up, the device ID and chain, and the recipient.
 */
final class CrumblesDirectBootStore {
  private static final String TAG = "CrumblesDirectBootStore";
  private static final String PREFS_NAME = "crumbles_direct_boot";
  private static final String PREF_RECIPIENT = "recipient";
  private static final String PREF_DEVICE_ID = "deviceId";
  private static final String PREF_ATTESTATION_CHAIN = "attestationChain";
  private static final String PREF_NEXT_BATCH = "nextBatch";
  private static final String PREF_LOSS_REPORTS = "lossReports";
  private static final String PREF_ALERT = "alertAfterUnlock";

  /** At most this many bytes of batches wait for the unlock, as in the staging area. */
  private static final long CAP_BYTES = 16L * 1024 * 1024;

  /**
   * Counts the forgotten recipients, so that a batch saved for a replaced key is not remembered.
   */
  private static final AtomicLong forgottenRecipients = new AtomicLong();

  private final SharedPreferences preferences;
  private final File filesDirectory;
  private final File batchesDirectory;

  CrumblesDirectBootStore(Context context) {
    Context deviceContext = context.createDeviceProtectedStorageContext();
    preferences = deviceContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    filesDirectory = deviceContext.getFilesDir();
    batchesDirectory = new File(filesDirectory, "logs_before_unlock");
  }

  /** Returns how many recipients were forgotten so far, for {@link #rememberRecipient}. */
  static long forgottenRecipients() {
    return forgottenRecipients.get();
  }

  /** Forgets the recipient, as when the encryption key changes. */
  static void forgetRecipient(Context context) {
    synchronized (CrumblesDirectBootStore.class) {
      forgottenRecipients.incrementAndGet();
      new CrumblesDirectBootStore(context)
          .preferences
          .edit()
          .remove(PREF_RECIPIENT)
          .remove(PREF_DEVICE_ID)
          .remove(PREF_ATTESTATION_CHAIN)
          .commit();
    }
  }

  /**
   * Remembers {@code recipient}, for which a batch sealing {@code deviceId} and {@code
   * attestationChain} was just saved, unless a recipient was forgotten since {@link
   * #forgottenRecipients} returned {@code forgottenBefore}: the key may have changed meanwhile.
   */
  void rememberRecipient(
      long forgottenBefore,
      PublicKey recipient,
      String deviceId,
      ImmutableList<ByteString> attestationChain) {
    synchronized (CrumblesDirectBootStore.class) {
      if (forgottenRecipients.get() != forgottenBefore) {
        return;
      }
      preferences
          .edit()
          .putString(PREF_RECIPIENT, Base64.getEncoder().encodeToString(recipient.getEncoded()))
          .putString(PREF_DEVICE_ID, deviceId)
          .putString(
              PREF_ATTESTATION_CHAIN,
              attestationChain.stream()
                  .map(certificate -> Base64.getEncoder().encodeToString(certificate.toByteArray()))
                  .collect(joining(",")))
          .apply();
    }
  }

  /**
   * Returns whether a batch can be saved: a recipient is remembered, the saved batches are below
   * their cap, and usable space is at least what a retrieval of security logs requires.
   */
  // Suppress "UsableSpace" because the threshold is the one that the retrievals of security logs
  // check against usable space too.
  @SuppressLint("UsableSpace")
  boolean canSaveBatch() {
    long savedBytes = batches().stream().mapToLong(File::length).sum();
    return preferences.contains(PREF_RECIPIENT)
        && savedBytes < CAP_BYTES
        && filesDirectory.getUsableSpace()
            >= CrumblesDeviceAdminReceiver.MIN_SECURITY_USABLE_SPACE_BYTES;
  }

  /**
   * Encrypts {@code logs} to the recipient and saves them as the newest batch, with the attestation
   * chain that the batch seals, if it can.
   */
  boolean saveBatch(byte[] logs) {
    long forgottenBefore = forgottenRecipients();
    try {
      PublicKey recipient =
          KeyFactory.getInstance("RSA")
              .generatePublic(
                  new X509EncodedKeySpec(
                      Base64.getDecoder().decode(preferences.getString(PREF_RECIPIENT, ""))));
      String attestationChain = preferences.getString(PREF_ATTESTATION_CHAIN, "");
      LogBatch batch =
          CrumblesMain.getLogsEncryptorInstance()
              .encryptLogsBeforeFirstUnlock(
                  logs,
                  recipient,
                  preferences.getString(PREF_DEVICE_ID, ""),
                  parseChain(attestationChain));
      synchronized (CrumblesDirectBootStore.class) {
        // A key change or a wipe since the recipient was read keeps it from getting the batch.
        if (forgottenRecipients() != forgottenBefore) {
          return false;
        }
        long number = preferences.getLong(PREF_NEXT_BATCH, 0);
        preferences.edit().putLong(PREF_NEXT_BATCH, number + 1).commit();
        batchesDirectory.mkdirs();
        File file = new File(batchesDirectory, String.format(Locale.US, "%019d.bin", number));
        // Signing the batch after the unlock must not add a signature for another chain.
        Files.write(chainFile(file).toPath(), attestationChain.getBytes(UTF_8));
        @SuppressWarnings("unused")
        var unusedBatchFile =
            CrumblesMain.getLogsEncryptorInstance()
                .serializeBytes(batch, batchesDirectory, file.getName());
        return true;
      }
    } catch (GeneralSecurityException
        | IllegalArgumentException
        | IOException
        | CrumblesKeysException
        | CrumblesLogsEncryptionException e) {
      Log.e(TAG, "Failed to save a batch before the first unlock.", e);
      return false;
    }
  }

  /** Returns the attestation chain that {@code batch} sealed, or an empty list if it is unknown. */
  ImmutableList<ByteString> sealedChain(File batch) {
    try {
      return parseChain(new String(Files.readAllBytes(chainFile(batch).toPath()), UTF_8));
    } catch (IOException | IllegalArgumentException e) {
      Log.w(TAG, "The attestation chain of a batch saved before the unlock is unknown.", e);
      return ImmutableList.of();
    }
  }

  /** Deletes {@code batch} with its attestation chain, and returns whether the batch is gone. */
  boolean deleteBatch(File batch) {
    @SuppressWarnings("unused")
    var unusedDeleted = chainFile(batch).delete();
    return batch.delete();
  }

  /**
   * Deletes every saved batch, as when the user wipes the batches on the device, and returns how
   * many were deleted.
   */
  int deleteAllBatches() {
    synchronized (CrumblesDirectBootStore.class) {
      int deleted = 0;
      for (File batch : batches()) {
        if (deleteBatch(batch)) {
          deleted++;
        }
      }
      File[] chains = batchesDirectory.listFiles((directory, name) -> name.endsWith(".chain"));
      for (File chain : chains == null ? new File[0] : chains) {
        @SuppressWarnings("unused")
        var unusedDeleted = chain.delete();
      }
      return deleted;
    }
  }

  /**
   * Deletes those of {@code files} that are saved batches, each with its attestation chain, as when
   * the user discards them, and returns how many were deleted.
   */
  int deleteBatches(Collection<File> files) {
    synchronized (CrumblesDirectBootStore.class) {
      int deleted = 0;
      for (File batch : batches()) {
        if (files.contains(batch) && deleteBatch(batch)) {
          deleted++;
        }
      }
      return deleted;
    }
  }

  /** Returns whether a recipient is remembered, whether or not there is room for a batch. */
  boolean hasRecipient() {
    return preferences.contains(PREF_RECIPIENT);
  }

  /** Returns the saved batches, oldest first. */
  ImmutableList<File> batches() {
    File[] files = batchesDirectory.listFiles((directory, name) -> name.endsWith(".bin"));
    return files == null
        ? ImmutableList.of()
        : Arrays.stream(files).sorted().collect(toImmutableList());
  }

  /**
   * Keeps {@code report} of a possible loss until the unlock, with the alert it asks for, unless
   * the same report is kept already.
   */
  void deferLossReport(String report, boolean alertUser) {
    if (!values(PREF_LOSS_REPORTS).contains(report)) {
      add(PREF_LOSS_REPORTS, report);
    }
    if (alertUser) {
      preferences.edit().putBoolean(PREF_ALERT, true).apply();
    }
  }

  /** Returns and forgets the loss reports kept until the unlock. */
  ImmutableList<String> takeLossReports() {
    ImmutableList<String> reports = values(PREF_LOSS_REPORTS);
    preferences.edit().remove(PREF_LOSS_REPORTS).remove(PREF_ALERT).apply();
    return reports;
  }

  /** Returns whether a loss report kept until the unlock asks for an alert. */
  boolean isAlertDeferred() {
    return preferences.getBoolean(PREF_ALERT, false);
  }

  private static File chainFile(File batch) {
    String name = batch.getName();
    String stem = name.substring(0, name.length() - ".bin".length());
    return new File(batch.getParentFile(), stem + ".chain");
  }

  private static ImmutableList<ByteString> parseChain(String chain) {
    return Splitter.on(',')
        .omitEmptyStrings()
        .splitToList(chain)
        .stream()
        .map(certificate -> ByteString.copyFrom(Base64.getDecoder().decode(certificate)))
        .collect(toImmutableList());
  }

  private ImmutableList<String> values(String key) {
    return ImmutableList.copyOf(
        Splitter.on('\n').omitEmptyStrings().splitToList(preferences.getString(key, "")));
  }

  private void add(String key, String value) {
    preferences.edit().putString(key, preferences.getString(key, "") + value + "\n").apply();
  }
}
