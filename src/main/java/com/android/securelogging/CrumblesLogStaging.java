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

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.DSYNC;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

import android.content.Context;
import android.util.Log;
import androidx.annotation.VisibleForTesting;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.crypto.AEADBadTagException;

/**
 * Holds log batches that arrive while no recipient key is available, sealed by {@link
 * CrumblesLogStagingSealer}, until {@link #drain} hands them over to be encrypted to the recipient.
 *
 * <p>Staged batches use at most {@link #CAP_BYTES}. A batch that does not fit is refused rather
 * than evicting older ones, and the user is alerted as when the storage cap is reached.
 *
 * <p>Thread-safe: staging, draining, counting, wiping and emptiness checks synchronize on {@link
 * #LOCK}.
 */
final class CrumblesLogStaging {
  /** Guards the staged batches. Lock order: this lock, then the receiver's {@code EXCERPT_LOCK}. */
  private static final Object LOCK = new Object();

  /** The most bytes that staged batches may use. */
  static final long CAP_BYTES = 16L * 1024 * 1024;

  @VisibleForTesting static final String AUDIT_EVENT_STAGING_FULL = "LOGS_STAGING_FULL";

  @VisibleForTesting
  static final String AUDIT_EVENT_STAGED_LOGS_UNREADABLE = "STAGED_LOGS_UNREADABLE";

  private static final String TAG = "CrumblesLogStaging";
  private static final String SEALED_SUFFIX = ".sealed";
  // Zero-padded sequence numbers, so that names sort in staging order.
  private static final Pattern BATCH_NAME = Pattern.compile("\\d{19}(?:-[NS])?\\.sealed");

  enum WriteResult {
    STORED,
    DROPPED,
    FAILED
  }

  /** Receives the batches that {@link #drain} hands over. */
  interface BatchWriter {
    /** Stores {@code logs} durably elsewhere. */
    WriteResult write(boolean isNetworkBatch, byte[] logs);
  }

  private final Context context;
  private final File directory;

  /** Creates the staging area of the app that {@code context} belongs to. */
  CrumblesLogStaging(Context context) {
    this.context = context;
    this.directory = new File(context.getNoBackupFilesDir(), "staged_logs");
  }

  /** Returns whether no batch is staged. */
  boolean isEmpty() {
    synchronized (LOCK) {
      return listBatches().length == 0;
    }
  }

  /** Returns how many batches are staged. */
  int countBatches() {
    synchronized (LOCK) {
      return listBatches().length;
    }
  }

  /** Deletes every staged batch and returns how many were deleted. */
  int wipeAllBatches() {
    synchronized (LOCK) {
      int deletedCount = 0;
      for (File batch : listBatches()) {
        if (batch.delete()) {
          deletedCount++;
        } else {
          Log.e(TAG, "Failed to delete staged batch " + batch.getName());
        }
      }
      return deletedCount;
    }
  }

  /** Runs {@code action} holding the staging lock, so that it may then take the excerpt lock. */
  static <T> T callLocked(Supplier<T> action) {
    synchronized (LOCK) {
      return action.get();
    }
  }

  /**
   * Seals {@code logs} and stages them after the batches already staged, unless they do not fit.
   *
   * @return whether the batch was staged
   * @throws GeneralSecurityException if the Keystore fails
   * @throws IOException if the batch cannot be written
   */
  boolean stage(boolean isNetworkBatch, byte[] logs) throws GeneralSecurityException, IOException {
    synchronized (LOCK) {
    File[] batches = listBatches();
    long usedBytes = Arrays.stream(batches).mapToLong(File::length).sum();
    long sealedBytes = (long) logs.length + CrumblesLogStagingSealer.OVERHEAD_BYTES;
    if (usedBytes + sealedBytes > CAP_BYTES) {
      reportFull(usedBytes, sealedBytes);
      return false;
    }
    long sequence = batches.length == 0 ? 1 : sequenceOf(batches[batches.length - 1]) + 1;
    String name =
        String.format(Locale.US, "%019d", sequence)
            + (isNetworkBatch ? "-N" : "-S")
            + SEALED_SUFFIX;
    byte[] sealed = CrumblesLogStagingSealer.seal(logs, name);
    Path temp = Files.createDirectories(directory.toPath()).resolve(name + ".tmp");
    // The platform keeps no copy of the logs, so they must be durable before staging succeeds.
    Files.write(temp, sealed, CREATE, TRUNCATE_EXISTING, WRITE, DSYNC);
    Files.move(temp, temp.resolveSibling(name), ATOMIC_MOVE);
    return true;
    }
  }

  /**
   * Hands the staged batches to {@code writer}, oldest first, and deletes each one it stores. Stops
   * at the first batch that {@code writer} does not store or that cannot be read for now, keeping
   * it and the newer batches in order. A batch that can never be read is reported and deleted.
   *
   * @return the number of batches that {@code writer} stored
   */
  int drain(BatchWriter writer) {
    synchronized (LOCK) {
    int stored = 0;
    for (File batch : listBatches()) {
      byte[] logs;
      try {
        logs = CrumblesLogStagingSealer.unseal(Files.readAllBytes(batch.toPath()), batch.getName());
      } catch (AEADBadTagException e) {
        reportUnreadable(batch, e);
        continue;
      } catch (GeneralSecurityException | IOException e) {
        Log.e(TAG, "Failed to unseal a staged batch; keeping it and the newer ones.", e);
        return stored;
      }
      WriteResult result = writer.write(batch.getName().contains("-N.sealed"), logs);
      if (result == WriteResult.FAILED) {
        return stored;
      }
      // DROPPED is deliberately not counted: the writer discarded the batch rather than storing
      // it, so it is only deleted below.
      if (result == WriteResult.STORED) {
        stored++;
      }
      delete(batch);
    }
    return stored;
    }
  }

  private File[] listBatches() {
    File[] batches = directory.listFiles((dir, name) -> BATCH_NAME.matcher(name).matches());
    if (batches == null) {
      return new File[0];
    }
    Arrays.sort(batches);
    return batches;
  }

  private static long sequenceOf(File batch) {
    String name = batch.getName();
    return Long.parseLong(name.substring(0, 19));
  }

  private void reportFull(long usedBytes, long sealedBytes) {
    Log.w(TAG, "Staging is full; refusing the batch rather than evicting older ones.");
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_STAGING_FULL,
            "Staged log batches use "
                + usedBytes
                + " of "
                + CAP_BYTES
                + " permitted bytes; a batch of "
                + sealedBytes
                + " bytes was refused.");
    CrumblesLogStorageQuota.notifyUser(context, R.string.notification_text_storage_stopped);
  }

  private void reportUnreadable(File batch, AEADBadTagException e) {
    Log.e(TAG, "Deleting a staged batch that fails authentication.", e);
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(
            AUDIT_EVENT_STAGED_LOGS_UNREADABLE,
            "Staged log batch "
                + batch.getName()
                + " failed authentication and was deleted: it was altered, or its device key is"
                + " gone.");
    delete(batch);
  }

  private static void delete(File batch) {
    if (!batch.delete()) {
      Log.e(TAG, "Failed to delete staged batch " + batch.getName());
    }
  }
}
