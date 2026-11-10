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
import android.util.Log;
import androidx.annotation.WorkerThread;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import java.io.File;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.InstantSource;
import java.util.Objects;
import java.util.Optional;

/** Tells the holder of the outgoing external key about an encryption key change beforehand. */
final class CrumblesKeyHandover {
  private static final String TAG = "CrumblesKeyHandover";

  /** Result of a handover. */
  enum Outcome {
    /** No external key is active, so there is nobody to hand over to. */
    NOT_NEEDED,
    /** The handover record was uploaded to the upload destination. */
    UPLOADED,
    /** No upload destination is set, so the record stays pending for background sync. */
    KEPT_ON_DEVICE,
    /** The record could not be uploaded, so it stays pending for background sync. */
    UPLOAD_FAILED,
    /** The record could not be created, so the holder of the outgoing key is not told. */
    NOT_SEALED
  }

  /**
   * Seals a record of an upcoming key change, whose description should include the new key's
   * fingerprint when known, to the active external key. Uploads it on the calling thread if an
   * upload destination is set; otherwise, or if the upload fails, it stays pending.
   *
   * <p>Never call this on the main thread: uploading to a WebDAV server is network I/O.
   */
  @WorkerThread
  static Outcome handOver(Context context, String changeDescription) {
    Outcome outcome = sealAndUpload(context, changeDescription);
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent("KEY_HANDOVER_" + outcome.name(), changeDescription);
    return outcome;
  }

  private static Outcome sealAndUpload(Context context, String changeDescription) {
    CrumblesExternalPublicKeyManager keyManager =
        CrumblesExternalPublicKeyManager.getInstance(context);
    if (!keyManager.isExternalKeySelected()) {
      return Outcome.NOT_NEEDED;
    }
    PublicKey outgoingKey = keyManager.getActiveExternalPublicKey();
    if (outgoingKey == null) {
      if (Objects.equals(
          keyManager.getActiveKeyId(), CrumblesDataStoreHolder.UNREADABLE_STORE_ACTIVE_KEY_ID)) {
        return Outcome.NOT_NEEDED;
      }
      Log.e(TAG, "The outgoing external key cannot be read.");
      return Outcome.NOT_SEALED;
    }
    Optional<Path> handoverBatch;
    try {
      handoverBatch =
          CrumblesDeviceAdminReceiver.encryptAndSaveLogs(
              context, false, describeHandover(context, changeDescription, outgoingKey), outgoingKey);
    } catch (CrumblesKeysException | CrumblesLogsEncryptionException | QuotaRefusedException e) {
      Log.e(TAG, "Failed to seal the handover record.", e);
      return Outcome.NOT_SEALED;
    }
    if (handoverBatch.isEmpty()) {
      return Outcome.NOT_SEALED;
    }
    if (!CrumblesSendAndMarkProcessingWorker.isUploadDestinationConfigured(context)) {
      return Outcome.KEPT_ON_DEVICE;
    }
    // Closing the uploader wipes any WebDAV credentials it holds.
    try (RemoteStorageUploader uploader =
        CrumblesSendAndMarkProcessingWorker.resolveStorageUploader(context)) {
      if (uploader == null) {
        return Outcome.UPLOAD_FAILED;
      }
      File batchFile = handoverBatch.get().toFile();
      return CrumblesSendAndMarkProcessingWorker.uploadSingleFile(
              context, uploader, batchFile, batchFile.getParentFile())
          ? Outcome.UPLOADED
          : Outcome.UPLOAD_FAILED;
    }
  }

  private static byte[] describeHandover(
      Context context, String changeDescription, PublicKey outgoingKey)
      throws CrumblesKeysException {
    return String.join(
            "\n",
            "Crumbles key handover",
            "Change: " + changeDescription,
            "Outgoing key fingerprint: "
                + CrumblesLogsEncryptor.getPublicKeyFingerprint(outgoingKey).replace('\n', ':'),
            "Time: " + InstantSource.system().instant(),
            "Device: " + CrumblesDeviceIdManager.getDeviceId(context))
        .getBytes(UTF_8);
  }

  private CrumblesKeyHandover() {}
}
