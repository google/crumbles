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
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.util.Log;
import androidx.annotation.WorkerThread;
import com.android.securelogging.CrumblesSendAndMarkProcessingWorker.UploadDestination;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.android.securelogging.exceptions.CrumblesLogsEncryptionException;
import java.io.File;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.InstantSource;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;

/**
 * Tells the holder of the external key about a change of that key or of the upload destination
 * beforehand, at the destination they read.
 */
final class CrumblesKeyHandover {
  private static final String TAG = "CrumblesKeyHandover";

  /** Result of a handover. */
  enum Outcome {
    /** No external key is active, so there is nobody to hand over to. */
    NOT_NEEDED,
    /**
     * The handover record was uploaded: to a WebDAV server, which confirmed it, or for a key
     * change, to the upload folder.
     */
    UPLOADED,
    /**
     * The storage app of the upload folder took the notice of a destination change and served it
     * back. It can do that from a cache on the device and never sync the notice, for example while
     * a firewall, Data Saver or its own settings keep it offline, so nothing confirms the delivery.
     */
    UPLOADED_UNCONFIRMED,
    /**
     * As {@link #UPLOADED_UNCONFIRMED}, while the device had no validated network, so the storage
     * app could not have synced the notice yet.
     */
    UPLOADED_OFFLINE,
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
   * upload destination is set; otherwise, or if the upload fails, it stays pending. A WebDAV server
   * presenting a key other than the pinned one is reported to the user as for regular uploads.
   *
   * <p>Never call this on the main thread: uploading to a WebDAV server is network I/O.
   */
  @WorkerThread
  static Outcome handOver(Context context, String changeDescription) {
    Outcome outcome =
        sealAndUpload(
            context,
            "Crumbles key handover",
            changeDescription,
            CrumblesSendAndMarkProcessingWorker.readUploadDestination(context),
            /* shouldUpload= */ () -> true);
    // A key change keeps the upload folder, whose daily re-check of kept copies sends the record
    // again if the storage app loses it.
    if (outcome.equals(Outcome.UPLOADED_UNCONFIRMED)) {
      outcome = Outcome.UPLOADED;
    }
    logOutcome(context, "KEY_HANDOVER_", outcome, changeDescription);
    return outcome;
  }

  /**
   * Seals a record of an upcoming upload destination change, whose description should name the new
   * destination, to the active external key. Then uploads it on the calling thread to {@code
   * outgoing}, the destination that the change replaces, as read before the change: a destination
   * saved meanwhile never gets the record. The record stays pending for background sync instead if
   * {@code outgoing} is not set, if {@code shouldUpload} returns false once the record is sealed,
   * or if the upload fails. Only a WebDAV server confirms the upload: an upload to a folder is
   * {@link Outcome#UPLOADED_UNCONFIRMED}, or {@link Outcome#UPLOADED_OFFLINE} without a validated
   * network.
   *
   * <p>Never call this on the main thread: uploading to a WebDAV server is network I/O.
   */
  @WorkerThread
  static Outcome handOverDestination(
      Context context,
      String changeDescription,
      UploadDestination outgoing,
      BooleanSupplier shouldUpload) {
    Outcome outcome =
        sealAndUpload(
            context,
            "Crumbles upload destination change",
            changeDescription,
            outgoing,
            shouldUpload);
    if (outcome.equals(Outcome.UPLOADED_UNCONFIRMED) && !hasValidatedNetwork(context)) {
      outcome = Outcome.UPLOADED_OFFLINE;
    }
    logOutcome(context, "DESTINATION_HANDOVER_", outcome, changeDescription);
    return outcome;
  }

  private static void logOutcome(
      Context context, String auditEventPrefix, Outcome outcome, String changeDescription) {
    CrumblesAppAuditLogger.getInstance(context)
        .logEvent(auditEventPrefix + outcome.name(), changeDescription);
  }

  /** Returns whether the active network of the device reaches the internet. */
  private static boolean hasValidatedNetwork(Context context) {
    ConnectivityManager connectivity = context.getSystemService(ConnectivityManager.class);
    NetworkCapabilities capabilities =
        connectivity == null
            ? null
            : connectivity.getNetworkCapabilities(connectivity.getActiveNetwork());
    return capabilities != null
        && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
  }

  /**
   * Seals a record, made of {@code title} and {@code changeDescription}, to the active external key
   * and, while {@code shouldUpload} returns true, uploads it to {@code destination}.
   */
  private static Outcome sealAndUpload(
      Context context,
      String title,
      String changeDescription,
      UploadDestination destination,
      BooleanSupplier shouldUpload) {
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
              context,
              /* isNetworkBatch= */ false,
              describeHandover(context, title, changeDescription, outgoingKey),
              outgoingKey);
    } catch (CrumblesKeysException | CrumblesLogsEncryptionException | QuotaRefusedException e) {
      Log.e(TAG, "Failed to seal the handover record.", e);
      return Outcome.NOT_SEALED;
    }
    if (handoverBatch.isEmpty()) {
      return Outcome.NOT_SEALED;
    }
    if (!destination.isConfigured()) {
      return Outcome.KEPT_ON_DEVICE;
    }
    // Once the caller stops waiting, the record waits for background sync instead, which sends it
    // to the destination saved by then.
    if (!shouldUpload.getAsBoolean()) {
      return Outcome.UPLOAD_FAILED;
    }
    // Closing the uploader wipes any WebDAV credentials it holds.
    try (RemoteStorageUploader uploader =
        CrumblesSendAndMarkProcessingWorker.resolveStorageUploader(context, destination)) {
      if (uploader == null) {
        return Outcome.UPLOAD_FAILED;
      }
      File batchFile = handoverBatch.get().toFile();
      if (CrumblesSendAndMarkProcessingWorker.uploadSingleFile(
          context, uploader, batchFile, batchFile.getParentFile())) {
        // A storage app serves the record back from its cache on the device, whether or not it
        // syncs it later. Only a WebDAV server's answer shows that the record left the device.
        return uploader.getStorageType().equals(StorageType.STORAGE_TYPE_WEBDAV)
            ? Outcome.UPLOADED
            : Outcome.UPLOADED_UNCONFIRMED;
      }
      if (uploader.rejectedServerKey()) {
        CrumblesSendAndMarkProcessingWorker.reportServerKeyRejected(context);
      }
      return Outcome.UPLOAD_FAILED;
    }
  }

  private static byte[] describeHandover(
      Context context, String title, String changeDescription, PublicKey outgoingKey)
      throws CrumblesKeysException {
    return String.join(
            "\n",
            title,
            "Change: " + changeDescription,
            "Sealed to key fingerprint: "
                + CrumblesLogsEncryptor.getPublicKeyFingerprint(outgoingKey).replace('\n', ':'),
            "Time: " + InstantSource.system().instant(),
            "Device: " + CrumblesDeviceIdManager.getDeviceId(context))
        .getBytes(UTF_8);
  }

  private CrumblesKeyHandover() {}
}
