/*
 * Copyright 2025 Google LLC
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

import static com.google.common.base.Preconditions.checkNotNull;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.util.Log;
import androidx.documentfile.provider.DocumentFile;
import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Remote storage uploader for Google Drive via Android Storage Access Framework. */
public final class GoogleDriveStorageUploader implements RemoteStorageUploader {

  private static final String TAG = "GoogleDriveUploader";
  private static final String DIGEST_ALGORITHM = "SHA-256";
  private final DocumentFile targetDir;
  private boolean transportFailed;
  private boolean failedMidBody;

  public GoogleDriveStorageUploader(DocumentFile targetDir) {
    this.targetDir = checkNotNull(targetDir, "targetDir cannot be null");
  }

  /**
   * Copies {@code file} into the destination folder and reads the copy back: the upload only counts
   * if the provider returns exactly the bytes it was given. An incomplete copy is removed.
   *
   * <p>Both transfers run on a thread of their own, through channels that their deadline closes to
   * end a read or write that the provider leaves blocked. A transfer that closing cannot end keeps
   * its thread, not the caller's. Each call into the provider has a deadline too.
   */
  @Override
  public boolean uploadFile(Context context, File file, String remoteFileName) {
    transportFailed = false;
    failedMidBody = false;
    DocumentFile targetDocFile = null;
    boolean uploaded = false;
    // Set on the thread of the copy once it starts: from then until the copy ends, a failure in
    // transit happens while the body is being sent.
    AtomicBoolean copyStarted = new AtomicBoolean();
    boolean copied = false;
    try {
      DocumentFile created =
          CrumblesTransferDeadline.callProvider(
              targetDir.getUri(),
              () -> targetDir.createFile("application/octet-stream", remoteFileName));
      if (created == null) {
        return false;
      }
      if (!isInTargetDir(context, created.getUri())) {
        // Neither written nor deleted: the provider chooses this URI, and could name a document in
        // another folder that Crumbles has access to.
        Log.e(TAG, "The provider created " + remoteFileName + " outside the upload folder");
        return false;
      }
      targetDocFile = created;
      MessageDigest sentDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
      try (InputStream in = new DigestInputStream(new FileInputStream(file), sentDigest)) {
        FileChannel out = openChannel(context, targetDocFile, "w");
        @SuppressWarnings("unused")
        var unusedBytes =
            CrumblesTransferDeadline.runTransfer(
                targetDocFile.getUri(),
                file.length(),
                out,
                deadline -> {
                  copyStarted.set(true);
                  return CrumblesTransferDeadline.copy(in, Channels.newOutputStream(out), deadline);
                });
      }
      copied = true;
      // Reading one byte more than the file tells a longer copy from an exact one.
      if (MessageDigest.isEqual(
          sentDigest.digest(), readBackDigest(context, targetDocFile, file.length() + 1))) {
        uploaded = true;
        return true;
      }
      Log.e(TAG, "The uploaded copy of " + remoteFileName + " differs from the local file");
    } catch (ClosedChannelException e) {
      // Only a deadline ends a transfer or a provider call this way. A provider that stalls one
      // copy stalls the next.
      transportFailed = true;
      failedMidBody = copyStarted.get() && !copied;
      Log.e(TAG, "The provider did not finish copying " + remoteFileName + " in time", e);
    } catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
      // Any app can provide the folder, and binder passes on the runtime exceptions that its
      // provider throws, such as SecurityException or IllegalStateException. They fail this upload
      // instead of the worker, which then keeps the batch for a retry and reports the failure.
      Log.e(TAG, "Failed to upload file " + remoteFileName + " to Google Drive destination", e);
    } finally {
      if (!uploaded && targetDocFile != null && !delete(targetDocFile)) {
        Log.w(TAG, "Could not remove the incomplete copy of " + remoteFileName);
      }
    }
    return false;
  }

  /**
   * Returns whether {@code document} is in the destination folder: a content URI of the same
   * provider, which reports it as a child of the folder within the deadline for a call. A file URI
   * can carry the provider's authority too, and would name a file on this device.
   */
  private boolean isInTargetDir(Context context, Uri document) throws IOException {
    Uri folder = targetDir.getUri();
    return Objects.equals(document.getScheme(), ContentResolver.SCHEME_CONTENT)
        && Objects.equals(document.getAuthority(), folder.getAuthority())
        && CrumblesTransferDeadline.callProvider(
            folder,
            () ->
                DocumentsContract.isChildDocument(context.getContentResolver(), folder, document));
  }

  /**
   * Reads {@code document} back from its provider and returns the digest of its content. It opens
   * the document within the deadline for a call, and reads at most {@code maxBytes} within the
   * deadline for that many, so that a provider that never answers, never ends or never serves the
   * stream cannot stall the upload.
   */
  static byte[] readBackDigest(Context context, DocumentFile document, long maxBytes)
      throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
    FileChannel in = openChannel(context, document, "r");
    @SuppressWarnings("unused")
    var unusedBytes =
        CrumblesTransferDeadline.runTransfer(
            document.getUri(),
            maxBytes,
            in,
            deadline ->
                CrumblesTransferDeadline.copy(
                    new DigestInputStream(
                        ByteStreams.limit(Channels.newInputStream(in), maxBytes), digest),
                    ByteStreams.nullOutputStream(),
                    deadline));
    return digest.digest();
  }

  /**
   * Opens {@code document} in {@code mode}, within the deadline for a call to its provider, and
   * returns a channel on it. Closing the channel closes the document.
   */
  private static FileChannel openChannel(Context context, DocumentFile document, String mode)
      throws IOException {
    AssetFileDescriptor descriptor =
        CrumblesTransferDeadline.callProvider(
            document.getUri(),
            () ->
                CrumblesExternalContentResolver.openAssetFileDescriptor(
                    context, document.getUri(), mode));
    try {
      return Objects.equals(mode, "r")
          ? descriptor.createInputStream().getChannel()
          : descriptor.createOutputStream().getChannel();
    } catch (IOException e) {
      Closeables.close(descriptor, /* swallowIOException= */ true);
      throw e;
    }
  }

  /** Returns whether the provider of {@code document} deleted it in time. */
  private static boolean delete(DocumentFile document) {
    try {
      return CrumblesTransferDeadline.callProvider(document.getUri(), document::delete);
    } catch (IOException e) {
      // The provider holds this call, or an earlier one, past its deadline. The caller logs it.
      return false;
    }
  }

  @Override
  public StorageType getStorageType() {
    return StorageType.STORAGE_TYPE_GOOGLE_DRIVE;
  }

  @Override
  public boolean transportFailed() {
    return transportFailed;
  }

  @Override
  public boolean failedMidBody() {
    return failedMidBody;
  }

  @Override
  public String getDestinationDescription() {
    return "Google Drive";
  }
}
