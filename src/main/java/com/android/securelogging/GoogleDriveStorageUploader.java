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

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.util.Log;
import androidx.documentfile.provider.DocumentFile;
import com.google.android.libraries.security.content.SafeContentResolver;
import com.google.android.libraries.security.content.SafeContentResolver.SourcePolicy;
import com.google.common.io.ByteStreams;
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

/** Remote storage uploader for Google Drive via Android Storage Access Framework. */
public final class GoogleDriveStorageUploader implements RemoteStorageUploader {

  private static final String TAG = "GoogleDriveUploader";
  private static final String DIGEST_ALGORITHM = "SHA-256";
  private final DocumentFile targetDir;
  private boolean transportFailed;

  public GoogleDriveStorageUploader(DocumentFile targetDir) {
    this.targetDir = checkNotNull(targetDir, "targetDir cannot be null");
  }

  /**
   * Copies {@code file} into the destination folder and reads the copy back: the upload only counts
   * if the provider returns exactly the bytes it was given. An incomplete copy is removed.
   *
   * <p>Both transfers go through channels, which their deadline closes to end a read or write that
   * the provider leaves blocked.
   */
  @Override
  public boolean uploadFile(Context context, File file, String remoteFileName) {
    DocumentFile targetDocFile = null;
    boolean uploaded = false;
    try {
      targetDocFile = targetDir.createFile("application/octet-stream", remoteFileName);
      if (targetDocFile == null) {
        return false;
      }
      MessageDigest sentDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
      try (InputStream in = new DigestInputStream(new FileInputStream(file), sentDigest);
          AssetFileDescriptor copy =
              SafeContentResolver.openAssetFileDescriptor(
                  context, targetDocFile.getUri(), "w", SourcePolicy.EXTERNAL_ONLY);
          FileChannel out = copy.createOutputStream().getChannel();
          CrumblesTransferDeadline.Disarm deadline =
              CrumblesTransferDeadline.arm(file.length(), out)) {
        ByteStreams.copy(in, Channels.newOutputStream(out));
      }
      // Reading one byte more than the file tells a longer copy from an exact one.
      if (MessageDigest.isEqual(
          sentDigest.digest(), readBackDigest(context, targetDocFile, file.length() + 1))) {
        uploaded = true;
        return true;
      }
      Log.e(TAG, "The uploaded copy of " + remoteFileName + " differs from the local file");
    } catch (ClosedChannelException e) {
      // Only the deadline closes a channel early. A provider that stalls one copy stalls the next.
      transportFailed = true;
      Log.e(TAG, "The provider did not finish copying " + remoteFileName + " in time", e);
    } catch (IOException | NoSuchAlgorithmException | RuntimeException e) {
      // Any app can provide the folder, and binder passes on the runtime exceptions that its
      // provider throws, such as SecurityException or IllegalStateException. They fail this upload
      // instead of the worker, which then keeps the batch for a retry and reports the failure.
      Log.e(TAG, "Failed to upload file " + remoteFileName + " to Google Drive destination", e);
    } finally {
      if (!uploaded && targetDocFile != null && !targetDocFile.delete()) {
        Log.w(TAG, "Could not remove the incomplete copy of " + remoteFileName);
      }
    }
    return false;
  }

  /**
   * Reads {@code document} back from its provider and returns the digest of its content. It reads
   * at most {@code maxBytes}, within the deadline for that many, so that a provider that never ends
   * or never serves the stream cannot stall the upload.
   */
  static byte[] readBackDigest(Context context, DocumentFile document, long maxBytes)
      throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
    try (AssetFileDescriptor copy =
            SafeContentResolver.openAssetFileDescriptor(
                context, document.getUri(), "r", SourcePolicy.EXTERNAL_ONLY);
        FileChannel in = copy.createInputStream().getChannel();
        CrumblesTransferDeadline.Disarm deadline = CrumblesTransferDeadline.arm(maxBytes, in)) {
      ByteStreams.exhaust(
          new DigestInputStream(ByteStreams.limit(Channels.newInputStream(in), maxBytes), digest));
    }
    return digest.digest();
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
  public String getDestinationDescription() {
    return "Google Drive";
  }
}
