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

import android.content.Context;
import java.io.File;

/**
 * Interface for uploading encrypted log files to a remote storage destination.
 *
 * <p>Implementations that hold credential material in memory release it in {@link #close()}, so
 * callers should use an uploader inside a try-with-resources block.
 */
public interface RemoteStorageUploader extends AutoCloseable {

  /**
   * Uploads a single encrypted log file to the configured remote destination.
   *
   * @param context Application context.
   * @param file The local file to upload.
   * @param remoteFileName The destination file name on remote storage.
   * @return {@code true} if upload succeeded and file write is verified, {@code false} otherwise.
   */
  boolean uploadFile(Context context, File file, String remoteFileName);

  /** Returns the storage type identifier constant (e.g., GOOGLE_DRIVE or WEBDAV). */
  StorageType getStorageType();

  /** Returns a human-readable display description of the destination for notifications/logs. */
  String getDestinationDescription();

  /**
   * Returns whether an upload failed because the server presented a key other than the pinned one.
   */
  default boolean rejectedServerKey() {
    return false;
  }

  /**
   * Returns whether the last upload failed in transit, for example because the destination could
   * not be reached or did not finish before the deadline, rather than because it refused the batch.
   */
  boolean transportFailed();

  /**
   * Returns whether the last upload failed in transit while its body was being sent, as when a
   * large batch outlasts its deadline on a slow link. Unlike a failure while connecting, or while
   * waiting for the destination to confirm the batch, it does not mean that the next, smaller,
   * batches would fail too.
   */
  boolean failedMidBody();

  /**
   * Releases any credential material this uploader holds in memory.
   *
   * <p>Overrides {@link AutoCloseable#close()} without its checked exception, so callers never need
   * to handle one. The default implementation does nothing, for uploaders that hold no secrets.
   */
  @Override
  default void close() {}
}
