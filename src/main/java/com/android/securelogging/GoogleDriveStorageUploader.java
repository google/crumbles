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
import android.util.Log;
import androidx.documentfile.provider.DocumentFile;
import com.google.android.libraries.security.content.SafeContentResolver;
import com.google.android.libraries.security.content.SafeContentResolver.SourcePolicy;
import com.google.common.io.ByteStreams;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Remote storage uploader for Google Drive via Android Storage Access Framework. */
public final class GoogleDriveStorageUploader implements RemoteStorageUploader {

  private static final String TAG = "GoogleDriveUploader";
  private final DocumentFile targetDir;

  public GoogleDriveStorageUploader(DocumentFile targetDir) {
    this.targetDir = checkNotNull(targetDir, "targetDir cannot be null");
  }

  @Override
  public boolean uploadFile(Context context, File file, String remoteFileName) {
    try {
      DocumentFile targetDocFile = targetDir.createFile("application/octet-stream", remoteFileName);
      if (targetDocFile != null) {
        try (InputStream in = new FileInputStream(file);
            OutputStream out =
                SafeContentResolver.openOutputStream(
                    context, targetDocFile.getUri(), SourcePolicy.EXTERNAL_ONLY)) {
          if (out != null) {
            ByteStreams.copy(in, out);
            out.flush();
            return true;
          }
        }
      }
    } catch (IOException | SecurityException e) {
      Log.e(TAG, "Failed to upload file " + remoteFileName + " to Google Drive destination", e);
    }
    return false;
  }

  @Override
  public StorageType getStorageType() {
    return StorageType.STORAGE_TYPE_GOOGLE_DRIVE;
  }

  @Override
  public String getDestinationDescription() {
    return "Google Drive";
  }
}
