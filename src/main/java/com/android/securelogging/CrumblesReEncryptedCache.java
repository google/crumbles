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

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;
import androidx.core.content.FileProvider;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Manages the cache directory that temporarily stages re-encrypted logs shared with another app.
 *
 * <p>Those files are copies of sensitive log content, so neither they nor the grants to read them
 * may outlive the share they were created for.
 */
final class CrumblesReEncryptedCache {

  private static final String TAG = "[CrumblesReEncryptedCache]";

  /** Returns the cache directory that stages re-encrypted logs for sharing. */
  static File getDirectory(Context context) {
    return new File(context.getCacheDir(), CrumblesConstants.TEMP_RE_ENCRYPTED_DIR);
  }

  /**
   * Deletes the re-encryption cache directory with all of its content, revoking every grant to read
   * each file before deleting it.
   *
   * <p>Nothing outside the directory returned by {@link #getDirectory} is touched. {@link
   * Files#walkFileTree(Path, FileVisitor)} does not follow symbolic links by default, keeping the
   * sweep inside the cache directory.
   */
  static void sweep(Context context) {
    Path directory = getDirectory(context).toPath();
    if (!Files.exists(directory)) {
      return;
    }
    try {
      Files.walkFileTree(
          directory,
          new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                throws IOException {
              revokeReadGrants(context, file.toFile());
              Files.deleteIfExists(file);
              return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                throws IOException {
              if (exc != null) {
                throw exc;
              }
              Files.deleteIfExists(dir);
              return FileVisitResult.CONTINUE;
            }
          });
    } catch (IOException e) {
      Log.w(TAG, "Failed to sweep re-encrypted log cache directory.", e);
    }
  }

  /**
   * Ends every grant to read {@code file}, whichever app holds it, including a grant made before
   * the process restarted.
   */
  private static void revokeReadGrants(Context context, File file) {
    Uri uri;
    try {
      uri = FileProvider.getUriForFile(context, CrumblesConstants.FILE_PROVIDER_AUTHORITY, file);
    } catch (IllegalArgumentException e) {
      // The provider cannot name the file, for instance a link that resolves outside its roots, so
      // it never served the file and no grant to read it exists.
      Log.w(TAG, "Staged file has no content URI, so there is no grant to revoke.", e);
      return;
    }
    context.revokeUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
  }

  private CrumblesReEncryptedCache() {}
}
