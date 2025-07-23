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
import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.FileProvider;
import java.io.File;

/** A helper class to wrap the static FileProvider.getUriForFile call for testability. */
public class CrumblesUriGenerator {

  private static final String TAG = "CrumblesUriGenerator";

  /**
   * Generates a content URI for a given file using the app's FileProvider.
   *
   * @param context The application context.
   * @param file The file for which to create a URI.
   * @return The content URI, or null if an error occurs.
   */
  @Nullable
  public Uri getUriForFile(@NonNull Context context, @NonNull File file) {
    try {
      String authority = context.getPackageName() + ".fileprovider";
      return FileProvider.getUriForFile(context, authority, file);
    } catch (IllegalArgumentException e) {
      Log.e(TAG, "Error getting URI for file " + file.getName() + ": " + e.getMessage());
      return null;
    }
  }
}
