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
