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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import java.io.File;
import java.util.ArrayList;

/**
 * BroadcastReceiver that receives Chooser share completion callbacks (Intent.EXTRA_CHOSEN_COMPONENT)
 * and transitions confirmed log files from _processing.bin to _sent.bin.
 */
public class CrumblesShareResultReceiver extends BroadcastReceiver {

  private static final String TAG = "CrumblesShareResultReceiver";

  @Override
  public void onReceive(Context context, Intent intent) {
    if (context == null || intent == null) {
      return;
    }

    if (!intent.hasExtra(Intent.EXTRA_CHOSEN_COMPONENT)) {
      Log.d(TAG, "Chooser result received without EXTRA_CHOSEN_COMPONENT; skipping.");
      return;
    }

    ArrayList<String> fileNames = intent.getStringArrayListExtra(CrumblesConstants.EXTRA_FILES);
    if (fileNames == null || fileNames.isEmpty()) {
      Log.w(TAG, "Chooser result received with EXTRA_CHOSEN_COMPONENT but no file names extra.");
      return;
    }

    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return;
    }

    int markedCount = 0;
    for (String fileName : fileNames) {
      if (fileName == null
          || !fileName.startsWith(CrumblesConstants.ENCRYPTED_LOG_FILE_NAME)
          || !fileName.endsWith(CrumblesConstants.PROCESSING_SUFFIX)) {
        continue;
      }

      File file;
      try {
        file = new File(directory, new File(fileName).getName()).getCanonicalFile();
        if (!file.getParentFile().equals(directory.getCanonicalFile())) {
          Log.w(TAG, "Potential path traversal attempt ignored for file: " + fileName);
          continue;
        }
      } catch (Exception e) {
        Log.e(TAG, "Failed to resolve canonical path for file: " + fileName, e);
        continue;
      }

      if (!file.exists()) {
        Log.w(TAG, "Processing file not found for marking sent: " + file.getAbsolutePath());
        continue;
      }

      String originalName = file.getName();
      String baseName =
          originalName.substring(
              0, originalName.length() - CrumblesConstants.PROCESSING_SUFFIX.length());
      String newName = baseName + CrumblesConstants.SENT_SUFFIX;
      File sentFile = new File(directory, newName);

      if (file.renameTo(sentFile)) {
        Log.d(TAG, "Marked as sent: " + originalName + " -> " + newName);
        markedCount++;
      } else {
        Log.e(TAG, "Failed to mark as sent: " + originalName);
      }
    }

    if (markedCount > 0) {
      CrumblesAppAuditLogger.getInstance(context)
          .logEvent(
              "LOGS_MARKED_SENT",
              "Successfully marked " + markedCount + " log file(s) as sent.");
    }
  }
}
