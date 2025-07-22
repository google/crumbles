package com.android.securelogging;

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import java.io.File;

/**
 * A {@link Worker} that renames files from _processing.bin to _sent.bin to indicate they have been
 * processed and sent.
 */
public class CrumblesMarkProcessingAsSentWorker extends Worker {

  private static final String TAG = "CrumblesMarkProcessingAsSentWorker";

  public CrumblesMarkProcessingAsSentWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  @NonNull
  @Override
  public Result doWork() {
    Log.d(TAG, "CrumblesMarkProcessingAsSentWorker doWork() started");
    Context context = getApplicationContext();

    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return Result.failure();
    }

    // Find files ending ONLY in _processing.bin.
    File[] processingBinFiles =
        directory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.PROCESSING_SUFFIX));

    if (processingBinFiles == null || processingBinFiles.length == 0) {
      Log.d(TAG, "No _processing.bin files found to mark.");
      return Result.success();
    }

    Log.d(TAG, "Found " + processingBinFiles.length + " _processing.bin files to mark as sent.");
    int markedCount = 0;
    for (File file : processingBinFiles) {
      String originalName = file.getName();
      // Construct the new file name (_sent.bin).
      if (originalName.endsWith(CrumblesConstants.PROCESSING_SUFFIX)) {
        String baseName =
            originalName.substring(
                0, originalName.length() - CrumblesConstants.PROCESSING_SUFFIX.length());
        String newName = baseName + CrumblesConstants.SENT_SUFFIX;
        File newFile = new File(directory, newName);

        if (file.renameTo(newFile)) {
          Log.d(TAG, "Marked: " + originalName + " to " + newName);
          markedCount++;
        } else {
          // Failure to rename one file shouldn't stop the worker.
          Log.e(TAG, "Failed to mark: " + originalName);
        }
      } else {
        // Should not happen based on listFiles filter, but as a safeguard.
        Log.e(
            TAG,
            "File did not end with "
                + CrumblesConstants.PROCESSING_SUFFIX
                + " unexpectedly: "
                + originalName);
      }
    }

    Log.d(TAG, "Marking task finished. Successfully marked " + markedCount + " files as sent.");
    return Result.success();
  }
}
