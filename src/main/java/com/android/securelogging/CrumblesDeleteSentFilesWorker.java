package com.android.securelogging;

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import java.io.File;

/**
 * A {@link Worker} that deletes files with the "_sent.bin" suffix from the app's private directory.
 */
public class CrumblesDeleteSentFilesWorker extends Worker {

  private static final String TAG = "CrumblesDeleteSentFilesWorker";

  public CrumblesDeleteSentFilesWorker(
      @NonNull Context context, @NonNull WorkerParameters workerParams) {
    super(context, workerParams);
  }

  @NonNull
  @Override
  public Result doWork() {
    Log.d(TAG, "CrumblesDeleteSentFilesWorker doWork() started");
    Context context = getApplicationContext();

    File directory =
        new File(
            context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (!directory.exists()) {
      Log.e(TAG, "Log directory not found: " + directory.getAbsolutePath());
      return Result.failure();
    }

    // Find files ending ONLY in _sent.bin.
    File[] sentBinFiles =
        directory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.SENT_SUFFIX));

    if (sentBinFiles == null || sentBinFiles.length == 0) {
      Log.d(TAG, "No _sent.bin files found for deletion.");
      return Result.success();
    }

    Log.d(TAG, "Found " + sentBinFiles.length + " _sent.bin files to delete.");
    int deletedCount = 0;
    for (File file : sentBinFiles) {
      if (file.exists()) {
        if (file.delete()) {
          Log.d(TAG, "Deleted: " + file.getName());
          deletedCount++;
        } else {
          // Failure to delete one file shouldn't stop the worker.
          Log.e(TAG, "Failed to delete: " + file.getName());
        }
      }
    }

    Log.d(
        TAG,
        "Deletion task finished. Successfully deleted "
            + deletedCount
            + " files with _sent suffix.");
    return Result.success();
  }
}
