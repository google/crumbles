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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.util.Log;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.Configuration;
import androidx.work.ListenableWorker;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.TestListenableWorkerBuilder;
import androidx.work.testing.WorkManagerTestInitHelper;
import java.io.File;
import java.io.IOException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Tests the {@link CrumblesDeleteSentFilesWorker} class. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesDeleteSentFilesWorkerTest {

  private Context context;
  private File logDirectory;

  @Before
  public void setUp() throws IOException {
    context = ApplicationProvider.getApplicationContext();

    Configuration config =
        new Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(new SynchronousExecutor())
            .build();
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config);

    File baseDir = context.getFilesDir();
    logDirectory = new File(baseDir, CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    if (logDirectory.exists()) {
      deleteRecursive(logDirectory);
    }
    assertTrue("Test log directory could not be created", logDirectory.mkdirs());
  }

  @After
  public void tearDown() {
    if (logDirectory != null && logDirectory.exists()) {
      deleteRecursive(logDirectory);
    }
  }

  private void deleteRecursive(File fileOrDirectory) {
    if (fileOrDirectory.isDirectory()) {
      File[] children = fileOrDirectory.listFiles();
      if (children != null) {
        for (File child : children) {
          deleteRecursive(child);
        }
      }
    }
    fileOrDirectory.delete();
  }

  private File createFile(String name) throws IOException {
    File file = new File(logDirectory, name);
    assertTrue("Could not create test file: " + name, file.createNewFile());
    return file;
  }

  @Test
  public void doWork_noSentFiles_returnsSuccess() {
    // GIVEN: The log directory exists but contains no _sent.bin files.
    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success and no files should have been present to delete.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(logDirectory.listFiles()).isEmpty();
  }

  @Test
  public void doWork_deletesSentFiles_returnsSuccess() throws IOException {
    // GIVEN: Multiple _sent.bin files and other files exist in the log directory.
    File sentFile1 = createFile("log1" + CrumblesConstants.SENT_SUFFIX);
    File sentFile2 = createFile("log2" + CrumblesConstants.SENT_SUFFIX);
    File processingFile = createFile("log3" + CrumblesConstants.PROCESSING_SUFFIX);
    File otherFile = createFile("other_log.txt");

    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success, _sent.bin files should be deleted and other files
    // should remain.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());

    assertThat(sentFile1.exists()).isFalse();
    assertThat(sentFile2.exists()).isFalse();

    assertThat(processingFile.exists()).isTrue();
    assertThat(otherFile.exists()).isTrue();
  }

  @Test
  public void doWork_logDirectoryMissing_returnsFailure() {
    // GIVEN: The log directory does not exist.
    assertTrue(logDirectory.exists());
    deleteRecursive(logDirectory);
    assertThat(logDirectory.exists()).isFalse();

    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return failure.
    assertThat(result).isEqualTo(ListenableWorker.Result.failure());
  }

  @Test
  public void doWork_emptyDirectory_returnsSuccess() {
    // GIVEN: The log directory exists and is empty (as per setup).
    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(logDirectory.listFiles()).isEmpty(); // Directory should remain empty.
  }

  @Test
  public void doWork_fileWithoutCorrectSuffix_isNotDeleted() throws IOException {
    // GIVEN: Files exist that do not strictly end with _sent.bin.
    File notSentFile = createFile("some_file.txt");
    File sentFileWithExtraStuff = createFile("abc" + CrumblesConstants.SENT_SUFFIX + ".tmp");
    File exactSentFile = createFile("exact" + CrumblesConstants.SENT_SUFFIX);

    CrumblesDeleteSentFilesWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesDeleteSentFilesWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success, and only the exact _sent.bin file should be deleted.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(notSentFile.exists()).isTrue();
    assertThat(sentFileWithExtraStuff.exists()).isTrue();
    assertThat(exactSentFile.exists()).isFalse();
  }
}
