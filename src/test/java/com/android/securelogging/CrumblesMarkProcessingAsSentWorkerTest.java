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
import static org.junit.Assert.assertNotNull;
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

/** Tests for {@link CrumblesMarkProcessingAsSentWorker}. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesMarkProcessingAsSentWorkerTest {

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
  public void doWork_noProcessingFiles_returnsSuccess() {
    // GIVEN: The log directory exists but contains no _processing.bin files.
    CrumblesMarkProcessingAsSentWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesMarkProcessingAsSentWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success and no files should be marked as sent.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    File[] sentFiles =
        logDirectory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.SENT_SUFFIX));
    assertNotNull(sentFiles);
    assertThat(sentFiles).isEmpty();
  }

  @Test
  public void doWork_renamesProcessingFilesToSent_returnsSuccess() throws IOException {
    // GIVEN: Multiple _processing.bin files and other files exist in the log directory.
    File processingFile1 = createFile("log1" + CrumblesConstants.PROCESSING_SUFFIX);
    File processingFile2 = createFile("log2" + CrumblesConstants.PROCESSING_SUFFIX);
    File otherFile = createFile("other_log.txt");
    File alreadySentFile = createFile("log3" + CrumblesConstants.SENT_SUFFIX);

    CrumblesMarkProcessingAsSentWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesMarkProcessingAsSentWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success, _processing.bin files should be renamed to _sent.bin
    // and other files should be untouched.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());

    assertThat(processingFile1.exists()).isFalse();
    assertThat(processingFile2.exists()).isFalse();

    File sentFile1 = new File(logDirectory, "log1" + CrumblesConstants.SENT_SUFFIX);
    File sentFile2 = new File(logDirectory, "log2" + CrumblesConstants.SENT_SUFFIX);
    assertThat(sentFile1.exists()).isTrue();
    assertThat(sentFile2.exists()).isTrue();

    assertThat(otherFile.exists()).isTrue();
    assertThat(alreadySentFile.exists()).isTrue();

    File[] allSentFiles =
        logDirectory.listFiles((dir, name) -> name.endsWith(CrumblesConstants.SENT_SUFFIX));
    assertNotNull(allSentFiles);
    assertThat(allSentFiles).hasLength(3); // log1_sent, log2_sent, and the pre-existing log3_sent.
  }

  @Test
  public void doWork_logDirectoryMissing_returnsFailure() {
    // GIVEN: The log directory does not exist.
    assertTrue(logDirectory.exists());
    deleteRecursive(logDirectory);
    assertThat(logDirectory.exists()).isFalse();

    CrumblesMarkProcessingAsSentWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesMarkProcessingAsSentWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return failure.
    assertThat(result).isEqualTo(ListenableWorker.Result.failure());
  }

  @Test
  public void doWork_emptyDirectory_returnsSuccess() {
    // GIVEN: The log directory exists and is empty (as per setup).
    CrumblesMarkProcessingAsSentWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesMarkProcessingAsSentWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(logDirectory.listFiles()).isEmpty(); // Directory should remain empty.
  }

  @Test
  public void doWork_fileWithoutCorrectSuffix_isNotRenamed() throws IOException {
    // GIVEN: Files exist that do not strictly end with _processing.bin.
    File notProcessingFile = createFile("some_file.txt");
    File processingFileWithExtraStuff =
        createFile("abc" + CrumblesConstants.PROCESSING_SUFFIX + ".tmp");
    File exactProcessingFile = createFile("exact" + CrumblesConstants.PROCESSING_SUFFIX);

    CrumblesMarkProcessingAsSentWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesMarkProcessingAsSentWorker.class).build();

    // WHEN: The worker's doWork method is called.
    ListenableWorker.Result result = worker.doWork();

    // THEN: The worker should return success, and only the exact _processing.bin file should be
    // renamed.
    assertThat(result).isEqualTo(ListenableWorker.Result.success());
    assertThat(notProcessingFile.exists()).isTrue();
    assertThat(new File(logDirectory, "some_file" + CrumblesConstants.SENT_SUFFIX).exists())
        .isFalse();

    assertThat(processingFileWithExtraStuff.exists()).isTrue();
    assertThat(new File(logDirectory, "abc" + CrumblesConstants.SENT_SUFFIX + ".tmp").exists())
        .isFalse();

    assertThat(exactProcessingFile.exists()).isFalse();
    assertThat(new File(logDirectory, "exact" + CrumblesConstants.SENT_SUFFIX).exists()).isTrue();
  }
}
