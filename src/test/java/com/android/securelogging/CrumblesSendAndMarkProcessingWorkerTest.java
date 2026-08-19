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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.ListenableWorker.Result;
import androidx.work.testing.TestListenableWorkerBuilder;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.InstantSource;
import java.util.concurrent.ExecutionException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowLog;

/** Unit tests for {@link CrumblesSendAndMarkProcessingWorker}. */
@RunWith(RobolectricTestRunner.class)
public class CrumblesSendAndMarkProcessingWorkerTest {
  private Context context;
  private File testDirectory;

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;

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

  @CanIgnoreReturnValue
  private File createFile(String namePrefix, long timestamp, String suffix, String content)
      throws IOException {
    String fileName = namePrefix + timestamp + suffix;
    File file = new File(testDirectory, fileName);
    Files.writeString(file.toPath(), content);
    assertTrue("File should exist after creation: " + file.getAbsolutePath(), file.exists());
    return file;
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    context = ApplicationProvider.getApplicationContext();
    ShadowLog.stream = System.out;

    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);

    // Clear shared preferences
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit();

    File baseDir = context.getFilesDir();
    testDirectory = new File(baseDir, CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);

    if (testDirectory.exists()) {
      deleteRecursive(testDirectory);
    }
    assertTrue(
        "Test directory should be created: " + testDirectory.getAbsolutePath(),
        testDirectory.mkdirs());
  }

  @After
  public void tearDown() {
    if (testDirectory != null && testDirectory.exists()) {
      deleteRecursive(testDirectory);
    }
    CrumblesMain.setLogsEncryptorInstanceForTest(null);
    CrumblesAppAuditLogger.setInstanceForTest(null);
  }

  @Test
  public void doWork_whenNoKeyAvailable_deletesAllLogsAndReturnsSuccess()
      throws IOException, ExecutionException, InterruptedException {
    // Given: No keys exist
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    // When: Worker runs
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: Returns success and orphaned log file is deleted
    assertEquals(Result.success(), result);
    assertFalse("Orphaned log file should be deleted", fileToProcess.exists());
  }

  @Test
  public void doWork_whenDestinationNotConfigured_returnsRetryAndPreservesLogFiles()
      throws IOException, ExecutionException, InterruptedException {
    // Given: Key is available, but upload destination is not configured
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    // When: Worker runs
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: Returns retry to prevent data loss, and original log file remains intact
    assertEquals(Result.retry(), result);
    assertTrue("Original log file must be preserved without data loss", fileToProcess.exists());
  }

  @Test
  public void doWork_whenDestinationPermissionMissing_returnsRetryAndPreservesLogFiles()
      throws IOException, ExecutionException, InterruptedException {
    // Given: Key is available and destination URI is saved, but OS persistable permission is missing
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(
            CrumblesConstants.PREF_UPLOAD_DESTINATION_URI,
            "content://com.android.externalstorage.documents/tree/fake")
        .commit();

    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    // When: Worker runs
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: Returns retry due to missing permission grant, logs audit event, and original file is preserved
    assertEquals(Result.retry(), result);
    assertTrue("Original log file must be preserved on permission check failure", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(eq("UPLOAD_DESTINATION_PERMISSION_REVOKED"), anyString());
  }

  @Test
  public void doWork_whenFileCannotBeRenamedToProcessing_returnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    // Given: Key is available and destination URI is configured
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(
            CrumblesConstants.PREF_UPLOAD_DESTINATION_URI,
            "content://com.android.externalstorage.documents/tree/fake")
        .commit();

    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    // Make testDirectory read-only so renaming fails
    testDirectory.setWritable(false);

    try {
      // When: Worker runs
      CrumblesSendAndMarkProcessingWorker worker =
          TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
              .build();
      Result result = worker.startWork().get();

      // Then: Returns retry and preserves original log file
      assertEquals(Result.retry(), result);
      assertTrue("Original log file must be preserved on rename failure", fileToProcess.exists());
    } finally {
      testDirectory.setWritable(true);
    }
  }

  @Test
  public void doWork_noUnprocessedFiles_returnsSuccess()
      throws ExecutionException, InterruptedException {
    // Given: Key is available, but no .bin files exist
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);

    // When: Worker runs
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: Returns success
    assertEquals(Result.success(), result);
  }
}
