/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.ListenableWorker.Result;
import androidx.work.testing.TestListenableWorkerBuilder;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.InstantSource;
import java.util.concurrent.ExecutionException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowNotificationManager;
import org.robolectric.shadows.ShadowPackageManager;

/** Unit tests for {@link CrumblesSendAndMarkProcessingWorker}. */
@RunWith(RobolectricTestRunner.class)
public class CrumblesSendAndMarkProcessingWorkerTest {
  private Context context;
  private File testDirectory;

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesUriGenerator mockUriGenerator;
  private KeyPair testKeyPair;

  /**
   * Helper method to insert a suffix before the extension of a filename.
   *
   * @param filename The filename to modify.
   * @param suffix The suffix to insert.
   * @return The modified filename with the suffix inserted.
   */
  private String insertSuffixBeforeExtension(String filename, String suffix) {
    int dotIndex = filename.lastIndexOf('.');
    if (dotIndex != -1) {
      return filename.substring(0, dotIndex) + suffix + filename.substring(dotIndex);
    }
    return filename + suffix;
  }

  private void deleteRecursive(File fileOrDirectory) {
    if (fileOrDirectory.isDirectory()) {
      for (File child : fileOrDirectory.listFiles()) {
        deleteRecursive(child);
      }
    }
    fileOrDirectory.delete();
  }

  /**
   * Helper method to create a file with a specific timestamp, processing status, and sent status.
   * The file name is based on the timestamp, and it is marked as processing or sent if the
   * corresponding parameter is true.
   */
  @CanIgnoreReturnValue
  private File createFile(String namePrefix, long timestamp, String suffix, String content)
      throws IOException {
    String fileName = namePrefix + timestamp + suffix;
    File file = new File(testDirectory, fileName);
    try (FileOutputStream fos = new FileOutputStream(file)) {
      fos.write(content.getBytes(StandardCharsets.UTF_8));
    }
    assertTrue("File should exist after creation: " + file.getAbsolutePath(), file.exists());
    return file;
  }

  private void setupMockEmailClient(ShadowPackageManager shadowPackageManager) {
    ComponentName emailClientComponent = new ComponentName("com.example.email", "EmailActivity");
    shadowPackageManager.addActivityIfNotPresent(emailClientComponent);
    IntentFilter intentFilter = new IntentFilter(Intent.ACTION_SEND_MULTIPLE);
    intentFilter.addCategory(Intent.CATEGORY_DEFAULT);
    try {
      intentFilter.addDataType("application/octet-stream");
    } catch (IntentFilter.MalformedMimeTypeException e) {
      fail("Test setup failed: Malformed MIME type: " + e.getMessage());
    }
    shadowPackageManager.addIntentFilterForActivity(emailClientComponent, intentFilter);
  }

  private Uri createDummyUriForFile(File file) {
    return Uri.parse("content://com.android.securelogging.fileprovider/test/" + file.getName());
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    context = ApplicationProvider.getApplicationContext();
    ShadowLog.stream = System.out;

    testKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);

    CrumblesSendAndMarkProcessingWorker.testUriGeneratorInstance = mockUriGenerator;

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
    // Clean up the static mock instances.
    CrumblesSendAndMarkProcessingWorker.testUriGeneratorInstance = null;
  }

  @Test
  public void doWork_whenInternalKeyAvailable_proceedsWithUpload()
      throws IOException, ExecutionException, InterruptedException {
    // Given: An internal key is available.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    // And: An unprocessed file exists.
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    // And: An email client is available.
    setupMockEmailClient(Shadows.shadowOf(context.getPackageManager()));
    // And: Our mock UriGenerator will successfully return a dummy URI for any file.
    when(mockUriGenerator.getUriForFile(any(Context.class), any(File.class)))
        .thenAnswer(invocation -> createDummyUriForFile(invocation.getArgument(1)));

    // When: The worker executes.
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: The worker succeeds and shows a notification.
    assertEquals(Result.success(), result);
    File processingFile =
        new File(
            testDirectory, insertSuffixBeforeExtension(fileToProcess.getName(), "_processing"));
    assertTrue("File should have been renamed to processing.", processingFile.exists());
    assertFalse("Original file should have been removed.", fileToProcess.exists());
    ShadowNotificationManager shadowManager =
        Shadows.shadowOf(
            (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE));
    assertTrue("A notification should have been shown.", shadowManager.size() > 0);
  }

  @Test
  public void doWork_unprocessedFilesExistAndNoEmailClient_returnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    // Given: Keys are available.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    // And: An unprocessed file exists.
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");
    // And: No email client is available.
    // And: Our mock UriGenerator will successfully return a dummy URI.
    when(mockUriGenerator.getUriForFile(any(Context.class), any(File.class)))
        .thenAnswer(invocation -> createDummyUriForFile(invocation.getArgument(1)));

    // When: The worker executes.
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: The result should be retry because no email client was found.
    assertEquals(Result.retry(), result);
    // And: The file was still renamed.
    File processingFile =
        new File(
            testDirectory, insertSuffixBeforeExtension(fileToProcess.getName(), "_processing"));
    assertTrue("File should have been renamed to processing.", processingFile.exists());
  }

  @Test
  public void doWork_whenExternalKeyAvailable_proceedsWithUpload()
      throws IOException, ExecutionException, InterruptedException, CrumblesKeysException {
    // Given: An external key is available.
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);

    // Use a real manager to save the key to the test's shared preferences.
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(testKeyPair.getPublic());

    // And: An email client is available.
    setupMockEmailClient(Shadows.shadowOf(context.getPackageManager()));
    // And: Our mock UriGenerator will successfully return a dummy URI.
    when(mockUriGenerator.getUriForFile(any(Context.class), any(File.class)))
        .thenAnswer(invocation -> createDummyUriForFile(invocation.getArgument(1)));

    // When: The worker executes.
    CrumblesSendAndMarkProcessingWorker worker =
        TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
            .build();
    Result result = worker.startWork().get();

    // Then: The worker succeeds.
    assertEquals(Result.success(), result);
  }
}
