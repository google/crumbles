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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import androidx.annotation.Nullable;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.ListenableWorker.Result;
import androidx.work.testing.TestListenableWorkerBuilder;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.time.InstantSource;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowNotificationManager;

/** Unit tests for {@link CrumblesSendAndMarkProcessingWorker}. */
@RunWith(RobolectricTestRunner.class)
public class CrumblesSendAndMarkProcessingWorkerTest {
  private static final String DRIVE_AUTHORITY = "com.google.android.apps.docs.storage";
  private static final Uri VALID_DRIVE_URI =
      Uri.parse("content://" + DRIVE_AUTHORITY + "/tree/valid_drive");

  private Context context;
  private File testDirectory;
  private FakeGoogleDriveContentProvider fakeDriveProvider;

  @Mock private CrumblesLogsEncryptor mockLogsEncryptor;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;

  /** Fake ContentProvider simulating Google Drive storage via Storage Access Framework. */
  public static class FakeGoogleDriveContentProvider extends ContentProvider {
    private File tempDriveDir;
    private boolean shouldFailStreaming;
    private boolean isInvalidDirectory;

    public void setShouldFailStreaming(boolean fail) {
      this.shouldFailStreaming = fail;
    }

    public void setIsInvalidDirectory(boolean invalid) {
      this.isInvalidDirectory = invalid;
    }

    @Override
    public boolean onCreate() {
      tempDriveDir = new File(getContext().getFilesDir(), "fake_remote_drive");
      tempDriveDir.mkdirs();
      return true;
    }

    @Override
    public Cursor query(
        Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
      if (isInvalidDirectory) {
        return null;
      }
      String[] columns =
          projection != null
              ? projection
              : new String[] {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_FLAGS,
              };
      MatrixCursor cursor = new MatrixCursor(columns);
      Object[] row = new Object[columns.length];
      for (int i = 0; i < columns.length; i++) {
        String col = columns[i];
        if (Objects.equals(col, DocumentsContract.Document.COLUMN_DOCUMENT_ID)) {
          row[i] = "valid_drive";
        } else if (Objects.equals(col, DocumentsContract.Document.COLUMN_MIME_TYPE)) {
          row[i] = DocumentsContract.Document.MIME_TYPE_DIR;
        } else if (Objects.equals(col, DocumentsContract.Document.COLUMN_FLAGS)) {
          row[i] =
              DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
                  | DocumentsContract.Document.FLAG_SUPPORTS_WRITE;
        }
      }
      cursor.addRow(row);
      return cursor;
    }

    @Override
    public Bundle call(String method, @Nullable String arg, @Nullable Bundle extras) {
      if (Objects.equals(method, "android:createDocument")) {
        String name =
            extras != null
                ? extras.getString(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    extras.getString(Intent.EXTRA_TITLE, "log.bin"))
                : "log.bin";
        File created = new File(tempDriveDir, name);
        try {
          created.createNewFile();
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        Bundle res = new Bundle();
        res.putParcelable("uri", Uri.parse("content://" + DRIVE_AUTHORITY + "/document/" + name));
        return res;
      }
      return null;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      if (shouldFailStreaming) {
        throw new FileNotFoundException("Simulated upload streaming failure");
      }
      return ParcelFileDescriptor.open(
          new File(tempDriveDir, uri.getLastPathSegment()), ParcelFileDescriptor.MODE_READ_WRITE);
    }

    @Override
    public String getType(Uri uri) {
      return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
      return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
      return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
      return 0;
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

  @CanIgnoreReturnValue
  private File createFile(String namePrefix, long timestamp, String suffix, String content)
      throws IOException {
    String fileName = namePrefix + timestamp + suffix;
    File file = new File(testDirectory, fileName);
    Files.writeString(file.toPath(), content);
    assertTrue("File should exist after creation: " + file.getAbsolutePath(), file.exists());
    return file;
  }

  @CanIgnoreReturnValue
  private Result runWorker() throws ExecutionException, InterruptedException {
    return TestListenableWorkerBuilder.from(context, CrumblesSendAndMarkProcessingWorker.class)
        .build()
        .startWork()
        .get();
  }

  private void configureDestination(Uri uri, boolean grantPermission) {
    if (grantPermission) {
      context
          .getContentResolver()
          .takePersistableUriPermission(
              uri, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
    }
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_UPLOAD_DESTINATION_URI, uri.toString())
        .commit();
  }

  private void assertNotificationPosted(boolean isError) {
    NotificationManager nm =
        (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    ShadowNotificationManager snm = Shadows.shadowOf(nm);
    assertThat(snm.size()).isGreaterThan(0);

    NotificationChannel channel =
        nm.getNotificationChannel(CrumblesConstants.NOTIFICATION_CHANNEL_ID);
    assertThat(channel).isNotNull();
    assertThat(channel.getDescription())
        .isEqualTo("Status notifications for encrypted log uploads.");

    Notification notification =
        snm.getNotification(CrumblesSendAndMarkProcessingWorker.UPLOAD_NOTIFICATION_ID);
    assertThat(notification).isNotNull();
    assertThat(notification.flags & Notification.FLAG_AUTO_CANCEL)
        .isEqualTo(Notification.FLAG_AUTO_CANCEL);

    assertThat(notification.contentIntent).isNotNull();
    Intent savedIntent = Shadows.shadowOf(notification.contentIntent).getSavedIntent();
    assertThat(savedIntent).isNotNull();
    assertThat(
            savedIntent.getFlags()
                & (Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP))
        .isEqualTo(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
    assertThat(savedIntent.getComponent().getClassName()).isEqualTo(CrumblesMain.class.getName());

    int expectedIcon =
        isError ? android.R.drawable.stat_notify_error : android.R.drawable.stat_sys_upload_done;
    assertThat(notification.icon).isEqualTo(expectedIcon);
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    context = ApplicationProvider.getApplicationContext();
    ShadowLog.stream = System.out;

    CrumblesMain.setLogsEncryptorInstanceForTest(mockLogsEncryptor);
    CrumblesAppAuditLogger.setInstanceForTest(mockAuditLogger);
    fakeDriveProvider =
        Robolectric.setupContentProvider(FakeGoogleDriveContentProvider.class, DRIVE_AUTHORITY);

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
    assertTrue("Test directory should be created", testDirectory.mkdirs());
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
  public void doWork_whenNoKeyAvailable_preservesLogsAndReturnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(false);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(
        "Encrypted log file must be preserved when key is unavailable", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_DEFERRED_NO_KEY"),
            eq(
                "Upload deferred because active encryption key is unavailable; logs preserved on"
                    + " disk."));
    assertNotificationPosted(/* isError= */ true);
  }

  @Test
  public void doWork_whenSingleStaleProcessingFileExists_recoversFileToBin()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File staleFile =
        createFile(
            "log_",
            InstantSource.system().instant().toEpochMilli(),
            CrumblesConstants.PROCESSING_SUFFIX,
            "content");

    runWorker();

    assertFalse(staleFile.exists());
    File recoveredFile =
        new File(
            testDirectory,
            staleFile.getName().replace(CrumblesConstants.PROCESSING_SUFFIX, ".bin"));
    assertTrue("Stale processing file must be recovered to .bin", recoveredFile.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_RECOVERED_PROCESSING"),
            eq("Recovered 1 stale processing log file(s) for upload retry."));
  }

  @Test
  public void doWork_whenMultipleStaleProcessingFilesExist_recoversAllFilesToBin()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File file1 =
        createFile(
            "log1_",
            InstantSource.system().instant().toEpochMilli(),
            CrumblesConstants.PROCESSING_SUFFIX,
            "c1");
    File file2 =
        createFile(
            "log2_",
            InstantSource.system().instant().toEpochMilli() + 10,
            CrumblesConstants.PROCESSING_SUFFIX,
            "c2");

    runWorker();

    assertFalse(file1.exists());
    assertFalse(file2.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_RECOVERED_PROCESSING"),
            eq("Recovered 2 stale processing log file(s) for upload retry."));
  }

  @Test
  public void doWork_whenStaleRecoveryRenameFails_doesNotLogAuditEvent()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    createFile(
        "log_",
        InstantSource.system().instant().toEpochMilli(),
        CrumblesConstants.PROCESSING_SUFFIX,
        "content");

    testDirectory.setWritable(false);
    try {
      runWorker();
      verify(mockAuditLogger, never())
          .logEvent(eq("LOGS_UPLOAD_RECOVERED_PROCESSING"), anyString());
    } finally {
      testDirectory.setWritable(true);
    }
  }

  @Test
  public void doWork_whenDestinationNotConfigured_returnsRetryAndPreservesLogFiles()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue("Original log file must be preserved without data loss", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_NOT_CONFIGURED"),
            eq("Upload deferred: Google Drive destination folder is not configured."));
    assertNotificationPosted(/* isError= */ true);
  }

  @Test
  public void doWork_whenDestinationPermissionMissing_returnsRetryAndPreservesLogFiles()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ false);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue(
        "Original log file must be preserved on permission check failure", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_PERMISSION_REVOKED"),
            eq("Upload failed because persistable write permission was missing or revoked."));
    assertNotificationPosted(/* isError= */ true);
  }

  @Test
  public void doWork_whenDestinationPermissionGrantedButDirectoryInvalid_returnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    fakeDriveProvider.setIsInvalidDirectory(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue("Original file must be preserved", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("UPLOAD_DESTINATION_INVALID"),
            eq("Upload deferred: destination folder is inaccessible or unwritable."));
    assertNotificationPosted(/* isError= */ true);
  }

  @Test
  public void doWork_whenUploadSucceeds_streamsFileAndMarksSentAndNotifies()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.success(), result);
    assertFalse(fileToProcess.exists());
    File sentFile =
        new File(
            testDirectory, fileToProcess.getName().replace(".bin", CrumblesConstants.SENT_SUFFIX));
    assertTrue("Uploaded file must be marked as sent", sentFile.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_SUCCESS"),
            eq(
                "Successfully automatically uploaded 1 log file(s) to Google Drive"
                    + " destination."));
    assertNotificationPosted(/* isError= */ false);
  }

  @Test
  public void doWork_whenStreamingFails_rollsBackFileAndNotifiesUser()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    fakeDriveProvider.setShouldFailStreaming(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    Result result = runWorker();

    assertEquals(Result.retry(), result);
    assertTrue("File must be rolled back to original .bin for retry", fileToProcess.exists());
    verify(mockAuditLogger)
        .logEvent(
            eq("LOGS_UPLOAD_FAILED"),
            eq("One or more log files failed to upload; preserved safely on device for retry."));
    assertNotificationPosted(/* isError= */ true);
  }

  @Test
  public void doWork_whenFileCannotBeRenamedToProcessing_returnsRetry()
      throws IOException, ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    configureDestination(VALID_DRIVE_URI, /* grantPermission= */ true);
    File fileToProcess =
        createFile("log_", InstantSource.system().instant().toEpochMilli(), ".bin", "content");

    testDirectory.setWritable(false);
    try {
      Result result = runWorker();
      assertEquals(Result.retry(), result);
      assertTrue("Original log file must be preserved on rename failure", fileToProcess.exists());
    } finally {
      testDirectory.setWritable(true);
    }
  }

  @Test
  public void doWork_noUnprocessedFiles_returnsSuccess()
      throws ExecutionException, InterruptedException {
    when(mockLogsEncryptor.doesPrivateKeyExist()).thenReturn(true);
    Result result = runWorker();
    assertEquals(Result.success(), result);
  }
}
