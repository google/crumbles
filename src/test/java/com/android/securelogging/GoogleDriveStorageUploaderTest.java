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

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import androidx.annotation.Nullable;
import androidx.documentfile.provider.DocumentFile;
import androidx.test.core.app.ApplicationProvider;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link GoogleDriveStorageUploader}. */
@RunWith(RobolectricTestRunner.class)
public final class GoogleDriveStorageUploaderTest {

  private static final String AUTHORITY = "com.android.securelogging.test.drive";
  private static final Uri TREE_URI =
      DocumentsContract.buildTreeDocumentUri(AUTHORITY, "root_folder");
  private static final Context context = ApplicationProvider.getApplicationContext();
  private static final GoogleDriveStorageUploader uploader =
      new GoogleDriveStorageUploader(DocumentFile.fromTreeUri(context, TREE_URI));

  private File testFile;
  private TestDriveContentProvider provider;

  /** Fake ContentProvider simulating Storage Access Framework document creation. */
  public static class TestDriveContentProvider extends ContentProvider {
    private File tempDriveDir;
    private boolean shouldFailStreaming;
    private boolean shouldFailCreate;

    public void setShouldFailStreaming(boolean fail) {
      this.shouldFailStreaming = fail;
    }

    public void setShouldFailCreate(boolean fail) {
      this.shouldFailCreate = fail;
    }

    @Override
    public boolean onCreate() {
      tempDriveDir = new File(getContext().getFilesDir(), "fake_drive_dir");
      return tempDriveDir.exists() || tempDriveDir.mkdirs();
    }

    @Override
    public Cursor query(
        Uri uri, String[] proj, String sel, String[] selArgs, String sortOrder) {
      MatrixCursor cursor =
          new MatrixCursor(
              new String[] {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_FLAGS,
              });
      cursor.addRow(
          new Object[] {
            "root_folder",
            DocumentsContract.Document.MIME_TYPE_DIR,
            DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
                | DocumentsContract.Document.FLAG_SUPPORTS_WRITE,
          });
      return cursor;
    }

    @Override
    public Bundle call(String method, @Nullable String arg, @Nullable Bundle extras) {
      if (Objects.equals(method, "android:createDocument")) {
        if (shouldFailCreate) {
          return null;
        }
        String name =
            extras != null
                ? extras.getString(
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME, "uploaded_file.bin")
                : "uploaded_file.bin";
        File docFile = new File(tempDriveDir, name);
        try {
          docFile.createNewFile();
        } catch (IOException e) {
          return null;
        }
        Bundle bundle = new Bundle();
        bundle.putParcelable("uri", Uri.parse("content://" + AUTHORITY + "/document/" + name));
        return bundle;
      }
      return super.call(method, arg, extras);
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      if (shouldFailStreaming) {
        throw new FileNotFoundException("Simulated stream failure");
      }
      return ParcelFileDescriptor.open(
          new File(tempDriveDir, uri.getLastPathSegment()), ParcelFileDescriptor.MODE_READ_WRITE);
    }

    @Override
    public String getType(Uri uri) {
      return "application/octet-stream";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
      return null;
    }

    @Override
    public int delete(Uri uri, String sel, String[] args) {
      return 0;
    }

    @Override
    public int update(Uri uri, ContentValues v, String s, String[] a) {
      return 0;
    }
  }

  @Before
  public void setUp() throws Exception {
    provider =
        Robolectric.buildContentProvider(TestDriveContentProvider.class)
            .create(AUTHORITY)
            .get();
    testFile = new File(context.getFilesDir(), "local_test.bin");
    Files.writeString(testFile.toPath(), "encrypted test content");
  }

  @After
  public void tearDown() {
    if (testFile != null && testFile.exists()) {
      testFile.delete();
    }
  }

  @Test
  public void uploadFile_whenSuccessful_streamsDataAndReturnsTrue() throws Exception {
    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isTrue();
    File uploadedFile = new File(context.getFilesDir(), "fake_drive_dir/destination_log.bin");
    assertThat(Files.readString(uploadedFile.toPath())).isEqualTo("encrypted test content");
  }

  @Test
  public void uploadFile_whenCreateFails_returnsFalse() {
    provider.setShouldFailCreate(true);
    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isFalse();
  }

  @Test
  public void uploadFile_whenStreamingFails_returnsFalse() {
    provider.setShouldFailStreaming(true);
    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isFalse();
  }

  @Test
  public void getStorageTypeAndDescription_returnExpectedValues() {
    assertThat(uploader.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_GOOGLE_DRIVE);
    assertThat(uploader.getDestinationDescription()).isEqualTo("Google Drive");
  }
}
