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
import static com.google.common.truth.TruthJUnit.assume;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import android.content.ContentProvider;
import android.content.ContentResolver;
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
import com.google.common.truth.Expect;
import com.google.common.util.concurrent.Uninterruptibles;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.ClosedChannelException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowSystemClock;

/** Unit tests for {@link GoogleDriveStorageUploader}. */
@RunWith(RobolectricTestRunner.class)
public final class GoogleDriveStorageUploaderTest {

  private static final String AUTHORITY = "com.android.securelogging.test.drive";
  private static final String OTHER_AUTHORITY = "com.android.securelogging.test.other";
  private static final Uri TREE_URI =
      DocumentsContract.buildTreeDocumentUri(AUTHORITY, "root_folder");

  /** A file that reads as an endless stream of zeros. */
  private static final File ENDLESS_FILE = new File("/dev/zero");

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private GoogleDriveStorageUploader uploader;
  private File testFile;
  private TestDriveContentProvider provider;

  /** Fake ContentProvider simulating Storage Access Framework document creation. */
  public static class TestDriveContentProvider extends ContentProvider {
    File tempDriveDir;
    int queryFault;
    @Nullable Uri createdDocumentUri;
    private boolean shouldFailStreaming;
    private boolean shouldFailCreate;
    private boolean shouldAlterReadBack;
    private boolean shouldWithholdWriteStream;
    private boolean shouldWithholdReadBack;
    private boolean shouldCrash;
    private boolean shouldReadBackEndlessly;
    @Nullable File stalledReadBack;

    /** A file that writes to the copy go to instead of the document, such as a pipe. */
    @Nullable File stalledCopy;

    private final List<String> deletedDocuments = new ArrayList<>();
    private final List<String> documentsOpenedForWriting = new ArrayList<>();

    /** The call that the provider holds until {@link #release} opens: a method, or "openFile". */
    @Nullable String heldCall;

    final CountDownLatch release = new CountDownLatch(1);
    final CountDownLatch heldCallEntered = new CountDownLatch(1);
    final CountDownLatch copyOpened = new CountDownLatch(1);
    final CountDownLatch readBackOpened = new CountDownLatch(1);

    public void setShouldFailStreaming(boolean fail) {
      this.shouldFailStreaming = fail;
    }

    public void setShouldFailCreate(boolean fail) {
      this.shouldFailCreate = fail;
    }

    /** Makes reads return other bytes than the ones written, like a provider that lost data. */
    public void setShouldAlterReadBack(boolean alter) {
      this.shouldAlterReadBack = alter;
    }

    /** Makes writes return no stream at all. */
    public void setShouldWithholdWriteStream(boolean withhold) {
      this.shouldWithholdWriteStream = withhold;
    }

    /** Makes reads return no stream at all. */
    public void setShouldWithholdReadBack(boolean withhold) {
      this.shouldWithholdReadBack = withhold;
    }

    /** Makes opening a document throw an unchecked exception, like a provider with a bug. */
    public void setShouldCrash(boolean crash) {
      this.shouldCrash = crash;
    }

    /** Makes reads return a stream that never ends. */
    public void setShouldReadBackEndlessly(boolean endless) {
      this.shouldReadBackEndlessly = endless;
    }

    @Override
    public boolean onCreate() {
      tempDriveDir = new File(getContext().getFilesDir(), "fake_drive_dir");
      return tempDriveDir.exists() || tempDriveDir.mkdirs();
    }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sortOrder) {
      if (queryFault == 2) {
        throw new SecurityException("revoked");
      } else if (queryFault == 1) {
        return null;
      }
      if (uri.getPath() != null && !uri.getPath().endsWith("root_folder")) {
        MatrixCursor c = new MatrixCursor(proj);
        boolean isName = Objects.equals(proj[0], DocumentsContract.Document.COLUMN_DISPLAY_NAME);
        File[] files =
            uri.getPath().contains("/children")
                ? Objects.requireNonNullElse(tempDriveDir.listFiles(), new File[0])
                : new File[] {new File(tempDriveDir, DocumentsContract.getDocumentId(uri))};
        for (File f : files) {
          if (f.exists()) {
            c.addRow(
                new Object[] {isName ? f.getName().replaceFirst("^dup\\d+_", "") : f.getName()});
          }
        }
        return c;
      }
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
      holdIf(method);
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
        bundle.putParcelable(
            "uri",
            createdDocumentUri != null
                ? createdDocumentUri
                : DocumentsContract.buildDocumentUriUsingTree(TREE_URI, name));
        return bundle;
      }
      if (Objects.equals(method, "android:isChildDocument") && extras != null) {
        // Only documents directly in the fake folder are its children. Like a hostile provider, it
        // judges by the last path segment alone, so it claims file URIs too.
        Uri document = extras.getParcelable("android.content.extra.TARGET_URI", Uri.class);
        Bundle result = new Bundle();
        result.putBoolean("result", !document.getLastPathSegment().contains("/"));
        return result;
      }
      if (Objects.equals(method, "android:deleteDocument") && extras != null) {
        String name = extras.getParcelable("uri", Uri.class).getLastPathSegment();
        deletedDocuments.add(name);
        return new File(tempDriveDir, name).delete() ? new Bundle() : null;
      }
      return super.call(method, arg, extras);
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      holdIf("openFile");
      if (shouldFailStreaming) {
        throw new FileNotFoundException("Simulated stream failure");
      }
      if (shouldCrash) {
        throw new IllegalStateException("Simulated provider crash");
      }
      File document = new File(tempDriveDir, uri.getLastPathSegment());
      if (!mode.equals("r")) {
        documentsOpenedForWriting.add(uri.getLastPathSegment());
      }
      if (!mode.equals("r") && shouldWithholdWriteStream) {
        return null;
      }
      if (!mode.equals("r")) {
        copyOpened.countDown();
      }
      if (!mode.equals("r") && stalledCopy != null) {
        return ParcelFileDescriptor.open(stalledCopy, ParcelFileDescriptor.MODE_READ_WRITE);
      }
      if (mode.equals("r") && shouldWithholdReadBack) {
        return null;
      }
      if (mode.equals("r") && stalledReadBack != null) {
        readBackOpened.countDown();
        return ParcelFileDescriptor.open(stalledReadBack, ParcelFileDescriptor.MODE_READ_ONLY);
      }
      if (mode.equals("r") && shouldReadBackEndlessly) {
        return ParcelFileDescriptor.open(ENDLESS_FILE, ParcelFileDescriptor.MODE_READ_ONLY);
      }
      if (mode.equals("r") && shouldAlterReadBack) {
        document = new File(tempDriveDir, "altered_copy.bin");
        try {
          Files.write(document.toPath(), "encrypted test conten".getBytes(UTF_8));
        } catch (IOException e) {
          throw new FileNotFoundException(e.getMessage());
        }
      }
      return ParcelFileDescriptor.open(document, ParcelFileDescriptor.MODE_READ_WRITE);
    }

    @Override
    public String getType(Uri uri) {
      return "application/octet-stream";
    }

    void holdIf(String call) {
      if (Objects.equals(call, heldCall)) {
        heldCallEntered.countDown();
        try {
          release.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
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
    context = ApplicationProvider.getApplicationContext();
    provider =
        Robolectric.buildContentProvider(TestDriveContentProvider.class).create(AUTHORITY).get();
    uploader = new GoogleDriveStorageUploader(DocumentFile.fromTreeUri(context, TREE_URI));
    testFile = new File(context.getFilesDir(), "local_test.bin");
    Files.write(testFile.toPath(), "encrypted test content".getBytes(UTF_8));
  }

  @After
  public void tearDown() throws Exception {
    provider.release.countDown();
    awaitProviderAnswers(TREE_URI);
    if (testFile != null && testFile.exists()) {
      testFile.delete();
    }
  }

  @Test
  public void uploadFile_whenSuccessful_streamsDataAndReturnsTrue() throws Exception {
    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isTrue();
    File uploadedFile = new File(context.getFilesDir(), "fake_drive_dir/destination_log.bin");
    assertThat(new String(Files.readAllBytes(uploadedFile.toPath()), UTF_8))
        .isEqualTo("encrypted test content");
    assertThat(provider.deletedDocuments).isEmpty();
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
    assertThat(provider.deletedDocuments).containsExactly("destination_log.bin");
  }

  @Test
  public void uploadFile_whenProviderReturnsOtherBytes_returnsFalseAndRemovesTheCopy() {
    provider.setShouldAlterReadBack(true);

    boolean uploaded = uploader.uploadFile(context, testFile, "destination_log.bin");

    expect.that(uploaded).isFalse();
    expect.that(provider.deletedDocuments).containsExactly("destination_log.bin");
  }

  @Test
  public void uploadFile_whenProviderWithholdsWriteStream_returnsFalse() {
    provider.setShouldWithholdWriteStream(true);

    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isFalse();
    assertThat(provider.deletedDocuments).containsExactly("destination_log.bin");
  }

  @Test
  public void uploadFile_whenProviderWithholdsTheCopy_returnsFalse() {
    provider.setShouldWithholdReadBack(true);

    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isFalse();
    assertThat(provider.deletedDocuments).containsExactly("destination_log.bin");
  }

  @Test
  public void uploadFile_whenProviderThrowsUncheckedException_returnsFalse() {
    provider.setShouldCrash(true);

    assertThat(uploader.uploadFile(context, testFile, "destination_log.bin")).isFalse();
    assertThat(provider.deletedDocuments).containsExactly("destination_log.bin");
  }

  @Test
  public void uploadFile_whenProviderCreatesDocumentOfAnotherProvider_neitherWritesNorDeletesIt() {
    TestDriveContentProvider otherProvider =
        Robolectric.buildContentProvider(TestDriveContentProvider.class)
            .create(OTHER_AUTHORITY)
            .get();
    provider.createdDocumentUri =
        DocumentsContract.buildDocumentUriUsingTree(
            DocumentsContract.buildTreeDocumentUri(OTHER_AUTHORITY, "root_folder"), "victim.bin");

    boolean uploaded = uploader.uploadFile(context, testFile, "destination_log.bin");

    expect.that(uploaded).isFalse();
    expect.that(otherProvider.documentsOpenedForWriting).isEmpty();
    expect.that(otherProvider.deletedDocuments).isEmpty();
  }

  @Test
  public void uploadFile_whenProviderCreatesDocumentOutsideTheFolder_neitherWritesNorDeletesIt() {
    provider.createdDocumentUri =
        DocumentsContract.buildDocumentUriUsingTree(TREE_URI, "other_folder/victim.bin");

    boolean uploaded = uploader.uploadFile(context, testFile, "destination_log.bin");

    expect.that(uploaded).isFalse();
    expect.that(provider.documentsOpenedForWriting).isEmpty();
    expect.that(provider.deletedDocuments).isEmpty();
  }

  @Test
  public void uploadFile_whenProviderCreatesFileUriWithItsAuthority_neitherWritesNorDeletesIt()
      throws Exception {
    Path victim = Files.createTempFile("victim", ".bin");
    Files.write(victim, "other data".getBytes(UTF_8));
    provider.createdDocumentUri =
        new Uri.Builder()
            .scheme(ContentResolver.SCHEME_FILE)
            .authority(AUTHORITY)
            .path(victim.toString())
            .build();

    boolean uploaded = uploader.uploadFile(context, testFile, "destination_log.bin");

    expect.that(uploaded).isFalse();
    expect.that(new String(Files.readAllBytes(victim), UTF_8)).isEqualTo("other data");
    expect.that(provider.deletedDocuments).isEmpty();
  }

  @Test
  public void uploadFile_whenProviderReadsBackEndlessly_returnsFalseAndRemovesTheCopy() {
    assume().that(ENDLESS_FILE.exists()).isTrue();
    provider.setShouldReadBackEndlessly(true);

    boolean uploaded = uploader.uploadFile(context, testFile, "destination_log.bin");

    expect.that(uploaded).isFalse();
    expect.that(provider.deletedDocuments).containsExactly("destination_log.bin");
  }

  @Test
  public void uploadFile_whenProviderNeverServesTheReadBack_givesUpAtTheDeadline()
      throws Exception {
    File pipe = new File(context.getCacheDir(), "stalled_pipe");
    assertThat(new ProcessBuilder("mkfifo", pipe.getPath()).start().waitFor()).isEqualTo(0);
    ExecutorService uploadThread = Executors.newSingleThreadExecutor();
    // Holding the pipe open for writing, but writing nothing, leaves every read of it blocked.
    try (RandomAccessFile idleWriter = new RandomAccessFile(pipe, "rw")) {
      provider.stalledReadBack = pipe;
      Future<Boolean> upload =
          uploadThread.submit(() -> uploader.uploadFile(context, testFile, "destination_log.bin"));
      assertThat(provider.readBackOpened.await(/* timeout= */ 5, SECONDS)).isTrue();

      boolean uploaded = awaitPastDeadline(upload);

      expect.that(uploaded).isFalse();
      expect.that(uploader.transportFailed()).isTrue();
      expect.that(uploader.failedMidBody()).isFalse();
      expect.that(provider.deletedDocuments).containsExactly("destination_log.bin");
    } finally {
      uploadThread.shutdownNow();
    }
  }

  @Test
  public void uploadFile_whenTheProviderStopsTakingTheCopy_failsMidBody() throws Exception {
    // More than a pipe holds, so that the copy blocks once nothing drains the pipe.
    Files.write(testFile.toPath(), new byte[1 << 20]);
    File pipe = new File(context.getCacheDir(), "undrained_pipe");
    assertThat(new ProcessBuilder("mkfifo", pipe.getPath()).start().waitFor()).isEqualTo(0);
    provider.stalledCopy = pipe;

    boolean uploaded = uploadPastDeadline(testFile);

    expect.that(uploaded).isFalse();
    expect.that(uploader.transportFailed()).isTrue();
    expect.that(uploader.failedMidBody()).isTrue();
  }

  @Test
  public void uploadFile_afterAnUploadFailedInTransit_reportsOnlyItsOwnOutcome() throws Exception {
    Files.write(testFile.toPath(), new byte[1 << 20]);
    File pipe = new File(context.getCacheDir(), "pipe_drained_by_nothing");
    assertThat(new ProcessBuilder("mkfifo", pipe.getPath()).start().waitFor()).isEqualTo(0);
    provider.stalledCopy = pipe;
    assertThat(uploadPastDeadline(testFile)).isFalse();
    provider.stalledCopy = null;

    boolean uploaded = uploader.uploadFile(context, testFile, "next_log.bin");

    expect.that(uploaded).isTrue();
    expect.that(uploader.transportFailed()).isFalse();
    expect.that(uploader.failedMidBody()).isFalse();
  }

  @Test
  public void uploadFile_whenClosingCannotEndTheCopy_givesUpAndRefusesTheProviderUntilItEnds()
      throws Exception {
    File batch = new File(context.getCacheDir(), "unending_batch");
    assertThat(new ProcessBuilder("mkfifo", batch.getPath()).start().waitFor()).isEqualTo(0);
    // Holding the pipe open for writing, but writing nothing, blocks the copy where closing the
    // provider's channel cannot end it, as on a FUSE proxy descriptor whose provider never
    // answers a write.
    try (RandomAccessFile idleWriter = new RandomAccessFile(batch, "rw")) {
      assertThat(uploadPastDeadline(batch)).isFalse();
      assertThat(uploader.transportFailed()).isTrue();

      boolean uploadedAgain = uploader.uploadFile(context, testFile, "second_log.bin");

      expect.that(uploadedAgain).isFalse();
      expect.that(uploader.transportFailed()).isTrue();
      expect.that(new File(provider.tempDriveDir, "second_log.bin").exists()).isFalse();
    }
  }

  @Test
  public void uploadFile_whenProviderNeverAnswersCreateDocument_givesUpAtTheDeadline()
      throws Exception {
    provider.heldCall = "android:createDocument";

    boolean uploaded = uploadPastDeadline(testFile);

    expect.that(uploaded).isFalse();
    expect.that(uploader.transportFailed()).isTrue();
    expect.that(uploader.failedMidBody()).isFalse();
  }

  @Test
  public void uploadFile_whenProviderNeverAnswersIsChildDocument_givesUpWithoutTouchingTheCopy()
      throws Exception {
    provider.heldCall = "android:isChildDocument";

    boolean uploaded = uploadPastDeadline(testFile);

    expect.that(uploaded).isFalse();
    expect.that(uploader.transportFailed()).isTrue();
    expect.that(provider.documentsOpenedForWriting).isEmpty();
    expect.that(provider.deletedDocuments).isEmpty();
  }

  @Test
  public void uploadFile_whenProviderNeverOpensTheCopy_givesUpWithoutCallingItToDeleteTheCopy()
      throws Exception {
    provider.heldCall = "openFile";

    boolean uploaded = uploadPastDeadline(testFile);

    expect.that(uploaded).isFalse();
    expect.that(uploader.transportFailed()).isTrue();
    expect.that(uploader.failedMidBody()).isFalse();
    expect.that(provider.deletedDocuments).isEmpty();
  }

  @Test
  public void getStorageTypeAndDescription_returnExpectedValues() {
    assertThat(uploader.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_GOOGLE_DRIVE);
    assertThat(uploader.getDestinationDescription()).isEqualTo("Google Drive");
  }

  /** Uploads {@code file} on another thread, and moves the clock on until the upload ends. */
  private boolean uploadPastDeadline(File file) throws Exception {
    ExecutorService uploadThread = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> upload =
          uploadThread.submit(() -> uploader.uploadFile(context, file, "destination_log.bin"));
      CountDownLatch stall =
          provider.heldCall != null ? provider.heldCallEntered : provider.copyOpened;
      assertThat(stall.await(/* timeout= */ 5, SECONDS)).isTrue();
      return awaitPastDeadline(upload);
    } finally {
      uploadThread.shutdownNow();
    }
  }

  /** Waits until the provider of {@code document} takes calls again, once it returns a held one. */
  static void awaitProviderAnswers(Uri document) throws Exception {
    for (int attempt = 0; attempt < 100; attempt++) {
      try {
        @SuppressWarnings("unused")
        var unusedAnswer = CrumblesTransferDeadline.callProvider(document, () -> true);
        return;
      } catch (ClosedChannelException e) {
        Uninterruptibles.sleepUninterruptibly(10, MILLISECONDS);
      }
    }
  }

  /**
   * Moves the clock past the transfer deadline, repeatedly until {@code upload} ends, as the upload
   * sets its deadline only once it starts, and returns its result.
   */
  static boolean awaitPastDeadline(Future<Boolean> upload) throws Exception {
    for (int attempt = 0; attempt < 100 && !upload.isDone(); attempt++) {
      // Let the background upload enter its blocked I/O before jumping the deadline clock.
      Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
      ShadowSystemClock.advanceBy(Duration.ofHours(1));
    }
    return upload.get(/* timeout= */ 1, SECONDS);
  }
}
