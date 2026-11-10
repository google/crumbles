/*
 * Copyright 2026 Google LLC
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
import static org.junit.Assert.assertThrows;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.net.Uri;
import androidx.core.content.FileProvider;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.common.truth.Expect;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Tests for {@link CrumblesReEncryptedCache}. */
@RunWith(AndroidJUnit4.class)
public class CrumblesReEncryptedCacheTest {

  private static final Context context = ApplicationProvider.getApplicationContext();

  @Rule public final Expect expect = Expect.create();

  private File cacheDirectory;

  /** A grant revoked by the code under test, with whether the file was still there then. */
  private record Revocation(Uri uri, int modeFlags, boolean fileStillExisted) {}

  @Before
  public void setUp() throws Exception {
    cacheDirectory = CrumblesReEncryptedCache.getDirectory(context);
    // FileProvider caches its roots per authority, but each Robolectric test has new app dirs.
    Field fileProviderRoots = FileProvider.class.getDeclaredField("sCache");
    fileProviderRoots.setAccessible(true);
    ((Map<?, ?>) fileProviderRoots.get(null)).clear();
  }

  /** Returns a context that records the grants revoked through it instead of revoking them. */
  private Context recordingRevocationsIn(List<Revocation> revocations) {
    return new ContextWrapper(context) {
      @Override
      public void revokeUriPermission(Uri uri, int modeFlags) {
        File file = new File(cacheDirectory, uri.getPath().replaceFirst("^/shared_logs/", ""));
        revocations.add(new Revocation(uri, modeFlags, file.exists()));
      }
    };
  }

  private static Uri sharedLogUri(String path) {
    return Uri.parse(
        "content://" + CrumblesConstants.FILE_PROVIDER_AUTHORITY + "/shared_logs/" + path);
  }

  @Test
  public void getDirectory_returnsReEncryptionSubdirectoryOfCacheDir() {
    File directory = CrumblesReEncryptedCache.getDirectory(context);

    expect.that(directory.getName()).isEqualTo(CrumblesConstants.TEMP_RE_ENCRYPTED_DIR);
    expect.that(directory.getParentFile()).isEqualTo(context.getCacheDir());
  }

  @Test
  public void fileProvider_namesStagedFilesButNoStoredBatch() {
    // The app's directories change from test to test, so this test reads them from its own app.
    Context appContext = ApplicationProvider.getApplicationContext();
    File stagedFile = new File(CrumblesReEncryptedCache.getDirectory(appContext), "log1.bin");
    File storedBatch =
        new File(
            new File(
                appContext.getFilesDir(),
                CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY),
            "log_1.bin");

    expect
        .that(
            FileProvider.getUriForFile(
                appContext, CrumblesConstants.FILE_PROVIDER_AUTHORITY, stagedFile))
        .isEqualTo(sharedLogUri("log1.bin"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            FileProvider.getUriForFile(
                appContext, CrumblesConstants.FILE_PROVIDER_AUTHORITY, storedBatch));
  }

  @Test
  public void sweep_deletesStagedFilesAndDirectory() throws Exception {
    assertThat(cacheDirectory.mkdirs()).isTrue();
    File stagedFile = new File(cacheDirectory, "re_encrypted_log.bin");
    Files.writeString(stagedFile.toPath(), "re-encrypted content");

    CrumblesReEncryptedCache.sweep(context);

    expect.that(stagedFile.exists()).isFalse();
    expect.that(cacheDirectory.exists()).isFalse();
  }

  @Test
  public void sweep_deletesNestedStagedFiles() throws Exception {
    File nestedDirectory = new File(cacheDirectory, "nested");
    assertThat(nestedDirectory.mkdirs()).isTrue();
    File nestedFile = new File(nestedDirectory, "re_encrypted_log.bin");
    Files.writeString(nestedFile.toPath(), "re-encrypted content");

    CrumblesReEncryptedCache.sweep(context);

    expect.that(nestedFile.exists()).isFalse();
    expect.that(cacheDirectory.exists()).isFalse();
  }

  @Test
  public void sweep_revokesReadGrantOfEachStagedFileBeforeDeletingIt() throws Exception {
    File nestedDirectory = new File(cacheDirectory, "nested");
    assertThat(nestedDirectory.mkdirs()).isTrue();
    Files.writeString(new File(cacheDirectory, "log1.bin").toPath(), "re-encrypted content");
    Files.writeString(new File(nestedDirectory, "log2.bin").toPath(), "re-encrypted content");
    List<Revocation> revocations = new ArrayList<>();

    CrumblesReEncryptedCache.sweep(recordingRevocationsIn(revocations));

    assertThat(revocations)
        .containsExactly(
            new Revocation(
                sharedLogUri("log1.bin"),
                Intent.FLAG_GRANT_READ_URI_PERMISSION,
                /* fileStillExisted= */ true),
            new Revocation(
                sharedLogUri("nested/log2.bin"),
                Intent.FLAG_GRANT_READ_URI_PERMISSION,
                /* fileStillExisted= */ true));
  }

  @Test
  public void sweep_withLinkOutsideProviderRoots_deletesLinkWithoutRevoking() throws Exception {
    assertThat(cacheDirectory.mkdirs()).isTrue();
    File outsideFile = new File(context.getFilesDir(), "outside_provider_roots.bin");
    Files.writeString(outsideFile.toPath(), "unshared content");
    Path link =
        Files.createSymbolicLink(
            new File(cacheDirectory, "link.bin").toPath(), outsideFile.toPath());
    List<Revocation> revocations = new ArrayList<>();

    CrumblesReEncryptedCache.sweep(recordingRevocationsIn(revocations));

    expect.that(revocations).isEmpty();
    expect.that(Files.exists(link, LinkOption.NOFOLLOW_LINKS)).isFalse();
    expect.that(outsideFile.exists()).isTrue();
  }

  @Test
  public void sweep_keepsFilesOutsideTheReEncryptionDirectory() throws Exception {
    assertThat(cacheDirectory.mkdirs()).isTrue();
    File otherCacheFile = new File(context.getCacheDir(), "other_cached_file.bin");
    Files.writeString(otherCacheFile.toPath(), "unrelated cached content");
    File otherCacheDirectory = new File(context.getCacheDir(), "other_cache_dir");
    assertThat(otherCacheDirectory.mkdirs()).isTrue();
    File encryptedLogFile = new File(context.getFilesDir(), "encrypted_log.bin");
    Files.writeString(encryptedLogFile.toPath(), "encrypted log content");

    CrumblesReEncryptedCache.sweep(context);

    expect.that(otherCacheFile.exists()).isTrue();
    expect.that(otherCacheDirectory.exists()).isTrue();
    expect.that(encryptedLogFile.exists()).isTrue();
    expect.that(context.getCacheDir().exists()).isTrue();
  }

  @Test
  public void sweep_withoutDirectory_leavesCacheDirUntouched() {
    assertThat(cacheDirectory.exists()).isFalse();

    CrumblesReEncryptedCache.sweep(context);

    expect.that(cacheDirectory.exists()).isFalse();
    expect.that(context.getCacheDir().exists()).isTrue();
  }
}
