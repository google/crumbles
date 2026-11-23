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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.robolectric.Shadows.shadowOf;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.MediaStore;
import androidx.annotation.Nullable;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;

/** Unit tests for {@link CrumblesExternalContentResolver}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesExternalContentResolverTest {

  private static final String EXTERNAL_AUTHORITY = "com.example.storage.documents";
  private static final String GOOGLE_EXPORTED_AUTHORITY = "com.google.example.exported";
  private static final String LEGACY_DRIVE_AUTHORITY = "com.google.android.apps.docs.storage.legacy";
  private static final String DISALLOWED_AUTHORITY_MESSAGE =
      "Cannot open disallowed content URI authority.";

  @Rule public final TemporaryFolder tempFolder = new TemporaryFolder();

  private static final Context context = ApplicationProvider.getApplicationContext();

  private File backingFile;

  /** Fake content provider serving a single backing file or returning null streams when requested. */
  public static final class TestContentProvider extends ContentProvider {
    static final AtomicReference<File> servedFile = new AtomicReference<>();
    static final AtomicBoolean returnNullFile = new AtomicBoolean();

    @Override
    public boolean onCreate() {
      return true;
    }

    @Nullable
    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
      File file = servedFile.get();
      if (returnNullFile.get() || file == null) {
        return null;
      }
      int pfdMode =
          mode.contains("w")
              ? ParcelFileDescriptor.MODE_WRITE_ONLY | ParcelFileDescriptor.MODE_TRUNCATE
              : ParcelFileDescriptor.MODE_READ_ONLY;
      return ParcelFileDescriptor.open(file, pfdMode);
    }

    @Nullable
    @Override
    public Cursor query(
        Uri uri,
        @Nullable String[] projection,
        @Nullable String selection,
        @Nullable String[] selectionArgs,
        @Nullable String sortOrder) {
      return null;
    }

    @Nullable
    @Override
    public String getType(Uri uri) {
      return "application/octet-stream";
    }

    @Nullable
    @Override
    public Uri insert(Uri uri, @Nullable ContentValues values) {
      return null;
    }

    @Override
    public int delete(Uri uri, @Nullable String selection, @Nullable String[] selectionArgs) {
      return 0;
    }

    @Override
    public int update(
        Uri uri,
        @Nullable ContentValues values,
        @Nullable String selection,
        @Nullable String[] selectionArgs) {
      return 0;
    }
  }

  @Before
  public void setUp() throws Exception {
    backingFile = tempFolder.newFile("sample.bin");
    Files.write(backingFile.toPath(), "external payload".getBytes(UTF_8));
    TestContentProvider.servedFile.set(backingFile);
    TestContentProvider.returnNullFile.set(false);
  }

  @Test
  public void openInputStream_whenSchemeIsNotContent_throwsFileNotFoundException() {
    Uri fileUri = Uri.fromFile(backingFile);

    assertThrows(
        FileNotFoundException.class,
        () -> CrumblesExternalContentResolver.openInputStream(context, fileUri));
  }

  @Test
  public void openInputStream_whenProviderBelongsToSamePackage_throwsFileNotFoundException() {
    String internalAuthority = "com.android.securelogging.fileprovider";
    Robolectric.setupContentProvider(TestContentProvider.class, internalAuthority);
    registerProvider(internalAuthority, context.getPackageName(), /* exported= */ false);
    Uri uri = Uri.parse("content://" + internalAuthority + "/logs/batch.bin");

    assertThrows(
        FileNotFoundException.class,
        () -> CrumblesExternalContentResolver.openInputStream(context, uri));
  }

  @Test
  public void openInputStream_whenUserPrefixedOwnAuthority_throwsFileNotFoundException() {
    String internalAuthority = "com.android.securelogging.fileprovider";
    Robolectric.setupContentProvider(TestContentProvider.class, internalAuthority);
    registerProvider(internalAuthority, context.getPackageName(), /* exported= */ false);
    Uri uri = Uri.parse("content://0@" + internalAuthority + "/logs/batch.bin");

    FileNotFoundException thrown =
        assertThrows(
            FileNotFoundException.class,
            () -> CrumblesExternalContentResolver.openInputStream(context, uri));

    assertThat(thrown).hasMessageThat().isEqualTo(DISALLOWED_AUTHORITY_MESSAGE);
  }

  @Test
  public void openInputStream_whenAuthorityIsEmpty_throwsFileNotFoundException() {
    Uri uri = Uri.parse("content:///document/1");

    FileNotFoundException thrown =
        assertThrows(
            FileNotFoundException.class,
            () -> CrumblesExternalContentResolver.openInputStream(context, uri));

    assertThat(thrown).hasMessageThat().isEqualTo(DISALLOWED_AUTHORITY_MESSAGE);
  }

  @Test
  public void openInputStream_whenNoInstalledPackageProvidesTheAuthority_opensStream()
      throws Exception {
    // Registered with the content resolver, but with no package that the package manager knows.
    Robolectric.setupContentProvider(TestContentProvider.class, EXTERNAL_AUTHORITY);
    Uri uri = Uri.parse("content://" + EXTERNAL_AUTHORITY + "/document/1");

    try (InputStream stream = CrumblesExternalContentResolver.openInputStream(context, uri)) {
      assertThat(new String(stream.readAllBytes(), UTF_8)).isEqualTo("external payload");
    }
  }

  @Test
  public void openInputStream_whenExportedGoogleProviderWithoutGrant_throwsFileNotFoundException() {
    Robolectric.setupContentProvider(TestContentProvider.class, GOOGLE_EXPORTED_AUTHORITY);
    registerProvider(
        GOOGLE_EXPORTED_AUTHORITY, "com.google.android.apps.restricted", /* exported= */ true);
    Uri uri = Uri.parse("content://" + GOOGLE_EXPORTED_AUTHORITY + "/item/1");
    Context ungrantedContext = contextWithUriPermission(PackageManager.PERMISSION_DENIED);

    assertThrows(
        FileNotFoundException.class,
        () -> CrumblesExternalContentResolver.openInputStream(ungrantedContext, uri));
  }

  @Test
  public void openInputStream_whenExportedGoogleProviderWithUriGrant_opensStream() throws Exception {
    Robolectric.setupContentProvider(TestContentProvider.class, GOOGLE_EXPORTED_AUTHORITY);
    registerProvider(
        GOOGLE_EXPORTED_AUTHORITY, "com.google.android.apps.docs", /* exported= */ true);
    Uri uri = Uri.parse("content://" + GOOGLE_EXPORTED_AUTHORITY + "/item/1");
    Context grantedContext = contextWithUriPermission(PackageManager.PERMISSION_GRANTED);

    try (InputStream stream =
        CrumblesExternalContentResolver.openInputStream(grantedContext, uri)) {
      assertThat(new String(stream.readAllBytes(), UTF_8)).isEqualTo("external payload");
    }
  }

  @Test
  public void openInputStream_whenExternalThirdPartyProvider_opensStream() throws Exception {
    Robolectric.setupContentProvider(TestContentProvider.class, EXTERNAL_AUTHORITY);
    registerProvider(EXTERNAL_AUTHORITY, "com.example.storage", /* exported= */ true);
    Uri uri = Uri.parse("content://" + EXTERNAL_AUTHORITY + "/document/1");
    Context ungrantedContext = contextWithUriPermission(PackageManager.PERMISSION_DENIED);

    try (InputStream stream =
        CrumblesExternalContentResolver.openInputStream(ungrantedContext, uri)) {
      assertThat(new String(stream.readAllBytes(), UTF_8)).isEqualTo("external payload");
    }
  }

  @Test
  public void openInputStream_whenLegacyDriveOrMediaStoreAuthority_opensStream() throws Exception {
    Robolectric.setupContentProvider(TestContentProvider.class, LEGACY_DRIVE_AUTHORITY);
    registerProvider(LEGACY_DRIVE_AUTHORITY, "com.google.android.apps.docs", /* exported= */ true);
    Robolectric.setupContentProvider(TestContentProvider.class, MediaStore.AUTHORITY);
    registerProvider(MediaStore.AUTHORITY, "com.android.providers.media", /* exported= */ true);
    Context ungrantedContext = contextWithUriPermission(PackageManager.PERMISSION_DENIED);

    try (InputStream driveStream =
            CrumblesExternalContentResolver.openInputStream(
                ungrantedContext, Uri.parse("content://" + LEGACY_DRIVE_AUTHORITY + "/1"));
        InputStream mediaStream =
            CrumblesExternalContentResolver.openInputStream(
                ungrantedContext, Uri.parse("content://" + MediaStore.AUTHORITY + "/1"))) {
      assertThat(new String(driveStream.readAllBytes(), UTF_8)).isEqualTo("external payload");
      assertThat(new String(mediaStream.readAllBytes(), UTF_8)).isEqualTo("external payload");
    }
  }

  @Test
  public void openInputStream_whenProviderReturnsNull_throwsFileNotFoundException() {
    Robolectric.setupContentProvider(TestContentProvider.class, EXTERNAL_AUTHORITY);
    registerProvider(EXTERNAL_AUTHORITY, "com.example.storage", /* exported= */ true);
    TestContentProvider.returnNullFile.set(true);
    Uri uri = Uri.parse("content://" + EXTERNAL_AUTHORITY + "/document/1");

    assertThrows(
        FileNotFoundException.class,
        () -> CrumblesExternalContentResolver.openInputStream(context, uri));
  }

  @Test
  public void openAssetFileDescriptor_whenWriteGrantHeld_opensDescriptor() throws Exception {
    Robolectric.setupContentProvider(TestContentProvider.class, EXTERNAL_AUTHORITY);
    registerProvider(EXTERNAL_AUTHORITY, "com.google.android.apps.docs", /* exported= */ true);
    Uri uri = Uri.parse("content://" + EXTERNAL_AUTHORITY + "/document/1");
    Context grantedContext = contextWithUriPermission(PackageManager.PERMISSION_GRANTED);

    try (AssetFileDescriptor afd =
        CrumblesExternalContentResolver.openAssetFileDescriptor(grantedContext, uri, "w")) {
      assertThat(afd).isNotNull();
    }
  }

  @Test
  public void openAssetFileDescriptor_whenModeUnsupported_throwsIllegalArgumentException() {
    Uri uri = Uri.parse("content://" + EXTERNAL_AUTHORITY + "/document/1");

    assertThrows(
        IllegalArgumentException.class,
        () -> CrumblesExternalContentResolver.openAssetFileDescriptor(context, uri, "invalid"));
  }

  private static Context contextWithUriPermission(int permissionResult) {
    return new ContextWrapper(context) {
      @Override
      public int checkUriPermission(Uri uri, int pid, int uid, int modeFlags) {
        return permissionResult;
      }
    };
  }

  private static void registerProvider(String authority, String packageName, boolean exported) {
    ProviderInfo info = new ProviderInfo();
    info.authority = authority;
    info.packageName = packageName;
    info.name = packageName + ".TestProvider";
    info.exported = exported;
    shadowOf(context.getPackageManager()).addOrUpdateProvider(info);
  }
}
