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

import static com.google.common.base.Preconditions.checkNotNull;

import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.Process;
import android.provider.MediaStore;
import androidx.annotation.Nullable;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Resolves external {@code content://} URIs while blocking confused-deputy reads or writes against
 * internal or ungranted first-party providers.
 */
// Enforces Crumbles' external-only URI policy before delegating to ContentResolver.
@SuppressWarnings("ContentResolverUri")
@SuppressLint("ContentResolverUri")
public final class CrumblesExternalContentResolver {

  private static final String LEGACY_DRIVE_AUTHORITY = "com.google.android.apps.docs.storage.legacy";

  private static final ImmutableList<String> GOOGLE_PACKAGE_PREFIXES =
      ImmutableList.of(
          "com.android.",
          "com.google.",
          "com.chrome.",
          "com.nest.",
          "com.waymo.",
          "com.waze",
          "com.waze.");

  private CrumblesExternalContentResolver() {}

  /**
   * Opens a read-only stream to an external {@code content://} URI.
   *
   * @throws FileNotFoundException if the URI is not {@code content://}, violates external-source
   *     restrictions, or resolves to {@code null}
   */
  public static InputStream openInputStream(Context context, Uri uri) throws FileNotFoundException {
    checkNotNull(context);
    checkNotNull(uri);
    verifyExternalContentUri(context, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
    InputStream stream = context.getContentResolver().openInputStream(uri);
    if (stream == null) {
      throw new FileNotFoundException("Content resolver returned null stream.");
    }
    return stream;
  }

  /**
   * Opens an asset file descriptor for an external {@code content://} URI in {@code mode}.
   *
   * @throws FileNotFoundException if the URI is not {@code content://}, violates external-source
   *     restrictions, or resolves to {@code null}
   * @throws IllegalArgumentException if {@code mode} is not a supported access mode
   */
  @CanIgnoreReturnValue
  public static AssetFileDescriptor openAssetFileDescriptor(
      Context context, Uri uri, String mode) throws FileNotFoundException {
    checkNotNull(context);
    checkNotNull(uri);
    checkNotNull(mode);
    verifyExternalContentUri(context, uri, modeToGrantFlag(mode));
    AssetFileDescriptor descriptor = context.getContentResolver().openAssetFileDescriptor(uri, mode);
    if (descriptor == null) {
      throw new FileNotFoundException("Content resolver returned null asset file descriptor.");
    }
    return descriptor;
  }

  private static void verifyExternalContentUri(Context context, Uri uri, int modeFlags)
      throws FileNotFoundException {
    if (!Objects.equals(uri.getScheme(), ContentResolver.SCHEME_CONTENT)) {
      throw new FileNotFoundException("Unsupported URI scheme: " + uri.getScheme());
    }
    if (!isAllowedExternalAuthority(context, uri, modeFlags)) {
      throw new FileNotFoundException("Cannot open disallowed content URI authority.");
    }
  }

  private static boolean isAllowedExternalAuthority(Context context, Uri uri, int modeFlags) {
    String authority = uri.getAuthority();
    if (Strings.isNullOrEmpty(authority)) {
      return false;
    }
    PackageManager packageManager = context.getPackageManager();
    ProviderInfo providerInfo = packageManager.resolveContentProvider(authority, /* flags= */ 0);
    if (providerInfo == null) {
      int userPrefixIndex = authority.lastIndexOf('@');
      if (userPrefixIndex > -1) {
        authority = authority.substring(userPrefixIndex + 1);
        providerInfo = packageManager.resolveContentProvider(authority, /* flags= */ 0);
      }
      if (providerInfo == null) {
        // An authority absent from this user's PackageManager cannot belong to this app itself.
        return true;
      }
    }
    if (Objects.equals(context.getPackageName(), providerInfo.packageName)) {
      return false;
    }
    if (context.checkUriPermission(uri, Process.myPid(), Process.myUid(), modeFlags)
        == PackageManager.PERMISSION_GRANTED) {
      return true;
    }
    if (providerInfo.exported && isRestrictedExportedProvider(authority, providerInfo.packageName)) {
      return false;
    }
    return true;
  }

  private static boolean isRestrictedExportedProvider(
      String authority, @Nullable String packageName) {
    if (Objects.equals(authority, MediaStore.AUTHORITY)
        || Objects.equals(authority, LEGACY_DRIVE_AUTHORITY)) {
      return false;
    }
    if (packageName == null) {
      return false;
    }
    for (String prefix : GOOGLE_PACKAGE_PREFIXES) {
      if (prefix.endsWith(".")) {
        if (packageName.startsWith(prefix)) {
          return true;
        }
      } else if (packageName.equals(prefix)) {
        return true;
      }
    }
    return false;
  }

  private static int modeToGrantFlag(String mode) {
    return switch (mode) {
      case "r" -> Intent.FLAG_GRANT_READ_URI_PERMISSION;
      case "w", "wt", "wa", "rw", "rwt" -> Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
      default -> throw new IllegalArgumentException("Unsupported mode: " + mode);
    };
  }
}
