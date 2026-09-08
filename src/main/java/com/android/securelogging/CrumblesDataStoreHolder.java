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

import android.content.Context;
import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.ProtoSerializer;
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler;
import androidx.datastore.guava.GuavaDataStore;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.File;

/**
 * Manages the process-wide singleton {@link GuavaDataStore} instance for Crumbles key preferences.
 *
 * <p>Jetpack DataStore strictly enforces at most one active DataStore instance per file per
 * process to avoid file locking collisions. This holder ensures a single shared instance is used
 * across Activities, Receivers, and Workers.
 */
public final class CrumblesDataStoreHolder {

  public static final String DATA_STORE_FILE_NAME = "user_key_prefs.pb";
  private static final String DATA_STORE_DIR = "datastore";

  // Suppress "NonFinalStaticField" because the GuavaDataStore instance must be lazily
  // initialized with the Android Application Context to maintain a process-wide singleton.
  @SuppressWarnings("NonFinalStaticField")
  private static GuavaDataStore<UserKeyPreferences> instance;

  private CrumblesDataStoreHolder() {}

  /**
   * Returns the process-wide singleton {@link GuavaDataStore} instance.
   *
   * @param context the Android application or component context
   * @return the shared {@link GuavaDataStore} instance
   */
  public static synchronized GuavaDataStore<UserKeyPreferences> getInstance(Context context) {
    if (instance == null) {
      File dataStoreFile =
          new File(
              context.getApplicationContext().getFilesDir(),
              DATA_STORE_DIR + File.separator + DATA_STORE_FILE_NAME);
      instance = createDataStore(dataStoreFile);
    }
    return instance;
  }

  /**
   * Creates a {@link GuavaDataStore} backed by the specified file.
   *
   * @param file the backing Protobuf file
   * @return a configured {@link GuavaDataStore} instance
   */
  public static GuavaDataStore<UserKeyPreferences> createDataStore(File file) {
    return new GuavaDataStore.Builder<UserKeyPreferences>(
            new ProtoSerializer<>(
                UserKeyPreferences.getDefaultInstance(),
                ExtensionRegistryLite.getGeneratedRegistry()),
            () -> file)
        .setCorruptionHandler(
            new ReplaceFileCorruptionHandler<>(
                (CorruptionException unused) -> UserKeyPreferences.getDefaultInstance()))
        .build();
  }
}
