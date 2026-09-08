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
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import androidx.datastore.guava.GuavaDataStore;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.protobuf.ByteString;
import java.io.File;
import java.io.FileOutputStream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

/** Unit tests for {@link CrumblesDataStoreHolder}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesDataStoreHolderTest {

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();

  private Context context;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
  }

  @Test
  public void getInstance_returnsSameSingletonInstance() {
    GuavaDataStore<UserKeyPreferences> first = CrumblesDataStoreHolder.getInstance(context);
    GuavaDataStore<UserKeyPreferences> second = CrumblesDataStoreHolder.getInstance(context);

    assertThat(first).isNotNull();
    assertThat(second).isSameInstanceAs(first);
  }

  @Test
  public void createDataStore_writesAndReadsPreferences() throws Exception {
    File testFile = new File(tempFolder.getRoot(), "test_user_key_prefs.pb");
    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(testFile);

    EncryptedPayload payload =
        EncryptedPayload.newBuilder()
            .setCiphertext(ByteString.copyFromUtf8("cipher"))
            .setInitializationVector(ByteString.copyFromUtf8("iv"))
            .setWrappedEncryptionKey(ByteString.copyFromUtf8("key"))
            .build();

    dataStore
        .updateDataAsync(
            prefs ->
                prefs.toBuilder()
                    .setActiveKeyId("test_key_id_123")
                    .putExternalPublicKeys("test_key_id_123", payload)
                    .build())
        .get();

    UserKeyPreferences loaded = dataStore.getDataAsync().get();
    assertThat(loaded.getActiveKeyId()).isEqualTo("test_key_id_123");
    assertThat(loaded.getExternalPublicKeysMap()).containsKey("test_key_id_123");
    assertThat(loaded.getExternalPublicKeysOrThrow("test_key_id_123")).isEqualTo(payload);
  }

  @Test
  public void createDataStore_whenFileCorrupted_replacesWithDefaultInstance() throws Exception {
    File testFile = new File(tempFolder.getRoot(), "corrupt_user_key_prefs.pb");
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write("corrupted garbage byte content not valid protobuf".getBytes(UTF_8));
    }

    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(testFile);
    UserKeyPreferences loaded = dataStore.getDataAsync().get();

    assertThat(loaded).isEqualTo(UserKeyPreferences.getDefaultInstance());
    assertThat(loaded.getActiveKeyId()).isEmpty();
  }
}
