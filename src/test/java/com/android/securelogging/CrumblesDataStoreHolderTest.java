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

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.service.notification.StatusBarNotification;
import androidx.datastore.guava.GuavaDataStore;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.google.protobuf.ByteString;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.Arrays;
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
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    getNotificationManager().cancelAll();
  }

  private NotificationManager getNotificationManager() {
    return (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
  }

  private File writeCorruptStore(String fileName) throws Exception {
    File corruptFile = new File(tempFolder.getRoot(), fileName);
    try (FileOutputStream fos = new FileOutputStream(corruptFile)) {
      fos.write("corrupted garbage byte content not valid protobuf".getBytes(UTF_8));
    }
    return corruptFile;
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
    File testFile = writeCorruptStore("corrupt_user_key_prefs.pb");

    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(testFile);
    UserKeyPreferences loaded = dataStore.getDataAsync().get();

    assertThat(loaded).isEqualTo(UserKeyPreferences.getDefaultInstance());
    assertThat(loaded.getActiveKeyId()).isEmpty();
  }

  @Test
  public void createDataStore_whenFileCorrupted_preservesUnreadableFile() throws Exception {
    File testFile = writeCorruptStore("preserved_user_key_prefs.pb");
    byte[] corruptBytes = Files.readAllBytes(testFile.toPath());

    CrumblesDataStoreHolder.createDataStore(testFile, context).getDataAsync().get();

    File preservedFile =
        new File(testFile.getAbsolutePath() + CrumblesDataStoreHolder.CORRUPT_FILE_SUFFIX);
    assertThat(preservedFile.exists()).isTrue();
    assertThat(Files.readAllBytes(preservedFile.toPath())).isEqualTo(corruptBytes);
  }

  @Test
  public void createDataStore_whenAlreadyPreservedOnce_overwritesThePreservedFile()
      throws Exception {
    File testFile = writeCorruptStore("recorrupt_user_key_prefs.pb");
    File preservedFile =
        new File(testFile.getAbsolutePath() + CrumblesDataStoreHolder.CORRUPT_FILE_SUFFIX);
    Files.writeString(preservedFile.toPath(), "an older unreadable store");
    byte[] corruptBytes = Files.readAllBytes(testFile.toPath());

    CrumblesDataStoreHolder.createDataStore(testFile, context).getDataAsync().get();

    assertThat(Files.readAllBytes(preservedFile.toPath())).isEqualTo(corruptBytes);
    assertThat(
            Arrays.stream(tempFolder.getRoot().listFiles())
                .filter(f -> f.getName().endsWith(CrumblesDataStoreHolder.CORRUPT_FILE_SUFFIX)))
        .hasSize(1);
  }

  @Test
  public void createDataStore_whenFileCorrupted_logsAuditEvent() throws Exception {
    File testFile = writeCorruptStore("audited_user_key_prefs.pb");

    CrumblesDataStoreHolder.createDataStore(testFile, context).getDataAsync().get();

    CrumblesAuditEvent event =
        CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().get(0);
    assertThat(event.getEventType())
        .isEqualTo(CrumblesDataStoreHolder.AUDIT_EVENT_PREFERENCES_UNREADABLE);
    assertThat(event.getMessage()).contains("could not be read");
  }

  @Test
  public void createDataStore_whenFileCorrupted_notifiesUserOffTheLockScreen() throws Exception {
    File testFile = writeCorruptStore("notified_user_key_prefs.pb");

    CrumblesDataStoreHolder.createDataStore(testFile, context).getDataAsync().get();

    StatusBarNotification postedNotification =
        Arrays.stream(getNotificationManager().getActiveNotifications())
            .filter(
                n -> n.getId() == CrumblesDataStoreHolder.PREFERENCES_UNREADABLE_NOTIFICATION_ID)
            .findFirst()
            .orElse(null);
    assertThat(postedNotification).isNotNull();
    Notification notification = postedNotification.getNotification();
    assertThat(notification.visibility).isEqualTo(Notification.VISIBILITY_SECRET);
    assertThat(notification.flags & Notification.FLAG_AUTO_CANCEL)
        .isEqualTo(Notification.FLAG_AUTO_CANCEL);
    NotificationChannel channel =
        getNotificationManager()
            .getNotificationChannel(CrumblesConstants.DATA_INTEGRITY_NOTIFICATION_CHANNEL_ID);
    assertThat(channel.getLockscreenVisibility()).isEqualTo(Notification.VISIBILITY_SECRET);
    assertThat(channel.getDescription())
        .isEqualTo(context.getString(R.string.notification_channel_description_data_integrity));
  }

  @Test
  public void createDataStore_withoutContext_doesNotNotifyUser() throws Exception {
    File testFile = writeCorruptStore("silent_user_key_prefs.pb");

    CrumblesDataStoreHolder.createDataStore(testFile).getDataAsync().get();

    assertThat(getNotificationManager().getActiveNotifications()).isEmpty();
    assertThat(CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents()).isEmpty();
  }
}
