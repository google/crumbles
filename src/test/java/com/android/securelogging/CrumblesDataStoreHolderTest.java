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
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.service.notification.StatusBarNotification;
import androidx.datastore.guava.GuavaDataStore;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.Nullable;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

/** Unit tests for {@link CrumblesDataStoreHolder}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesDataStoreHolderTest {

  private static final String ACTIVE_KEY_ID = "test_key_id_123";
  private static final UserKeyPreferences PREFERENCES =
      UserKeyPreferences.newBuilder().setActiveKeyId(ACTIVE_KEY_ID).build();

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  @Rule public final Expect expect = Expect.create();

  private Context context;

  @Before
  public void setUp() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = false;
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = false;
    context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    getNotificationManager().cancelAll();
  }

  @After
  public void tearDown() {
    FakeAndroidKeyStoreSpi.setUserAuthenticated(false);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
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
  public void getInstance_returnsSameSingletonAndAuthenticatesExistingUnmacedStore()
      throws Exception {
    File storeFile =
        new File(
            context.getFilesDir(), "datastore/" + CrumblesDataStoreHolder.DATA_STORE_FILE_NAME);
    storeFile.getParentFile().mkdirs();
    Files.write(storeFile.toPath(), PREFERENCES.toByteArray());

    GuavaDataStore<UserKeyPreferences> first = CrumblesDataStoreHolder.getInstance(context);
    GuavaDataStore<UserKeyPreferences> second = CrumblesDataStoreHolder.getInstance(context);

    expect.that(second).isSameInstanceAs(first);
    expect.that(first.updateDataAsync(p -> p).get().getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
    UserKeyPreferences migrated =
        UserKeyPreferences.parseFrom(
            Files.readAllBytes(storeFile.toPath()), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(migrated.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
    expect.that(migrated.getStoreMac().size()).isEqualTo(32);

    File alteredFile =
        newStoreFile(migrated.toBuilder().setActiveKeyId("attacker_key_id").build().toByteArray());
    UserKeyPreferences loadedAfterTampering =
        CrumblesDataStoreHolder.createDataStore(alteredFile, context).getDataAsync().get();
    expect
        .that(loadedAfterTampering.getActiveKeyId())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_ACTIVE_KEY_ID);
    expect
        .that(latestAuditEvent().getEventType())
        .isEqualTo(CrumblesDataStoreHolder.AUDIT_EVENT_PREFERENCES_ALTERED);

    first.updateDataAsync(_ -> CrumblesDataStoreHolder.UNREADABLE_STORE_REPLACEMENT).get();
    expect
        .that(CrumblesKeyHandover.handOver(context, "recover from unreadable store"))
        .isEqualTo(CrumblesKeyHandover.Outcome.NOT_NEEDED);
    first.updateDataAsync(_ -> PREFERENCES).get();
    expect
        .that(CrumblesKeyHandover.handOver(context, "missing outgoing key"))
        .isEqualTo(CrumblesKeyHandover.Outcome.NOT_SEALED);
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
  public void createDataStore_whenFileCorrupted_replacesWithUnreadableSentinel() throws Exception {
    File testFile = writeCorruptStore("corrupt_user_key_prefs.pb");

    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(testFile);
    UserKeyPreferences loaded = dataStore.getDataAsync().get();

    assertThat(loaded).isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_REPLACEMENT);
    assertThat(loaded.getActiveKeyId())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_ACTIVE_KEY_ID);
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
                n -> n.getId() == CrumblesConstants.PREFERENCES_UNREADABLE_NOTIFICATION_ID)
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
    // Only the tombstone written by clearAllLogs() in setUp() is present.
    assertThat(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType))
        .containsExactly("AUDIT_LOG_CLEARED");
  }

  @Test
  public void createDataStore_writesWithStrongBoxHmacKeyAndReadsBack() throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    File file = newStoreFile(signedStore);
    // A second write must reuse the existing HMAC key rather than replacing it in Keystore.
    expect.that(writtenStore(PREFERENCES)).isEqualTo(signedStore);

    KeyGenParameterSpec keySpec = FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec();
    expect.that(keySpec.getKeystoreAlias()).isEqualTo(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    expect
        .that(keySpec.getPurposes())
        .isEqualTo(KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
    expect.that(keySpec.getDigests()).asList().containsExactly(KeyProperties.DIGEST_SHA256);
    expect.that(keySpec.isStrongBoxBacked()).isTrue();
    expect.that(keySpec.isUserAuthenticationRequired()).isFalse();
    expect.that(keySpec.isUnlockedDeviceRequired()).isFalse();
    expect
        .that(
            UserKeyPreferences.parseFrom(signedStore, ExtensionRegistryLite.getEmptyRegistry())
                .getStoreMac()
                .size())
        .isEqualTo(32);
    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
    expect.that(preservedFileOf(file).exists()).isFalse();
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();
  }

  @Test
  public void createDataStore_whenStrongBoxUnavailable_authenticatesWithTeeKey() throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = false;
    File file = newStoreFile(writtenStore(PREFERENCES));

    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();

    expect.that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void createDataStore_whenStrongBoxFails_authenticatesWithTeeKey() throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = true;
    File file = newStoreFile(writtenStore(PREFERENCES));

    expect
        .that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked())
        .isFalse();
    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void createDataStore_whenStrongBoxRejectsParams_authenticatesWithTeeKey()
      throws Exception {
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = true;
    File file = newStoreFile(writtenStore(PREFERENCES));

    expect
        .that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked())
        .isFalse();
    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void createDataStore_whenKeystoreThrowsProviderException_failsReadAndWriteAndKeepsStore()
      throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    File file = newStoreFile(signedStore);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        () -> {
          throw new ProviderException("Keystore failed");
        });
    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(file, context);
    CrumblesPreferencesSerializer serializer = new CrumblesPreferencesSerializer();

    assertThrows(ExecutionException.class, () -> dataStore.getDataAsync().get());
    assertThrows(
        IOException.class,
        () ->
            serializer.writeTo(
                PREFERENCES, OutputStream.nullOutputStream(), /* continuation= */ null));
    expect.that(Files.readAllBytes(file.toPath())).isEqualTo(signedStore);
    expect.that(preservedFileOf(file).exists()).isFalse();
  }

  @Test
  public void createDataStore_whenStrongBoxFailsWithGeneralSecurityException_fallsBackToTeeKey()
      throws Exception {
    installKeyGeneratorSpi(StrongBoxGeneralSecurityFailingHmacKeyGeneratorSpi.class);
    File file = newStoreFile(writtenStore(PREFERENCES));

    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();

    expect.that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void createDataStore_whenStrongBoxFailsWithProviderException_fallsBackToTeeKey()
      throws Exception {
    installKeyGeneratorSpi(StrongBoxProviderFailingHmacKeyGeneratorSpi.class);
    File file = newStoreFile(writtenStore(PREFERENCES));

    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();

    expect.that(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void createDataStore_whenStoreAltered_reportsItAndFailsClosed() throws Exception {
    byte[] altered =
        UserKeyPreferences.parseFrom(
                writtenStore(PREFERENCES), ExtensionRegistryLite.getEmptyRegistry())
            .toBuilder()
            .setActiveKeyId("attacker_key_id")
            .build()
            .toByteArray();
    File file = newStoreFile(altered);

    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(file, context);
    UserKeyPreferences loaded = dataStore.getDataAsync().get();
    CrumblesExternalPublicKeyManager keyManager =
        new CrumblesExternalPublicKeyManager(dataStore, new CrumblesLogsEncryptor(context));

    expect
        .that(loaded.getActiveKeyId())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_ACTIVE_KEY_ID);
    expect.that(keyManager.isExternalKeySelected()).isTrue();
    expect.that(keyManager.getActiveExternalPublicKey()).isNull();
    expect
        .that(latestAuditEvent().getEventType())
        .isEqualTo(CrumblesDataStoreHolder.AUDIT_EVENT_PREFERENCES_ALTERED);
    expect.that(latestAuditEvent().getMessage()).contains("failed its integrity check");
    expect.that(Files.readAllBytes(preservedFileOf(file).toPath())).isEqualTo(altered);
  }

  @Test
  public void createDataStore_whenHmacRemovedAfterKeyCreated_reportsAlteration() throws Exception {
    File file =
        newStoreFile(
            UserKeyPreferences.parseFrom(
                    writtenStore(PREFERENCES), ExtensionRegistryLite.getEmptyRegistry())
                .toBuilder()
                .clearStoreMac()
                .build()
                .toByteArray());

    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();

    expect
        .that(loaded.getActiveKeyId())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_ACTIVE_KEY_ID);
    expect
        .that(latestAuditEvent().getEventType())
        .isEqualTo(CrumblesDataStoreHolder.AUDIT_EVENT_PREFERENCES_ALTERED);
  }

  @Test
  public void createDataStore_whenHmacKeyLost_reportsAlteration() throws Exception {
    File file = newStoreFile(writtenStore(PREFERENCES));
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);

    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();

    expect
        .that(loaded.getActiveKeyId())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_ACTIVE_KEY_ID);
    expect
        .that(latestAuditEvent().getEventType())
        .isEqualTo(CrumblesDataStoreHolder.AUDIT_EVENT_PREFERENCES_ALTERED);
  }

  @Test
  public void createDataStore_whenStoreDeletedAfterHmacKeyCreated_reportsAlterationAndFailsClosed()
      throws Exception {
    File file = newStoreFile(writtenStore(PREFERENCES));
    Files.delete(file.toPath());

    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(file, context);
    UserKeyPreferences loaded = dataStore.getDataAsync().get();
    CrumblesExternalPublicKeyManager keyManager =
        new CrumblesExternalPublicKeyManager(dataStore, new CrumblesLogsEncryptor(context));

    expect.that(loaded).isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_REPLACEMENT);
    File deletedWithoutContext = new File(tempFolder.getRoot(), "deleted_without_context.pb");
    expect
        .that(CrumblesDataStoreHolder.createDataStore(deletedWithoutContext).getDataAsync().get())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_REPLACEMENT);
    expect
        .that(new CrumblesPreferencesSerializer(/* file= */ null, context).getDefaultValue())
        .isEqualTo(CrumblesDataStoreHolder.UNREADABLE_STORE_REPLACEMENT);
    expect.that(keyManager.isExternalKeySelected()).isTrue();
    expect.that(keyManager.getActiveExternalPublicKey()).isNull();
    expect
        .that(latestAuditEvent().getEventType())
        .isEqualTo(CrumblesDataStoreHolder.AUDIT_EVENT_PREFERENCES_ALTERED);
    expect
        .that(
            Arrays.stream(getNotificationManager().getActiveNotifications())
                .map(StatusBarNotification::getId))
        .containsExactly(CrumblesConstants.PREFERENCES_UNREADABLE_NOTIFICATION_ID);
  }

  @Test
  public void createDataStore_whenNoStoreWrittenYet_startsEmptyWithoutReporting() throws Exception {
    File file = new File(tempFolder.getRoot(), "new_store.pb");

    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(file, context).getDataAsync().get();

    expect.that(loaded).isEqualTo(UserKeyPreferences.getDefaultInstance());
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();
  }

  @Test
  public void createDataStore_whenKeystoreUnavailable_failsReadAndKeepsStore() throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    File file = newStoreFile(signedStore);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(file, context);
    var readFuture = dataStore.getDataAsync();
    InputStream closedInput = InputStream.nullInputStream();
    closedInput.close();
    OutputStream nullOutput = OutputStream.nullOutputStream();
    CrumblesPreferencesSerializer serializer = new CrumblesPreferencesSerializer(file, context);

    expect.that(serializer.getDefaultValue()).isEqualTo(UserKeyPreferences.getDefaultInstance());
    assertThrows(ExecutionException.class, readFuture::get);
    assertThrows(
        IOException.class, () -> serializer.readFrom(closedInput, /* continuation= */ null));
    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, nullOutput, /* continuation= */ null));

    expect.that(Files.readAllBytes(file.toPath())).isEqualTo(signedStore);
    expect.that(preservedFileOf(file).exists()).isFalse();
  }

  @Test
  public void createDataStore_whenKeystoreThrowsProviderException_failsReadAndKeepsStore()
      throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    File file = newStoreFile(signedStore);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        () -> {
          throw new ProviderException("Keystore backend failure");
        });
    GuavaDataStore<UserKeyPreferences> dataStore =
        CrumblesDataStoreHolder.createDataStore(file, context);
    var readFuture = dataStore.getDataAsync();
    OutputStream nullOutput = OutputStream.nullOutputStream();
    CrumblesPreferencesSerializer serializer = new CrumblesPreferencesSerializer(file, context);

    expect.that(serializer.getDefaultValue()).isEqualTo(UserKeyPreferences.getDefaultInstance());
    assertThrows(ExecutionException.class, readFuture::get);
    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, nullOutput, /* continuation= */ null));

    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    expect.that(Files.readAllBytes(file.toPath())).isEqualTo(signedStore);
    expect.that(preservedFileOf(file).exists()).isFalse();
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();
  }

  @Test
  public void write_whenStoreDeletedAndWriteFails_preservesHmacKey() throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES); // creates the HMAC key
    File file = newStoreFile(signedStore);
    Files.delete(file.toPath());
    file.mkdir(); // makes the file un-writable so that the next write fails
    var writeFuture = CrumblesDataStoreHolder.createDataStore(file).updateDataAsync(p -> p);

    assertThrows(ExecutionException.class, writeFuture::get);
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    expect
        .that(
            new CrumblesPreferencesSerializer()
                .writeTo(PREFERENCES, OutputStream.nullOutputStream(), /* continuation= */ null))
        .isNotNull();
  }

  @Test
  public void writeTo_whenInitialWriteFails_deletesNewlyCreatedMacKey() throws Exception {
    AtomicBoolean keyCreatedBeforeWriteFailure = new AtomicBoolean();
    OutputStream failingOutput =
        new OutputStream() {
          @Override
          public void write(int b) throws IOException {
            keyCreatedBeforeWriteFailure.set(
                FakeAndroidKeyStoreSpi.keystoreEntries.containsKey(
                    CrumblesPreferencesSerializer.MAC_KEY_ALIAS));
            throw new IOException("disk full");
          }
        };
    CrumblesPreferencesSerializer serializer = new CrumblesPreferencesSerializer();

    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, failingOutput, /* continuation= */ null));
    expect.that(keyCreatedBeforeWriteFailure.get()).isTrue();
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);

    File unwritableStore = tempFolder.newFolder("unwritable_initial_store.pb");
    var failedWrite =
        CrumblesDataStoreHolder.createDataStore(unwritableStore, context)
            .updateDataAsync(_ -> PREFERENCES);
    assertThrows(ExecutionException.class, failedWrite::get);
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    File missingStore = new File(tempFolder.getRoot(), "never_written_after_failed_init.pb");
    expect
        .that(CrumblesDataStoreHolder.createDataStore(missingStore, context).getDataAsync().get())
        .isEqualTo(UserKeyPreferences.getDefaultInstance());
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();

    installDeleteFailingKeyStoreSpi();
    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, failingOutput, /* continuation= */ null));
  }

  @Test
  public void writeTo_whenMacKeyExistsThrowsGeneralSecurityExceptionAndWriteFails_preservesMacKey()
      throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    FakeAndroidKeyStoreSpi.Entry realEntry =
        FakeAndroidKeyStoreSpi.keystoreEntries.get(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    CrumblesPreferencesSerializer serializer = new CrumblesPreferencesSerializer();
    OutputStream nullOutput = OutputStream.nullOutputStream();
    OutputStream failingOutput = failingOutputStream();

    // Persistent GeneralSecurityException: both macKeyExists() and withMac() fail.
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.Entry() {
          @Override
          public Key getKey() {
            return realEntry.getKey();
          }

          @Override
          public boolean isUserAuthenticationRequired() {
            return true;
          }
        });
    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, nullOutput, /* continuation= */ null));
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);

    // Transient GeneralSecurityException on macKeyExists(), followed by output.write() failure.
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.Entry() {
          @Override
          public Key getKey() {
            return realEntry.getKey();
          }

          @Override
          public boolean isUserAuthenticationRequired() {
            FakeAndroidKeyStoreSpi.keystoreEntries.put(
                CrumblesPreferencesSerializer.MAC_KEY_ALIAS, realEntry);
            return true;
          }
        });
    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, failingOutput, /* continuation= */ null));
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(newStoreFile(signedStore), context)
            .getDataAsync()
            .get();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void writeTo_whenMacKeyExistsThrowsProviderExceptionAndWriteFails_preservesMacKey()
      throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    FakeAndroidKeyStoreSpi.Entry realEntry =
        FakeAndroidKeyStoreSpi.keystoreEntries.get(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        () -> {
          FakeAndroidKeyStoreSpi.keystoreEntries.put(
              CrumblesPreferencesSerializer.MAC_KEY_ALIAS, realEntry);
          throw new ProviderException("transient Keystore failure");
        });
    CrumblesPreferencesSerializer serializer = new CrumblesPreferencesSerializer();
    OutputStream failingOutput = failingOutputStream();

    assertThrows(
        IOException.class,
        () -> serializer.writeTo(PREFERENCES, failingOutput, /* continuation= */ null));

    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    UserKeyPreferences loaded =
        CrumblesDataStoreHolder.createDataStore(newStoreFile(signedStore), context)
            .getDataAsync()
            .get();
    expect.that(loaded.getActiveKeyId()).isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void initializeDataStore_whenInitialWriteFails_deletesNewlyCreatedMacKey()
      throws Exception {
    File parentBlocker = tempFolder.newFile("datastore_parent_blocker");
    File unwritableStore = new File(parentBlocker, "user_key_prefs.pb");
    GuavaDataStore<UserKeyPreferences> failedStore =
        CrumblesDataStoreHolder.createDataStore(unwritableStore, context);

    assertThrows(
        ExecutionException.class,
        () -> CrumblesDataStoreHolder.initializeDataStore(failedStore).get());

    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    File nextStartupFile = new File(tempFolder.newFolder(), "user_key_prefs.pb");
    GuavaDataStore<UserKeyPreferences> nextStartupStore =
        CrumblesDataStoreHolder.createDataStore(nextStartupFile, context);
    expect
        .that(CrumblesDataStoreHolder.initializeDataStore(nextStartupStore).get())
        .isEqualTo(CrumblesPreferencesSerializer.withMac(UserKeyPreferences.getDefaultInstance()));
    expect
        .that(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType))
        .containsExactly("AUDIT_LOG_CLEARED");
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();
  }

  @Test
  public void initializeDataStore_whenComputeMacFailsAfterCreatingKey_deletesNewlyCreatedMacKey()
      throws Exception {
    FailingHmacMacSpi.keyExistedDuringMac.set(false);
    installFailingMacSpi();
    File storeFile = new File(tempFolder.newFolder(), "user_key_prefs.pb");
    GuavaDataStore<UserKeyPreferences> failedStore =
        CrumblesDataStoreHolder.createDataStore(storeFile, context);

    assertThrows(
        ExecutionException.class,
        () -> CrumblesDataStoreHolder.initializeDataStore(failedStore).get());

    expect.that(FailingHmacMacSpi.keyExistedDuringMac.get()).isTrue();
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .doesNotContainKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    File nextStartupFile = new File(tempFolder.newFolder(), "next_user_key_prefs.pb");
    UserKeyPreferences nextLoaded =
        CrumblesDataStoreHolder.createDataStore(nextStartupFile, context).getDataAsync().get();
    expect.that(nextLoaded).isEqualTo(UserKeyPreferences.getDefaultInstance());
    expect
        .that(
            CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType))
        .containsExactly("AUDIT_LOG_CLEARED");
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();
  }

  @Test
  public void initializeDataStore_whenMacKeyRollbackFails_propagatesInitialWriteFailure()
      throws Exception {
    File parentBlocker = tempFolder.newFile("rollback_failure_blocker");
    installDeleteFailingKeyStoreSpi();
    GuavaDataStore<UserKeyPreferences> failedStore =
        CrumblesDataStoreHolder.createDataStore(
            new File(parentBlocker, "user_key_prefs.pb"), context);

    ExecutionException thrown =
        assertThrows(
            ExecutionException.class,
            () -> CrumblesDataStoreHolder.initializeDataStore(failedStore).get());

    expect.that(thrown).hasCauseThat().isInstanceOf(IOException.class);
  }

  @Test
  public void initializeDataStore_whenMacKeyPreExistedAndInitFails_preservesMacKey()
      throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    File parentBlocker = tempFolder.newFile("preexisting_key_blocker");
    GuavaDataStore<UserKeyPreferences> failedStore =
        CrumblesDataStoreHolder.createDataStore(
            new File(parentBlocker, "user_key_prefs.pb"), /* context= */ null);

    assertThrows(
        ExecutionException.class,
        () -> CrumblesDataStoreHolder.initializeDataStore(failedStore).get());

    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    expect
        .that(
            CrumblesDataStoreHolder.createDataStore(newStoreFile(signedStore), context)
                .getDataAsync()
                .get()
                .getActiveKeyId())
        .isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void initializeDataStore_whenMacKeyCheckThrowsAndInitFails_preservesMacKey()
      throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    FakeAndroidKeyStoreSpi.Entry realEntry =
        FakeAndroidKeyStoreSpi.keystoreEntries.get(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    File parentBlocker = tempFolder.newFile("transient_keystore_blocker");

    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        new FakeAndroidKeyStoreSpi.Entry() {
          @Override
          public Key getKey() {
            return realEntry.getKey();
          }

          @Override
          public boolean isUserAuthenticationRequired() {
            FakeAndroidKeyStoreSpi.keystoreEntries.put(
                CrumblesPreferencesSerializer.MAC_KEY_ALIAS, realEntry);
            return true;
          }
        });
    GuavaDataStore<UserKeyPreferences> gseFailedStore =
        CrumblesDataStoreHolder.createDataStore(
            new File(parentBlocker, "gse_prefs.pb"), /* context= */ null);
    assertThrows(
        ExecutionException.class,
        () -> CrumblesDataStoreHolder.initializeDataStore(gseFailedStore).get());
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);

    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        () -> {
          FakeAndroidKeyStoreSpi.keystoreEntries.put(
              CrumblesPreferencesSerializer.MAC_KEY_ALIAS, realEntry);
          throw new ProviderException("transient Keystore failure");
        });
    GuavaDataStore<UserKeyPreferences> providerFailedStore =
        CrumblesDataStoreHolder.createDataStore(
            new File(parentBlocker, "provider_prefs.pb"), /* context= */ null);
    assertThrows(
        ExecutionException.class,
        () -> CrumblesDataStoreHolder.initializeDataStore(providerFailedStore).get());
    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsKey(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    expect
        .that(
            CrumblesDataStoreHolder.createDataStore(newStoreFile(signedStore), context)
                .getDataAsync()
                .get()
                .getActiveKeyId())
        .isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void initializeDataStore_whenStoreReadFails_preservesMacKey() throws Exception {
    byte[] signedStore = writtenStore(PREFERENCES);
    FakeAndroidKeyStoreSpi.Entry realEntry =
        FakeAndroidKeyStoreSpi.keystoreEntries.get(CrumblesPreferencesSerializer.MAC_KEY_ALIAS);
    GuavaDataStore<UserKeyPreferences> failedStore =
        CrumblesDataStoreHolder.createDataStore(newStoreFile(signedStore), context);
    // Fails the HMAC check of the read that precedes the initial write, so the init fails before
    // it could create the key.
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesPreferencesSerializer.MAC_KEY_ALIAS,
        () -> {
          FakeAndroidKeyStoreSpi.keystoreEntries.put(
              CrumblesPreferencesSerializer.MAC_KEY_ALIAS, realEntry);
          throw new ProviderException("transient Keystore failure");
        });

    assertThrows(
        ExecutionException.class,
        () -> CrumblesDataStoreHolder.initializeDataStore(failedStore).get());

    expect
        .that(FakeAndroidKeyStoreSpi.keystoreEntries)
        .containsEntry(CrumblesPreferencesSerializer.MAC_KEY_ALIAS, realEntry);
    expect
        .that(
            CrumblesDataStoreHolder.createDataStore(newStoreFile(signedStore), context)
                .getDataAsync()
                .get()
                .getActiveKeyId())
        .isEqualTo(ACTIVE_KEY_ID);
  }

  @Test
  public void initializeDataStore_whenStoreReadDuringFirstWrite_doesNotReportItDeleted()
      throws Exception {
    File file = new File(tempFolder.newFolder(), "user_key_prefs.pb");

    expect.that(readDuringFirstWrite(file)).isEqualTo(UserKeyPreferences.getDefaultInstance());
  }

  @Test
  public void initializeDataStore_whenPreHmacStoreReadDuringFirstWrite_doesNotReportItAltered()
      throws Exception {
    File file = newStoreFile(PREFERENCES.toByteArray());

    expect.that(readDuringFirstWrite(file)).isEqualTo(PREFERENCES);
  }

  /**
   * Reads the store at {@code file} while its initial write is held after bumping the store
   * version, so that the read does not wait for it, then expects nothing to have been reported.
   */
  private UserKeyPreferences readDuringFirstWrite(File file) throws Exception {
    CompletableFuture<Void> writing = new CompletableFuture<>();
    CompletableFuture<Void> readDone = new CompletableFuture<>();
    var serializer =
        new CrumblesPreferencesSerializer(file, context) {
          @Override
          public Object writeTo(
              UserKeyPreferences preferences, OutputStream output, Continuation<? super Unit> c) {
            writing.complete(null);
            // Goes on once the read is done, or after 5 s if the read waits for this write.
            readDone.completeOnTimeout(null, 5, SECONDS).join();
            return super.writeTo(preferences, output, c);
          }
        };
    var dataStore = CrumblesDataStoreHolder.createDataStore(file, context, serializer);
    var initFuture = CrumblesDataStoreHolder.initializeDataStore(dataStore);
    writing.join();
    var readFuture = dataStore.getDataAsync();
    readFuture.addListener(() -> readDone.complete(null), Runnable::run);
    initFuture.get();
    expect.that(latestAuditEvent().getEventType()).isEqualTo("AUDIT_LOG_CLEARED");
    expect.that(getNotificationManager().getActiveNotifications()).isEmpty();
    expect.that(preservedFileOf(file).exists()).isFalse();
    return readFuture.get();
  }

  /** Returns the bytes that a DataStore writes for {@code preferences}, including the HMAC. */
  private byte[] writtenStore(UserKeyPreferences preferences) throws Exception {
    File file = new File(tempFolder.newFolder(), "written_store.pb");
    CrumblesDataStoreHolder.createDataStore(file).updateDataAsync(_ -> preferences).get();
    return Files.readAllBytes(file.toPath());
  }

  private File newStoreFile(byte[] contents) throws Exception {
    File file = new File(tempFolder.newFolder(), "store.pb");
    Files.write(file.toPath(), contents);
    return file;
  }

  private static OutputStream failingOutputStream() {
    return new OutputStream() {
      @Override
      public void write(int b) throws IOException {
        throw new IOException("disk full");
      }
    };
  }

  private static void installKeyGeneratorSpi(Class<? extends KeyGeneratorSpi> spiClass) {
    FakeAndroidKeyStoreProvider provider = new FakeAndroidKeyStoreProvider();
    provider.put("KeyGenerator.HmacSHA256", spiClass.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(provider, 1);
  }

  private static void installDeleteFailingKeyStoreSpi() {
    FakeAndroidKeyStoreProvider provider = new FakeAndroidKeyStoreProvider();
    provider.put(
        "KeyStore." + FakeAndroidKeyStoreProvider.PROVIDER_NAME,
        DeleteFailingKeyStoreSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(provider, 1);
  }

  private static void installFailingMacSpi() {
    FakeAndroidKeyStoreProvider provider = new FakeAndroidKeyStoreProvider();
    provider.put("Mac.HmacSHA256", FailingHmacMacSpi.class.getName());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(provider, 1);
  }

  private static File preservedFileOf(File file) {
    return new File(file.getAbsolutePath() + CrumblesDataStoreHolder.CORRUPT_FILE_SUFFIX);
  }

  private CrumblesAuditEvent latestAuditEvent() {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().get(0);
  }

  private abstract static class TeeOnlyHmacKeyGeneratorSpi extends KeyGeneratorSpi {
    private static final SecureRandom RANDOM = new SecureRandom();
    @Nullable protected KeyGenParameterSpec spec;

    @Override
    protected void engineInit(SecureRandom random) {}

    @Override
    protected void engineInit(int keysize, SecureRandom random) {}

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException {
      if (!(params instanceof KeyGenParameterSpec keySpec)) {
        throw new InvalidAlgorithmParameterException("Expected KeyGenParameterSpec");
      }
      this.spec = keySpec;
      FakeAndroidKeyStoreSpi.setLatestKeyGenParameterSpec(keySpec);
    }

    @Override
    protected SecretKey engineGenerateKey() {
      byte[] keyBytes = new byte[32];
      RANDOM.nextBytes(keyBytes);
      SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");
      if (spec != null) {
        FakeAndroidKeyStoreSpi.keystoreEntries.put(spec.getKeystoreAlias(), () -> key);
      }
      return key;
    }
  }

  /**
   * Fake HMAC {@link KeyGeneratorSpi} whose StrongBox key generation fails with a checked {@link
   * InvalidAlgorithmParameterException} other than {@code StrongBoxUnavailableException}.
   */
  public static final class StrongBoxGeneralSecurityFailingHmacKeyGeneratorSpi
      extends TeeOnlyHmacKeyGeneratorSpi {
    public StrongBoxGeneralSecurityFailingHmacKeyGeneratorSpi() {}

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException {
      super.engineInit(params, random);
      if (spec != null && spec.isStrongBoxBacked()) {
        throw new InvalidAlgorithmParameterException("StrongBox rejected key parameters");
      }
    }
  }

  /**
   * Fake HMAC {@link KeyGeneratorSpi} whose StrongBox key generation fails with {@link
   * ProviderException}.
   */
  public static final class StrongBoxProviderFailingHmacKeyGeneratorSpi
      extends TeeOnlyHmacKeyGeneratorSpi {
    public StrongBoxProviderFailingHmacKeyGeneratorSpi() {}

    @Override
    protected SecretKey engineGenerateKey() {
      if (spec != null && spec.isStrongBoxBacked()) {
        throw new ProviderException("StrongBox hardware failure");
      }
      return super.engineGenerateKey();
    }
  }

  /** Fake {@link FakeAndroidKeyStoreSpi} whose {@code deleteEntry} fails with ProviderException. */
  public static final class DeleteFailingKeyStoreSpi extends FakeAndroidKeyStoreSpi {
    public DeleteFailingKeyStoreSpi() {}

    @Override
    public void engineDeleteEntry(String alias) {
      throw new ProviderException("Keystore delete failed");
    }
  }

  /**
   * Fake HMAC {@link MacSpi} that fails during MAC computation after Keystore key generation has
   * already populated {@link CrumblesPreferencesSerializer#MAC_KEY_ALIAS}.
   */
  public static final class FailingHmacMacSpi extends MacSpi {
    static final AtomicBoolean keyExistedDuringMac = new AtomicBoolean();

    public FailingHmacMacSpi() {}

    @Override
    protected int engineGetMacLength() {
      return 32;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) {
      keyExistedDuringMac.set(
          FakeAndroidKeyStoreSpi.keystoreEntries.containsKey(
              CrumblesPreferencesSerializer.MAC_KEY_ALIAS));
    }

    @Override
    protected void engineUpdate(byte input) {}

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {}

    @Override
    protected byte[] engineDoFinal() {
      throw new ProviderException("Keystore HMAC operation failed");
    }

    @Override
    protected void engineReset() {}
  }
}
