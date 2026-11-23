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
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.robolectric.Shadows.shadowOf;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.security.ProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class CrumblesLogStagingTest {
  private static final String FIRST_BATCH = "0000000000000000001-S.sealed";
  private static final String SECOND_BATCH = "0000000000000000002-S.sealed";

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private File directory;
  private CrumblesLogStaging staging;

  @Before
  public void setUp() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
    context = ApplicationProvider.getApplicationContext();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
    directory = new File(context.getNoBackupFilesDir(), "staged_logs");
    staging = new CrumblesLogStaging(context);
  }

  @After
  public void tearDown() {
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Test
  public void drain_handsOverTheStagedBatchesOldestFirstAndEmptiesStaging() throws Exception {
    stageAll("first", "", "third");

    List<String> written = drainAll();

    expect.that(written).containsExactly("first", "", "third").inOrder();
    expect.that(staging.isEmpty()).isTrue();
  }

  @Test
  public void drain_whenWriterFails_stopsAtThatBatch() throws Exception {
    stageAll("first", "second", "third");
    List<String> offered = new ArrayList<>();

    int stored =
        staging.drain(
            (isNetwork, logs) ->
                (offered.add(new String(logs, UTF_8)) && offered.size() == 1)
                    ? CrumblesLogStaging.WriteResult.STORED
                    : CrumblesLogStaging.WriteResult.FAILED);

    expect.that(stored).isEqualTo(1);
    expect.that(offered).containsExactly("first", "second").inOrder();
    expect.that(staging.isEmpty()).isFalse();
  }

  @Test
  public void drain_whenWriterDropsBatch_deletesItWithoutCountingAsStoredAndContinues()
      throws Exception {
    stageAll("first", "second");
    List<String> offered = new ArrayList<>();

    int stored =
        staging.drain(
            (isNetwork, logs) ->
                (offered.add(new String(logs, UTF_8)) && offered.size() == 1)
                    ? CrumblesLogStaging.WriteResult.DROPPED
                    : CrumblesLogStaging.WriteResult.STORED);

    expect.that(stored).isEqualTo(1);
    expect.that(offered).containsExactly("first", "second").inOrder();
    expect.that(staging.isEmpty()).isTrue();
  }

  @Test
  public void drain_afterWriterFailed_handsOverTheKeptBatchesInOrder() throws Exception {
    stageAll("first", "second");
    int stored = staging.drain((isNetwork, logs) -> CrumblesLogStaging.WriteResult.FAILED);
    expect.that(stored).isEqualTo(0);

    List<String> written = drainAll();

    assertThat(written).containsExactly("first", "second").inOrder();
  }

  @Test
  public void drain_whenBatchFailsAuthentication_reportsAndDeletesItAndGoesOn() throws Exception {
    stageAll("first", "second");
    // A batch moved into another batch's place no longer authenticates.
    Files.copy(
        new File(directory, SECOND_BATCH).toPath(),
        new File(directory, FIRST_BATCH).toPath(),
        REPLACE_EXISTING);

    List<String> written = drainAll();

    expect.that(written).containsExactly("second");
    expect.that(staging.isEmpty()).isTrue();
    expect
        .that(auditMessages(CrumblesLogStaging.AUDIT_EVENT_STAGED_LOGS_UNREADABLE))
        .containsExactly(
            "Staged log batch "
                + FIRST_BATCH
                + " failed authentication and was deleted: it was altered, or its device key is"
                + " gone.");
  }

  @Test
  public void drain_whenBatchCannotBeReadForNow_keepsItAndTheNewerOnes() throws Exception {
    stageAll("first", "second");
    File first = new File(directory, FIRST_BATCH);
    // Reading a directory fails as an I/O error would.
    assertThat(first.delete() && first.mkdir()).isTrue();

    List<String> written = drainAll();

    expect.that(written).isEmpty();
    expect.that(new File(directory, SECOND_BATCH).exists()).isTrue();
    expect.that(auditMessages(CrumblesLogStaging.AUDIT_EVENT_STAGED_LOGS_UNREADABLE)).isEmpty();
  }

  @Test
  public void drain_whenKeystoreThrowsProviderException_keepsTheBatches() throws Exception {
    stageAll("first", "second");
    FakeAndroidKeyStoreSpi.failKeyLookup(
        CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS,
        new ProviderException("Keystore cannot be reached."));

    List<String> written = drainAll();

    expect.that(written).isEmpty();
    expect.that(directory.list()).asList().containsExactly(FIRST_BATCH, SECOND_BATCH);
    expect.that(auditMessages(CrumblesLogStaging.AUDIT_EVENT_STAGED_LOGS_UNREADABLE)).isEmpty();
  }

  @Test
  public void drain_whenKeystoreThrowsOtherUncheckedException_keepsTheBatches() throws Exception {
    stageAll("first", "second");
    // As Keystore does on some OEM builds.
    FakeAndroidKeyStoreSpi.failKeyLookup(
        CrumblesLogStagingSealer.WRAPPING_KEY_ALIAS, new IllegalStateException("Keystore failed."));

    List<String> written = drainAll();

    expect.that(written).isEmpty();
    expect.that(directory.list()).asList().containsExactly(FIRST_BATCH, SECOND_BATCH);
    expect.that(auditMessages(CrumblesLogStaging.AUDIT_EVENT_STAGED_LOGS_UNREADABLE)).isEmpty();
  }

  @Test
  public void stage_whenBatchFillsStagingExactly_stagesIt() throws Exception {
    long sealedBytes = stageAndMeasure("batch");
    fillStaging(CrumblesLogStaging.CAP_BYTES - 2 * sealedBytes);

    boolean staged = staging.stage(false, "batch".getBytes(UTF_8));

    assertThat(staged).isTrue();
  }

  @Test
  public void stage_whenBatchDoesNotFit_refusesItAndAlertsTheUser() throws Exception {
    long sealedBytes = stageAndMeasure("batch");
    fillStaging(CrumblesLogStaging.CAP_BYTES - 2 * sealedBytes + 1);

    boolean staged = staging.stage(false, "batch".getBytes(UTF_8));

    Notification notification =
        shadowOf(context.getSystemService(NotificationManager.class))
            .getNotification(CrumblesConstants.STORAGE_NOTIFICATION_ID);
    expect.that(staged).isFalse();
    expect.that(directory.list()).hasLength(2);
    expect
        .that(auditMessages(CrumblesLogStaging.AUDIT_EVENT_STAGING_FULL))
        .containsExactly(
            "Staged log batches use "
                + (CrumblesLogStaging.CAP_BYTES - sealedBytes + 1)
                + " of 16777216 permitted bytes; a batch of "
                + sealedBytes
                + " bytes was refused.");
    expect
        .that(notification.extras.getString(Notification.EXTRA_TEXT))
        .isEqualTo(context.getString(R.string.notification_text_storage_stopped));
  }

  @Test
  public void stage_afterAFloodOfNetworkBatches_stillStagesASecurityBatch() throws Exception {
    // Sixteen batches of this size fill staging exactly.
    byte[] logs =
        new byte[(int) (CrumblesLogStaging.CAP_BYTES / 16 - CrumblesLogStagingSealer.OVERHEAD_BYTES)];
    for (int i = 0; i < 16; i++) {
      var unused = staging.stage(/* isNetworkBatch= */ true, logs);
    }

    boolean staged = staging.stage(/* isNetworkBatch= */ false, logs);

    expect.that(staged).isTrue();
    expect.that(staging.countBatches()).isEqualTo(13);
  }

  @Test
  public void stage_whenNetworkBatchWouldUseTheSecurityReserve_refusesItAndSaysWhy()
      throws Exception {
    long sealedBytes = stageAndMeasure("batch");
    fillStaging(
        CrumblesLogStaging.CAP_BYTES - CrumblesLogStaging.SECURITY_RESERVE_BYTES - sealedBytes);

    boolean staged = staging.stage(/* isNetworkBatch= */ true, "batch".getBytes(UTF_8));

    expect.that(staged).isFalse();
    expect
        .that(auditMessages(CrumblesLogStaging.AUDIT_EVENT_STAGING_FULL))
        .containsExactly(
            "Staged log batches use 12582912 of 12582912 permitted bytes; a batch of 94 bytes was"
                + " refused. Network batches leave the last 4194304 bytes to security batches.");
  }

  private void stageAll(String... batches) throws Exception {
    for (String batch : batches) {
      assertThat(staging.stage(false, batch.getBytes(UTF_8))).isTrue();
    }
  }

  /** Stages {@code logs} as the first batch and returns the size of its file. */
  private long stageAndMeasure(String logs) throws Exception {
    stageAll(logs);
    return new File(directory, FIRST_BATCH).length();
  }

  /** Adds a staged batch of {@code bytes} bytes, ahead of the others, without writing them. */
  private void fillStaging(long bytes) throws IOException {
    File filler = new File(directory, "0000000000000000000-S.sealed");
    try (RandomAccessFile file = new RandomAccessFile(filler, "rw")) {
      file.setLength(bytes);
    }
  }

  private List<String> drainAll() {
    List<String> written = new ArrayList<>();
    int stored =
        staging.drain(
            (isNetwork, logs) -> {
              written.add(new String(logs, UTF_8));
              return CrumblesLogStaging.WriteResult.STORED;
            });
    expect.that(stored).isEqualTo(written.size());
    return written;
  }

  private List<String> auditMessages(String eventType) {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .filter(event -> event.getEventType().equals(eventType))
        .map(CrumblesAuditEvent::getMessage)
        .toList();
  }
}
