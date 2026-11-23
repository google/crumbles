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

package com.android.securelogging.audit;

import static com.android.securelogging.audit.CrumblesAppAuditLogger.CHAIN_KEY_ALIAS;
import static com.android.securelogging.audit.CrumblesAppAuditLogger.MAX_RECORDS_PER_EVENT_TYPE;
import static com.android.securelogging.audit.CrumblesAppAuditLogger.RECORDS_DROPPED_EVENT_TYPE;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesConstants;
import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesAuditExcerpt;
import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesChainVerification;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.ProviderException;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

/** Unit tests for the {@link CrumblesAppAuditLogger} class. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesAppAuditLoggerTest {

  private static final String MALFORMED_LINE = "{\"timestamp\": not-json";
  private static final int OVERSIZED_LOG_FILE_BYTES =
      Math.toIntExact(CrumblesConstants.MAX_LOG_FILE_SIZE_BYTES + 1);
  private static final Instant RATE_LIMIT_WINDOW_START = Instant.parse("2026-10-17T10:00:00Z");

  @Rule public final Expect expect = Expect.create();

  private Context appContext;
  private CrumblesAppAuditLogger auditLogger;
  private File currentLogFile;
  private File oldLogFile;
  private File dataKeyFile;
  private File reserveFile;
  private File dropMarkerFile;

  @Before
  public void setUp() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = true;
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = false;
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = false;
    appContext = ApplicationProvider.getApplicationContext();
    File logDir = appContext.getNoBackupFilesDir();
    currentLogFile = new File(logDir, CrumblesConstants.CURRENT_LOG_FILE_NAME);
    oldLogFile = new File(logDir, CrumblesConstants.OLD_LOG_FILE_NAME);
    dataKeyFile = new File(logDir, CrumblesConstants.AUDIT_LOG_KEY_FILE_NAME);
    reserveFile = new File(logDir, CrumblesAppAuditLogger.RESERVE_FILE_NAME);
    dropMarkerFile = new File(logDir, CrumblesAppAuditLogger.DROP_MARKER_FILE_NAME);

    // Reset the singleton instance before each test.
    CrumblesAppAuditLogger.setInstanceForTest(null);

    // Manually delete files to ensure the directory is clean.
    if (currentLogFile.exists()) {
      currentLogFile.delete();
    }
    if (oldLogFile.exists()) {
      oldLogFile.delete();
    }
    if (dataKeyFile.exists()) {
      dataKeyFile.delete();
    }
    reserveFile.delete();
    dropMarkerFile.delete();

    // Get a fresh logger instance for the test.
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
  }

  @After
  public void tearDown() {
    // Clean up logs and reset the singleton for the next test class.
    if (auditLogger != null) {
      auditLogger.clearAllLogs();
    }
    CrumblesAppAuditLogger.setInstanceForTest(null);
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  private long countLinesInFile(File file) throws IOException {
    if (!file.exists()) {
      return 0;
    }
    long lines = 0;
    try (BufferedReader reader = Files.newBufferedReader(file.toPath(), UTF_8)) {
      while (reader.readLine() != null) {
        lines++;
      }
    }
    return lines;
  }

  @Test
  public void verifyChain_whenTwoRotationsAfterLegacyPrefix_reportsIntactChain() throws Exception {
    String legacyLine1 =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_EVENT", "First legacy record", "tag1")
            .toJsonString();
    String legacyLine2 =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_EVENT", "Second legacy record", "tag2")
            .toJsonString();
    if (!currentLogFile.exists()) {
      currentLogFile.createNewFile();
    }
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(legacyLine1, legacyLine2),
        UTF_8,
        StandardOpenOption.APPEND);

    // Reload lastTag from disk so rotation chains onto the legacy prefix properly.
    Method loadLastTagMethod = CrumblesAppAuditLogger.class.getDeclaredMethod("loadLastTag");
    loadLastTagMethod.setAccessible(true);
    Field lastTagField = CrumblesAppAuditLogger.class.getDeclaredField("lastTag");
    lastTagField.setAccessible(true);
    lastTagField.set(auditLogger, loadLastTagMethod.invoke(auditLogger));

    Method rotateMethod =
        CrumblesAppAuditLogger.class.getDeclaredMethod("rotateLogFiles", Instant.class);
    rotateMethod.setAccessible(true);

    rotateMethod.invoke(auditLogger, Instant.now());
    auditLogger.logEvent("EVENT_1", "First numbered event");
    rotateMethod.invoke(auditLogger, Instant.now());
    auditLogger.logEvent("EVENT_2", "Second numbered event");

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    // 2 legacy + 1 tombstone + 1 numbered + 1 tombstone + 1 numbered = 6
    expect.that(verification.getTotalRecords()).isEqualTo(4);
  }

  @Test
  public void logEvent_whenEventLogged_thenAppendedToFileAndAddedToMemoryCache()
      throws IOException {
    String eventType = "TEST_LOG_EVENT";
    String message = "Test log message 1.";

    auditLogger.logEvent(eventType, message);

    List<CrumblesAuditEvent> cachedEvents = auditLogger.getMemoryCachedEvents();
    assertThat(cachedEvents).isNotEmpty();
    assertThat(cachedEvents.get(0).getEventType()).isEqualTo(eventType);

    assertThat(currentLogFile.exists()).isTrue();
    assertThat(countLinesInFile(currentLogFile)).isEqualTo(1);
    try (BufferedReader reader = Files.newBufferedReader(currentLogFile.toPath(), UTF_8)) {
      String line = reader.readLine();
      assertThat(line).isNotNull();
      assertThat(line).doesNotContain(message);
    }
  }

  @Test
  public void logEvent_whenMemoryCacheExceedsMax_thenOldestIsRemovedFromCache() {
    // Given: MAX_MEMORY_EVENTS are logged. This is the loop you likely deleted.
    for (int i = 0; i < CrumblesConstants.MAX_MEMORY_EVENTS; i++) {
      auditLogger.logEvent("CACHE_FILL_EVENT_" + i, "Event " + i);
    }

    // And: One more event is prepared.
    String newestEventType = "NEWEST_EVENT";
    String newestMessage = "This is the newest event.";

    // When: The final event that exceeds the max is logged.
    auditLogger.logEvent(newestEventType, newestMessage);

    // Then: The memory cache size should still be MAX_MEMORY_EVENTS.
    List<CrumblesAuditEvent> cachedEvents = auditLogger.getMemoryCachedEvents();
    assertThat(cachedEvents).hasSize(CrumblesConstants.MAX_MEMORY_EVENTS);

    // And: The newest event should be at the start of the cache.
    assertThat(cachedEvents.get(0).getEventType()).isEqualTo(newestEventType);

    // And: The original, oldest event should now be gone.
    boolean eventZeroPresent =
        cachedEvents.stream().anyMatch(event -> event.getMessage().equals("Event 0"));
    assertThat(eventZeroPresent).isFalse();
  }

  @Test
  public void logEvent_whenCurrentLogFileExceedsMaxSize_thenRotatesLogs() throws Exception {
    // Given: The old log file does not exist.
    assertThat(oldLogFile.exists()).isFalse();

    // When: We write events in a loop until the current log file's size exceeds the maximum. Each
    // event has its own type, so that the rate limit records them all.
    for (int i = 0; currentLogFile.length() <= CrumblesConstants.MAX_LOG_FILE_SIZE_BYTES; i++) {
      auditLogger.logEvent("FILLER_" + i, "Adding data to exceed max size.");
    }

    // This next log event MUST trigger the rotation logic.
    auditLogger.logEvent("POST_ROTATION_EVENT", "This event triggers rotation.");

    // Then: The old log file should now exist.
    assertThat(oldLogFile.exists()).isTrue();

    // And: The new current log file should start with the rotation tombstone, followed by the
    // event logged after rotation, and the chain should run through both files.
    ImmutableList<CrumblesAuditEvent> records = readRecords(currentLogFile);
    assertThat(records.stream().map(CrumblesAuditEvent::getEventType))
        .containsExactly("AUDIT_LOG_ROTATED", "POST_ROTATION_EVENT")
        .inOrder();
    assertThat(records.get(0).getMessage()).isEqualTo("Audit log rotated; no records discarded.");
    CrumblesChainVerification verification = auditLogger.verifyChain();
    assertThat(verification.isIntact()).isTrue();
    assertThat(verification.getVerifiedRecords()).isEqualTo(verification.getTotalRecords());
  }

  @Test
  public void logEvent_whenRotationDiscardsOldLogFile_tombstoneGivesItsRecordCountAndDigest()
      throws Exception {
    synchronized (auditLogger.fileLock) {
      Files.write(oldLogFile.toPath(), "first record\n\nsecond record\n".getBytes(UTF_8));
      Files.write(currentLogFile.toPath(), new byte[OVERSIZED_LOG_FILE_BYTES]);
    }

    auditLogger.logEvent("POST_ROTATION_EVENT", "This event triggers rotation.");

    assertThat(readRecords(currentLogFile).get(0).getMessage())
        .isEqualTo(
            "Audit log rotated; 2 records discarded, SHA-256 of the discarded file:"
                + " fb045d8b3c2d5588fa7c58b94f7de72fb3279b0d84d6fa6bdede66465eaa5b58, first tag:"
                + " none, last tag: none.");
  }

  @Test
  public void logEvent_whenOldLogFileUnreadable_tombstoneStatesDigestFailed() throws Exception {
    // The old log path is an empty directory, which rotation can delete but not read.
    synchronized (auditLogger.fileLock) {
      assertThat(oldLogFile.mkdir()).isTrue();
      Files.write(currentLogFile.toPath(), new byte[OVERSIZED_LOG_FILE_BYTES]);
    }

    auditLogger.logEvent("POST_ROTATION_EVENT", "This event triggers rotation.");

    assertThat(readRecords(currentLogFile).get(0).getMessage())
        .isEqualTo("Audit log rotated; failed to digest the discarded records.");
  }

  @Test
  public void logEvent_whenTombstoneCannotBeSealed_keepsTheOldLogFile() throws Exception {
    synchronized (auditLogger.fileLock) {
      Files.write(oldLogFile.toPath(), "kept record\n".getBytes(UTF_8));
      Files.write(currentLogFile.toPath(), new byte[OVERSIZED_LOG_FILE_BYTES]);
    }
    restartLoggerWithUnusableDataKey();

    auditLogger.logEvent("EVENT_1", "Cannot be sealed either.");

    expect
        .that(new String(Files.readAllBytes(oldLogFile.toPath()), UTF_8))
        .isEqualTo("kept record\n");
    expect.that(currentLogFile.length()).isGreaterThan(CrumblesConstants.MAX_LOG_FILE_SIZE_BYTES);
    expect.that(auditLogger.getWriteFailureCount()).isEqualTo(2);
  }

  @Test
  public void logEvent_numbersRecordsAcrossRestartsAndClearing() throws Exception {
    if (!currentLogFile.exists()) {
      currentLogFile.createNewFile();
    }
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(
            new CrumblesAuditEvent(Instant.now(), "LEGACY", "Written before numbering.")
                .toJsonString()),
        UTF_8);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_1", "First numbered message.");
    auditLogger.logEvent("EVENT_2", "Second numbered message.");
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_3", "Logged after a restart.");
    ImmutableList<CrumblesAuditEvent> recordsBeforeClearing = readRecords(currentLogFile);

    auditLogger.clearAllLogs();
    auditLogger.logEvent("EVENT_5", "Logged after clearing.");

    expect
        .that(recordsBeforeClearing.stream().map(CrumblesAuditEvent::getSequenceNumber))
        .containsExactly(
            OptionalLong.empty(), OptionalLong.of(1), OptionalLong.of(2), OptionalLong.of(3))
        .inOrder();
    expect
        .that(readRecords(currentLogFile).stream().map(CrumblesAuditEvent::getSequenceNumber))
        .containsExactly(OptionalLong.of(4), OptionalLong.of(5))
        .inOrder();
  }

  @Test
  public void verifyChain_whenSequenceNumberAltered_reportsBreakAtThatRecord() throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    auditLogger.logEvent("EVENT_3", "Third message.");
    List<String> lines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    CrumblesAuditRecordSealer sealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(dataKeyFile));
    lines.set(
        1,
        sealer.seal(
            sealer.unseal(lines.get(1)).replace("\"sequenceNumber\":2", "\"sequenceNumber\":7")));
    Files.write(currentLogFile.toPath(), lines, UTF_8);

    assertThat(auditLogger.verifyChain().getFirstBrokenIndex()).isEqualTo(1);
  }

  @Test
  public void logEvent_whenEventTypeExceedsRateLimit_recordsTheLimitThenSaysSo() throws Exception {
    restartLoggerWithClock(() -> RATE_LIMIT_WINDOW_START);

    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 3; i++) {
      auditLogger.logEvent("REPEATED", "Repeated event.");
    }
    auditLogger.logEvent("OTHER", "Another event type is still recorded.");

    ImmutableList<CrumblesAuditEvent> records = readRecords(currentLogFile);
    expect
        .that(records.stream().map(CrumblesAuditEvent::getEventType))
        .containsExactlyElementsIn(
            ImmutableList.<String>builder()
                .addAll(Collections.nCopies(MAX_RECORDS_PER_EVENT_TYPE, "REPEATED"))
                .add("AUDIT_EVENTS_RATE_LIMITED", "OTHER")
                .build())
        .inOrder();
    expect
        .that(records.get(MAX_RECORDS_PER_EVENT_TYPE).getMessage())
        .isEqualTo(
            "More than 60 REPEATED events in 60 minutes; further ones until 2026-10-17T11:00:00Z"
                + " are counted but not recorded.");
  }

  @Test
  public void logEvent_afterRateLimitWindowEnds_recordsHowManyEventsWereNotRecorded()
      throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(RATE_LIMIT_WINDOW_START);
    restartLoggerWithClock(now::get);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 3; i++) {
      auditLogger.logEvent("REPEATED", "Repeated event.");
    }
    auditLogger.logEvent("OTHER", "Within its rate limit.");
    int recordsInFirstWindow = readRecords(currentLogFile).size();
    now.set(RATE_LIMIT_WINDOW_START.plus(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW));
    SystemClock.sleep(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW.toMillis());

    auditLogger.logEvent("REPEATED", "Recorded again in a new window.");

    ImmutableList<CrumblesAuditEvent> records = readRecords(currentLogFile);
    ImmutableList<CrumblesAuditEvent> laterRecords =
        records.subList(recordsInFirstWindow, records.size());
    expect
        .that(laterRecords.stream().map(CrumblesAuditEvent::getMessage))
        .containsExactly(
            "3 REPEATED events from 2026-10-17T10:00:00Z to 2026-10-17T11:00:00Z were counted but"
                + " not recorded.",
            "Recorded again in a new window.")
        .inOrder();
  }

  @Test
  public void getInstance_whenRateLimitWindowActiveAcrossRestart_preservesCountsAndNoticeState()
      throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(RATE_LIMIT_WINDOW_START);
    restartLoggerWithClock(now::get);
    for (int i = 0; i < 40; i++) {
      auditLogger.logEvent("PARTIAL", "Partial window event.");
    }
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 1; i++) {
      auditLogger.logEvent("SATURATED", "Saturated window event.");
    }
    List<String> lines = Files.readAllLines(currentLogFile.toPath(), UTF_8);
    // Keep the 40 PARTIAL events and only the AUDIT_EVENTS_RATE_LIMITED start notice for SATURATED.
    List<String> retainedLines = new ArrayList<>(lines.subList(0, 40));
    retainedLines.add(lines.get(lines.size() - 1));
    Files.write(currentLogFile.toPath(), retainedLines, UTF_8);

    restartLoggerWithClock(now::get);
    int beforeCount = readRecords(currentLogFile).size();
    for (int i = 0; i < 25; i++) {
      auditLogger.logEvent("PARTIAL", "After restart.");
    }
    auditLogger.logEvent("SATURATED", "Still dropped without duplicate notice.");

    ImmutableList<CrumblesAuditEvent> newRecords =
        readRecords(currentLogFile).subList(beforeCount, readRecords(currentLogFile).size());
    expect
        .that(newRecords.stream().map(CrumblesAuditEvent::getEventType))
        .containsExactlyElementsIn(
            ImmutableList.<String>builder()
                .addAll(Collections.nCopies(20, "PARTIAL"))
                .add("AUDIT_EVENTS_RATE_LIMITED")
                .build())
        .inOrder();
    expect
        .that(newRecords.get(20).getMessage())
        .isEqualTo(
            "More than 60 PARTIAL events in 60 minutes; further ones until 2026-10-17T11:00:00Z"
                + " are counted but not recorded.");
  }

  @Test
  public void getInstance_whenWindowStartedOverHourAgoWithRecentEvents_doesNotExtendExpiredWindow()
      throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(RATE_LIMIT_WINDOW_START);
    restartLoggerWithClock(now::get);
    auditLogger.logEvent("EXPIRED_TYPE", "Starts window at 10:00.");
    for (int i = 0; i < 10; i++) {
      auditLogger.logEvent("RENEWED_TYPE", "First window at 10:00.");
    }

    Duration halfWindow = Duration.ofMinutes(30);
    now.set(RATE_LIMIT_WINDOW_START.plus(halfWindow));
    SystemClock.sleep(halfWindow.toMillis());
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE; i++) {
      auditLogger.logEvent("EXPIRED_TYPE", "Logged 30m into first window, with rate-limit notice.");
    }

    Instant secondHour = RATE_LIMIT_WINDOW_START.plus(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW);
    now.set(secondHour);
    SystemClock.sleep(halfWindow.toMillis());
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE; i++) {
      auditLogger.logEvent("RENEWED_TYPE", "Fills second window starting at 11:00.");
    }

    // Restart at 11:00: EXPIRED_TYPE's 10:00 window has ended despite 10:30 events & notice, while
    // RENEWED_TYPE's 11:00 window (after its expired 10:00 window) is active and full.
    restartLoggerWithClock(now::get);
    int recordsAtRestart = readRecords(currentLogFile).size();
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE; i++) {
      auditLogger.logEvent("EXPIRED_TYPE", "Allowed in fresh window after restart.");
    }
    auditLogger.logEvent("RENEWED_TYPE", "Dropped because 11:00 window is full.");

    ImmutableList<CrumblesAuditEvent> postRestartRecords =
        readRecords(currentLogFile).subList(recordsAtRestart, readRecords(currentLogFile).size());
    expect
        .that(postRestartRecords.stream().map(CrumblesAuditEvent::getEventType))
        .containsExactlyElementsIn(
            ImmutableList.<String>builder()
                .addAll(Collections.nCopies(MAX_RECORDS_PER_EVENT_TYPE, "EXPIRED_TYPE"))
                .add("AUDIT_EVENTS_RATE_LIMITED")
                .build())
        .inOrder();
    expect
        .that(postRestartRecords.get(MAX_RECORDS_PER_EVENT_TYPE).getMessage())
        .contains("More than 60 RENEWED_TYPE events");
  }

  @Test
  public void getInstance_whenFutureTimestampOrEndedNoticeOnDisk_ignoresFutureAndClearsEndedWindow()
      throws Exception {
    AtomicReference<Instant> now =
        new AtomicReference<>(RATE_LIMIT_WINDOW_START.plus(Duration.ofHours(2)));
    restartLoggerWithClock(now::get);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE; i++) {
      auditLogger.logEvent("FUTURE_TYPE", "Logged while wall clock was ahead.");
    }

    now.set(RATE_LIMIT_WINDOW_START);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 1; i++) {
      auditLogger.logEvent("ENDED_TYPE", "Logged before monotonic window ends.");
    }
    // Monotonic clock advances 60m while wall clock only advances 10m, writing the end notice.
    now.set(RATE_LIMIT_WINDOW_START.plus(Duration.ofMinutes(10)));
    SystemClock.sleep(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW.toMillis());
    auditLogger.logEvent("TRIGGER_FLUSH", "Flushes ENDED_TYPE end notice.");

    restartLoggerWithClock(now::get);
    int beforeCount = readRecords(currentLogFile).size();
    auditLogger.logEvent("FUTURE_TYPE", "Recorded despite future-dated records.");
    auditLogger.logEvent("ENDED_TYPE", "Recorded because end notice closed the window.");

    ImmutableList<CrumblesAuditEvent> added =
        readRecords(currentLogFile).subList(beforeCount, readRecords(currentLogFile).size());
    expect
        .that(added.stream().map(CrumblesAuditEvent::getEventType))
        .containsExactly("FUTURE_TYPE", "ENDED_TYPE")
        .inOrder();
  }

  @Test
  public void getAllPersistedEventsForDisplay_afterRateLimitWindowEnds_flushesEndedWindowNotice()
      throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(RATE_LIMIT_WINDOW_START);
    restartLoggerWithClock(now::get);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 2; i++) {
      auditLogger.logEvent("REPEATED", "Repeated event.");
    }
    now.set(RATE_LIMIT_WINDOW_START.plus(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW));
    SystemClock.sleep(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW.toMillis());

    List<CrumblesAuditEvent> displayEvents = auditLogger.getAllPersistedEventsForDisplay();

    expect.that(displayEvents.get(0).getEventType()).isEqualTo("AUDIT_EVENTS_RATE_LIMITED");
    expect
        .that(displayEvents.get(0).getMessage())
        .isEqualTo(
            "2 REPEATED events from 2026-10-17T10:00:00Z to 2026-10-17T11:00:00Z were counted but"
                + " not recorded.");

    // If the data key is replaced during display unsealing, logDataKeyReplacement() logs it.
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    restartLoggerWithClock(now::get);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    var unused = auditLogger.getAllPersistedEventsForDisplay();
    expect
        .that(auditLogger.getMemoryCachedEvents().get(0).getEventType())
        .isEqualTo("AUDIT_LOG_KEY_REPLACED");
  }

  @Test
  public void getUnshippedExcerpt_afterRateLimitWindowEnds_includesEndedWindowNotice()
      throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(RATE_LIMIT_WINDOW_START);
    restartLoggerWithClock(now::get);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 2; i++) {
      auditLogger.logEvent("REPEATED", "Repeated event.");
    }
    int countBeforeExcerpt = readRecords(currentLogFile).size();
    now.set(RATE_LIMIT_WINDOW_START.plus(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW));
    SystemClock.sleep(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW.toMillis());

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    ImmutableList<CrumblesAuditEvent> records = readRecords(currentLogFile);
    expect.that(records).hasSize(countBeforeExcerpt + 1);
    expect
        .that(records.get(countBeforeExcerpt).getMessage())
        .isEqualTo(
            "2 REPEATED events from 2026-10-17T10:00:00Z to 2026-10-17T11:00:00Z were counted but"
                + " not recorded.");
    List<String> unsealedLines = readUnsealedRecords();
    expect
        .that(new String(excerpt.toBytes(), UTF_8))
        .contains(unsealedLines.get(unsealedLines.size() - 1));

    // If flushing an ended window during getUnshippedExcerpt replaces a corrupted data key,
    // logDataKeyReplacement() logs AUDIT_LOG_KEY_REPLACED outside fileLock.
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    restartLoggerWithClock(now::get);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 1; i++) {
      // First logEvent already triggers key replacement; reset again after filling window so the
      // flush inside getUnshippedExcerpt triggers replacement.
      auditLogger.logEvent("FLUSH_KEY", "Fills window.");
    }
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    restartLoggerWithClock(now::get);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 1; i++) {
      auditLogger.logEvent("FLUSH_KEY_2", "In-memory rate limit window while sealing fails.");
    }
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    now.set(now.get().plus(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW));
    SystemClock.sleep(CrumblesAppAuditLogger.RATE_LIMIT_WINDOW.toMillis());
    var unusedExcerpt = auditLogger.getUnshippedExcerpt();
    expect
        .that(auditLogger.getMemoryCachedEvents().get(0).getEventType())
        .isEqualTo("AUDIT_LOG_KEY_REPLACED");
  }

  @Test
  public void clearAllLogs_whenRateLimited_clearsRateLimitsAndAlwaysPersistsTombstone()
      throws Exception {
    restartLoggerWithClock(() -> RATE_LIMIT_WINDOW_START);
    for (int i = 0; i < MAX_RECORDS_PER_EVENT_TYPE + 2; i++) {
      auditLogger.logEvent("REPEATED", "Dropped after 60.");
      auditLogger.logEvent("AUDIT_LOG_CLEARED", "Flooding cleared type.");
    }
    expect
        .that(
            auditLogger.getMemoryCachedEvents().stream()
                .filter(e -> e.getEventType().equals("REPEATED"))
                .count())
        .isLessThan((long) MAX_RECORDS_PER_EVENT_TYPE);

    auditLogger.clearAllLogs();
    auditLogger.logEvent("REPEATED", "Recorded again after clearAllLogs.");

    expect
        .that(readRecords(currentLogFile).stream().map(CrumblesAuditEvent::getEventType))
        .containsExactly("AUDIT_LOG_CLEARED", "REPEATED")
        .inOrder();
  }

  @Test
  public void getMemoryCachedEvents_whenEventsLogged_returnsRecentEventsNewestFirst() {
    auditLogger.logEvent("EVENT_1", "Message 1.");
    auditLogger.logEvent("EVENT_2", "Message 2.");
    auditLogger.logEvent("EVENT_3", "Message 3.");

    List<CrumblesAuditEvent> cachedEvents = auditLogger.getMemoryCachedEvents();
    assertThat(cachedEvents).hasSize(3);
    assertThat(cachedEvents.get(0).getEventType()).isEqualTo("EVENT_3");
    assertThat(cachedEvents.get(1).getEventType()).isEqualTo("EVENT_2");
    assertThat(cachedEvents.get(2).getEventType()).isEqualTo("EVENT_1");
  }

  @Test
  public void loadInitialCacheFromFiles_whenOldFileHasLaterTimestamps_loadsInAppendOrder()
      throws IOException {
    // Given: Log files whose timestamps go back in time, as after the clock was set back.
    Instant t1 = Instant.now().minusMillis(3000);
    Instant t2 = Instant.now().minusMillis(2000);
    Instant t3 = Instant.now().minusMillis(1000);
    Instant t4 = InstantSource.system().instant();

    // Acquire the file lock before writing to files
    synchronized (auditLogger.fileLock) {
      try (Writer fw = Files.newBufferedWriter(oldLogFile.toPath(), UTF_8)) {
        fw.write(new CrumblesAuditEvent(t1, "OLD_EVENT_1", "Old msg 1").toJsonString() + "\n");
        fw.write(new CrumblesAuditEvent(t3, "OLD_EVENT_2", "Old msg 2").toJsonString() + "\n");
      }

      try (Writer fw = Files.newBufferedWriter(currentLogFile.toPath(), UTF_8)) {
        fw.write(
            new CrumblesAuditEvent(t2, "CURRENT_EVENT_1", "Current msg 1").toJsonString() + "\n");
        fw.write(
            new CrumblesAuditEvent(t4, "CURRENT_EVENT_2", "Current msg 2").toJsonString() + "\n");
      }
    }

    // When: A new logger instance is created by resetting the singleton.
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesAppAuditLogger newLogger = CrumblesAppAuditLogger.getInstance(appContext);

    // Then: The cache holds the events of both files, last appended first, whatever their time.
    assertThat(newLogger.getMemoryCachedEvents().stream().map(CrumblesAuditEvent::getEventType))
        .containsExactly("CURRENT_EVENT_2", "CURRENT_EVENT_1", "OLD_EVENT_2", "OLD_EVENT_1")
        .inOrder();
  }

  @Test
  public void getAllPersistedEventsForDisplay_whenClockWasSetBack_listsLastAppendedFirst()
      throws IOException {
    Instant now = Instant.now();
    if (!currentLogFile.exists()) {
      currentLogFile.createNewFile();
    }
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(
            new CrumblesAuditEvent(now, "BEFORE", "Logged first.").toJsonString(),
            new CrumblesAuditEvent(now.minus(Duration.ofDays(365)), "AFTER", "Logged next.")
                .toJsonString()),
        UTF_8);

    List<CrumblesAuditEvent> displayEvents = auditLogger.getAllPersistedEventsForDisplay();

    assertThat(displayEvents.stream().map(CrumblesAuditEvent::getEventType))
        .containsExactly("AFTER", "BEFORE")
        .inOrder();
  }

  @Test
  public void getAllPersistedEventsForDisplay_whenFilesHaveContent_returnsCombinedSortedEvents()
      throws IOException {
    Instant t1 = Instant.now().minusMillis(30000);
    Instant t2 = Instant.now().minusMillis(20000);
    Instant t3 = Instant.now().minusMillis(10000);

    // Acquire the file lock before writing to files
    synchronized (auditLogger.fileLock) {
      try (Writer fw = Files.newBufferedWriter(oldLogFile.toPath(), UTF_8)) {
        fw.write(new CrumblesAuditEvent(t1, "E_OLD", "Event from old file").toJsonString() + "\n");
      }
      try (Writer fw = Files.newBufferedWriter(currentLogFile.toPath(), UTF_8)) {
        fw.write(
            new CrumblesAuditEvent(t2, "E_CURR1", "Event 1 from current file").toJsonString()
                + "\n");
        fw.write(new CrumblesAuditEvent(t3, "E_CURR2", "Newest event").toJsonString() + "\n");
      }
    }

    List<CrumblesAuditEvent> displayEvents = auditLogger.getAllPersistedEventsForDisplay();

    assertThat(displayEvents).hasSize(3);
    // The events are listed newest first, last appended first.
    assertThat(displayEvents.get(0).getTimestamp()).isEqualTo(t3);
    assertThat(displayEvents.get(1).getTimestamp()).isEqualTo(t2);
    assertThat(displayEvents.get(2).getTimestamp()).isEqualTo(t1);
  }

  @Test
  public void getUnshippedExcerpt_sealedRecord_shipsAsPlaintextJson() throws Exception {
    auditLogger.logEvent("EVENT_1", "Test message.");
    List<String> rawRecords = Files.readAllLines(currentLogFile.toPath(), UTF_8);
    String sealedRecord = rawRecords.get(0);
    assertThat(sealedRecord).contains("\"sealed\"");

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();
    String shippedText = new String(excerpt.toBytes(), UTF_8);

    assertThat(shippedText).doesNotContain("\"sealed\"");
    assertThat(shippedText).contains("Test message.");
  }

  @Test
  public void getUnshippedExcerpt_unsealableRecord_staysSealed() throws Exception {
    auditLogger.logEvent("EVENT_1", "Test message.");

    // Corrupt the data key so unseal throws GeneralSecurityException.
    byte[] key = Files.readAllBytes(dataKeyFile.toPath());
    key[key.length - 1] = (byte) ~key[key.length - 1];
    Files.write(dataKeyFile.toPath(), key);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();
    String shippedText = new String(excerpt.toBytes(), UTF_8);

    assertThat(shippedText).contains("\"sealed\"");
    assertThat(shippedText).doesNotContain("Test message.");
  }

  @Test
  public void getUnshippedExcerpt_whenAllRecordsAlreadyShipped_doesNotUnsealThem()
      throws Exception {
    auditLogger.logEvent("SHIPPED_EVENT", "Sealed into an earlier batch.");
    auditLogger.markShipped(auditLogger.getUnshippedExcerpt());
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    expect.that(new String(excerpt.toBytes(), UTF_8)).doesNotContain("SHIPPED_EVENT");
    expect
        .that(
            auditLogger.getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .doesNotContain("AUDIT_LOG_KEY_REPLACED");
  }

  @Test
  public void getUnshippedExcerpt_whenDataKeyReplacedAfterStartup_logsKeyReplacedEvent()
      throws Exception {
    auditLogger.logEvent("SHIPPED_EVENT", "Sealed into an earlier batch.");
    auditLogger.markShipped(auditLogger.getUnshippedExcerpt());
    auditLogger.logEvent("UNSHIPPED_EVENT", "Sealed under the lost key.");
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    String shippedText = new String(excerpt.toBytes(), UTF_8);
    expect.that(shippedText).contains("\"sealed\"");
    expect.that(shippedText).doesNotContain("UNSHIPPED_EVENT");
    List<CrumblesAuditEvent> events = auditLogger.getMemoryCachedEvents();
    expect.that(events.get(0).getEventType()).isEqualTo("AUDIT_LOG_KEY_REPLACED");
    expect
        .that(events.get(0).getMessage())
        .endsWith("Earlier records that can no longer be read: 2.");
  }

  @Test
  public void getUnshippedExcerpt_whenNothingShipped_holdsEveryRecordAndTheChainHead()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    List<String> records = readUnsealedRecords();
    String headTag = CrumblesAuditEvent.fromJsonString(records.get(1)).getTag();

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    assertThat(excerpt.getHeadTag()).hasValue(headTag);
    assertThat(new String(excerpt.toBytes(), UTF_8))
        .isEqualTo(
            "\n--- Crumbles activity log since record none ---\n"
                + String.join("\n", records)
                + "\n--- Crumbles activity log chain head: "
                + headTag
                + " ---\n");
  }

  @Test
  public void getUnshippedExcerpt_afterMarkShipped_holdsLaterRecordsSinceThePreviousHead()
      throws Exception {
    auditLogger.logEvent("SHIPPED_EVENT", "Sealed into an earlier batch.");
    CrumblesAuditExcerpt shipped = auditLogger.getUnshippedExcerpt();
    auditLogger.markShipped(shipped);
    auditLogger.logEvent("NEW_EVENT", "Logged after the earlier batch.");
    String newRecord = readUnsealedRecords().get(1);

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    assertThat(new String(excerpt.toBytes(), UTF_8))
        .isEqualTo(
            "\n--- Crumbles activity log since record "
                + shipped.getHeadTag().orElseThrow()
                + " ---\n"
                + newRecord
                + "\n--- Crumbles activity log chain head: "
                + CrumblesAuditEvent.fromJsonString(newRecord).getTag()
                + " ---\n");
  }

  @Test
  public void getUnshippedExcerpt_whenLastShippedRecordIsGone_marksTheGap() throws Exception {
    auditLogger.logEvent("SHIPPED_EVENT", "Sealed into an earlier batch.");
    CrumblesAuditExcerpt shipped = auditLogger.getUnshippedExcerpt();
    auditLogger.markShipped(shipped);
    auditLogger.clearAllLogs();
    auditLogger.logEvent("NEW_EVENT", "Logged after the log was cleared.");
    List<String> records = readUnsealedRecords();

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    assertThat(new String(excerpt.toBytes(), UTF_8))
        .isEqualTo(
            "\n--- Crumbles activity log since record "
                + shipped.getHeadTag().orElseThrow()
                + " ---\n"
                + "--- The previous batch's last activity record is no longer on this device ---\n"
                + String.join("\n", records)
                + "\n--- Crumbles activity log chain head: "
                + CrumblesAuditEvent.fromJsonString(records.get(records.size() - 1)).getTag()
                + " ---\n");
  }

  @Test
  public void getUnshippedExcerpt_whenLogEmpty_reportsNoChainHead() {
    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    assertThat(excerpt.getHeadTag()).isEmpty();
    assertThat(new String(excerpt.toBytes(), UTF_8))
        .isEqualTo(
            """

            --- Crumbles activity log since record none ---
            --- Crumbles activity log chain head: none ---
            """);
  }

  @Test
  public void getUnshippedExcerpt_whenRecordCannotBeUnsealed_holdsItSealed() throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    String secondRecord = readUnsealedRecords().get(1);
    alterSealedRecord(0);
    String alteredRecord = Files.readAllLines(currentLogFile.toPath(), UTF_8).get(0);

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    assertThat(new String(excerpt.toBytes(), UTF_8))
        .isEqualTo(
            "\n--- Crumbles activity log since record none ---\n"
                + alteredRecord
                + "\n"
                + secondRecord
                + "\n--- Crumbles activity log chain head: "
                + CrumblesAuditEvent.fromJsonString(secondRecord).getTag()
                + " ---\n");
  }

  @Test
  public void getUnshippedExcerpt_whenUnsealedLineIsNotRecord_holdsItSealed() throws Exception {
    // A line that an attacker could have added to the log while earlier versions kept it in
    // cleartext, and that the logger sealed in place since.
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of("--- Crumbles activity log since record forged ---"),
        UTF_8);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    String sealedLine = Files.readAllLines(currentLogFile.toPath(), UTF_8).get(0);

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    assertThat(new String(excerpt.toBytes(), UTF_8))
        .isEqualTo(
            "\n--- Crumbles activity log since record none ---\n"
                + sealedLine
                + "\n--- Crumbles activity log chain head: none ---\n");
  }

  @Test
  public void clearAllLogs_whenCalled_thenOnlyTombstoneRemains() throws IOException {
    auditLogger.logEvent("CLEAR_TEST_EVENT_1", "Message to be cleared 1.");

    auditLogger.clearAllLogs();

    List<CrumblesAuditEvent> cachedEvents = auditLogger.getMemoryCachedEvents();
    assertThat(cachedEvents).hasSize(1);
    assertThat(cachedEvents.get(0).getEventType()).isEqualTo("AUDIT_LOG_CLEARED");
    assertThat(cachedEvents.get(0).getMessage()).isEqualTo("Audit log cleared; 1 records removed.");
    assertThat(countLinesInFile(currentLogFile)).isEqualTo(1);
    assertThat(oldLogFile.exists()).isFalse();
  }

  @Test
  public void clearAllLogs_whenRecordsInBothFiles_writesTombstoneWithRemovedCount()
      throws IOException {
    synchronized (auditLogger.fileLock) {
      Files.write(
          oldLogFile.toPath(),
          ImmutableList.of(
              new CrumblesAuditEvent(Instant.now(), "OLD_EVENT_1", "Old msg 1").toJsonString(),
              new CrumblesAuditEvent(Instant.now(), "OLD_EVENT_2", "Old msg 2").toJsonString()),
          UTF_8);
    }
    auditLogger.logEvent("CURRENT_EVENT", "Current message.");

    auditLogger.clearAllLogs();

    List<CrumblesAuditEvent> events = auditLogger.getAllPersistedEventsForDisplay();
    assertThat(events).hasSize(1);
    assertThat(events.get(0).getEventType()).isEqualTo("AUDIT_LOG_CLEARED");
    assertThat(events.get(0).getMessage()).isEqualTo("Audit log cleared; 3 records removed.");
  }

  @Test
  public void clearAllLogs_whenLogFileUnreadable_writesTombstoneStatingCountFailed() {
    // The log path exists but is a directory, so reading its records fails.
    synchronized (auditLogger.fileLock) {
      assertThat(currentLogFile.mkdir()).isTrue();
    }

    auditLogger.clearAllLogs();

    List<CrumblesAuditEvent> events = auditLogger.getAllPersistedEventsForDisplay();
    assertThat(events).hasSize(1);
    assertThat(events.get(0).getMessage())
        .isEqualTo("Audit log cleared; failed to count removed records.");
  }

  @Test
  public void clearAllLogs_whenCalled_tombstoneVerifiesAsFirstRecordOfChain() {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");

    auditLogger.clearAllLogs();

    CrumblesChainVerification verification = auditLogger.verifyChain();
    assertThat(verification.isIntact()).isTrue();
    assertThat(verification.getTotalRecords()).isEqualTo(1);
    assertThat(verification.getVerifiedRecords()).isEqualTo(1);
    assertThat(verification.getUnverifiableRecords()).isEqualTo(0);
  }

  @Test
  public void clearShippedLogs_keepsTheUnshippedRecordsAfterTheTombstone() throws Exception {
    auditLogger.logEvent("SHIPPED_EVENT", "Sealed into an earlier batch.");
    auditLogger.markShipped(auditLogger.getUnshippedExcerpt());
    auditLogger.logEvent("UNSHIPPED_EVENT_1", "Logged while the earlier batch was written.");
    auditLogger.logEvent("UNSHIPPED_EVENT_2", "Logged by another thread before the clear.");
    CrumblesAuditEvent firstUnshipped =
        CrumblesAuditEvent.fromJsonString(readUnsealedRecords().get(1));

    int kept = auditLogger.clearShippedLogs();

    // Newest first.
    List<CrumblesAuditEvent> events = auditLogger.getAllPersistedEventsForDisplay();
    expect.that(kept).isEqualTo(2);
    expect
        .that(events.stream().map(CrumblesAuditEvent::getEventType).toList())
        .containsExactly("UNSHIPPED_EVENT_2", "UNSHIPPED_EVENT_1", "AUDIT_LOG_CLEARED")
        .inOrder();
    expect
        .that(events.stream().map(CrumblesAuditEvent::getSequenceNumber).toList())
        .containsExactly(OptionalLong.of(4), OptionalLong.of(3), OptionalLong.of(2))
        .inOrder();
    expect
        .that(events.get(2).getMessage())
        .isEqualTo("Audit log cleared; 3 records removed. (2 unshipped records follow)");
    expect.that(events.get(1).getMessage()).isEqualTo(firstUnshipped.getMessage());
    expect.that(events.get(1).getTimestamp()).isEqualTo(firstUnshipped.getTimestamp());
    expect.that(auditLogger.getUnshippedExcerpt().size()).isEqualTo(3);
    expect.that(auditLogger.verifyChain().isIntact()).isTrue();
  }

  @Test
  public void clearShippedLogs_whenEveryRecordIsShipped_leavesOnlyTheTombstone() {
    auditLogger.logEvent("SHIPPED_EVENT", "Sealed into an earlier batch.");
    auditLogger.markShipped(auditLogger.getUnshippedExcerpt());

    int kept = auditLogger.clearShippedLogs();

    List<CrumblesAuditEvent> events = auditLogger.getAllPersistedEventsForDisplay();
    expect.that(kept).isEqualTo(0);
    expect.that(events).hasSize(1);
    expect.that(events.get(0).getEventType()).isEqualTo("AUDIT_LOG_CLEARED");
    expect.that(events.get(0).getMessage()).isEqualTo("Audit log cleared; 1 records removed.");
  }

  @Test
  public void auditLogger_writesUnderNoBackupFilesDir() {
    auditLogger.logEvent("TEST", "x");

    File expected =
        new File(appContext.getNoBackupFilesDir(), CrumblesConstants.CURRENT_LOG_FILE_NAME);
    assertThat(expected.exists()).isTrue();
    assertThat(new File(appContext.getFilesDir(), CrumblesConstants.CURRENT_LOG_FILE_NAME).exists())
        .isFalse();
  }

  @Test
  public void verifyChain_whenLogsUntampered_reportsIntactChainAndKeystoreSpec() {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_3", "Third message after restart.");

    KeyGenParameterSpec spec = FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec();
    assertThat(spec.getPurposes())
        .isEqualTo(KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
    assertThat(spec.isUserAuthenticationRequired()).isFalse();
    assertThat(spec.isStrongBoxBacked()).isTrue();

    CrumblesChainVerification verification = auditLogger.verifyChain();
    assertThat(verification.isIntact()).isTrue();
    assertThat(verification.getTotalRecords()).isEqualTo(3);
    assertThat(verification.getVerifiedRecords()).isEqualTo(3);
    assertThat(verification.getUnverifiableRecords()).isEqualTo(0);
    assertThat(verification.getFirstBrokenIndex()).isEqualTo(-1);
  }

  @Test
  public void logEvent_whenStrongBoxUnavailable_fallsBackToTeeKey() {
    FakeAndroidKeyStoreSpi.isStrongBoxSupported = false;
    auditLogger.logEvent("EVENT_1", "Logged with TEE key.");
    assertThat(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
    assertThat(auditLogger.verifyChain().isIntact()).isTrue();
  }

  @Test
  public void logEvent_whenStrongBoxFails_fallsBackToTeeKey() {
    FakeAndroidKeyStoreSpi.isStrongBoxFailing = true;
    auditLogger.logEvent("EVENT_1", "Logged with TEE key.");
    assertThat(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
    assertThat(auditLogger.verifyChain().isIntact()).isTrue();
  }

  @Test
  public void logEvent_whenStrongBoxThrowsGeneralSecurityException_fallsBackToTeeKey() {
    FakeAndroidKeyStoreSpi.isStrongBoxThrowingGeneralSecurityException = true;
    auditLogger.logEvent("EVENT_1", "Logged with TEE key.");
    assertThat(FakeAndroidKeyStoreSpi.getLatestKeyGenParameterSpec().isStrongBoxBacked()).isFalse();
    assertThat(auditLogger.verifyChain().isIntact()).isTrue();
  }

  @Test
  public void verifyChain_whenRecordMessageEditedOrDeleted_detectsTampering() throws Exception {
    auditLogger.logEvent("EVENT_1", "Original message 1.");
    auditLogger.logEvent("EVENT_2", "Original message 2.");
    auditLogger.logEvent("EVENT_3", "Original message 3.");
    List<String> original = Files.readAllLines(currentLogFile.toPath(), UTF_8);
    List<String> edited = new ArrayList<>(original);
    CrumblesAuditRecordSealer sealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(dataKeyFile));
    edited.set(
        1,
        sealer.seal(
            sealer.unseal(edited.get(1)).replace("Original message 2.", "Tampered message 2.")));
    Files.write(currentLogFile.toPath(), edited, UTF_8);
    assertThat(auditLogger.verifyChain().getFirstBrokenIndex()).isEqualTo(1);
    Files.write(currentLogFile.toPath(), ImmutableList.of(original.get(0), original.get(2)), UTF_8);
    assertThat(auditLogger.verifyChain().getFirstBrokenIndex()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenKeyClearedOrUnavailable_countsRecordsAsUnverifiable() {
    auditLogger.logEvent("EVENT_1", "First message.");
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    assertThat(auditLogger.verifyChain().getUnverifiableRecords()).isEqualTo(1);

    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    auditLogger.logEvent("EVENT_2", "Logged without keystore.");
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    assertThat(auditLogger.verifyChain().getUnverifiableRecords()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenKeystoreFailsAfterKeyLoaded_verifiesEveryRecord() {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    Key chainKey = FakeAndroidKeyStoreSpi.keystoreEntries.get(CHAIN_KEY_ALIAS).getKey();
    // Removes the provider once the key is loaded, so later KeyStore.getInstance() calls throw.
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CHAIN_KEY_ALIAS,
        () -> {
          Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
          return chainKey;
        });

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getVerifiedRecords()).isEqualTo(2);
  }

  @Test
  public void verifyChain_whenPredecessorRotatedOut_countsFirstRecordAsUnverifiable() {
    auditLogger.logEvent("DISCARDED_EVENT", "Predecessor removed before verification.");
    assertThat(currentLogFile.delete()).isTrue();
    auditLogger.logEvent("ORPHANED_HEAD", "Chains onto discarded tag.");
    auditLogger.logEvent("FOLLOWING_EVENT", "Chains onto ORPHANED_HEAD.");

    CrumblesChainVerification verification = auditLogger.verifyChain();
    assertThat(verification.isIntact()).isFalse();
    assertThat(verification.getFirstBrokenIndex()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenEventsLoggedAfterClearAllLogs_verifiesEveryRecord() {
    auditLogger.logEvent("CLEARED_EVENT", "Removed by clearAllLogs.");
    auditLogger.clearAllLogs();
    auditLogger.logEvent("EVENT_1", "First message after clearing.");
    auditLogger.logEvent("EVENT_2", "Second message after clearing.");

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getTotalRecords()).isEqualTo(3);
    expect.that(verification.getVerifiedRecords()).isEqualTo(3);
    expect.that(verification.getUnverifiableRecords()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenUntaggedRecordFollowsVerifiedRecord_reportsBreak() throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    String untaggedLine =
        new CrumblesAuditEvent(Instant.now(), "INJECTED", "Untagged record.").toJsonString();
    if (!currentLogFile.exists()) {
      currentLogFile.createNewFile();
    }
    Files.write(
        currentLogFile.toPath(), ImmutableList.of(untaggedLine), UTF_8, StandardOpenOption.APPEND);

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isFalse();
    expect.that(verification.getFirstBrokenIndex()).isEqualTo(2);
    expect.that(verification.getVerifiedRecords()).isEqualTo(2);
    expect.that(verification.getUnverifiableRecords()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenMalformedLineFollowsVerifiedRecord_reportsBreakAtThatLine()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    auditLogger.logEvent("EVENT_3", "Third message.");
    List<String> lines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    lines.add(1, MALFORMED_LINE);
    Files.write(currentLogFile.toPath(), lines, UTF_8);

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.getFirstBrokenIndex()).isEqualTo(1);
    expect.that(verification.getTotalRecords()).isEqualTo(4);
    expect.that(verification.getVerifiedRecords()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenOldLogFileMissing_logsNoError() {
    auditLogger.logEvent("EVENT_1", "First message.");

    @SuppressWarnings("unused")
    var unusedVerification = auditLogger.verifyChain();

    assertThat(
            ShadowLog.getLogsForTag("CrumblesAppAuditLogger").stream()
                .filter(item -> item.type == Log.ERROR)
                .map(item -> item.msg))
        .isEmpty();
  }

  @Test
  public void getAllPersistedEventsForDisplay_whenLineMalformed_returnsFollowingEvents()
      throws IOException {
    Instant olderTimestamp = Instant.now().minusMillis(20000);
    Instant newerTimestamp = Instant.now().minusMillis(10000);
    if (!currentLogFile.exists()) {
      currentLogFile.createNewFile();
    }
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(
            new CrumblesAuditEvent(olderTimestamp, "BEFORE", "Before bad line.").toJsonString(),
            MALFORMED_LINE,
            new CrumblesAuditEvent(newerTimestamp, "AFTER", "After bad line.").toJsonString()),
        UTF_8);

    List<CrumblesAuditEvent> displayEvents = auditLogger.getAllPersistedEventsForDisplay();

    assertThat(displayEvents).hasSize(2);
    assertThat(displayEvents.get(0).getEventType()).isEqualTo("AFTER");
    assertThat(displayEvents.get(1).getEventType()).isEqualTo("BEFORE");
  }

  @Test
  public void getInstance_whenLineMalformed_loadsFollowingEventsIntoMemoryCache()
      throws IOException {
    if (!currentLogFile.exists()) {
      currentLogFile.createNewFile();
    }
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(
            MALFORMED_LINE,
            new CrumblesAuditEvent(Instant.now(), "AFTER", "After bad line.").toJsonString()),
        UTF_8);
    CrumblesAppAuditLogger.setInstanceForTest(null);

    CrumblesAppAuditLogger reloadedLogger = CrumblesAppAuditLogger.getInstance(appContext);

    assertThat(reloadedLogger.getMemoryCachedEvents()).hasSize(1);
    assertThat(reloadedLogger.getMemoryCachedEvents().get(0).getEventType()).isEqualTo("AFTER");
  }

  @Test
  public void logEvent_whenSigningFails_keepsEventInMemoryOnlyAndRecordsFailure()
      throws IOException {
    auditLogger.logEvent("EVENT_1", "Signed message.");
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);

    auditLogger.logEvent("UNSIGNED_EVENT", "Logged without keystore.");

    expect.that(countLinesInFile(currentLogFile)).isEqualTo(1);
    expect.that(auditLogger.getSigningFailureCount()).isEqualTo(1);
    expect
        .that(auditLogger.getMemoryCachedEvents().get(0).getEventType())
        .isEqualTo("UNSIGNED_EVENT");
  }

  @Test
  public void logEvent_whenChainKeyHmacThrowsProviderException_keepsEventInMemoryOnly()
      throws IOException {
    auditLogger.logEvent("EVENT_1", "Signed message.");
    // Like the AndroidKeyStore HMAC when its Keystore operation fails, as on a faulty StrongBox.
    SecretKey failingKey =
        new SecretKeySpec(new byte[32], "HmacSHA256") {
          @Override
          public byte[] getEncoded() {
            throw new ProviderException("Keystore operation failed");
          }
        };
    FakeAndroidKeyStoreSpi.keystoreEntries.put(CHAIN_KEY_ALIAS, () -> failingKey);

    auditLogger.logEvent("UNSIGNED_EVENT", "Logged while the Keystore fails.");

    expect.that(countLinesInFile(currentLogFile)).isEqualTo(1);
    expect.that(auditLogger.getSigningFailureCount()).isEqualTo(1);
    expect
        .that(auditLogger.getMemoryCachedEvents().get(0).getEventType())
        .isEqualTo("UNSIGNED_EVENT");
  }

  @Test
  public void getInstance_whenWrappingKeyThrowsProviderException_keepsEventsInMemoryOnly()
      throws IOException {
    FakeAndroidKeyStoreSpi.keystoreEntries.put(
        CrumblesAuditDataKey.WRAPPING_KEY_ALIAS,
        () -> {
          throw new ProviderException("Keystore operation failed");
        });
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("UNSEALED_EVENT", "Logged while the Keystore fails.");

    expect.that(countLinesInFile(currentLogFile)).isEqualTo(0);
    expect.that(auditLogger.getSealingFailureCount()).isEqualTo(1);
    expect
        .that(auditLogger.getMemoryCachedEvents().get(0).getEventType())
        .isEqualTo("UNSEALED_EVENT");
  }

  @Test
  public void clearAllLogs_afterSigningFailure_resetsSigningFailureCount() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    auditLogger.logEvent("UNSIGNED_EVENT", "Logged without keystore.");
    assertThat(auditLogger.getSigningFailureCount()).isEqualTo(1);
    Security.addProvider(new FakeAndroidKeyStoreProvider());

    auditLogger.clearAllLogs();

    assertThat(auditLogger.getSigningFailureCount()).isEqualTo(0);
  }

  @Test
  public void logEvent_afterSigningFailure_chainsOntoLastPersistedRecord() {
    auditLogger.logEvent("EVENT_1", "Signed message.");
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    auditLogger.logEvent("UNSIGNED_EVENT", "Logged without keystore.");
    Security.addProvider(new FakeAndroidKeyStoreProvider());

    auditLogger.logEvent("EVENT_3", "Signed after recovery.");

    CrumblesChainVerification verification = auditLogger.verifyChain();
    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getTotalRecords()).isEqualTo(3);
    expect.that(verification.getVerifiedRecords()).isEqualTo(3);
  }

  @Test
  public void logEvent_afterWriteFailure_chainsOntoLastPersistedRecord() {
    auditLogger.logEvent("EVENT_1", "Persisted message.");
    assertThat(currentLogFile.renameTo(oldLogFile)).isTrue();
    // A directory can't be opened for appending, so the next write fails.
    assertThat(currentLogFile.mkdir()).isTrue();
    auditLogger.logEvent("UNWRITTEN_EVENT", "Lost because the write fails.");
    assertThat(currentLogFile.delete()).isTrue();

    auditLogger.logEvent("EVENT_3", "Persisted after the write failure.");

    CrumblesChainVerification verification = auditLogger.verifyChain();
    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getVerifiedRecords()).isEqualTo(3);
  }

  @Test
  public void getAllPersistedEventsForDisplay_afterRestart_unsealsRecords() {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    CrumblesAppAuditLogger.setInstanceForTest(null);
    CrumblesAppAuditLogger restartedLogger = CrumblesAppAuditLogger.getInstance(appContext);

    List<CrumblesAuditEvent> events = restartedLogger.getAllPersistedEventsForDisplay();

    assertThat(events.stream().map(CrumblesAuditEvent::getMessage).toList())
        .containsExactly("First message.", "Second message.");
  }

  @Test
  public void logEvent_whenDataKeyUnavailableAtRestart_chainsOntoLastSealedRecord() {
    auditLogger.logEvent("EVENT_1", "First message.");
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    Security.addProvider(new FakeAndroidKeyStoreProvider());

    auditLogger.logEvent("EVENT_2", "Logged once the Keystore is back.");

    CrumblesChainVerification verification = auditLogger.verifyChain();
    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getVerifiedRecords()).isEqualTo(2);
  }

  @Test
  public void logEvent_whenSealingFails_keepsEventInMemoryOnlyAndRecordsFailure() {
    restartLoggerWithUnusableDataKey();

    auditLogger.logEvent("UNSEALED_EVENT", "Never written in cleartext.");

    expect.that(currentLogFile.exists()).isFalse();
    expect.that(auditLogger.getSealingFailureCount()).isEqualTo(1);
    expect
        .that(auditLogger.getMemoryCachedEvents().get(0).getEventType())
        .isEqualTo("UNSEALED_EVENT");
  }

  @Test
  public void clearAllLogs_afterSealingFailure_resetsSealingFailureCount() {
    restartLoggerWithUnusableDataKey();
    auditLogger.logEvent("UNSEALED_EVENT", "Never written in cleartext.");
    assertThat(auditLogger.getSealingFailureCount()).isEqualTo(1);
    assertThat(dataKeyFile.delete()).isTrue();

    auditLogger.clearAllLogs();

    assertThat(auditLogger.getSealingFailureCount()).isEqualTo(0);
  }

  @Test
  public void getUnshippedExcerpt_afterSealingFailures_holdsTheDroppedRecordsSummary() {
    restartLoggerWithUnusableDataKey();
    auditLogger.logEvent("UNSEALED_1", "Never written in cleartext.");
    auditLogger.logEvent("UNSEALED_2", "Not tried while the summary cannot be sealed either.");
    assertThat(dataKeyFile.delete()).isTrue();

    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();

    expect.that(excerpt.size()).isEqualTo(1);
    expect.that(new String(excerpt.toBytes(), UTF_8)).contains("2 activity records could not");
  }

  @Test
  public void getInstance_afterClearAllLogs_cannotUnsealCopiesOfClearedRecords() throws Exception {
    auditLogger.logEvent("CLEARED_EVENT", "Removed by clearAllLogs.");
    List<String> clearedRecords = Files.readAllLines(currentLogFile.toPath(), UTF_8);
    byte[] storedDataKey = Files.readAllBytes(dataKeyFile.toPath());
    auditLogger.clearAllLogs();
    // Copies of the records and of the stored data key, as could be left on flash.
    Files.write(currentLogFile.toPath(), clearedRecords, UTF_8);
    Files.write(dataKeyFile.toPath(), storedDataKey);
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    assertThat(
            auditLogger.getAllPersistedEventsForDisplay().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .doesNotContain("CLEARED_EVENT");
  }

  @Test
  public void getInstance_afterClearAllLogs_unsealsRecordsLoggedAfterClearing() {
    auditLogger.logEvent("CLEARED_EVENT", "Removed by clearAllLogs.");
    auditLogger.clearAllLogs();
    auditLogger.logEvent("EVENT_1", "Logged after clearing.");
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    assertThat(
            auditLogger.getAllPersistedEventsForDisplay().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .containsExactly("EVENT_1", "AUDIT_LOG_CLEARED");
  }

  @Test
  public void clearAllLogs_whenDataKeyCannotBeDestroyed_stillDeletesLogFiles() {
    auditLogger.logEvent("EVENT_1", "First message.");
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);

    auditLogger.clearAllLogs();

    assertThat(currentLogFile.exists()).isFalse();
  }

  @Test
  public void getInstance_whenStoredDataKeyFailsAuthentication_logsKeyReplacedEvent()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    CrumblesAuditEvent newestEvent = auditLogger.getMemoryCachedEvents().get(0);
    expect.that(newestEvent.getEventType()).isEqualTo("AUDIT_LOG_KEY_REPLACED");
    expect
        .that(newestEvent.getMessage())
        .endsWith("Earlier records that can no longer be read: 2.");
  }

  @Test
  public void getInstance_whenWrappingKeyLost_logsKeyReplacedEvent() {
    auditLogger.logEvent("EVENT_1", "First message.");
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesAuditDataKey.WRAPPING_KEY_ALIAS);
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    CrumblesAuditEvent newestEvent = auditLogger.getMemoryCachedEvents().get(0);
    expect.that(newestEvent.getEventType()).isEqualTo("AUDIT_LOG_KEY_REPLACED");
    expect
        .that(newestEvent.getMessage())
        .endsWith("Earlier records that can no longer be read: 1.");
  }

  @Test
  public void getInstance_afterClearAllLogs_logsNoKeyReplacedEvent() {
    auditLogger.logEvent("CLEARED_EVENT", "Removed by clearAllLogs.");
    auditLogger.clearAllLogs();
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    assertThat(
            auditLogger.getMemoryCachedEvents().stream()
                .map(CrumblesAuditEvent::getEventType)
                .toList())
        .doesNotContain("AUDIT_LOG_KEY_REPLACED");
  }

  @Test
  public void logEvent_whenDataKeyReplacedAfterStartup_logsKeyReplacedEventAfterIt()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);

    auditLogger.logEvent("EVENT_2", "Sealed under the new data key.");

    List<CrumblesAuditEvent> events = auditLogger.getMemoryCachedEvents();
    expect.that(events.get(0).getEventType()).isEqualTo("AUDIT_LOG_KEY_REPLACED");
    expect
        .that(events.get(0).getMessage())
        .endsWith("Earlier records that can no longer be read: 1.");
    expect.that(events.get(1).getEventType()).isEqualTo("EVENT_2");
  }

  @Test
  public void verifyChain_whenDataKeyUnavailable_countsRecordsAsUnverifiable() throws Exception {
    auditLogger.logEvent("EVENT_1", "Written in cleartext by an earlier version.");
    auditLogger.logEvent("EVENT_2", "Sealed.");
    rewriteFirstRecordInCleartext();
    restartLoggerWithUnusableDataKey();

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getUnverifiableRecords()).isEqualTo(2);
  }

  @Test
  public void verifyChain_whenSealedRecordsFollowCleartextRecords_verifiesEveryRecord()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "Written in cleartext by an earlier version.");
    rewriteFirstRecordInCleartext();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    auditLogger.logEvent("EVENT_2", "Sealed.");

    CrumblesChainVerification verification = auditLogger.verifyChain();
    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getVerifiedRecords()).isEqualTo(2);
  }

  @Test
  public void getInstance_whenRecordsAreInCleartext_sealsThemInPlace() throws Exception {
    auditLogger.logEvent("EVENT_1", "Written in cleartext by an earlier version.");
    rewriteFirstRecordInCleartext();
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    expect
        .that(new String(Files.readAllBytes(currentLogFile.toPath()), UTF_8))
        .doesNotContain("earlier version");
    expect.that(auditLogger.verifyChain().getVerifiedRecords()).isEqualTo(1);
    expect.that(auditLogger.getAllPersistedEventsForDisplay()).hasSize(1);
  }

  @Test
  public void getInstance_whenOldLogFileIsInCleartext_sealsItInPlace() throws Exception {
    auditLogger.logEvent("EVENT_1", "Written in cleartext by an earlier version.");
    rewriteFirstRecordInCleartext();
    assertThat(currentLogFile.renameTo(oldLogFile)).isTrue();
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    assertThat(new String(Files.readAllBytes(oldLogFile.toPath()), UTF_8))
        .doesNotContain("earlier version");
  }

  @Test
  public void getInstance_whenCleartextLineIsMalformed_stillReportsBreakAtThatLine()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    List<String> lines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    lines.add(1, MALFORMED_LINE);
    Files.write(currentLogFile.toPath(), lines, UTF_8);
    CrumblesAppAuditLogger.setInstanceForTest(null);

    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    expect
        .that(new String(Files.readAllBytes(currentLogFile.toPath()), UTF_8))
        .doesNotContain("not-json");
    expect.that(auditLogger.verifyChain().getFirstBrokenIndex()).isEqualTo(1);
  }

  @Test
  public void getInstance_whenCleartextRecordsCannotBeSealed_leavesThemReadable() throws Exception {
    auditLogger.logEvent("EVENT_1", "Written in cleartext by an earlier version.");
    rewriteFirstRecordInCleartext();

    restartLoggerWithUnusableDataKey();

    expect
        .that(new String(Files.readAllBytes(currentLogFile.toPath()), UTF_8))
        .contains("earlier version");
    expect.that(auditLogger.getAllPersistedEventsForDisplay()).hasSize(1);
    expect
        .that(new File(currentLogFile.getPath() + CrumblesConstants.TEMP_FILE_SUFFIX).exists())
        .isFalse();
  }

  @Test
  public void logEvent_doesNotWriteMessageToLogcat() {
    auditLogger.logEvent("EVENT_1", "Secret message.");

    assertThat(
            ShadowLog.getLogsForTag("CrumblesAppAuditLogger").stream()
                .map(item -> item.msg)
                .filter(msg -> msg.contains("Secret message.")))
        .isEmpty();
  }

  @Test
  public void verifyChain_whenSealedRecordAltered_reportsBreakAtThatRecord() throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    auditLogger.logEvent("EVENT_3", "Third message.");
    alterSealedRecord(1);

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.getFirstBrokenIndex()).isEqualTo(1);
    expect.that(verification.getVerifiedRecords()).isEqualTo(1);
  }

  @Test
  public void getAllPersistedEventsForDisplay_whenSealedRecordAltered_skipsThatRecord()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    auditLogger.logEvent("EVENT_3", "Third message.");
    alterSealedRecord(1);

    List<CrumblesAuditEvent> events = auditLogger.getAllPersistedEventsForDisplay();

    assertThat(events.stream().map(CrumblesAuditEvent::getEventType).toList())
        .containsExactly("EVENT_1", "EVENT_3");
  }

  @Test
  public void getUnshippedExcerpt_isEmptyAndSize_reflectUnshippedRecords() {
    expect.that(auditLogger.getUnshippedExcerpt().isEmpty()).isTrue();
    expect.that(auditLogger.getUnshippedExcerpt().size()).isEqualTo(0);
    auditLogger.logEvent("EVENT_1", "Unshipped record.");
    CrumblesAuditExcerpt excerpt = auditLogger.getUnshippedExcerpt();
    expect.that(excerpt.isEmpty()).isFalse();
    expect.that(excerpt.size()).isEqualTo(1);
    auditLogger.markShipped(excerpt);
    expect.that(auditLogger.getUnshippedExcerpt().isEmpty()).isTrue();
    expect.that(auditLogger.getUnshippedExcerpt().size()).isEqualTo(0);
  }

  @Test
  public void clearAllLogs_whenUnsealedRecordsReported_appendsCountToTombstone() {
    auditLogger.logEvent("UNSEALED_EVENT", "Unshipped record that could not be sealed.");
    auditLogger.clearAllLogs(/* unsealedRecordCount= */ 1);
    assertThat(auditLogger.getAllPersistedEventsForDisplay().get(0).getMessage())
        .isEqualTo(
            "Audit log cleared; 1 records removed."
                + " (1 unshipped records could not be sealed before clear)");
  }

  @Test
  public void verifyChain_whenGenesisHeadHasSequenceGreaterThanOne_reportsBreak() throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    // Force the first record to be deleted without clearAllLogs, simulating missing earlier
    // records.
    List<String> lines = Files.readAllLines(currentLogFile.toPath(), UTF_8);
    Files.write(currentLogFile.toPath(), lines.subList(1, 2), UTF_8);

    CrumblesChainVerification verification = auditLogger.verifyChain();
    assertThat(verification.isIntact()).isFalse();
    assertThat(verification.getFirstBrokenIndex()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenLogDeletedBeforeRestartWithoutClearing_reportsBreak() {
    auditLogger.logEvent("EVENT_1", "First message.");
    assertThat(currentLogFile.delete()).isTrue();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_2", "Chains onto GENESIS with sequence 2.");

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isFalse();
    expect.that(verification.getFirstBrokenIndex()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenLeadingUntaggedRecordPrecedesHigherSequenceHead_reportsIntactChain()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "Advances sequence number pref to 1.");
    String untaggedLine =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_EVENT", "Untagged legacy record.")
            .toJsonString();
    Files.write(currentLogFile.toPath(), ImmutableList.of(untaggedLine), UTF_8);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_2", "First tagged record after untagged prefix, with sequence 2.");

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getTotalRecords()).isEqualTo(2);
    expect.that(verification.getVerifiedRecords()).isEqualTo(1);
    expect.that(verification.getUnverifiableRecords()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenTwoRotationsAfterUntaggedLegacyPrefix_reportsIntactChain()
      throws Exception {
    String untaggedLegacy =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_EVENT", "Untagged legacy record.")
            .toJsonString();
    Files.write(currentLogFile.toPath(), ImmutableList.of(untaggedLegacy), UTF_8);
    Method rotateMethod =
        CrumblesAppAuditLogger.class.getDeclaredMethod("rotateLogFiles", Instant.class);
    rotateMethod.setAccessible(true);

    rotateMethod.invoke(auditLogger, Instant.now());
    auditLogger.logEvent("EVENT_1", "First numbered event.");
    rotateMethod.invoke(auditLogger, Instant.now());
    auditLogger.logEvent("EVENT_2", "Second numbered event.");

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getTotalRecords()).isEqualTo(4);
    expect.that(verification.getVerifiedRecords()).isEqualTo(4);
  }

  @Test
  public void verifyChain_whenOldLogFileAbsentOrDeletedAfterRotation_verifiesOrReportsBreak()
      throws Exception {
    expect.that(auditLogger.verifyChain().getTotalRecords()).isEqualTo(0);

    Method rotateMethod =
        CrumblesAppAuditLogger.class.getDeclaredMethod("rotateLogFiles", Instant.class);
    rotateMethod.setAccessible(true);

    // Rotation when currentLogFile is empty discards oldLogFile and anchors currentLogFile[0] on
    // its last tag with currentLogStartIndex == 0.
    auditLogger.logEvent("EVENT_1", "Discarded by rotation.");
    assertThat(currentLogFile.renameTo(oldLogFile)).isTrue();
    rotateMethod.invoke(auditLogger, Instant.now());

    CrumblesChainVerification emptyOldVerification = auditLogger.verifyChain();
    expect.that(emptyOldVerification.isIntact()).isTrue();
    expect.that(emptyOldVerification.getVerifiedRecords()).isEqualTo(1);

    // Deleting a non-empty oldLogFile after rotation breaks the chain at index 0.
    auditLogger.logEvent("EVENT_2", "Moved to oldLogFile on next rotation.");
    rotateMethod.invoke(auditLogger, Instant.now());
    assertThat(oldLogFile.delete()).isTrue();

    CrumblesChainVerification deletedOldVerification = auditLogger.verifyChain();
    expect.that(deletedOldVerification.isIntact()).isFalse();
    expect.that(deletedOldVerification.getFirstBrokenIndex()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenUnnumberedRecordFollowsLegacyOrNumberedRecord_verifiesOrReportsBreak()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "Initializes chain key.");
    SecretKey chainKey =
        (SecretKey) FakeAndroidKeyStoreSpi.keystoreEntries.get(CHAIN_KEY_ALIAS).getKey();

    // An unnumbered record following a numbered record is a break even with a valid HMAC tag.
    String firstTag = readRecords(currentLogFile).get(0).getTag();
    CrumblesAuditEvent unnumberedUnsigned =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_AFTER_NUMBERED", "Unnumbered record");
    String unnumberedSignedJson =
        unnumberedUnsigned
            .withTag(unnumberedUnsigned.computeTag(chainKey, firstTag))
            .toJsonString();
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(unnumberedSignedJson),
        UTF_8,
        StandardOpenOption.APPEND);

    CrumblesChainVerification brokenVerification = auditLogger.verifyChain();
    expect.that(brokenVerification.isIntact()).isFalse();
    expect.that(brokenVerification.getFirstBrokenIndex()).isEqualTo(1);

    // Two legacy unnumbered records where the first has an unverifiable pre-rotation tag and the
    // second validly chains onto it: first is unverifiable, second is verified.
    CrumblesAuditEvent legacyFirst =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_1", "Unnumbered head", "legacy-tag-1");
    CrumblesAuditEvent legacySecondUnsigned =
        new CrumblesAuditEvent(Instant.now(), "LEGACY_2", "Unnumbered chained onto legacy head");
    CrumblesAuditEvent legacySecond =
        legacySecondUnsigned.withTag(legacySecondUnsigned.computeTag(chainKey, "legacy-tag-1"));
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(legacyFirst.toJsonString(), legacySecond.toJsonString()),
        UTF_8);

    CrumblesChainVerification legacyVerification = auditLogger.verifyChain();
    expect.that(legacyVerification.isIntact()).isTrue();
    expect.that(legacyVerification.getVerifiedRecords()).isEqualTo(1);
    expect.that(legacyVerification.getUnverifiableRecords()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenUnreadableSealedRecordsFollowNumberedRecord_verifiesAcrossKeyChange()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "Cleartext in old file.");
    rewriteFirstRecordInCleartext();
    assertThat(currentLogFile.renameTo(oldLogFile)).isTrue();
    auditLogger.logEvent("EVENT_2", "Sealed under old data key.");
    auditLogger.logEvent("EVENT_3", "Second record sealed under old data key.");
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_5", "Sealed under new data key.");

    CrumblesChainVerification intactVerification = auditLogger.verifyChain();

    expect.that(intactVerification.isIntact()).isTrue();
    expect.that(intactVerification.getTotalRecords()).isEqualTo(5);
    expect.that(intactVerification.getVerifiedRecords()).isEqualTo(3);
    expect.that(intactVerification.getUnverifiableRecords()).isEqualTo(2);

    // Deleting one unreadable sealed record causes a sequence gap at the first readable record.
    List<String> currentLines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    currentLines.remove(0);
    Files.write(currentLogFile.toPath(), currentLines, UTF_8);

    CrumblesChainVerification brokenVerification = auditLogger.verifyChain();

    expect.that(brokenVerification.isIntact()).isFalse();
    expect.that(brokenVerification.getFirstBrokenIndex()).isEqualTo(2);
  }

  @Test
  public void verifyChain_whenUnreadableSealedRecordFollowsCleartextRecord_countsUnverifiable()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "Cleartext first record.");
    auditLogger.logEvent("EVENT_2", "Sealed under lost key.");
    auditLogger.logEvent("EVENT_3", "Cleartext third record.");
    List<String> lines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    CrumblesAuditRecordSealer currentSealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(dataKeyFile));
    String cleartextFirst = currentSealer.unseal(lines.get(0));
    String cleartextSecond = currentSealer.unseal(lines.get(1));
    String cleartextThird = currentSealer.unseal(lines.get(2));
    File otherKeyFile = new File(appContext.getNoBackupFilesDir(), "other_audit_key");
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesAuditDataKey.WRAPPING_KEY_ALIAS);
    String foreignSealedSecond =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(otherKeyFile)).seal(cleartextSecond);
    assertThat(otherKeyFile.delete()).isTrue();
    FakeAndroidKeyStoreSpi.keystoreEntries.remove(CrumblesAuditDataKey.WRAPPING_KEY_ALIAS);
    assertThat(dataKeyFile.delete()).isTrue();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(cleartextFirst, foreignSealedSecond, cleartextThird),
        UTF_8);

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isTrue();
    expect.that(verification.getVerifiedRecords()).isEqualTo(2);
    expect.that(verification.getUnverifiableRecords()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenSealedRecordAlteredAndKeyReplacedForged_reportsBreakAtAlteredRecord()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "First message.");
    auditLogger.logEvent("EVENT_2", "Second message.");
    auditLogger.logEvent("EVENT_3", "Third message.");
    alterSealedRecord(1);
    String forgedKeyReplaced =
        new CrumblesAuditEvent(
                Instant.now(), "AUDIT_LOG_KEY_REPLACED", "Forged key replacement.", "forged-tag")
            .withSequenceNumber(4)
            .toJsonString();
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(forgedKeyReplaced),
        UTF_8,
        StandardOpenOption.APPEND);

    CrumblesChainVerification verification = auditLogger.verifyChain();

    expect.that(verification.isIntact()).isFalse();
    expect.that(verification.getFirstBrokenIndex()).isEqualTo(1);
  }

  @Test
  public void verifyChain_whenCurrentLogFileEmptyWithChainKeyPresent_verifiesOldRecordsOrEmpty() {
    auditLogger.logEvent("EVENT_1", "Moved to old log file.");
    assertThat(currentLogFile.renameTo(oldLogFile)).isTrue();

    CrumblesChainVerification oldOnlyVerification = auditLogger.verifyChain();

    expect.that(oldOnlyVerification.isIntact()).isTrue();
    expect.that(oldOnlyVerification.getTotalRecords()).isEqualTo(1);
    expect.that(oldOnlyVerification.getVerifiedRecords()).isEqualTo(1);
    expect.that(oldOnlyVerification.getUnverifiableRecords()).isEqualTo(0);

    assertThat(oldLogFile.delete()).isTrue();

    CrumblesChainVerification emptyVerification = auditLogger.verifyChain();

    expect.that(emptyVerification.isIntact()).isTrue();
    expect.that(emptyVerification.getTotalRecords()).isEqualTo(0);
    expect.that(emptyVerification.getVerifiedRecords()).isEqualTo(0);
    expect.that(emptyVerification.getUnverifiableRecords()).isEqualTo(0);
  }

  @Test
  public void verifyChain_whenFirstRecordUnreadableBeforeKeyReplacement_verifiesAndDetectsTamper()
      throws Exception {
    auditLogger.logEvent("EVENT_1", "Sealed under old data key.");
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
    auditLogger.logEvent("EVENT_2", "Sealed under new data key.");

    CrumblesChainVerification intactVerification = auditLogger.verifyChain();

    expect.that(intactVerification.isIntact()).isTrue();
    expect.that(intactVerification.getTotalRecords()).isEqualTo(3);
    expect.that(intactVerification.getVerifiedRecords()).isEqualTo(2);
    expect.that(intactVerification.getUnverifiableRecords()).isEqualTo(1);

    alterSealedRecord(2);

    CrumblesChainVerification tamperedVerification = auditLogger.verifyChain();

    expect.that(tamperedVerification.isIntact()).isFalse();
    expect.that(tamperedVerification.getFirstBrokenIndex()).isEqualTo(2);
    expect.that(tamperedVerification.getVerifiedRecords()).isEqualTo(1);
    expect.that(tamperedVerification.getUnverifiableRecords()).isEqualTo(1);
  }

  @Test
  public void getInstance_whenSequenceNumberPrefStale_countsReadableAndTrailingSealedRecords()
      throws Exception {
    // Case 1: Readable numbered record followed by unreadable sealed records and lost pref.
    auditLogger.logEvent("EVENT_1", "Cleartext in old file.");
    rewriteFirstRecordInCleartext();
    assertThat(currentLogFile.renameTo(oldLogFile)).isTrue();
    auditLogger.logEvent("EVENT_2", "Sealed under old data key.");
    auditLogger.logEvent("EVENT_3", "Second record sealed under old data key.");
    List<String> sealedLines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    appContext
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putLong("last_sequence_number", 0)
        .commit();
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    expect
        .that(auditLogger.getAllPersistedEventsForDisplay().get(0).getSequenceNumber())
        .isEqualTo(OptionalLong.of(4));
    expect.that(auditLogger.verifyChain().isIntact()).isTrue();

    // Case 2: Trailing malformed (non-sealed) line is not counted, and all-sealed unreadable
    // records recover sequence numbers from sealed record count when pref is lost.
    assertThat(oldLogFile.delete()).isTrue();
    Files.write(
        currentLogFile.toPath(),
        ImmutableList.of(sealedLines.get(0), sealedLines.get(1), MALFORMED_LINE),
        UTF_8);
    appContext
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putLong("last_sequence_number", 0)
        .commit();
    Files.write(dataKeyFile.toPath(), new byte[(int) dataKeyFile.length()]);
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);

    expect
        .that(auditLogger.getAllPersistedEventsForDisplay().get(0).getSequenceNumber())
        .isEqualTo(OptionalLong.of(3));
  }

  @Test
  public void logEvent_withReserveFile_retriesOnceAndReplenishesReserve() throws Exception {
    expect.that(reserveFile.length()).isEqualTo(CrumblesAppAuditLogger.RESERVE_FILE_BYTES);
    byte[] markedReserve = new byte[CrumblesAppAuditLogger.RESERVE_FILE_BYTES];
    markedReserve[0] = 0x5A;
    Files.write(reserveFile.toPath(), markedReserve);
    AtomicInteger failures = new AtomicInteger();
    CrumblesAppAuditLogger logger = newFailableLogger(InstantSource.system(), failures);
    logger.logEvent("NORMAL_EVENT", "Keeps existing full-sized reserve intact.");
    expect.that(Files.readAllBytes(reserveFile.toPath())[0]).isEqualTo((byte) 0x5A);
    failures.set(1);
    logger.logEvent("LOG_RETRIEVAL_DEFERRED", "Persisted after rolling back partial write.");
    expect.that(failures.get()).isEqualTo(-1);
    expect.that(reserveFile.length()).isEqualTo(CrumblesAppAuditLogger.RESERVE_FILE_BYTES);
    expect.that(reserveFile.delete() && reserveFile.mkdir()).isTrue();
    logger.logEvent("RESERVE_BLOCKED", "Still persists when reserve replenishment fails.");
    expect.that(reserveFile.delete()).isTrue();
    failures.set(1);
    logger.logEvent("NO_RESERVE_LEFT", "Does not retry when reserve is absent.");
    expect.that(failures.get()).isEqualTo(0);
    expect.that(logger.getWriteFailureCount()).isEqualTo(1);
    expect.that(logger.verifyChain().isIntact() && logger.verifyChain().getVerifiedRecords() == 3)
        .isTrue();
  }

  @Test
  public void logEvent_afterWriteFailures_persistsSummaryBeforeNextEvent() throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(utc("12:00:00Z"));
    AtomicInteger failures = new AtomicInteger();
    CrumblesAppAuditLogger logger = newFailableLogger(now::get, failures);
    logger.logEvent("EVENT_0", "Initial record.");
    long firstSeq = readRecords(currentLogFile).get(0).getSequenceNumber().orElseThrow();
    String initialHead = logger.getUnshippedExcerpt().getHeadTag().orElseThrow();
    failures.set(10);
    logAt(logger, now, "12:00:01.123456Z", "DROPPED_1", "First failed write.");
    logAt(logger, now, "12:00:05.789Z", "DROPPED_2", "Second failed write.");
    expect.that(logger.getWriteFailureCount()).isEqualTo(2);
    expect.that(reserveFile.exists()).isFalse();
    expect.that(logger.getUnshippedExcerpt().getHeadTag()).hasValue(initialHead);
    failures.set(0);
    logAt(logger, now, "12:00:10Z", "EVENT_3", "Recovered write.");
    expect.that(logger.getWriteFailureCount()).isEqualTo(0);
    expect.that(reserveFile.length()).isEqualTo(CrumblesAppAuditLogger.RESERVE_FILE_BYTES);
    ImmutableList<CrumblesAuditEvent> persisted = readRecords(currentLogFile);
    expectDroppedSummary(persisted.get(1), 2, "12:00:01.123Z", "12:00:05.789Z");
    expect.that(persisted.get(2).getSequenceNumber()).hasValue(firstSeq + 2);
    List<CrumblesAuditEvent> cached = logger.getMemoryCachedEvents();
    expect.that(cached.get(1).getEventType()).isEqualTo(RECORDS_DROPPED_EVENT_TYPE);
    expect.that(logger.verifyChain().isIntact() && logger.verifyChain().getVerifiedRecords() == 3)
        .isTrue();
  }

  @Test
  public void logEvent_whenSummaryOrRotationFails_keepsWindowAndClearResets() throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(utc("13:00:01Z"));
    AtomicInteger failures = new AtomicInteger(10);
    CrumblesAppAuditLogger logger = newFailableLogger(now::get, failures);
    logger.logEvent("DROPPED_1", "Partial write on missing file deletes it.");
    expect.that(currentLogFile.exists()).isFalse();
    Files.write(currentLogFile.toPath(), new byte[OVERSIZED_LOG_FILE_BYTES]);
    failures.set(1);
    logAt(logger, now, "13:00:02Z", "DROPPED_2", "Summary write fails.");
    expect.that(logger.getWriteFailureCount()).isEqualTo(2);
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    logAt(logger, now, "13:00:03Z", "DROPPED_3", "Summary signing fails.");
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    expect.that(logger.getWriteFailureCount()).isEqualTo(3);
    expect.that(currentLogFile.delete()).isTrue();
    failures.set(0);
    logAt(logger, now, "13:00:04Z", "RECOVERED", "Flushes preserved window.");
    expectDroppedSummary(readRecords(currentLogFile).get(0), 3, "13:00:01Z", "13:00:03Z");
    Files.write(currentLogFile.toPath(), new byte[OVERSIZED_LOG_FILE_BYTES]);
    Files.write(oldLogFile.toPath(), "kept".getBytes(UTF_8));
    expect.that(reserveFile.delete()).isTrue();
    failures.set(2);
    logAt(logger, now, "13:00:08Z", "ROTATE_WRITE_FAILS", "Uses rotate reserve; keeps old log.");
    expect.that(failures.get()).isEqualTo(0);
    expect.that(new String(Files.readAllBytes(oldLogFile.toPath()), UTF_8)).isEqualTo("kept");
    expect.that(oldLogFile.delete()).isTrue();
    File pin = new File(oldLogFile, "pin");
    expect.that(oldLogFile.mkdir() && pin.createNewFile()).isTrue();
    logAt(logger, now, "13:00:09Z", "ROTATE_BLOCKED", "Replenishes reserves; rename fails.");
    expect.that(reserveFile.length()).isEqualTo(CrumblesAppAuditLogger.RESERVE_FILE_BYTES);
    expect.that(logger.getWriteFailureCount()).isEqualTo(2);
    expect.that(pin.delete() && oldLogFile.delete() && currentLogFile.delete()).isTrue();
    logAt(logger, now, "13:00:10Z", "RECOVERED_2", "Flushes new window.");
    expectDroppedSummary(readRecords(currentLogFile).get(0), 2, "13:00:09Z", "13:00:09Z");
    failures.set(2);
    logger.logEvent("DROPPED_4", "Fails before clear.");
    logger.clearAllLogs();
    expect.that(logger.getWriteFailureCount()).isEqualTo(0);
    expect
        .that(readRecords(currentLogFile).get(0).getMessage())
        .isEqualTo("Audit log cleared; 2 records removed (1 unpersisted records were also lost).");
  }

  @Test
  public void restartAndFailingClearAllLogs_persistDropWindowAcrossInstances() throws Exception {
    AtomicReference<Instant> now = new AtomicReference<>(utc("14:00:00Z"));
    AtomicInteger failures = new AtomicInteger();
    CrumblesAppAuditLogger logger = newFailableLogger(now::get, failures);
    logger.logEvent("EVENT_0", "Initial.");
    failures.set(10);
    logAt(logger, now, "14:00:01Z", "DROP_1", "First.");
    logAt(logger, now, "14:00:02Z", "DROP_2", "Second.");
    expect.that(dropMarkerFile.length()).isEqualTo(CrumblesAppAuditLogger.DROP_MARKER_FILE_BYTES);
    now.set(utc("14:00:03Z"));
    CrumblesAppAuditLogger fullRestart = newFailableLogger(now::get, failures);
    expect.that(fullRestart.getWriteFailureCount()).isEqualTo(2);
    logAt(fullRestart, now, "14:00:04Z", "DROP_3", "Third across still-full restart.");
    failures.set(0);
    now.set(utc("14:00:05Z"));
    CrumblesAppAuditLogger recovered = newFailableLogger(now::get, failures);
    expect.that(recovered.getWriteFailureCount()).isEqualTo(0);
    expect.that(Files.readAllBytes(dropMarkerFile.toPath())).isEqualTo(new byte[20]);
    expectDroppedSummary(recovered.getMemoryCachedEvents().get(0), 3, "14:00:01Z", "14:00:04Z");
    expect.that(recovered.verifyChain().isIntact()).isTrue();
    expect.that(recovered.verifyChain().getVerifiedRecords()).isEqualTo(2);
    failures.set(10);
    logAt(recovered, now, "14:00:07Z", "DROP_B", "Lost before failing clear.");
    expect.that(currentLogFile.delete() && currentLogFile.mkdir()).isTrue();
    now.set(utc("14:00:08Z"));
    recovered.clearAllLogs();
    expect
        .that(recovered.getMemoryCachedEvents().get(0).getMessage())
        .contains("failed to count removed records (1 unpersisted records were also lost).");
    expect.that(recovered.getWriteFailureCount()).isEqualTo(2);
    failures.set(0);
    recovered = newFailableLogger(now::get, failures);
    expectDroppedSummary(recovered.getMemoryCachedEvents().get(0), 2, "14:00:07Z", "14:00:08Z");
    Files.write(dropMarkerFile.toPath(), new byte[] {1, 2});
    failures.set(10);
    now.set(utc("14:00:09Z"));
    newFailableLogger(now::get, failures).clearAllLogs();
    failures.set(0);
    recovered = newFailableLogger(now::get, failures);
    expectDroppedSummary(recovered.getMemoryCachedEvents().get(0), 1, "14:00:09Z", "14:00:09Z");
  }

  private static void logAt(
      CrumblesAppAuditLogger logger, AtomicReference<Instant> now, String t, String k, String msg) {
    now.set(utc(t)); logger.logEvent(k, msg);
  }

  private static Instant utc(String time) {
    return Instant.parse("2026-03-01T" + time);
  }

  private void expectDroppedSummary(CrumblesAuditEvent event, int count, String start, String end) {
    String prefix = count + " activity records could not be persisted between 2026-03-01T";
    expect.that(event.getMessage()).isEqualTo(prefix + start + " and 2026-03-01T" + end + ".");
  }

  private CrumblesAppAuditLogger newFailableLogger(InstantSource clock, AtomicInteger failures) {
    return new CrumblesAppAuditLogger(appContext, clock, (file, line) -> {
      if (failures.getAndDecrement() > 0) {
        if (!file.isDirectory()) {
          Files.write(
              file.toPath(), new byte[9], StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        throw new IOException("No space left on device");
      }
      CrumblesAppAuditLogger.appendLineToFile(file, line);
    });
  }

  /** Rewrites the first record of the current log file in cleartext, as earlier versions did. */
  private void rewriteFirstRecordInCleartext() throws Exception {
    List<String> lines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    CrumblesAuditRecordSealer sealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(dataKeyFile));
    lines.set(0, sealer.unseal(lines.get(0)));
    Files.write(currentLogFile.toPath(), lines, UTF_8);
  }

  /** Returns the records of the current log file, unsealed. */
  private List<String> readUnsealedRecords() throws Exception {
    CrumblesAuditRecordSealer sealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(dataKeyFile));
    List<String> records = new ArrayList<>();
    for (String line : Files.readAllLines(currentLogFile.toPath(), UTF_8)) {
      records.add(sealer.unseal(line));
    }
    return records;
  }

  /** Alters the ciphertext of the sealed record on line {@code index} of the current log file. */
  private void alterSealedRecord(int index) throws Exception {
    List<String> lines = new ArrayList<>(Files.readAllLines(currentLogFile.toPath(), UTF_8));
    JSONObject fields = new JSONObject(lines.get(index));
    String sealedRecord = fields.getString("sealed");
    char replacement = sealedRecord.charAt(20) == 'A' ? 'B' : 'A';
    fields.put("sealed", sealedRecord.substring(0, 20) + replacement + sealedRecord.substring(21));
    lines.set(index, fields.toString());
    Files.write(currentLogFile.toPath(), lines, UTF_8);
  }

  /** Restarts the logger with a directory where its data key belongs, so the key can't load. */
  private void restartLoggerWithUnusableDataKey() {
    assertThat(dataKeyFile.delete()).isTrue();
    assertThat(dataKeyFile.mkdir()).isTrue();
    CrumblesAppAuditLogger.setInstanceForTest(null);
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
  }

  /** Restarts the logger so that it timestamps events with {@code clock}. */
  private void restartLoggerWithClock(InstantSource clock) {
    CrumblesAppAuditLogger.setInstanceForTest(new CrumblesAppAuditLogger(appContext, clock));
    auditLogger = CrumblesAppAuditLogger.getInstance(appContext);
  }

  /** Returns the records of {@code file} in file order, unsealed. */
  private ImmutableList<CrumblesAuditEvent> readRecords(File file) throws Exception {
    CrumblesAuditRecordSealer sealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(dataKeyFile));
    ImmutableList.Builder<CrumblesAuditEvent> records = ImmutableList.builder();
    for (String line : Files.readAllLines(file.toPath(), UTF_8)) {
      records.add(CrumblesAuditEvent.fromJsonString(sealer.unseal(line)));
    }
    return records.build();
  }
}
