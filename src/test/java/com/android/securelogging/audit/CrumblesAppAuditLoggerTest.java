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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesConstants;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.time.Instant;
import java.time.InstantSource;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/** Unit tests for the {@link CrumblesAppAuditLogger} class. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesAppAuditLoggerTest {

  private Context appContext;
  private CrumblesAppAuditLogger auditLogger;
  private File currentLogFile;
  private File oldLogFile;

  @Before
  public void setUp() {
    appContext = ApplicationProvider.getApplicationContext();
    File logDir = appContext.getFilesDir();
    currentLogFile = new File(logDir, CrumblesConstants.CURRENT_LOG_FILE_NAME);
    oldLogFile = new File(logDir, CrumblesConstants.OLD_LOG_FILE_NAME);

    // Reset the singleton instance before each test.
    CrumblesAppAuditLogger.setInstanceForTest(null);

    // Manually delete files to ensure the directory is clean.
    if (currentLogFile.exists()) {
      currentLogFile.delete();
    }
    if (oldLogFile.exists()) {
      oldLogFile.delete();
    }

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
      assertThat(line).contains("\"message\":\"" + message + "\"");
    }
  }

  @Test
  public void logEvent_whenMemoryCacheExceedsMax_thenOldestIsRemovedFromCache() {
    // Given: MAX_MEMORY_EVENTS are logged. This is the loop you likely deleted.
    for (int i = 0; i < CrumblesConstants.MAX_MEMORY_EVENTS; i++) {
      auditLogger.logEvent("CACHE_FILL_EVENT", "Event " + i);
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
  public void logEvent_whenCurrentLogFileExceedsMaxSize_thenRotatesLogs() throws IOException {
    // Given: The old log file does not exist.
    assertThat(oldLogFile.exists()).isFalse();

    // When: We write events in a loop until the current log file's size exceeds the maximum.
    while (currentLogFile.length() <= CrumblesConstants.MAX_LOG_FILE_SIZE_BYTES) {
      auditLogger.logEvent("FILLER", "Adding data to exceed max size.");
    }

    // This next log event MUST trigger the rotation logic.
    auditLogger.logEvent("POST_ROTATION_EVENT", "This event triggers rotation.");

    // Then: The old log file should now exist.
    assertThat(oldLogFile.exists()).isTrue();

    // And: The new current log file should exist and contain only the single event logged after
    // rotation.
    assertThat(currentLogFile.exists()).isTrue();
    assertThat(countLinesInFile(currentLogFile)).isEqualTo(1);
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
  public void loadInitialCacheFromFiles_whenFilesExist_loadsCacheCorrectly() throws IOException {
    // Given: Log files with predefined content.
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

    // Then: The cache should contain the latest events from BOTH files, sorted correctly.
    List<CrumblesAuditEvent> cachedEvents = newLogger.getMemoryCachedEvents();

    assertThat(cachedEvents).isNotEmpty();
    assertThat(cachedEvents.size()).isAtMost(CrumblesConstants.MAX_MEMORY_EVENTS);
    assertThat(cachedEvents.get(0).getTimestamp()).isEqualTo(t4);
    assertThat(cachedEvents.get(1).getTimestamp()).isEqualTo(t3);
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
    // The events are sorted newest first (descending by timestamp).
    assertThat(displayEvents.get(0).getTimestamp()).isEqualTo(t3);
    assertThat(displayEvents.get(1).getTimestamp()).isEqualTo(t2);
    assertThat(displayEvents.get(2).getTimestamp()).isEqualTo(t1);
  }

  @Test
  public void clearAllLogs_whenCalled_thenMemoryCacheAndFilesAreCleared() {
    auditLogger.logEvent("CLEAR_TEST_EVENT_1", "Message to be cleared 1.");
    assertThat(auditLogger.getMemoryCachedEvents()).isNotEmpty();
    assertThat(currentLogFile.exists()).isTrue();

    auditLogger.clearAllLogs();

    assertThat(auditLogger.getMemoryCachedEvents()).isEmpty();
    assertThat(currentLogFile.exists()).isFalse();
    assertThat(oldLogFile.exists()).isFalse();
  }
}
