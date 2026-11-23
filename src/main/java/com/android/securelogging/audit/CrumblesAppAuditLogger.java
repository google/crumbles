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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.lang.Math.min;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.annotation.Nullable;
import com.android.securelogging.CrumblesConstants;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.json.JSONException;

/** CrumblesAppAuditLogger is a singleton class that logs app audit events to a file. */
public class CrumblesAppAuditLogger {
  private static final String TAG = "CrumblesAppAuditLogger";
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String KEY_REPLACED_EVENT_TYPE = "AUDIT_LOG_KEY_REPLACED";
  static final String CHAIN_KEY_ALIAS = "crumbles_audit_chain_hmac_key";
  static final String RESERVE_FILE_NAME = "app_audit_log.reserve";
  static final String ROTATE_RESERVE_FILE_NAME = "app_audit_log.rotate.reserve";
  static final String DROP_MARKER_FILE_NAME = "app_audit_log.drops";
  static final String RECORDS_DROPPED_EVENT_TYPE = "AUDIT_RECORDS_DROPPED";
  static final int RESERVE_FILE_BYTES = 16 * 1024;
  static final int ROTATE_RESERVE_FILE_BYTES = 4 * 1024;
  static final int DROP_MARKER_FILE_BYTES = Integer.BYTES + 2 * Long.BYTES;
  private static final String AUDIT_LOG_CLEARED_EVENT_TYPE = "AUDIT_LOG_CLEARED";
  private static final String AUDIT_LOG_ROTATED_EVENT_TYPE = "AUDIT_LOG_ROTATED";
  private static final String AUDIT_EVENTS_RATE_LIMITED_EVENT_TYPE = "AUDIT_EVENTS_RATE_LIMITED";

  /**
   * Most records of one event type written per {@link #RATE_LIMIT_WINDOW}, so that an event that
   * can be triggered at will cannot flood the log and push older records out through rotation.
   */
  static final int MAX_RECORDS_PER_EVENT_TYPE = 60;

  static final Duration RATE_LIMIT_WINDOW = Duration.ofHours(1);
  private static final Pattern RATE_LIMIT_START_PATTERN =
      Pattern.compile("More than \\d+ (\\S+) events in");
  private static final Pattern RATE_LIMIT_END_PATTERN =
      Pattern.compile("\\d+ (\\S+) events from .* were counted but not recorded\\.");

  /** Appends a single sealed record line to an audit log file. */
  interface RecordWriter {
    void appendLine(File file, String line) throws IOException;
  }

  @SuppressWarnings("NonFinalStaticField")
  private static CrumblesAppAuditLogger instance;

  private final Context appContext;
  private final InstantSource clock;
  private final RecordWriter recordWriter;
  private final File currentLogFile;
  private final File oldLogFile;
  private final File reserveFile;
  private final File rotateReserveFile;
  private final File dropMarkerFile;
  private final CrumblesAuditDataKey dataKey;
  private final CrumblesAuditRecordSealer sealer;
  private final ArrayDeque<CrumblesAuditEvent> memoryCache;
  private final Map<String, RateLimitWindow> rateLimitWindows = new HashMap<>();
  protected final Object fileLock = new Object();
  @Nullable private String lastTag;
  private long lastSequenceNumber;
  private int signingFailureCount;
  private int sealingFailureCount;
  private int droppedWriteCount;
  private Instant firstFailureTime = Instant.EPOCH;
  private Instant lastFailureTime = Instant.EPOCH;

  /** Creates a logger that timestamps events with {@code clock}. */
  CrumblesAppAuditLogger(Context context, InstantSource clock) {
    this(context, clock, CrumblesAppAuditLogger::appendLineToFile);
  }

  CrumblesAppAuditLogger(Context context, InstantSource clock, RecordWriter recordWriter) {
    this.appContext = context.getApplicationContext();
    this.clock = clock;
    this.recordWriter = recordWriter;
    File logDir = this.appContext.getNoBackupFilesDir();
    this.currentLogFile = new File(logDir, CrumblesConstants.CURRENT_LOG_FILE_NAME);
    this.oldLogFile = new File(logDir, CrumblesConstants.OLD_LOG_FILE_NAME);
    this.reserveFile = new File(logDir, RESERVE_FILE_NAME);
    this.rotateReserveFile = new File(logDir, ROTATE_RESERVE_FILE_NAME);
    this.dropMarkerFile = new File(logDir, DROP_MARKER_FILE_NAME);
    this.dataKey =
        new CrumblesAuditDataKey(new File(logDir, CrumblesConstants.AUDIT_LOG_KEY_FILE_NAME));
    this.sealer = new CrumblesAuditRecordSealer(dataKey);
    this.memoryCache = new ArrayDeque<>();
    loadDataKey();
    sealCleartextRecords();
    loadInitialCacheFromFiles();
    synchronized (fileLock) {
      this.lastTag = loadLastTag();
      this.lastSequenceNumber = loadLastSequenceNumber();
      loadDroppedStateLocked();
      flushDroppedSummaryLocked(clock.instant());
      if (droppedWriteCount == 0) {
        ensureAuxiliaryFilesLocked();
      }
    }
    rebuildRateLimitsFromTail();
  }

  public static synchronized CrumblesAppAuditLogger getInstance(Context context) {
    if (instance == null) {
      instance = new CrumblesAppAuditLogger(context, InstantSource.system());
      instance.logDataKeyReplacement();
    }
    return instance;
  }

  public void logEvent(String eventType, String message) {
    CrumblesAuditEvent event = new CrumblesAuditEvent(clock.instant(), eventType, message);

    // The message stays out of logcat, which would keep a cleartext copy of the record.
    Log.d(TAG, "Logging audit event: " + eventType);

    synchronized (fileLock) {
      if (isWithinRateLimit(event)) {
        persistAndCache(event);
      }
    }
    logDataKeyReplacement();
  }

  /**
   * Appends {@code event} to the current log file as the next record of the chain, rotating the
   * files first if it is full. Must be called with {@link #fileLock} held.
   */
  private void persistAndCache(CrumblesAuditEvent event) {
    persist(event);
    addToMemoryCache(event);
  }

  private void persist(CrumblesAuditEvent event) {
    flushDroppedSummaryLocked(event.getTimestamp());
    if (droppedWriteCount == 0
        && currentLogFile.exists()
        && currentLogFile.length() > CrumblesConstants.MAX_LOG_FILE_SIZE_BYTES) {
      rotateLogFiles(event.getTimestamp());
    }
    if (droppedWriteCount > 0) {
      recordWriteFailureLocked(event.getTimestamp());
    } else {
      var unused = persistEventLocked(event, /* rotateToOld= */ false, /* recordFailure= */ true);
      if (droppedWriteCount == 0) {
        ensureAuxiliaryFilesLocked();
      }
    }
  }

  /** Writes and caches the summary of the records that could not be written, if there are any. */
  private void flushDroppedSummaryLocked(Instant timestamp) {
    if (droppedWriteCount == 0) {
      return;
    }
    String summaryMessage = droppedWriteCount + " activity records could not be persisted between "
        + firstFailureTime + " and " + lastFailureTime + ".";
    CrumblesAuditEvent persisted =
        persistEventLocked(
            new CrumblesAuditEvent(timestamp, RECORDS_DROPPED_EVENT_TYPE, summaryMessage),
            /* rotateToOld= */ false,
            /* recordFailure= */ false);
    if (persisted != null) {
      clearDroppedStateLocked();
      ensureAuxiliaryFilesLocked();
      addToMemoryCache(persisted);
    }
  }

  @Nullable
  private CrumblesAuditEvent persistEventLocked(
      CrumblesAuditEvent event, boolean rotateToOld, boolean recordFailure) {
    String eventType = event.getEventType();
    event = event.withSequenceNumber(lastSequenceNumber + 1);
    String baseTag = lastTag != null ? lastTag : CrumblesAuditEvent.GENESIS_TAG;
    Optional<String> nextTag = signEvent(event, baseTag);
    if (nextTag.isEmpty()) {
      // Untagged records must never be persisted, as they would be indistinguishable from
      // records injected by an attacker.
      signingFailureCount++;
      Log.e(TAG, "Not persisting audit event because signing failed: " + eventType);
      if (recordFailure) {
        recordWriteFailureLocked(event.getTimestamp());
      }
      return null;
    }
    event = event.withTag(nextTag.get());
    String sealedRecord;
    try {
      sealedRecord = sealer.seal(event.toJsonString());
    } catch (GeneralSecurityException | IOException e) {
      // Writing the record in cleartext instead would defeat sealing the log at rest.
      sealingFailureCount++;
      Log.e(TAG, "Not persisting audit event because sealing failed: " + eventType, e);
      if (recordFailure) {
        recordWriteFailureLocked(event.getTimestamp());
      }
      return null;
    }
    try {
      if (rotateToOld) {
        File rotated = new File(currentLogFile.getPath() + CrumblesConstants.TEMP_FILE_SUFFIX);
        rotated.delete();
        appendRecordLocked(rotated, sealedRecord, /* allowRotateReserve= */ true);
        rotateIntoPlace(rotated);
      } else {
        appendRecordLocked(currentLogFile, sealedRecord, /* allowRotateReserve= */ false);
      }
    } catch (IOException e) {
      // lastTag is not advanced, so the next record chains onto the last persisted one.
      Log.e(TAG, "Error writing audit event to file: " + eventType, e);
      if (recordFailure) {
        recordWriteFailureLocked(event.getTimestamp());
      }
      return null;
    }
    lastTag = nextTag.get();
    lastSequenceNumber = event.getSequenceNumber().getAsLong();
    appContext
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putLong("last_sequence_number", lastSequenceNumber)
        .apply();
    return event;
  }

  private void appendRecordLocked(File file, String sealedRecord, boolean allowRotateReserve)
      throws IOException {
    boolean existedBefore = file.exists();
    long lengthBeforeWrite = file.length();
    try {
      recordWriter.appendLine(file, sealedRecord);
    } catch (IOException firstError) {
      restoreFileLength(file, existedBefore, lengthBeforeWrite);
      File fallback = allowRotateReserve && !reserveFile.exists() ? rotateReserveFile : reserveFile;
      if (!fallback.delete()) {
        throw firstError;
      }
      try {
        recordWriter.appendLine(file, sealedRecord);
      } catch (IOException retryError) {
        restoreFileLength(file, existedBefore, lengthBeforeWrite);
        throw retryError;
      }
    }
  }

  private static void restoreFileLength(File file, boolean existedBefore, long lengthBeforeWrite) {
    if (!existedBefore) {
      file.delete();
      return;
    }
    try (RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rw")) {
      randomAccessFile.setLength(lengthBeforeWrite);
    } catch (IOException e) {
      Log.w(TAG, "Failed to truncate partial audit log write.", e);
    }
  }

  static void appendLineToFile(File file, String line) throws IOException {
    Files.write(
        file.toPath(),
        (line + "\n").getBytes(UTF_8),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND);
  }

  private void ensureAuxiliaryFilesLocked() {
    ensureReserveFile(reserveFile, RESERVE_FILE_BYTES);
    ensureReserveFile(rotateReserveFile, ROTATE_RESERVE_FILE_BYTES);
    if (dropMarkerFile.length() != DROP_MARKER_FILE_BYTES) {
      persistDroppedStateLocked();
    }
  }

  private static void ensureReserveFile(File file, int sizeBytes) {
    if (file.length() != sizeBytes) {
      try {
        Files.write(file.toPath(), new byte[sizeBytes]);
      } catch (IOException e) {
        Log.w(TAG, "Unable to preallocate audit log reserve file.", e);
      }
    }
  }

  private void recordWriteFailureLocked(Instant eventTimestamp) {
    Instant failureTime = eventTimestamp.truncatedTo(ChronoUnit.MILLIS);
    if (droppedWriteCount == 0) {
      firstFailureTime = failureTime;
    }
    lastFailureTime = failureTime;
    droppedWriteCount++;
    persistDroppedStateLocked();
  }

  private void clearDroppedStateLocked() {
    droppedWriteCount = 0;
    firstFailureTime = Instant.EPOCH;
    lastFailureTime = Instant.EPOCH;
    persistDroppedStateLocked();
  }

  private void loadDroppedStateLocked() {
    if (dropMarkerFile.length() != DROP_MARKER_FILE_BYTES) {
      return;
    }
    try {
      ByteBuffer buffer = ByteBuffer.wrap(Files.readAllBytes(dropMarkerFile.toPath()));
      droppedWriteCount = buffer.getInt();
      firstFailureTime = Instant.ofEpochMilli(buffer.getLong());
      lastFailureTime = Instant.ofEpochMilli(buffer.getLong());
    } catch (IOException e) {
      Log.w(TAG, "Unable to read audit drop marker.", e);
    }
  }

  private void persistDroppedStateLocked() {
    try (RandomAccessFile raf = new RandomAccessFile(dropMarkerFile, "rw")) {
      raf.write(
          ByteBuffer.allocate(DROP_MARKER_FILE_BYTES)
              .putInt(droppedWriteCount)
              .putLong(firstFailureTime.toEpochMilli())
              .putLong(lastFailureTime.toEpochMilli())
              .array());
      raf.getFD().sync();
    } catch (IOException e) {
      Log.w(TAG, "Unable to persist audit drop marker.", e);
    }
  }

  /**
   * Logs an event once the data key has replaced a stored key that could not be unwrapped, stating
   * how many records can no longer be read.
   */
  private void logDataKeyReplacement() {
    if (dataKey.takeStoredKeyReplacement()) {
      logEvent(
          KEY_REPLACED_EVENT_TYPE,
          "The activity log key could not be recovered and was replaced. Earlier records that"
              + " can no longer be read: "
              + countUnreadableRecords()
              + ".");
    }
  }

  /** Returns how many persisted records are sealed under a data key that is no longer available. */
  private long countUnreadableRecords() {
    synchronized (fileLock) {
      return readPersistedLines().stream().filter(this::isUnreadable).count();
    }
  }

  private boolean isUnreadable(String line) {
    try {
      var unused = sealer.unseal(line);
      return false;
    } catch (GeneralSecurityException | IOException e) {
      return true;
    }
  }

  private void addToMemoryCache(CrumblesAuditEvent event) {
    synchronized (memoryCache) {
      memoryCache.addFirst(event);
      if (memoryCache.size() > CrumblesConstants.MAX_MEMORY_EVENTS) {
        memoryCache.removeLast();
      }
    }
  }

  /**
   * Returns whether {@code event} may be persisted, counting it against the rate limit of its type.
   * Must be called with {@link #fileLock} held.
   *
   * <p>A type may write {@link #MAX_RECORDS_PER_EVENT_TYPE} records per window, which starts with
   * its first event. The first event over the limit writes a record saying so, and the first event
   * logged after the window ends writes how many events of the type were not recorded.
   */
  private boolean isWithinRateLimit(CrumblesAuditEvent event) {
    long nowElapsed = SystemClock.elapsedRealtime();
    reportEndedRateLimitWindows(nowElapsed, event.getTimestamp());
    RateLimitWindow window =
        rateLimitWindows.computeIfAbsent(
            event.getEventType(), unused -> new RateLimitWindow(nowElapsed, event.getTimestamp()));
    if (window.recordedEvents < MAX_RECORDS_PER_EVENT_TYPE) {
      window.recordedEvents++;
      return true;
    }
    window.droppedEvents++;
    if (window.droppedEvents == 1) {
      persistAndCache(
          new CrumblesAuditEvent(
              event.getTimestamp(),
              AUDIT_EVENTS_RATE_LIMITED_EVENT_TYPE,
              "More than "
                  + MAX_RECORDS_PER_EVENT_TYPE
                  + " "
                  + event.getEventType()
                  + " events in "
                  + RATE_LIMIT_WINDOW.toMinutes()
                  + " minutes; further ones until "
                  + window.endInstant()
                  + " are counted but not recorded."));
    }
    return false;
  }

  private void reportEndedRateLimitWindows(long nowElapsed, Instant nowInstant) {
    Iterator<Map.Entry<String, RateLimitWindow>> windows = rateLimitWindows.entrySet().iterator();
    while (windows.hasNext()) {
      Map.Entry<String, RateLimitWindow> entry = windows.next();
      RateLimitWindow window = entry.getValue();
      if (!window.isEnded(nowElapsed)) {
        continue;
      }
      windows.remove();
      if (window.droppedEvents > 0) {
        persistAndCache(
            new CrumblesAuditEvent(
                nowInstant,
                AUDIT_EVENTS_RATE_LIMITED_EVENT_TYPE,
                window.droppedEvents
                    + " "
                    + entry.getKey()
                    + " events from "
                    + window.startInstant
                    + " to "
                    + window.endInstant()
                    + " were counted but not recorded."));
      }
    }
  }

  /**
   * Loads the data key when the logger starts, which keeps key generation, slow with StrongBox, out
   * of the first {@link #logEvent} call.
   */
  private void loadDataKey() {
    try {
      dataKey.load();
    } catch (GeneralSecurityException | IOException e) {
      // Sealing and unsealing try again.
      Log.e(TAG, "Unable to load the audit log data key", e);
    }
  }

  /**
   * Seals in place the records that earlier versions wrote in cleartext, so that none of the
   * history stays readable. A file whose records cannot all be sealed is left as it is.
   */
  private void sealCleartextRecords() {
    synchronized (fileLock) {
      sealCleartextRecords(oldLogFile);
      sealCleartextRecords(currentLogFile);
    }
  }

  private void sealCleartextRecords(File file) {
    ImmutableList<String> lines = readNonEmptyLines(file);
    if (lines.stream().allMatch(CrumblesAuditRecordSealer::isSealed)) {
      return;
    }
    File sealedFile = new File(file.getPath() + CrumblesConstants.TEMP_FILE_SUFFIX);
    try {
      writeSealedCopy(lines, sealedFile);
      Files.move(sealedFile.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE);
    } catch (GeneralSecurityException | IOException e) {
      // The records stay readable in cleartext, and sealing them is retried at the next start.
      Log.e(TAG, "Unable to seal the cleartext records of " + file.getName(), e);
      if (sealedFile.exists() && !sealedFile.delete()) {
        Log.e(TAG, "Failed to delete " + sealedFile.getName());
      }
    }
  }

  /** Writes {@code lines} to {@code sealedFile}, sealing those that are still in cleartext. */
  private void writeSealedCopy(List<String> lines, File sealedFile)
      throws GeneralSecurityException, IOException {
    try (FileOutputStream output = new FileOutputStream(sealedFile)) {
      for (String line : lines) {
        String sealedLine = CrumblesAuditRecordSealer.isSealed(line) ? line : sealer.seal(line);
        output.write((sealedLine + "\n").getBytes(UTF_8));
      }
      // The cleartext file is only replaced once its sealed copy is durable.
      output.getFD().sync();
    }
  }

  private void rotateLogFiles(Instant timestamp) {
    var unused =
        persistEventLocked(
            new CrumblesAuditEvent(timestamp, AUDIT_LOG_ROTATED_EVENT_TYPE, describeOldLogFile()),
            /* rotateToOld= */ true,
            /* recordFailure= */ true);
  }

  private void rotateIntoPlace(File rotated) throws IOException {
    Log.i(TAG, "Audit log file size threshold reached. Rotating logs.");
    try {
      if (currentLogFile.exists()) {
        Files.move(
            currentLogFile.toPath(), oldLogFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
      } else {
        // The rotation record describes the old file as discarded, so discard it as before.
        Files.deleteIfExists(oldLogFile.toPath());
      }
      Files.move(rotated.toPath(), currentLogFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      rotated.delete();
      throw e;
    }
  }

  /** Returns the rotation tombstone message, which describes the records of the old log file. */
  private String describeOldLogFile() {
    if (!oldLogFile.exists()) {
      return "Audit log rotated; no records discarded.";
    }
    byte[] discardedFile;
    byte[] digest;
    try {
      discardedFile = Files.readAllBytes(oldLogFile.toPath());
      digest = MessageDigest.getInstance("SHA-256").digest(discardedFile);
    } catch (IOException | NoSuchAlgorithmException e) {
      Log.e(TAG, "Unable to digest the audit log file to be discarded.", e);
      return "Audit log rotated; failed to digest the discarded records.";
    }
    String firstTag = "none";
    String lastTag = "none";
    long discardedRecords = 0;
    Iterable<String> lines = Splitter.on('\n').split(new String(discardedFile, UTF_8));
    for (String line : lines) {
      if (!line.trim().isEmpty()) {
        discardedRecords++;
        if (Objects.equals(firstTag, "none")) {
          firstTag = tagOf(line).orElse("none");
        }
        lastTag = tagOf(line).orElse("none");
      }
    }
    return "Audit log rotated; "
        + discardedRecords
        + " records discarded, SHA-256 of the discarded file: "
        + BaseEncoding.base16().lowerCase().encode(digest)
        + ", first tag: "
        + firstTag
        + ", last tag: "
        + lastTag
        + ".";
  }

  private void rebuildRateLimitsFromTail() {
    long nowElapsed = SystemClock.elapsedRealtime();
    Instant nowInstant = clock.instant();
    List<CrumblesAuditEvent> events = new ArrayList<>();
    synchronized (fileLock) {
      for (String line : readPersistedLines()) {
        parseEvent(line).ifPresent(events::add);
      }
    }
    for (CrumblesAuditEvent event : events) {
      long ageMillis = nowInstant.toEpochMilli() - event.getTimestamp().toEpochMilli();
      if (ageMillis < 0) {
        continue;
      }
      long eventElapsedRealtime = nowElapsed - ageMillis;
      if (Objects.equals(event.getEventType(), AUDIT_EVENTS_RATE_LIMITED_EVENT_TYPE)) {
        Matcher mStart = RATE_LIMIT_START_PATTERN.matcher(event.getMessage());
        if (mStart.find()) {
          RateLimitWindow window =
              getOrCreateActiveWindow(mStart.group(1), eventElapsedRealtime, event.getTimestamp());
          window.recordedEvents = MAX_RECORDS_PER_EVENT_TYPE;
          window.droppedEvents = 1;
        } else {
          Matcher mEnd = RATE_LIMIT_END_PATTERN.matcher(event.getMessage());
          if (mEnd.find()) {
            rateLimitWindows.remove(mEnd.group(1));
          }
        }
      } else {
        RateLimitWindow window =
            getOrCreateActiveWindow(
                event.getEventType(), eventElapsedRealtime, event.getTimestamp());
        if (window.recordedEvents < MAX_RECORDS_PER_EVENT_TYPE) {
          window.recordedEvents++;
        }
      }
    }
    rateLimitWindows.values().removeIf(window -> window.isEnded(nowElapsed));
  }

  private RateLimitWindow getOrCreateActiveWindow(
      String eventType, long eventElapsedRealtime, Instant eventTimestamp) {
    RateLimitWindow existing = rateLimitWindows.get(eventType);
    if (existing != null && existing.isEnded(eventElapsedRealtime)) {
      rateLimitWindows.remove(eventType);
    }
    return rateLimitWindows.computeIfAbsent(
        eventType, unused -> new RateLimitWindow(eventElapsedRealtime, eventTimestamp));
  }

  private void loadInitialCacheFromFiles() {
    // Records in the order they were appended, newest first, as in getAllPersistedEventsForDisplay.
    List<CrumblesAuditEvent> loadedEvents = new ArrayList<>();
    readLastNEntriesFromFile(oldLogFile, loadedEvents, CrumblesConstants.MAX_MEMORY_EVENTS);
    readLastNEntriesFromFile(currentLogFile, loadedEvents, CrumblesConstants.MAX_MEMORY_EVENTS);
    Collections.reverse(loadedEvents);

    synchronized (memoryCache) {
      memoryCache.clear();
      int limit = min(loadedEvents.size(), CrumblesConstants.MAX_MEMORY_EVENTS);
      for (int i = 0; i < limit; i++) {
        memoryCache.add(loadedEvents.get(i));
      }
    }
    Log.d(TAG, "Initial audit log cache loaded with " + memoryCache.size() + " events.");
  }

  private void readLastNEntriesFromFile(File file, List<CrumblesAuditEvent> targetList, int n) {
    if (file == null || !file.exists() || file.length() == 0) {
      return;
    }
    ArrayDeque<CrumblesAuditEvent> fileEvents = new ArrayDeque<>();
    synchronized (fileLock) {
      try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
        String line;
        while ((line = bufferedReader.readLine()) != null) {
          if (!line.trim().isEmpty()) {
            parseEvent(line).ifPresent(fileEvents::add);
            if (fileEvents.size() > n) {
              fileEvents.removeFirst();
            }
          }
        }
      } catch (IOException e) {
        Log.e(TAG, "Error reading tail of audit log file: " + file.getName(), e);
      }
    }
    targetList.addAll(fileEvents);
  }

  /**
   * Returns how many events could not be signed since this logger was created or its logs were last
   * cleared. Such events are kept in the memory cache but are not persisted to the audit log file.
   */
  public int getSigningFailureCount() {
    synchronized (fileLock) {
      return signingFailureCount;
    }
  }

  /**
   * Returns how many signed events could not be sealed since this logger was created or its logs
   * were last cleared. Such events are kept in the memory cache but are not persisted, because the
   * audit log file never holds records in cleartext.
   */
  public int getSealingFailureCount() {
    synchronized (fileLock) {
      return sealingFailureCount;
    }
  }

  /** Returns how many events could not be written since startup, clearing, or summary flush. */
  public int getWriteFailureCount() {
    synchronized (fileLock) {
      return droppedWriteCount;
    }
  }

  public List<CrumblesAuditEvent> getMemoryCachedEvents() {
    synchronized (memoryCache) {
      return new ArrayList<>(memoryCache);
    }
  }

  /**
   * Returns the persisted records newest first, in the order they were appended.
   *
   * <p>The records are not sorted by timestamp: timestamps come from the wall clock, which anyone
   * holding the unlocked phone can set back so that the records of what they then do sort below
   * older ones. The order of the records is covered by the chain HMAC instead.
   */
  public List<CrumblesAuditEvent> getAllPersistedEventsForDisplay() {
    List<CrumblesAuditEvent> allEvents = new ArrayList<>();
    synchronized (fileLock) {
      reportEndedRateLimitWindows(SystemClock.elapsedRealtime(), clock.instant());
      for (String line : readPersistedLines()) {
        parseEvent(line).ifPresent(allEvents::add);
      }
    }
    logDataKeyReplacement();
    Collections.reverse(allEvents);
    return allEvents;
  }

  /**
   * Returns the records logged since the last record sealed into a stored log batch, in file order,
   * with the tag of that record and the current chain head. The records are unsealed, as the batch
   * is encrypted to its recipient.
   *
   * <p>If no record was sealed yet, or the last sealed record is no longer on this device, the
   * excerpt holds every record on the device, and in the latter case it also reports the gap.
   */
  public CrumblesAuditExcerpt getUnshippedExcerpt() {
    CrumblesAuditExcerpt excerpt;
    synchronized (fileLock) {
      flushDroppedSummaryLocked(clock.instant());
      reportEndedRateLimitWindows(SystemClock.elapsedRealtime(), clock.instant());
      List<String> records = new ArrayList<>();
      readRecordLines(oldLogFile, records);
      readRecordLines(currentLogFile, records);
      String shippedThroughTag =
          appContext
              .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
              .getString(CrumblesConstants.PREF_AUDIT_SHIPPED_THROUGH_TAG, /* defValue= */ null);
      int shippedThroughIndex =
          shippedThroughTag == null ? -1 : lastIndexOfTag(records, shippedThroughTag);
      excerpt =
          new CrumblesAuditExcerpt(
              shippedThroughTag,
              /* previousRecordMissing= */ shippedThroughTag != null && shippedThroughIndex < 0,
              records.subList(shippedThroughIndex + 1, records.size()).stream()
                  .map(this::unsealForExcerpt)
                  .collect(toImmutableList()),
              lastTag);
    }
    logDataKeyReplacement();
    return excerpt;
  }

  /**
   * Returns the record on {@code line}, unsealed. A record that cannot be unsealed stays sealed, and
   * so does one that does not start with an opening brace, which could forge the excerpt markers.
   */
  private String unsealForExcerpt(String line) {
    String record;
    try {
      record = sealer.unseal(line);
    } catch (GeneralSecurityException | IOException e) {
      // Its chain tag is in the clear, so the recipient can still follow the chain.
      return line;
    }
    return record.startsWith("{") ? record : line;
  }

  /**
   * Records that {@code excerpt} is sealed into a stored log batch, so that later excerpts start
   * after its last tagged record. An excerpt without tagged records keeps the current cursor.
   */
  public void markShipped(CrumblesAuditExcerpt excerpt) {
    Optional<String> lastRecordTag = excerpt.lastRecordTag();
    if (lastRecordTag.isEmpty()) {
      return;
    }
    appContext
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(CrumblesConstants.PREF_AUDIT_SHIPPED_THROUGH_TAG, lastRecordTag.get())
        .apply();
  }

  /** Appends the lines of {@code file} that hold a JSON record, exactly as persisted. */
  private static void readRecordLines(File file, List<String> records) {
    if (!file.exists()) {
      return;
    }
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(new FileInputStream(file), UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        // Other lines are dropped so that a corrupted log cannot forge the markers of an excerpt.
        if (line.startsWith("{")) {
          records.add(line);
        }
      }
    } catch (IOException e) {
      Log.e(TAG, "Error reading audit log file: " + file.getName(), e);
    }
  }

  private static int lastIndexOfTag(List<String> records, String tag) {
    for (int i = records.size() - 1; i >= 0; i--) {
      if (tagOf(records.get(i)).equals(Optional.of(tag))) {
        return i;
      }
    }
    return -1;
  }

  /** Returns the tag of the record on {@code line}, or empty if it has none or is unreadable. */
  private static Optional<String> tagOf(String line) {
    // Sealed records keep their tag in the clear.
    Optional<String> sealedChainTag = CrumblesAuditRecordSealer.sealedChainTag(line);
    if (sealedChainTag.isPresent()) {
      return sealedChainTag;
    }
    try {
      return Optional.ofNullable(CrumblesAuditEvent.fromJsonString(line).getTag());
    } catch (JSONException e) {
      return Optional.empty();
    }
  }

  /** Returns the non-empty lines of the old log file followed by those of the current one. */
  private ImmutableList<String> readPersistedLines() {
    return ImmutableList.<String>builder()
        .addAll(readNonEmptyLines(oldLogFile))
        .addAll(readNonEmptyLines(currentLogFile))
        .build();
  }

  private static ImmutableList<String> readNonEmptyLines(File file) {
    if (file == null || !file.exists() || file.length() == 0) {
      return ImmutableList.of();
    }
    ImmutableList.Builder<String> lines = ImmutableList.builder();
    try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
      String line;
      while ((line = bufferedReader.readLine()) != null) {
        if (!line.trim().isEmpty()) {
          lines.add(line);
        }
      }
    } catch (IOException e) {
      Log.e(TAG, "Error reading audit events from file: " + file.getName(), e);
    }
    return lines.build();
  }

  /**
   * Parses a single audit log line, unsealing it if needed, and logs and returns empty if the line
   * is malformed or cannot be unsealed.
   */
  private Optional<CrumblesAuditEvent> parseEvent(String line) {
    try {
      return Optional.of(CrumblesAuditEvent.fromJsonString(sealer.unseal(line)));
    } catch (JSONException e) {
      Log.e(TAG, "Skipping malformed audit log line.", e);
      return Optional.empty();
    } catch (GeneralSecurityException | IOException e) {
      Log.e(TAG, "Skipping audit log line that cannot be unsealed.", e);
      return Optional.empty();
    }
  }

  /**
   * Deletes all persisted audit records, then writes a signed tombstone record chained from {@link
   * CrumblesAuditEvent#GENESIS_TAG} that states how many records were removed, or that they could
   * not be counted.
   */
  public void clearAllLogs() {
    clearAllLogs(/* unsealedRecordCount= */ 0);
  }

  /**
   * Deletes all persisted audit records and writes a signed tombstone naming the removed count and,
   * if positive, {@code unsealedRecordCount} unshipped records not sealed before clearing.
   */
  public void clearAllLogs(int unsealedRecordCount) {
    clear(unsealedRecordCount, /* keptRecords= */ ImmutableList.of());
  }

  /**
   * Clears the activity log as {@link #clearAllLogs()} does, but keeps the records that no stored
   * log batch carries yet, such as those logged while the batch sealed before the clear was being
   * written, or by another thread since: they follow the tombstone as new records of the new chain,
   * so that the next batch ships them. Returns how many records were kept.
   *
   * <p>A record that cannot be unsealed is not kept: its data key is gone, so no one could read it.
   */
  @CanIgnoreReturnValue
  public int clearShippedLogs() {
    // Holding fileLock throughout, no record can be logged between reading the unshipped records
    // and clearing them.
    synchronized (fileLock) {
      ImmutableList.Builder<CrumblesAuditEvent> keptRecords = ImmutableList.builder();
      for (String record : getUnshippedExcerpt().records) {
        try {
          CrumblesAuditEvent event = CrumblesAuditEvent.fromJsonString(record);
          keptRecords.add(
              new CrumblesAuditEvent(
                  event.getTimestamp(), event.getEventType(), event.getMessage()));
        } catch (JSONException e) {
          Log.e(TAG, "Dropping an unshipped audit record that cannot be read.", e);
        }
      }
      ImmutableList<CrumblesAuditEvent> kept = keptRecords.build();
      clear(/* unsealedRecordCount= */ 0, kept);
      return kept.size();
    }
  }

  /**
   * Deletes all persisted audit records, writes the tombstone, then appends {@code keptRecords} as
   * the next records of the new chain.
   */
  private void clear(int unsealedRecordCount, ImmutableList<CrumblesAuditEvent> keptRecords) {
    synchronized (memoryCache) {
      memoryCache.clear();
    }
    synchronized (fileLock) {
      rateLimitWindows.clear();
      int priorDropped = droppedWriteCount;
      Instant priorFirstTime = firstFailureTime;
      String tombstoneMessage = buildTombstoneMessage(unsealedRecordCount, keptRecords.size());
      if (currentLogFile.exists() && !currentLogFile.delete()) {
        Log.e(TAG, "Failed to delete current audit log file.");
      }
      if (oldLogFile.exists() && !oldLogFile.delete()) {
        Log.e(TAG, "Failed to delete old audit log file.");
      }
      destroyDataKey();
      // New records chain from the genesis tag, or from what is left if a delete failed. Their
      // numbering continues, so the tombstone's number shows how many records came before it.
      lastTag = loadLastTag();
      if (lastTag == null) {
        lastSequenceNumber = Math.max(0, lastSequenceNumber - keptRecords.size());
      }
      signingFailureCount = 0;
      sealingFailureCount = 0;
      clearDroppedStateLocked();
      // Still holding the reentrant fileLock, so the tombstone is the first record of the
      // new chain. It is not subject to the rate limit.
      CrumblesAuditEvent tombstone =
          new CrumblesAuditEvent(clock.instant(), AUDIT_LOG_CLEARED_EVENT_TYPE, tombstoneMessage);
      addToMemoryCache(tombstone);
      persist(tombstone);
      if (droppedWriteCount > 0 && priorDropped > 0) {
        droppedWriteCount += priorDropped;
        firstFailureTime = priorFirstTime;
        persistDroppedStateLocked();
      }
      // Like the tombstone, the kept records are not subject to the rate limit.
      for (CrumblesAuditEvent keptRecord : keptRecords) {
        persistAndCache(keptRecord);
      }
    }
  }

  /**
   * Returns the tombstone message, which states the number of removed records if it is known, and
   * how many unshipped records could not be sealed before clearing or follow it.
   */
  private String buildTombstoneMessage(int unsealedRecordCount, int keptRecordCount) {
    String lostSuffix =
        droppedWriteCount > 0
            ? " (" + droppedWriteCount + " unpersisted records were also lost)"
            : "";
    String baseMessage;
    try {
      long removedRecords = countRecords(oldLogFile) + countRecords(currentLogFile);
      baseMessage = "Audit log cleared; " + removedRecords + " records removed" + lostSuffix + ".";
    } catch (IOException | UncheckedIOException e) {
      Log.e(TAG, "Error counting audit records to be removed.", e);
      baseMessage = "Audit log cleared; failed to count removed records" + lostSuffix + ".";
    }
    if (unsealedRecordCount > 0) {
      baseMessage +=
          " (" + unsealedRecordCount + " unshipped records could not be sealed before clear)";
    }
    if (keptRecordCount > 0) {
      baseMessage += " (" + keptRecordCount + " unshipped records follow)";
    }
    return baseMessage;
  }

  private static long countRecords(File file) throws IOException {
    if (!file.exists()) {
      return 0;
    }
    try (Stream<String> lines = Files.lines(file.toPath(), UTF_8)) {
      return lines.filter(line -> !line.trim().isEmpty()).count();
    }
  }

  /**
   * Destroys the data key, so that the cleared records can never be unsealed again, not even from
   * copies left on flash or by a failed delete. New records are sealed under a new data key.
   */
  private void destroyDataKey() {
    try {
      dataKey.destroy();
    } catch (GeneralSecurityException | IOException e) {
      Log.e(TAG, "Unable to destroy the audit log data key", e);
    }
  }

  public static synchronized void setInstanceForTest(CrumblesAppAuditLogger testInstance) {
    instance = testInstance;
  }

  @Nullable
  private String loadLastTag() {
    for (String line : readPersistedLines().reverse()) {
      // Sealed records keep their tag in the clear, so the chain head is known even when the data
      // key cannot be loaded.
      Optional<String> tag = CrumblesAuditRecordSealer.sealedChainTag(line);
      if (tag.isEmpty()) {
        tag = parseEvent(line).map(CrumblesAuditEvent::getTag);
      }
      if (tag.isPresent()) {
        return tag.get();
      }
    }
    return null;
  }

  /**
   * Returns the sequence number of the newest readable record, or 0 if that record predates
   * numbering or no record is readable, in which case numbering starts again from 1.
   */
  private long loadLastSequenceNumber() {
    long pref =
        appContext
            .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
            .getLong("last_sequence_number", 0);
    long newestOnDisk = 0;
    long trailingUnreadableSealed = 0;
    ImmutableList<String> lines;
    synchronized (fileLock) {
      lines = readPersistedLines();
    }
    for (int i = lines.size() - 1; i >= 0; i--) {
      String line = lines.get(i);
      Optional<CrumblesAuditEvent> evt = parseEvent(line);
      if (evt.isPresent()) {
        if (evt.get().getSequenceNumber().isPresent()) {
          newestOnDisk = evt.get().getSequenceNumber().getAsLong() + trailingUnreadableSealed;
          break;
        }
      } else if (CrumblesAuditRecordSealer.sealedChainTag(line).isPresent()) {
        trailingUnreadableSealed++;
      }
    }
    if (newestOnDisk == 0) {
      newestOnDisk = trailingUnreadableSealed;
    }
    return Math.max(pref, newestOnDisk);
  }

  public CrumblesChainVerification verifyChain() {
    ImmutableList<String> lines;
    int currentLogStartIndex;
    synchronized (fileLock) {
      ImmutableList<String> oldLines = readNonEmptyLines(oldLogFile);
      ImmutableList<String> currentLines = readNonEmptyLines(currentLogFile);
      lines = ImmutableList.<String>builder().addAll(oldLines).addAll(currentLines).build();
      currentLogStartIndex = oldLines.size();
    }
    try {
      Optional<SecretKey> key = loadChainKey();
      if (key.isPresent()) {
        // Loaded first, so that a record failing to unseal can only mean an altered record.
        dataKey.load();
        return verifyRecords(lines, currentLogStartIndex, key.get());
      }
    } catch (GeneralSecurityException | IOException e) {
      // Keystore errors say nothing about the records, so they must not be reported as a break.
      Log.e(TAG, "Unable to verify the audit chain", e);
    } catch (RuntimeException e) {
      Log.e(TAG, "Unable to verify the audit chain: check not possible", e);
    }
    return new CrumblesChainVerification(
        lines.size(), /* verifiedRecords= */ 0, lines.size(), /* firstBrokenIndex= */ -1);
  }

  /** Verifies the HMAC chain over {@code lines}, the persisted records from oldest to newest. */
  private CrumblesChainVerification verifyRecords(
      List<String> lines, int currentLogStartIndex, SecretKey key) throws GeneralSecurityException {
    List<Optional<CrumblesAuditEvent>> parsedEvents = new ArrayList<>(lines.size());
    for (String line : lines) {
      parsedEvents.add(parseEvent(line));
    }

    String expectedPrevious = CrumblesAuditEvent.GENESIS_TAG;
    if (currentLogStartIndex < lines.size()) {
      Optional<CrumblesAuditEvent> evt = parsedEvents.get(currentLogStartIndex);
      if (evt.isPresent()
          && Objects.equals(evt.get().getEventType(), AUDIT_LOG_ROTATED_EVENT_TYPE)) {
        String msg = evt.get().getMessage();
        int idx = msg.lastIndexOf("last tag: ");
        if (idx >= 0) {
          expectedPrevious = msg.substring(idx + 10);
          if (expectedPrevious.endsWith(".")) {
            expectedPrevious = expectedPrevious.substring(0, expectedPrevious.length() - 1);
          }
          if (expectedPrevious.equals("none")) {
            expectedPrevious = CrumblesAuditEvent.GENESIS_TAG;
          }
        }
      }
    }

    Optional<CrumblesAuditEvent> lastKeyReplaced = Optional.empty();
    String scanPrevTag = null;
    Iterator<Optional<CrumblesAuditEvent>> parsedIterator = parsedEvents.iterator();
    for (String line : lines) {
      Optional<CrumblesAuditEvent> evt = parsedIterator.next();
      String lineTag =
          evt.map(CrumblesAuditEvent::getTag)
              .or(() -> CrumblesAuditRecordSealer.sealedChainTag(line))
              .orElse(null);
      if (evt.isPresent()
          && lineTag != null
          && Objects.equals(evt.get().getEventType(), KEY_REPLACED_EVENT_TYPE)) {
        String anchor = scanPrevTag != null ? scanPrevTag : expectedPrevious;
        if (lineTag.equals(evt.get().computeTag(key, anchor))) {
          lastKeyReplaced = evt;
        }
      }
      if (lineTag != null) {
        scanPrevTag = lineTag;
      }
    }

    String previousTag = null;
    Long previousSeq = null;
    boolean seenReadableSealedRecord = false;
    int verified = 0;
    int unverifiable = 0;
    for (int i = 0; i < lines.size(); i++) {
      String line = lines.get(i);
      Optional<CrumblesAuditEvent> parsedEvent = parsedEvents.get(i);
      if (parsedEvent.isPresent() && CrumblesAuditRecordSealer.isSealed(line)) {
        seenReadableSealedRecord = true;
      }
      String tag = parsedEvent.map(CrumblesAuditEvent::getTag).orElse(null);
      Long curSeq =
          parsedEvent.isPresent() && parsedEvent.get().getSequenceNumber().isPresent()
              ? parsedEvent.get().getSequenceNumber().getAsLong()
              : null;

      if (tag == null) {
        tag = CrumblesAuditRecordSealer.sealedChainTag(line).orElse(null);
      }

      if (tag == null) {
        // Once a record has been verified, an untagged or malformed record is a gap in the chain.
        if (verified > 0) {
          return new CrumblesChainVerification(lines.size(), verified, unverifiable, i);
        }
        unverifiable++;
      } else if (previousTag == null) {
        if (parsedEvent.isPresent()
            && tag.equals(parsedEvent.get().computeTag(key, expectedPrevious))) {
          if (i == 0
              && expectedPrevious.equals(CrumblesAuditEvent.GENESIS_TAG)
              && curSeq != null
              && curSeq > 1L
              && !Objects.equals(parsedEvent.get().getEventType(), AUDIT_LOG_CLEARED_EVENT_TYPE)) {
            return new CrumblesChainVerification(lines.size(), verified, unverifiable, i);
          }
          verified++;
        } else {
          if (curSeq != null) {
            return new CrumblesChainVerification(lines.size(), verified, unverifiable, i);
          }
          unverifiable++;
        }
      } else {
        if (parsedEvent.isPresent() && curSeq == null && previousSeq != null) {
          return new CrumblesChainVerification(lines.size(), verified, unverifiable, i);
        }
        if (curSeq != null && previousSeq != null && !curSeq.equals(previousSeq + 1L)) {
          return new CrumblesChainVerification(lines.size(), verified, unverifiable, i);
        }

        if (parsedEvent.isPresent() && tag.equals(parsedEvent.get().computeTag(key, previousTag))) {
          verified++;
        } else if (parsedEvent.isEmpty()
            && (lastKeyReplaced.isPresent() || !seenReadableSealedRecord)) {
          unverifiable++;
        } else {
          return new CrumblesChainVerification(lines.size(), verified, unverifiable, i);
        }
      }
      previousTag = tag;
      if (parsedEvent.isPresent()) {
        previousSeq = curSeq;
        if (parsedEvent.equals(lastKeyReplaced)) {
          lastKeyReplaced = Optional.empty();
        }
      } else if (previousSeq != null) {
        previousSeq = previousSeq + 1L;
      }
    }
    return new CrumblesChainVerification(
        lines.size(), verified, unverifiable, /* firstBrokenIndex= */ -1);
  }

  /** Returns the tag chaining {@code event} onto {@code previousTag}, or empty on failure. */
  private static Optional<String> signEvent(CrumblesAuditEvent event, String previousTag) {
    try {
      Optional<SecretKey> key = loadChainKey();
      SecretKey chainKey = key.isPresent() ? key.get() : generateChainKey();
      return Optional.of(event.computeTag(chainKey, previousTag));
    } catch (GeneralSecurityException | IOException | ProviderException e) {
      // AndroidKeyStore throws an unchecked ProviderException when a Keystore operation fails, as
      // on a faulty StrongBox. Like the checked failures, it must not escape logEvent.
      Log.e(TAG, "Unable to compute audit chain HMAC tag", e);
      return Optional.empty();
    }
  }

  /** Returns the audit chain key, or empty if it has not been generated yet. */
  private static Optional<SecretKey> loadChainKey() throws GeneralSecurityException, IOException {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);
    return keyStore.getKey(CHAIN_KEY_ALIAS, /* password= */ null) instanceof SecretKey secretKey
        ? Optional.of(secretKey)
        : Optional.empty();
  }

  private static SecretKey generateChainKey() throws GeneralSecurityException {
    try {
      return generateChainKey(/* strongBoxBacked= */ true);
    } catch (GeneralSecurityException | ProviderException e) {
      return generateChainKey(/* strongBoxBacked= */ false);
    }
  }

  private static SecretKey generateChainKey(boolean strongBoxBacked)
      throws GeneralSecurityException {
    KeyGenerator keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE);
    keyGenerator.init(
        new KeyGenParameterSpec.Builder(
                CHAIN_KEY_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strongBoxBacked)
            .build());
    return keyGenerator.generateKey();
  }

  /** Counts the events of one type logged in a rate limit window. */
  private static final class RateLimitWindow {
    private final long startElapsedRealtimeMillis;
    private final Instant startInstant;
    private int recordedEvents;
    private int droppedEvents;

    private RateLimitWindow(long startElapsedRealtimeMillis, Instant startInstant) {
      this.startElapsedRealtimeMillis = startElapsedRealtimeMillis;
      this.startInstant = startInstant;
    }

    private Instant endInstant() {
      return startInstant.plus(RATE_LIMIT_WINDOW);
    }

    private boolean isEnded(long currentElapsedRealtimeMillis) {
      return currentElapsedRealtimeMillis - startElapsedRealtimeMillis
          >= RATE_LIMIT_WINDOW.toMillis();
    }
  }

  /** Result of verifying the on-disk audit log HMAC chain. */
  public static final class CrumblesChainVerification {
    private final int totalRecords;
    private final int verifiedRecords;
    private final int unverifiableRecords;
    private final int firstBrokenIndex;

    public CrumblesChainVerification(
        int totalRecords, int verifiedRecords, int unverifiableRecords, int firstBrokenIndex) {
      this.totalRecords = totalRecords;
      this.verifiedRecords = verifiedRecords;
      this.unverifiableRecords = unverifiableRecords;
      this.firstBrokenIndex = firstBrokenIndex;
    }

    public boolean isIntact() {
      return firstBrokenIndex < 0;
    }

    public int getTotalRecords() {
      return totalRecords;
    }

    public int getVerifiedRecords() {
      return verifiedRecords;
    }

    public int getUnverifiableRecords() {
      return unverifiableRecords;
    }

    public int getFirstBrokenIndex() {
      return firstBrokenIndex;
    }
  }

  /**
   * Activity log records written since the previous stored log batch, with the tag of the last
   * record of that batch and the chain head at the time they were read.
   *
   * <p>{@link #toBytes} renders the excerpt as a trailer to append to the log text of a batch. Its
   * lines are separated by {@code \n}: {@code --- Crumbles activity log since record <tag> ---}
   * naming the last record of the previous stored batch, a marker if that record is no longer on
   * this device, one unsealed record per line (sealed if it cannot be unsealed), and {@code ---
   * Crumbles activity log chain head: <tag> ---}. A missing tag reads {@code none}. Record lines
   * start with an opening brace and marker lines with {@code ---}.
   *
   * <p>The recipient checks that the since tag of each batch equals the chain head of the previous
   * batch. A mismatch means that a batch in between is missing, unless the batch is the first one
   * after a key change or a reinstall. The log text before the trailer can contain
   * attacker-controlled strings, so readers must use the last line that starts with {@code ---
   * Crumbles activity log since record}.
   */
  public static final class CrumblesAuditExcerpt {
    @Nullable private final String sinceTag;
    private final boolean previousRecordMissing;
    private final ImmutableList<String> records;
    @Nullable private final String headTag;

    private CrumblesAuditExcerpt(
        @Nullable String sinceTag,
        boolean previousRecordMissing,
        List<String> records,
        @Nullable String headTag) {
      this.sinceTag = sinceTag;
      this.previousRecordMissing = previousRecordMissing;
      this.records = ImmutableList.copyOf(records);
      this.headTag = headTag;
    }

    /** Returns whether this excerpt holds no activity records. */
    public boolean isEmpty() {
      return records.isEmpty();
    }

    /** Returns how many activity records this excerpt holds. */
    public int size() {
      return records.size();
    }

    /** Returns the tag of the newest record in the chain when the excerpt was read, if any. */
    public Optional<String> getHeadTag() {
      return Optional.ofNullable(headTag);
    }

    /** Returns the excerpt as a UTF-8 trailer to append to the log text of a batch. */
    public byte[] toBytes() {
      StringBuilder trailer =
          new StringBuilder("\n--- Crumbles activity log since record ")
              .append(sinceTag != null ? sinceTag : "none")
              .append(" ---\n");
      if (previousRecordMissing) {
        trailer.append(
            "--- The previous batch's last activity record is no longer on this device ---\n");
      }
      for (String line : records) {
        trailer.append(line).append('\n');
      }
      trailer
          .append("--- Crumbles activity log chain head: ")
          .append(getHeadTag().orElse("none"))
          .append(" ---\n");
      return trailer.toString().getBytes(UTF_8);
    }

    private Optional<String> lastRecordTag() {
      for (String line : records.reverse()) {
        Optional<String> tag = tagOf(line);
        if (tag.isPresent()) {
          return tag;
        }
      }
      return Optional.empty();
    }
  }
}
