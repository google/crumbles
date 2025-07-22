package com.android.securelogging.audit;

import static java.lang.Math.min;
import static java.util.Comparator.comparing;

import android.content.Context;
import android.util.Log;
import com.android.securelogging.CrumblesConstants;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONException;

/** CrumblesAppAuditLogger is a singleton class that logs app audit events to a file. */
public class CrumblesAppAuditLogger {
  private static final String TAG = "CrumblesAppAuditLogger";

  @SuppressWarnings("NonFinalStaticField")
  private static CrumblesAppAuditLogger instance;

  private final Context appContext;
  private final File currentLogFile;
  private final File oldLogFile;
  private final ArrayDeque<CrumblesAuditEvent> memoryCache;
  protected final Object fileLock = new Object();

  private CrumblesAppAuditLogger(Context context) {
    this.appContext = context.getApplicationContext();
    File logDir = this.appContext.getFilesDir();
    this.currentLogFile = new File(logDir, CrumblesConstants.CURRENT_LOG_FILE_NAME);
    this.oldLogFile = new File(logDir, CrumblesConstants.OLD_LOG_FILE_NAME);
    this.memoryCache = new ArrayDeque<>();
    loadInitialCacheFromFiles();
  }

  public static synchronized CrumblesAppAuditLogger getInstance(Context context) {
    if (instance == null) {
      instance = new CrumblesAppAuditLogger(context.getApplicationContext());
    }
    return instance;
  }

  public void logEvent(String eventType, String message) {
    Instant currentTimestamp = InstantSource.system().instant();
    CrumblesAuditEvent event = new CrumblesAuditEvent(currentTimestamp, eventType, message);

    Log.d(TAG, "Logging event: " + eventType + " - " + message);

    // 1. Add to in-memory cache.
    synchronized (memoryCache) {
      memoryCache.addFirst(event);
      if (memoryCache.size() > CrumblesConstants.MAX_MEMORY_EVENTS) {
        memoryCache.removeLast();
      }
    }

    // 2. Append to file and handle rotation.
    synchronized (fileLock) {
      try {
        if (currentLogFile.exists()
            && currentLogFile.length() > CrumblesConstants.MAX_LOG_FILE_SIZE_BYTES) {
          rotateLogFiles();
        }

        try (FileWriter fileWriter = new FileWriter(currentLogFile, true); // true for append.
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
          bufferedWriter.write(event.toJsonString());
          bufferedWriter.newLine();
        }
      } catch (IOException e) {
        Log.e(TAG, "Error writing audit event to file: " + eventType, e);
      }
    }
  }

  private void rotateLogFiles() {
    Log.i(TAG, "Audit log file size threshold reached. Rotating logs.");
    if (oldLogFile.exists()) {
      if (!oldLogFile.delete()) {
        Log.e(TAG, "Failed to delete old log file: " + oldLogFile.getAbsolutePath());
      }
    }
    if (currentLogFile.exists()) {
      if (!currentLogFile.renameTo(oldLogFile)) {
        Log.e(TAG, "Failed to rename current log file to old: " + currentLogFile.getAbsolutePath());
      }
    }
  }

  private void loadInitialCacheFromFiles() {
    List<CrumblesAuditEvent> loadedEvents = new ArrayList<>();
    readLastNEntriesFromFile(currentLogFile, loadedEvents, CrumblesConstants.MAX_MEMORY_EVENTS);
    readLastNEntriesFromFile(oldLogFile, loadedEvents, CrumblesConstants.MAX_MEMORY_EVENTS);

    Collections.sort(loadedEvents, comparing(CrumblesAuditEvent::getTimestamp).reversed());

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
    if (file == null || !file.exists() || file.length() == 0 || n <= 0) {
      return;
    }
    ArrayDeque<CrumblesAuditEvent> fileEvents = new ArrayDeque<>();
    synchronized (fileLock) {
      try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
        String line;
        while ((line = bufferedReader.readLine()) != null) {
          if (!line.trim().isEmpty()) {
            fileEvents.add(CrumblesAuditEvent.fromJsonString(line));
            if (fileEvents.size() > n) {
              fileEvents.removeFirst();
            }
          }
        }
      } catch (IOException | JSONException e) {
        Log.e(TAG, "Error reading tail of audit log file or parsing JSON: " + file.getName(), e);
      }
    }
    targetList.addAll(fileEvents);
  }

  public List<CrumblesAuditEvent> getMemoryCachedEvents() {
    synchronized (memoryCache) {
      return new ArrayList<>(memoryCache);
    }
  }

  public List<CrumblesAuditEvent> getAllPersistedEventsForDisplay() {
    List<CrumblesAuditEvent> allEvents = new ArrayList<>();
    synchronized (fileLock) {
      readFileContentsToList(oldLogFile, allEvents);
      readFileContentsToList(currentLogFile, allEvents);
    }
    Collections.sort(allEvents, comparing(CrumblesAuditEvent::getTimestamp).reversed());
    return allEvents;
  }

  private void readFileContentsToList(File file, List<CrumblesAuditEvent> eventsList) {
    if (file == null || !file.exists() || file.length() == 0) {
      return;
    }
    try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
      String line;
      while ((line = bufferedReader.readLine()) != null) {
        if (!line.trim().isEmpty()) {
          eventsList.add(CrumblesAuditEvent.fromJsonString(line));
        }
      }
    } catch (IOException | JSONException e) {
      Log.e(TAG, "Error reading audit events from file or parsing JSON: " + file.getName(), e);
    }
  }

  public void clearAllLogs() {
    synchronized (memoryCache) {
      memoryCache.clear();
    }
    synchronized (fileLock) {
      if (currentLogFile.exists() && !currentLogFile.delete()) {
        Log.e(TAG, "Failed to delete current audit log file.");
      }
      if (oldLogFile.exists() && !oldLogFile.delete()) {
        Log.e(TAG, "Failed to delete old audit log file.");
      }
    }
  }

  public static synchronized void setInstanceForTest(CrumblesAppAuditLogger testInstance) {
    instance = testInstance;
  }
}
