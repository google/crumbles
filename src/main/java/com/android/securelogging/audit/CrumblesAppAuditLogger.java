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

import static java.lang.Math.min;
import static java.util.Comparator.comparing;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;
import androidx.annotation.Nullable;
import com.android.securelogging.CrumblesConstants;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.json.JSONException;

/** CrumblesAppAuditLogger is a singleton class that logs app audit events to a file. */
public class CrumblesAppAuditLogger {
  private static final String TAG = "CrumblesAppAuditLogger";
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  static final String CHAIN_KEY_ALIAS = "crumbles_audit_chain_hmac_key";

  @SuppressWarnings("NonFinalStaticField")
  private static CrumblesAppAuditLogger instance;

  private final Context appContext;
  private final File currentLogFile;
  private final File oldLogFile;
  private final ArrayDeque<CrumblesAuditEvent> memoryCache;
  protected final Object fileLock = new Object();
  @Nullable private String lastTag;

  private CrumblesAppAuditLogger(Context context) {
    this.appContext = context.getApplicationContext();
    File logDir = this.appContext.getNoBackupFilesDir();
    this.currentLogFile = new File(logDir, CrumblesConstants.CURRENT_LOG_FILE_NAME);
    this.oldLogFile = new File(logDir, CrumblesConstants.OLD_LOG_FILE_NAME);
    this.memoryCache = new ArrayDeque<>();
    loadInitialCacheFromFiles();
    synchronized (fileLock) {
      this.lastTag = loadLastTag();
    }
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
      String baseTag = lastTag != null ? lastTag : CrumblesAuditEvent.GENESIS_TAG;
      String nextTag = signEvent(event, baseTag, /* createKeyIfMissing= */ true);
      event = event.withTag(nextTag);
      if (nextTag != null) {
        lastTag = nextTag;
      }
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

  @Nullable
  private String loadLastTag() {
    List<CrumblesAuditEvent> events = new ArrayList<>();
    readFileContentsToList(oldLogFile, events);
    readFileContentsToList(currentLogFile, events);
    for (int i = events.size() - 1; i >= 0; i--) {
      if (events.get(i).getTag() != null) {
        return events.get(i).getTag();
      }
    }
    return null;
  }

  public CrumblesChainVerification verifyChain() {
    List<CrumblesAuditEvent> events = new ArrayList<>();
    synchronized (fileLock) {
      readFileContentsToList(oldLogFile, events);
      readFileContentsToList(currentLogFile, events);
    }
    String previousTag = null;
    int verified = 0;
    int unverifiable = 0;
    for (int i = 0; i < events.size(); i++) {
      CrumblesAuditEvent event = events.get(i);
      String tag = event.getTag();
      String genesisTag = signEvent(event, CrumblesAuditEvent.GENESIS_TAG, false);
      if (tag == null || genesisTag == null) {
        unverifiable++;
        previousTag = tag;
        continue;
      }
      if (previousTag == null) {
        if (tag.equals(genesisTag)) {
          verified++;
        } else {
          unverifiable++;
        }
        previousTag = tag;
        continue;
      }
      if (!tag.equals(signEvent(event, previousTag, false))) {
        return new CrumblesChainVerification(events.size(), verified, unverifiable, i);
      }
      verified++;
      previousTag = tag;
    }
    return new CrumblesChainVerification(events.size(), verified, unverifiable, -1);
  }

  @Nullable
  private static String signEvent(
      CrumblesAuditEvent event, String previousTag, boolean createKeyIfMissing) {
    try {
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
      keyStore.load(null);
      Key key = keyStore.getKey(CHAIN_KEY_ALIAS, null);
      if (!(key instanceof SecretKey) && createKeyIfMissing) {
        key = generateChainKey();
      }
      return key instanceof SecretKey secretKey ? event.computeTag(secretKey, previousTag) : null;
    } catch (GeneralSecurityException | IOException e) {
      Log.e(TAG, "Unable to compute audit chain HMAC tag", e);
      return null;
    }
  }

  private static SecretKey generateChainKey() throws GeneralSecurityException {
    try {
      return generateChainKey(/* strongBoxBacked= */ true);
    } catch (StrongBoxUnavailableException e) {
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
}
