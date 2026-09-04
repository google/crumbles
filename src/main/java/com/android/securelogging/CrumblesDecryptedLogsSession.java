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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** In-memory manager retaining decrypted log entries in volatile memory. */
public final class CrumblesDecryptedLogsSession {
  private static final Object lock = new Object();
  private static final AtomicLong nextSessionId = new AtomicLong(1);
  private static final AtomicReference<CrumblesDecryptedLogsSession> activeSession = new AtomicReference<>();
  private final long sessionId;
  private final List<CrumblesDecryptedLogEntry> entries;

  private CrumblesDecryptedLogsSession(long sessionId, List<CrumblesDecryptedLogEntry> entries) {
    this.sessionId = sessionId;
    this.entries = new ArrayList<>(entries);
  }

  /** Starts a new session with the given entries, destroying any active session. */
  public static long startSession(List<CrumblesDecryptedLogEntry> entries) {
    synchronized (lock) {
      destroyActiveSession();
      long id = nextSessionId.incrementAndGet();
      activeSession.set(new CrumblesDecryptedLogsSession(id, entries));
      return id;
    }
  }

  /** Returns the active session if its ID matches {@code sessionId}. */
  public static Optional<CrumblesDecryptedLogsSession> getSession(long sessionId) {
    synchronized (lock) {
      CrumblesDecryptedLogsSession current = activeSession.get();
      return (current != null && current.sessionId == sessionId)
          ? Optional.of(current) : Optional.empty();
    }
  }

  /** Destroys the active session if its ID matches {@code sessionId}. */
  public static void destroySession(long sessionId) {
    getSession(sessionId).ifPresent(CrumblesDecryptedLogsSession::destroy);
  }

  /** Destroys the active session if one exists. */
  public static void destroyActiveSession() {
    Optional.ofNullable(activeSession.get()).ifPresent(CrumblesDecryptedLogsSession::destroy);
  }

  /** Returns an unmodifiable list of decrypted log entries in this session. */
  public List<CrumblesDecryptedLogEntry> getEntries() {
    return Collections.unmodifiableList(entries);
  }

  /** Securely wipes all log entries in this session and clears active session state. */
  public void destroy() {
    synchronized (lock) {
      activeSession.compareAndSet(this, null);
      for (CrumblesDecryptedLogEntry entry : entries) {
        entry.wipe();
      }
      entries.clear();
    }
  }
}
