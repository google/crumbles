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

import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;

/**
 * Ends uploads that outlast their deadline.
 *
 * <p>Socket and pipe timeouts bound each read, not a whole transfer. Without a deadline, a
 * destination that sends one byte at a time, or never drains what it is sent, would hold the upload
 * and its thread indefinitely.
 */
final class CrumblesTransferDeadline {

  private static final String TAG = "CrumblesTransferDeadline";

  /** Time for a transfer without a payload, such as a TLS handshake or a connection probe. */
  private static final Duration BASE = Duration.ofMinutes(1);

  /** Slowest upload rate, in bytes per second, that a payload is given time for. */
  private static final long MIN_BYTES_PER_SECOND = 64 * 1024;

  private static final Handler watchdog = startWatchdog();

  private CrumblesTransferDeadline() {}

  /**
   * Closes {@code transfer} once a transfer without a payload, such as a TLS handshake or a
   * connection probe, has had its time, unless the returned handle is closed first.
   */
  static Disarm arm(Closeable transfer) {
    return closeAfter(BASE, transfer);
  }

  /**
   * Closes {@code transfer} once a transfer of {@code payloadBytes} has had its time, unless the
   * returned handle is closed first. Closing {@code transfer} must make any I/O blocked on it fail.
   */
  static Disarm arm(long payloadBytes, Closeable transfer) {
    return closeAfter(BASE.plusSeconds(payloadBytes / MIN_BYTES_PER_SECOND), transfer);
  }

  private static Disarm closeAfter(Duration deadline, Closeable transfer) {
    Runnable cutOff =
        () -> {
          try {
            transfer.close();
          } catch (IOException e) {
            Log.w(TAG, "Failed to end a transfer past its deadline", e);
          }
        };
    watchdog.postDelayed(cutOff, deadline.toMillis());
    return () -> watchdog.removeCallbacks(cutOff);
  }

  /** Withdraws a deadline that {@link #arm} set. */
  interface Disarm extends AutoCloseable {
    /** A handle for a transfer that has no deadline yet. */
    Disarm NONE = () -> {};

    @Override
    void close();
  }

  private static Handler startWatchdog() {
    HandlerThread thread = new HandlerThread(TAG);
    thread.start();
    return new Handler(thread.getLooper());
  }
}
