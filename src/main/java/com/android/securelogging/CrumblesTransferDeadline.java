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

import android.net.Uri;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.util.concurrent.Uninterruptibles;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Ends uploads that outlast their deadline.
 *
 * <p>Socket and pipe timeouts bound each read, not a whole transfer. Without a deadline, a
 * destination that sends one byte at a time, or never drains what it is sent, would hold the upload
 * and its thread indefinitely. So would a documents provider that never answers a call.
 */
final class CrumblesTransferDeadline {

  private static final String TAG = "CrumblesTransferDeadline";

  /**
   * Time for a transfer without a payload, such as a TLS handshake or a connection probe, and for a
   * transfer to make progress.
   */
  private static final Duration BASE = Duration.ofMinutes(1);

  /**
   * Slowest upload rate, in bytes per second, that a payload is given time for. A slow or throttled
   * mobile link still gets a batch of a few MiB through.
   */
  private static final long MIN_BYTES_PER_SECOND = 8 * 1024;

  /**
   * Longest time that a transfer of any size gets: less than the ten minutes that WorkManager gives
   * a run, so that a destination that trickles a large batch cannot hold a run past its end.
   */
  private static final Duration CEILING = Duration.ofMinutes(8);

  /**
   * Time that a transfer closed past its deadline has to end before its provider counts as holding
   * it.
   */
  private static final Duration CLOSE_GRACE = Duration.ofSeconds(1);

  private static final Handler watchdog = startWatchdog();

  /**
   * Runs what can block on a provider for as long as the provider wants: calls into it, transfers
   * to and from it, and closing a transfer past its deadline. Then the caller, or the watchdog,
   * does not have to wait for it.
   */
  private static final ExecutorService blockingCalls = Executors.newCachedThreadPool();

  /** For each provider authority, the calls and transfers that outlasted their deadline. */
  private static final ConcurrentMap<String, Set<CountDownLatch>> stalledCalls =
      new ConcurrentHashMap<>();

  /** The budget of the task that this thread runs, if it runs one within a budget. */
  private static final ThreadLocal<Budget> currentBudget = new ThreadLocal<>();

  private CrumblesTransferDeadline() {}

  /**
   * Closes {@code transfer} once a transfer without a payload, such as a TLS handshake or a
   * connection probe, has had its time, unless the returned handle is closed first.
   */
  static Transfer arm(Closeable transfer) {
    // NOMUTANTS -- Integer division by MIN_BYTES_PER_SECOND yields 0 s for 0 B and 1 B.
    return arm(/* payloadBytes= */ 0, transfer);
  }

  /**
   * Closes {@code transfer} once a transfer of {@code payloadBytes} has had its time, unless the
   * returned handle is closed first. Closing {@code transfer} must make any I/O blocked on it fail.
   *
   * <p>A transfer has the time that its payload takes at {@link #MIN_BYTES_PER_SECOND}, but at most
   * {@link #CEILING}, and no longer than the budget of the task that this thread runs. It ends
   * sooner if it goes {@link #BASE} without progress, which it reports through {@link
   * Transfer#progressed}.
   */
  static Transfer arm(long payloadBytes, Closeable transfer) {
    Transfer deadline = new Transfer(payloadBytes, transfer, currentBudget.get());
    deadline.start();
    return deadline;
  }

  /**
   * Runs {@code task} on this thread within {@code budget}: the calls into documents providers and
   * the transfers that it makes end once the budget is spent, if not sooner. A budget that this
   * thread already had does not apply meanwhile.
   */
  static <T> T within(Budget budget, Supplier<T> task) {
    Budget outer = currentBudget.get();
    currentBudget.set(budget);
    try {
      return task.get();
    } finally {
      if (outer == null) {
        currentBudget.remove();
      } else {
        currentBudget.set(outer);
      }
    }
  }

  /**
   * Returns what {@code call}, a call to the documents provider of {@code document}, returns, or
   * throws what it throws, unless it takes longer than a transfer without a payload: then it throws
   * {@link ClosedChannelException}, as a transfer past its deadline does. A checked exception other
   * than an {@link IOException} comes as the cause of one. It throws that at once if the budget of
   * the task that this thread runs is spent, and when the budget runs out or stops during the call.
   *
   * <p>Binder lets a provider hold a call for as long as it wants, and nothing ends the call early.
   * So the call runs on another thread, which the provider keeps until it returns. Meanwhile, calls
   * to that provider fail at once, rather than leave it more threads.
   */
  static <T> T callProvider(Uri document, Callable<T> call) throws IOException {
    return callProvider(document, call, blockingCalls);
  }

  /** As {@link #callProvider(Uri, Callable)}, but runs {@code call} on {@code executor}. */
  static <T> T callProvider(Uri document, Callable<T> call, Executor executor) throws IOException {
    Set<CountDownLatch> stalled = stalledCallsTo(document);
    Budget budget = currentBudget.get();
    if (!stalled.isEmpty() || (budget != null && budget.isSpent())) {
      throw new ClosedChannelException();
    }
    // Set by the call as it starts, unless this thread sets it first as it stops waiting: then the
    // call never starts.
    AtomicBoolean started = new AtomicBoolean();
    CountDownLatch returned = new CountDownLatch(1);
    CompletableFuture<T> result = new CompletableFuture<>();
    Runnable task =
        () -> {
          if (!started.compareAndSet(false, true)) {
            return;
          }
          try {
            result.complete(call.call());
          } catch (Throwable failure) {
            // Propagated through ExecutionException to match FutureTask behavior.
            result.completeExceptionally(failure);
          } finally {
            returned.countDown();
          }
        };
    executor.execute(task);
    // Cancelling the result ends the wait for it, and started keeps it from starting if it has
    // not. A call in progress goes on until the provider returns it.
    Runnable cutOff = () -> result.cancel(/* mayInterruptIfRunning= */ false);
    long deadlineMillis = SystemClock.uptimeMillis() + BASE.toMillis();
    watchdog.postAtTime(
        cutOff, budget == null ? deadlineMillis : Math.min(deadlineMillis, budget.endMillis));
    if (budget != null) {
      budget.onStop(cutOff);
    }
    try {
      // The watchdog ends the wait at the deadline. The timed wait is for a watchdog that is late.
      return Uninterruptibles.getUninterruptibly(
          result, BASE.multipliedBy(2).toMillis(), TimeUnit.MILLISECONDS);
    } catch (CancellationException | TimeoutException e) {
      // A call that started holds the provider until it returns. One that has not started yet
      // never will, once this thread claims its start.
      if (!started.compareAndSet(false, true)) {
        stalled.add(returned);
      }
      ClosedChannelException closed = new ClosedChannelException();
      closed.initCause(e);
      throw closed;
    } catch (ExecutionException e) {
      Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
      Throwables.throwIfUnchecked(e.getCause());
      throw new IOException(e.getCause());
    } finally {
      watchdog.removeCallbacks(cutOff);
      if (budget != null) {
        budget.removeOnStop(cutOff);
      }
    }
  }

  /**
   * Returns what {@code transfer}, a copy to or from the documents provider of {@code document}
   * through {@code channel}, returns, or throws what it throws, unless it outlasts its deadline, as
   * {@link #arm(long, Closeable)} sets it for {@code payloadBytes}: then it throws {@link
   * ClosedChannelException}. A checked exception other than an {@link IOException} comes as the
   * cause of one. It closes {@code channel} once the transfer ends, or at the deadline, and never
   * on the calling thread.
   *
   * <p>The transfer runs on another thread. Closing the channel ends a read or write that a
   * provider leaves blocked, except on a FUSE proxy descriptor: its provider serves each read and
   * write itself, and can hold one past close() and signals. Such a transfer keeps its thread until
   * it returns, and, as for a call past its deadline, calls and transfers to that provider fail at
   * once meanwhile.
   */
  static <T> T runTransfer(
      Uri document, long payloadBytes, Closeable channel, TransferAction<T> transfer)
      throws IOException {
    return runTransfer(document, payloadBytes, channel, transfer, blockingCalls);
  }

  /**
   * As {@link #runTransfer(Uri, long, Closeable, TransferAction)}, but runs {@code transfer} on
   * {@code executor}.
   */
  static <T> T runTransfer(
      Uri document,
      long payloadBytes,
      Closeable channel,
      TransferAction<T> transfer,
      Executor executor)
      throws IOException {
    Set<CountDownLatch> stalled = stalledCallsTo(document);
    if (!stalled.isEmpty()) {
      blockingCalls.execute(() -> closeQuietly(channel));
      throw new ClosedChannelException();
    }
    // Set by the transfer as it starts, unless this thread sets it first as it stops waiting: then
    // the transfer never starts.
    AtomicBoolean started = new AtomicBoolean();
    CountDownLatch returned = new CountDownLatch(1);
    try (Transfer deadline = arm(payloadBytes, channel)) {
      // Within a spent budget, arming cuts the transfer off, which closes the channel.
      deadline.checkInTime();
      CompletableFuture<T> result = new CompletableFuture<>();
      Runnable task =
          () -> {
            if (!started.compareAndSet(false, true)) {
              return;
            }
            try (channel) {
              result.complete(transfer.run(deadline));
            } catch (Throwable failure) {
              // Propagated through ExecutionException to match FutureTask behavior.
              result.completeExceptionally(failure);
            } finally {
              returned.countDown();
            }
          };
      executor.execute(task);
      deadline.alsoCancel(result);
      try {
        // The watchdog ends the wait at the deadline; the timed wait is for a watchdog that is
        // late.
        return Uninterruptibles.getUninterruptibly(
            result, CEILING.plus(BASE).toMillis(), TimeUnit.MILLISECONDS);
      } catch (CancellationException | TimeoutException e) {
        deadline.cutOff();
        // A transfer that started holds the provider until it returns. One that has not started
        // yet never will, once this thread claims its start.
        if (!started.compareAndSet(false, true)
            && !Uninterruptibles.awaitUninterruptibly(
                returned, CLOSE_GRACE.toMillis(), TimeUnit.MILLISECONDS)) {
          stalled.add(returned);
        }
        ClosedChannelException closed = new ClosedChannelException();
        closed.initCause(e);
        throw closed;
      } catch (ExecutionException e) {
        Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
        Throwables.throwIfUnchecked(e.getCause());
        throw new IOException(e.getCause());
      }
    }
  }

  /**
   * Copies {@code in} to {@code out}, reporting each chunk to {@code deadline}, and returns how
   * many bytes it copied. It stops with {@link ClosedChannelException} once the deadline passes,
   * also when closing the transfer did not end it.
   */
  static long copy(InputStream in, OutputStream out, Transfer deadline) throws IOException {
    byte[] buffer = new byte[8192];
    long copied = 0;
    for (int read = in.read(buffer); read != -1; read = in.read(buffer)) {
      deadline.checkInTime();
      out.write(buffer, 0, read);
      copied += read;
      deadline.progressed();
    }
    return copied;
  }

  /** Returns the calls and transfers to the provider of {@code document} that it holds. */
  private static Set<CountDownLatch> stalledCallsTo(Uri document) {
    Set<CountDownLatch> stalled =
        stalledCalls.computeIfAbsent(
            Strings.nullToEmpty(document.getAuthority()), unused -> ConcurrentHashMap.newKeySet());
    stalled.removeIf(latch -> latch.getCount() == 0);
    return stalled;
  }

  private static void closeQuietly(Closeable transfer) {
    try {
      transfer.close();
    } catch (IOException e) {
      Log.w(TAG, "Failed to end a transfer past its deadline", e);
    }
  }

  /** Withdraws a deadline that {@link #arm} set. */
  interface Disarm extends AutoCloseable {
    /** A handle for a transfer that has no deadline yet. */
    Disarm NONE = () -> {};

    @Override
    void close();
  }

  /** A copy to or from a documents provider, which reports its progress to its deadline. */
  interface TransferAction<T> {
    T run(Transfer deadline) throws IOException;
  }

  /**
   * The deadline of a transfer, which closes the transfer once it is past the time for its payload,
   * or once it has gone {@link #BASE} without progress.
   */
  static final class Transfer implements Disarm {
    private final Closeable transfer;
    private final long endMillis;
    @Nullable private final Budget budget;
    private final Runnable check = this::check;
    private final Runnable cutOff = this::cutOff;
    private final AtomicBoolean cut = new AtomicBoolean();
    private volatile long lastProgressMillis;
    @Nullable private volatile Future<?> waitForEnd;
    private volatile boolean disarmed;

    private Transfer(long payloadBytes, Closeable transfer, @Nullable Budget budget) {
      this.transfer = transfer;
      this.budget = budget;
      long now = SystemClock.uptimeMillis();
      long time =
          Math.min(
              BASE.plusSeconds(payloadBytes / MIN_BYTES_PER_SECOND).toMillis(), CEILING.toMillis());
      this.endMillis = budget == null ? now + time : Math.min(now + time, budget.endMillis);
      this.lastProgressMillis = now;
    }

    /** Tells the deadline that the transfer moved bytes, which gives it {@link #BASE} for more. */
    void progressed() {
      lastProgressMillis = SystemClock.uptimeMillis();
    }

    /**
     * Throws {@link ClosedChannelException} if the transfer is past its deadline. Closing a
     * connection that is not open yet does not keep it from opening, so a transfer checks this
     * before it connects.
     */
    void checkInTime() throws ClosedChannelException {
      if (cut.get()) {
        throw new ClosedChannelException();
      }
    }

    @Override
    public void close() {
      // NOMUTANTS -- Concurrency guard for in-flight watchdog check() or Budget.stop().
      disarmed = true;
      watchdog.removeCallbacks(check);
      // NOMUTANTS -- Avoids retaining closed transfers in budget.cutOffs; disarmed prevents firing.
      if (budget != null) {
        budget.removeOnStop(cutOff);
      }
    }

    private void start() {
      if (budget != null) {
        budget.onStop(cutOff);
      }
      if (SystemClock.uptimeMillis() < nextCheckMillis()) {
        watchdog.postAtTime(check, nextCheckMillis());
      } else {
        // Past its deadline already, as within a spent budget.
        cutOff();
      }
    }

    private long nextCheckMillis() {
      return Math.min(endMillis, lastProgressMillis + BASE.toMillis());
    }

    private void check() {
      if (disarmed) {
        return;
      }
      long dueMillis = nextCheckMillis();
      if (SystemClock.uptimeMillis() < dueMillis) {
        watchdog.postAtTime(check, dueMillis);
      } else {
        cutOff();
      }
    }

    /** Makes the cut-off end {@code waitForEnd} too, which waits for the transfer to end. */
    private void alsoCancel(Future<?> waitForEnd) {
      this.waitForEnd = waitForEnd;
      if (cut.get()) {
        waitForEnd.cancel(/* mayInterruptIfRunning= */ false);
      }
    }

    private void cutOff() {
      if (disarmed || !cut.compareAndSet(false, true)) {
        return;
      }
      Future<?> pending = waitForEnd;
      if (pending != null) {
        pending.cancel(/* mayInterruptIfRunning= */ false);
      }
      // Closing can wait on the provider in turn, so it runs on another thread: the watchdog, and
      // whoever stops a budget, stay free.
      blockingCalls.execute(() -> closeQuietly(transfer));
    }
  }

  /**
   * Bounds the calls into documents providers and the transfers of a task that {@link #within}
   * runs: once the budget runs out or is stopped, they end as past their deadline, and later ones
   * fail at once.
   */
  static final class Budget {
    private final long endMillis;
    private final Set<Runnable> cutOffs = ConcurrentHashMap.newKeySet();
    private volatile boolean stopped;

    private Budget(long endMillis) {
      this.endMillis = endMillis;
    }

    /** Returns a budget that runs out {@code time} from now. */
    static Budget lasting(Duration time) {
      return new Budget(SystemClock.uptimeMillis() + time.toMillis());
    }

    /** Returns a budget that lasts until it is stopped. */
    static Budget untilStopped() {
      return new Budget(Long.MAX_VALUE);
    }

    /** Ends the budget now, and with it the calls and transfers in progress within it. */
    void stop() {
      stopped = true;
      cutOffs.forEach(Runnable::run);
    }

    /** Returns whether the budget ran out or was stopped. */
    boolean isSpent() {
      return stopped || SystemClock.uptimeMillis() >= endMillis;
    }

    private void onStop(Runnable cutOff) {
      cutOffs.add(cutOff);
      if (stopped) {
        cutOff.run();
      }
    }

    private void removeOnStop(Runnable cutOff) {
      // NOMUTANTS -- Memory cleanup only; disarmed already skips cutOff() on budget.stop().
      cutOffs.remove(cutOff);
    }
  }

  private static Handler startWatchdog() {
    HandlerThread thread = new HandlerThread(TAG);
    thread.start();
    return new Handler(thread.getLooper());
  }
}
