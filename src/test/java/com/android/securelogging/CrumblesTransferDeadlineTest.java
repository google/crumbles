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
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;
import static org.robolectric.Shadows.shadowOf;

import android.net.Uri;
import android.os.Looper;
import com.google.common.truth.Expect;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.testing.junit.testparameterinjector.TestParameter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;
import org.robolectric.Shadows;
import org.robolectric.shadows.ShadowLooper;
import org.robolectric.shadows.ShadowSystemClock;

/** Unit tests for {@link CrumblesTransferDeadline}. */
@RunWith(RobolectricTestParameterInjector.class)
public final class CrumblesTransferDeadlineTest {

  @Rule public final Expect expect = Expect.create();

  /** Opens at the end of each test, to let the provider return the call that it holds. */
  private final CountDownLatch release = new CountDownLatch(1);

  @After
  public void tearDown() {
    release.countDown();
  }

  @Test
  public void arm_givesAPayloadThatMakesProgressTimeAtEightKibibytesPerSecond() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.arm(/* payloadBytes= */ 1024 * 1024, closed::countDown)) {
      // A minute for the connection, then 128 s for 1 MiB at 8 KiB/s.
      makeProgressFor(deadline, Duration.ofSeconds(60 + 128).minusMillis(1));
      boolean closedEarly = closed.await(/* timeout= */ 100, MILLISECONDS);
      runDeadlinesAfter(Duration.ofMillis(1));

      expect.that(closedEarly).isFalse();
      expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    }
  }

  @Test
  public void arm_whenTheTransferMakesNoProgress_closesItAfterAMinute() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.arm(/* payloadBytes= */ 1024 * 1024, closed::countDown)) {
      runDeadlinesAfter(Duration.ofSeconds(59));
      boolean closedEarly = closed.await(/* timeout= */ 100, MILLISECONDS);
      runDeadlinesAfter(Duration.ofSeconds(1));

      expect.that(closedEarly).isFalse();
      expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    }
  }

  @Test
  public void arm_whenTheTransferKeepsTrickling_closesItAfterEightMinutes() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    // At 8 KiB/s, 64 MiB would get more than two hours.
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.arm(/* payloadBytes= */ 64L * 1024 * 1024, closed::countDown)) {
      makeProgressFor(deadline, Duration.ofSeconds(8 * 60 - 1));
      boolean closedEarly = closed.await(/* timeout= */ 100, MILLISECONDS);
      runDeadlinesAfter(Duration.ofSeconds(1));

      expect.that(closedEarly).isFalse();
      expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    }
  }

  @Test
  public void arm_withinABudget_closesTheTransferWhenTheBudgetRunsOut() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    CrumblesTransferDeadline.Budget budget =
        CrumblesTransferDeadline.Budget.lasting(Duration.ofMinutes(2));
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.within(
            budget,
            () ->
                CrumblesTransferDeadline.arm(/* payloadBytes= */ 1024 * 1024, closed::countDown))) {
      makeProgressFor(deadline, Duration.ofSeconds(119));
      boolean closedEarly = closed.await(/* timeout= */ 100, MILLISECONDS);
      runDeadlinesAfter(Duration.ofSeconds(1));

      expect.that(closedEarly).isFalse();
      expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    }
  }

  @Test
  public void arm_withinABudget_closesTheTransferAtOnceWhenTheBudgetIsStopped() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.untilStopped();
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.within(
            budget,
            () ->
                CrumblesTransferDeadline.arm(/* payloadBytes= */ 1024 * 1024, closed::countDown))) {

      budget.stop();

      assertThat(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    }
  }

  @Test
  public void arm_withinABudgetThatRanOut_isPastItsDeadlineAtOnce() {
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.lasting(Duration.ZERO);
    // With the watchdog paused, only arming can end the transfer.
    ShadowLooper watchdog = watchdog();
    watchdog.pause();

    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.within(
            budget, () -> CrumblesTransferDeadline.arm(/* payloadBytes= */ 0, () -> {}))) {

      assertThrows(ClosedChannelException.class, deadline::checkInTime);
    } finally {
      watchdog.unPause();
    }
  }

  @Test
  public void copy_pastTheDeadline_stopsWithClosedChannelException() throws Exception {
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.untilStopped();
    ByteArrayOutputStream copy = new ByteArrayOutputStream();
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.within(
            budget, () -> CrumblesTransferDeadline.arm(/* payloadBytes= */ 0, () -> {}))) {
      budget.stop();

      assertThrows(
          ClosedChannelException.class,
          () ->
              CrumblesTransferDeadline.copy(
                  new ByteArrayInputStream(new byte[] {1, 2, 3}), copy, deadline));
    }

    assertThat(copy.size()).isEqualTo(0);
  }

  @Test
  public void copy_whenInputIsEmpty_returnsZero() throws Exception {
    ByteArrayOutputStream copy = new ByteArrayOutputStream();
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.arm(/* payloadBytes= */ 0, () -> {})) {
      long copied =
          CrumblesTransferDeadline.copy(new ByteArrayInputStream(new byte[0]), copy, deadline);

      expect.that(copied).isEqualTo(0L);
      expect.that(copy.toByteArray()).isEmpty();
    }
  }

  @Test
  public void copy_returnsTheNumberOfBytesCopied() throws Exception {
    byte[] payload = {1, 2, 3, 4, 5};
    ByteArrayOutputStream copy = new ByteArrayOutputStream();
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.arm(payload.length, () -> {})) {
      long copied =
          CrumblesTransferDeadline.copy(new ByteArrayInputStream(payload), copy, deadline);

      expect.that(copied).isEqualTo(5L);
      expect.that(copy.toByteArray()).isEqualTo(payload);
    }
  }

  @Test
  public void copy_whenStreamPausesBetweenChunksWithinIdleTimeout_completesPastOneMinute()
      throws Exception {
    byte[] chunk = new byte[8192];
    ByteArrayOutputStream copiedBytes = new ByteArrayOutputStream();
    try (CrumblesTransferDeadline.Transfer deadline =
        CrumblesTransferDeadline.arm(/* payloadBytes= */ 1024L * 1024, () -> {})) {
      InputStream slowChunks =
          new InputStream() {
            private int remainingChunks = 3;

            @Override
            public int read() {
              throw new UnsupportedOperationException();
            }

            @Override
            public int read(byte[] b, int off, int len) {
              if (remainingChunks == 0) {
                return -1;
              }
              if (remainingChunks < 3) {
                runDeadlinesAfter(Duration.ofSeconds(35));
              }
              remainingChunks--;
              int toCopy = Math.min(len, chunk.length);
              System.arraycopy(chunk, 0, b, off, toCopy);
              return toCopy;
            }
          };

      long copied = CrumblesTransferDeadline.copy(slowChunks, copiedBytes, deadline);

      expect.that(copied).isEqualTo(3L * chunk.length);
      expect.that(copiedBytes.size()).isEqualTo(3 * chunk.length);
    }
  }

  @Test
  public void close_disarmsPendingDeadlineAndBudgetCallbacks() {
    CountDownLatch closed = new CountDownLatch(1);
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.untilStopped();

    CrumblesTransferDeadline.within(
            budget, () -> CrumblesTransferDeadline.arm(/* payloadBytes= */ 0, closed::countDown))
        .close();
    runDeadlinesAfter(Duration.ofMinutes(2));
    budget.stop();

    expect.that(watchdog().getNextScheduledTaskTime()).isEqualTo(Duration.ZERO);
    expect.that(closed.getCount()).isEqualTo(1);
  }

  @Test
  public void within_restoresOuterBudgetAfterInnerTaskEnds() {
    CrumblesTransferDeadline.Budget outer = CrumblesTransferDeadline.Budget.untilStopped();
    CrumblesTransferDeadline.Budget inner = CrumblesTransferDeadline.Budget.untilStopped();
    Uri document = Uri.parse("content://nested.budget.provider/document/1");
    AtomicReference<String> answerAfterInner = new AtomicReference<>();

    Throwable thrownAfterOuterStopped =
        CrumblesTransferDeadline.within(
            outer,
            () -> {
              @SuppressWarnings("unused")
              var unused =
                  CrumblesTransferDeadline.within(
                      inner,
                      () -> {
                        inner.stop();
                        return null;
                      });
              try {
                answerAfterInner.set(
                    CrumblesTransferDeadline.callProvider(document, () -> "answer"));
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
              outer.stop();
              return assertThrows(
                  IOException.class,
                  () -> CrumblesTransferDeadline.callProvider(document, () -> "unused"));
            });

    expect.that(answerAfterInner.get()).isEqualTo("answer");
    expect.that(thrownAfterOuterStopped).isInstanceOf(ClosedChannelException.class);
  }

  @Test
  public void arm_whileClosingAnEarlierTransferBlocks_stillEndsLaterTransfers() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);
    try (CrumblesTransferDeadline.Disarm blocked =
            CrumblesTransferDeadline.arm(this::awaitRelease);
        CrumblesTransferDeadline.Disarm later =
            CrumblesTransferDeadline.arm(/* payloadBytes= */ 8 * 1024, closed::countDown)) {
      // The blocked transfer's deadline passes first, a second before the later one's.
      ShadowSystemClock.advanceBy(Duration.ofSeconds(61));

      boolean laterClosed = closed.await(/* timeout= */ 5, SECONDS);

      assertThat(laterClosed).isTrue();
    }
  }

  @Test
  public void callProvider_whenTheCallThrowsACheckedException_throwsAnIOExceptionCausedByIt() {
    Exception failure = new Exception("not an IOException");

    IOException thrown =
        assertThrows(
            IOException.class,
            () ->
                CrumblesTransferDeadline.callProvider(
                    Uri.parse("content://failing.provider/document/1"),
                    () -> {
                      throw failure;
                    }));

    assertThat(thrown).hasCauseThat().isSameInstanceAs(failure);
  }

  @Test
  public void callProvider_justBeforeItsDeadline_keepsWaitingForTheAnswer() throws Exception {
    Uri document = Uri.parse("content://almost.timed.out.provider/document/1");
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try {
      Future<String> call = startHeldCallWaitingOnDeadline(caller, document);

      runDeadlinesAfter(Duration.ofMinutes(1).minusMillis(1));
      release.countDown();

      assertThat(call.get(/* timeout= */ 5, SECONDS)).isEqualTo("answer");
    } finally {
      caller.shutdown();
    }
  }

  @Test
  public void callProvider_atItsDeadline_givesUpWithoutWaitingOneMillisecondLonger()
      throws Exception {
    Uri document = Uri.parse("content://at.deadline.provider/document/1");
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try {
      Future<String> call = startHeldCallWaitingOnDeadline(caller, document);

      runDeadlinesAfter(Duration.ofMinutes(1));

      Throwable thrown =
          assertThrows(ExecutionException.class, () -> call.get(/* timeout= */ 5, SECONDS))
              .getCause();
      assertThat(thrown).isInstanceOf(ClosedChannelException.class);
    } finally {
      caller.shutdown();
    }
  }

  private Future<String> startHeldCallWaitingOnDeadline(ExecutorService caller, Uri document)
      throws Exception {
    CountDownLatch called = new CountDownLatch(1);
    AtomicReference<Thread> callerThread = new AtomicReference<>();
    Future<String> call =
        caller.submit(
            () -> {
              callerThread.set(Thread.currentThread());
              return CrumblesTransferDeadline.callProvider(
                  document,
                  () -> {
                    called.countDown();
                    release.await();
                    return "answer";
                  });
            });
    assertThat(called.await(/* timeout= */ 5, SECONDS)).isTrue();
    long waitDeadlineNanos = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (callerThread.get().getState() != Thread.State.TIMED_WAITING
        && System.nanoTime() < waitDeadlineNanos) {
      Uninterruptibles.sleepUninterruptibly(10, MILLISECONDS);
    }
    assertThat(callerThread.get().getState()).isEqualTo(Thread.State.TIMED_WAITING);
    return call;
  }

  @Test
  public void callProvider_pastTheDeadline_throwsClosedChannelExceptionCausedByTheCutOff()
      throws Exception {
    Throwable thrown = holdCallPastDeadline(Uri.parse("content://held.provider.four/document/1"));

    assertThat(thrown).isInstanceOf(ClosedChannelException.class);
    assertThat(thrown).hasCauseThat().isInstanceOf(CancellationException.class);
  }

  @Test
  public void callProvider_whileTheProviderHoldsACallPastItsDeadline_failsAtOnce()
      throws Exception {
    Uri document = Uri.parse("content://held.provider/document/1");
    assertThat(holdCallPastDeadline(document)).isInstanceOf(ClosedChannelException.class);
    AtomicBoolean called = new AtomicBoolean();

    assertThrows(
        ClosedChannelException.class,
        () -> CrumblesTransferDeadline.callProvider(document, () -> called.getAndSet(true)));

    expect.that(called.get()).isFalse();
  }

  @Test
  public void callProvider_whileOneProviderHoldsACall_stillCallsOtherProviders() throws Exception {
    assertThat(holdCallPastDeadline(Uri.parse("content://held.provider.two/document/1")))
        .isInstanceOf(ClosedChannelException.class);

    String answer =
        CrumblesTransferDeadline.callProvider(
            Uri.parse("content://other.provider/document/1"), () -> "answer");

    assertThat(answer).isEqualTo("answer");
  }

  @Test
  public void callProvider_onceTheHeldCallReturns_callsTheProviderAgain() throws Exception {
    Uri document = Uri.parse("content://held.provider.three/document/1");
    assertThat(holdCallPastDeadline(document)).isInstanceOf(ClosedChannelException.class);
    release.countDown();

    String answer = callUntilAnswered(document);

    assertThat(answer).isEqualTo("answer");
  }

  @Test
  public void callProvider_whenASecondTimedOutCallReturnsFirst_keepsFailingUntilTheFirstReturns()
      throws Exception {
    Uri document = Uri.parse("content://held.provider.five/document/1");
    CountDownLatch bothStarted = new CountDownLatch(2);
    CountDownLatch secondRelease = new CountDownLatch(1);
    ExecutorService callers = Executors.newFixedThreadPool(2);
    try {
      Future<Boolean> first =
          callers.submit(
              () ->
                  CrumblesTransferDeadline.callProvider(
                      document,
                      () -> {
                        bothStarted.countDown();
                        release.await();
                        return true;
                      }));
      Future<Boolean> second =
          callers.submit(
              () ->
                  CrumblesTransferDeadline.callProvider(
                      document,
                      () -> {
                        bothStarted.countDown();
                        secondRelease.await();
                        return true;
                      }));
      assertThat(bothStarted.await(/* timeout= */ 5, SECONDS)).isTrue();
      for (int attempt = 0; attempt < 100 && (!first.isDone() || !second.isDone()); attempt++) {
        ShadowSystemClock.advanceBy(Duration.ofHours(1));
        Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
      }
      assertThrows(ExecutionException.class, () -> first.get(/* timeout= */ 1, SECONDS));
      assertThrows(ExecutionException.class, () -> second.get(/* timeout= */ 1, SECONDS));

      // The second call finishes, while the first is still held by the provider.
      secondRelease.countDown();
      Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
      AtomicBoolean calledWhileFirstStillHeld = new AtomicBoolean();
      assertThrows(
          ClosedChannelException.class,
          () ->
              CrumblesTransferDeadline.callProvider(
                  document, () -> calledWhileFirstStillHeld.getAndSet(true)));
      expect.that(calledWhileFirstStillHeld.get()).isFalse();

      release.countDown();
      expect.that(callUntilAnswered(document)).isEqualTo("answer");
    } finally {
      secondRelease.countDown();
      callers.shutdown();
    }
  }

  @Test
  public void callProvider_withinASpentBudget_failsWithoutCallingTheProvider() {
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.untilStopped();
    budget.stop();
    AtomicBoolean called = new AtomicBoolean();

    Throwable thrown =
        CrumblesTransferDeadline.within(
            budget,
            () ->
                assertThrows(
                    IOException.class,
                    () ->
                        CrumblesTransferDeadline.callProvider(
                            Uri.parse("content://any.provider/document/1"),
                            () -> called.getAndSet(true))));

    expect.that(thrown).isInstanceOf(ClosedChannelException.class);
    expect.that(called.get()).isFalse();
  }

  @Test
  public void callProvider_whenTheBudgetIsStoppedDuringTheCall_stopsWaitingAtOnce()
      throws Exception {
    Uri document = Uri.parse("content://held.provider.six/document/1");
    CrumblesTransferDeadline.Budget budget = CrumblesTransferDeadline.Budget.untilStopped();
    CountDownLatch called = new CountDownLatch(1);
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> call =
          caller.submit(() ->
              CrumblesTransferDeadline.within(
                  budget,
                  () -> {
                    try {
                      return CrumblesTransferDeadline.callProvider(
                          document,
                          () -> {
                            called.countDown();
                            release.await();
                            return true;
                          });
                    } catch (IOException e) {
                      throw new UncheckedIOException(e);
                    }
                  }));
      assertThat(called.await(/* timeout= */ 5, SECONDS)).isTrue();

      budget.stop();

      Throwable thrown =
          assertThrows(ExecutionException.class, () -> call.get(/* timeout= */ 5, SECONDS))
              .getCause();
      assertThat(thrown).hasCauseThat().isInstanceOf(ClosedChannelException.class);
    } finally {
      caller.shutdown();
    }
  }

  @Test
  public void callProvider_whenTheBudgetEndsBeforeTheCallStarts_skipsItAndKeepsCallingTheProvider(
      @TestParameter BudgetEnd budgetEnd) throws Exception {
    Uri document = Uri.parse("content://queued.provider." + budgetEnd + "/document/1");
    BlockingQueue<Runnable> queued = new LinkedBlockingQueue<>();
    AtomicBoolean called = new AtomicBoolean();
    IOException thrown =
        endBudgetWhileQueued(
            budgetEnd,
            queued,
            () ->
                CrumblesTransferDeadline.callProvider(
                    document, () -> called.getAndSet(true), queued::add));

    String answer = CrumblesTransferDeadline.callProvider(document, () -> "answer");

    expect.that(thrown).isInstanceOf(ClosedChannelException.class);
    expect.that(called.get()).isFalse();
    expect.that(answer).isEqualTo("answer");
  }

  @Test
  public void runTransfer_returnsWhatTheTransferReturnsAndClosesTheChannel() throws Exception {
    CountDownLatch closed = new CountDownLatch(1);

    String result =
        CrumblesTransferDeadline.runTransfer(
            Uri.parse("content://transfer.provider/document/1"),
            /* payloadBytes= */ 0,
            closed::countDown,
            deadline -> "copied");

    expect.that(result).isEqualTo("copied");
    expect.that(closed.getCount()).isEqualTo(0);
  }

  @Test
  public void runTransfer_whenClosingDoesNotEndTheTransfer_givesUpAndRefusesTheProvider()
      throws Exception {
    Uri document = Uri.parse("content://fuse.provider/document/1");
    // Like a write on a FUSE proxy descriptor that its provider never answers: closing does not
    // end it.
    Throwable thrown =
        runTransferPastDeadline(
            document,
            () -> {},
            deadline -> {
              Uninterruptibles.awaitUninterruptibly(release);
              return 0L;
            });
    AtomicBoolean called = new AtomicBoolean();

    assertThrows(
        ClosedChannelException.class,
        () -> CrumblesTransferDeadline.callProvider(document, () -> called.getAndSet(true)));

    expect.that(thrown).isInstanceOf(ClosedChannelException.class);
    expect.that(called.get()).isFalse();
  }

  @Test
  public void runTransfer_whileTheProviderHoldsAnEarlierTransfer_failsAtOnce() throws Exception {
    Uri document = Uri.parse("content://fuse.provider.two/document/1");
    assertThat(
            runTransferPastDeadline(
                document,
                () -> {},
                deadline -> {
                  Uninterruptibles.awaitUninterruptibly(release);
                  return 0L;
                }))
        .isInstanceOf(ClosedChannelException.class);
    AtomicBoolean transferred = new AtomicBoolean();
    CountDownLatch closed = new CountDownLatch(1);

    assertThrows(
        ClosedChannelException.class,
        () ->
            CrumblesTransferDeadline.runTransfer(
                document,
                /* payloadBytes= */ 0,
                closed::countDown,
                deadline -> transferred.getAndSet(true)));

    expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    expect.that(transferred.get()).isFalse();
  }

  @Test
  public void runTransfer_whenClosingEndsTheTransfer_keepsCallingTheProvider() throws Exception {
    Uri document = Uri.parse("content://pipe.provider/document/1");
    CountDownLatch closed = new CountDownLatch(1);
    // Like a write to a pipe that nothing drains, which closing ends, a moment later.
    Throwable thrown =
        runTransferPastDeadline(
            document,
            closed::countDown,
            deadline -> {
              Uninterruptibles.awaitUninterruptibly(closed);
              Uninterruptibles.sleepUninterruptibly(200, MILLISECONDS);
              throw new AsynchronousCloseException();
            });

    String answer = CrumblesTransferDeadline.callProvider(document, () -> "answer");

    expect.that(thrown).isInstanceOf(ClosedChannelException.class);
    expect.that(answer).isEqualTo("answer");
  }

  @Test
  public void runTransfer_whenTheBudgetEndsBeforeItStarts_skipsItAndKeepsCallingTheProvider(
      @TestParameter BudgetEnd budgetEnd) throws Exception {
    Uri document = Uri.parse("content://queued.transfer.provider." + budgetEnd + "/document/1");
    BlockingQueue<Runnable> queued = new LinkedBlockingQueue<>();
    CountDownLatch closed = new CountDownLatch(1);
    AtomicBoolean transferred = new AtomicBoolean();
    IOException thrown =
        endBudgetWhileQueued(
            budgetEnd,
            queued,
            () ->
                CrumblesTransferDeadline.runTransfer(
                    document,
                    /* payloadBytes= */ 0,
                    closed::countDown,
                    deadline -> transferred.getAndSet(true),
                    queued::add));

    String copied =
        CrumblesTransferDeadline.runTransfer(
            document, /* payloadBytes= */ 0, () -> {}, deadline -> "copied");

    expect.that(thrown).isInstanceOf(ClosedChannelException.class);
    expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    expect.that(transferred.get()).isFalse();
    expect.that(copied).isEqualTo("copied");
  }

  @Test
  public void runTransfer_withinASpentBudget_closesTheChannelAndKeepsCallingTheProvider(
      @TestParameter BudgetEnd budgetEnd) throws Exception {
    Uri document = Uri.parse("content://spent.transfer.provider." + budgetEnd + "/document/1");
    CrumblesTransferDeadline.Budget budget = budgetEnd.newBudget();
    budgetEnd.end(budget);
    CountDownLatch closed = new CountDownLatch(1);
    AtomicBoolean transferred = new AtomicBoolean();
    IOException thrown =
        CrumblesTransferDeadline.within(
            budget,
            () ->
                assertThrows(
                    IOException.class,
                    () ->
                        CrumblesTransferDeadline.runTransfer(
                            document,
                            /* payloadBytes= */ 0,
                            closed::countDown,
                            deadline -> transferred.getAndSet(true))));

    String copied =
        CrumblesTransferDeadline.runTransfer(
            document, /* payloadBytes= */ 0, () -> {}, deadline -> "copied");

    expect.that(thrown).isInstanceOf(ClosedChannelException.class);
    expect.that(closed.await(/* timeout= */ 5, SECONDS)).isTrue();
    expect.that(transferred.get()).isFalse();
    expect.that(copied).isEqualTo("copied");
  }

  @Test
  public void budget_justBeforeItsTimeRunsOut_isNotSpent() {
    CrumblesTransferDeadline.Budget budget =
        CrumblesTransferDeadline.Budget.lasting(Duration.ofSeconds(10));

    ShadowSystemClock.advanceBy(Duration.ofSeconds(10).minusMillis(1));

    assertThat(budget.isSpent()).isFalse();
  }

  @Test
  public void budget_atItsTimeLimit_isSpent() {
    CrumblesTransferDeadline.Budget budget =
        CrumblesTransferDeadline.Budget.lasting(Duration.ofSeconds(10));

    ShadowSystemClock.advanceBy(Duration.ofSeconds(10));

    assertThat(budget.isSpent()).isTrue();
  }

  /** Moves the clock on by {@code time}, and runs the deadlines that are due by then. */
  private static void runDeadlinesAfter(Duration time) {
    ShadowSystemClock.advanceBy(time);
    for (Looper looper : ShadowLooper.getAllLoopers()) {
      if (looper.getThread().getName().equals("CrumblesTransferDeadline")) {
        shadowOf(looper).idle();
      }
    }
  }

  /** Returns the looper on which the watchdog ends transfers past their deadline. */
  private static ShadowLooper watchdog() {
    // Arming a deadline starts the watchdog, unless an earlier test did.
    CrumblesTransferDeadline.arm(() -> {}).close();
    return ShadowLooper.getAllLoopers().stream()
        .filter(looper -> looper.getThread().getName().equals("CrumblesTransferDeadline"))
        .map(Shadows::shadowOf)
        .findFirst()
        .orElseThrow();
  }

  /** Moves the clock on by {@code time}, reporting progress to {@code deadline} every 30 s. */
  private static void makeProgressFor(CrumblesTransferDeadline.Transfer deadline, Duration time) {
    Duration step = Duration.ofSeconds(30);
    for (Duration left = time; !left.isZero(); ) {
      Duration next = left.compareTo(step) < 0 ? left : step;
      runDeadlinesAfter(next);
      deadline.progressed();
      left = left.minus(next);
    }
  }

  /**
   * Runs {@code transfer} to the provider of {@code document} through {@code channel} on another
   * thread, moves the clock past its deadline until it ends, and returns what it threw.
   */
  private static Throwable runTransferPastDeadline(
      Uri document, Closeable channel, CrumblesTransferDeadline.TransferAction<Long> transfer)
      throws Exception {
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try {
      Future<Long> result =
          caller.submit(() ->
              CrumblesTransferDeadline.runTransfer(
                  document, /* payloadBytes= */ 0, channel, transfer));
      for (int attempt = 0; attempt < 100 && !result.isDone(); attempt++) {
        ShadowSystemClock.advanceBy(Duration.ofHours(1));
        Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
      }
      return assertThrows(ExecutionException.class, () -> result.get(/* timeout= */ 5, SECONDS))
          .getCause();
    } finally {
      caller.shutdown();
    }
  }

  /**
   * Runs {@code task} on another thread, within a budget that {@code budgetEnd} ends once the call
   * or transfer that {@code task} makes is in {@code queued}, before it starts. Returns what {@code
   * task} threw, and then runs what is in {@code queued}, as an executor that gets to it late does.
   */
  private static IOException endBudgetWhileQueued(
      BudgetEnd budgetEnd, BlockingQueue<Runnable> queued, ThrowingRunnable task) throws Exception {
    CrumblesTransferDeadline.Budget budget = budgetEnd.newBudget();
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try {
      Future<IOException> thrown =
          caller.submit(() ->
              CrumblesTransferDeadline.within(budget, () -> assertThrows(IOException.class, task)));
      Runnable queuedTask = queued.poll(/* timeout= */ 5, SECONDS);
      assertThat(queuedTask).isNotNull();
      budgetEnd.end(budget);
      IOException result = thrown.get(/* timeout= */ 5, SECONDS);
      queuedTask.run();
      return result;
    } finally {
      caller.shutdown();
    }
  }

  /** Blocks until {@link #release} opens, as a provider that holds a call does. */
  private void awaitRelease() {
    try {
      release.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Makes a call to the provider of {@code document} that it holds until {@link #release} opens,
   * and returns what the call threw once the clock passed its deadline.
   */
  private Throwable holdCallPastDeadline(Uri document) throws Exception {
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> call =
          caller.submit(() ->
              CrumblesTransferDeadline.callProvider(
                  document,
                  () -> {
                    release.await();
                    return true;
                  }));
      for (int attempt = 0; attempt < 100 && !call.isDone(); attempt++) {
        ShadowSystemClock.advanceBy(Duration.ofHours(1));
        Uninterruptibles.sleepUninterruptibly(50, MILLISECONDS);
      }
      return assertThrows(ExecutionException.class, () -> call.get(/* timeout= */ 1, SECONDS))
          .getCause();
    } finally {
      caller.shutdown();
    }
  }

  /** Returns the answer of the provider of {@code document}, once it takes calls again. */
  private static String callUntilAnswered(Uri document) throws Exception {
    for (int attempt = 1; ; attempt++) {
      try {
        return CrumblesTransferDeadline.callProvider(document, () -> "answer");
      } catch (ClosedChannelException e) {
        // The held call returns on another thread, so the provider takes calls a moment later.
        if (attempt == 100) {
          throw e;
        }
        Uninterruptibles.sleepUninterruptibly(10, MILLISECONDS);
      }
    }
  }

  /** Ways in which a budget ends. */
  private enum BudgetEnd {
    STOPPED {
      @Override
      CrumblesTransferDeadline.Budget newBudget() {
        return CrumblesTransferDeadline.Budget.untilStopped();
      }

      @Override
      void end(CrumblesTransferDeadline.Budget budget) {
        budget.stop();
      }
    },
    RAN_OUT {
      @Override
      CrumblesTransferDeadline.Budget newBudget() {
        // Less than the minute that a call or a transfer without a payload has, so that the budget
        // is what ends it.
        return CrumblesTransferDeadline.Budget.lasting(Duration.ofSeconds(30));
      }

      @Override
      void end(CrumblesTransferDeadline.Budget budget) {
        ShadowSystemClock.advanceBy(Duration.ofSeconds(30));
      }
    };

    /** Returns a budget that {@link #end} ends. */
    abstract CrumblesTransferDeadline.Budget newBudget();

    /** Ends {@code budget}, which {@link #newBudget} returned. */
    abstract void end(CrumblesTransferDeadline.Budget budget);
  }
}
