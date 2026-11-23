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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesChainVerification;
import com.google.common.collect.ImmutableList;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntSupplier;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/** Tests for {@link CrumblesAuditLogViewerPresenter}. */
@RunWith(JUnit4.class)
public class CrumblesAuditLogViewerPresenterTest {

  private static final CrumblesAuditEvent TEST_EVENT =
      new CrumblesAuditEvent(Instant.ofEpochMilli(1L), "TEST", "Message");
  private static final CrumblesChainVerification INTACT_CHAIN =
      new CrumblesChainVerification(
          /* totalRecords= */ 1,
          /* verifiedRecords= */ 1,
          /* unverifiableRecords= */ 0,
          /* firstBrokenIndex= */ -1);

  @Mock private CrumblesAuditLogViewerContract.View mockView;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;
  @Mock private IntSupplier mockSealBeforeClear;

  private CrumblesAuditLogViewerPresenter presenter;

  @Before
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    presenter =
        new CrumblesAuditLogViewerPresenter(
            mockView, mockAuditLogger, Runnable::run, Runnable::run, mockSealBeforeClear);
  }

  @Test
  public void onViewingConfirmed_whenNoLogs_showsNoLogsMessage() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(ImmutableList.of());
    presenter.onViewingConfirmed();
    verify(mockView).showNoLogsMessage();
    verify(mockView, never()).showLogs(any());
  }

  @Test
  public void onViewingConfirmed_whenLogsExist_displaysLogs() {
    List<CrumblesAuditEvent> testEvents = new ArrayList<>();
    testEvents.add(new CrumblesAuditEvent(Instant.ofEpochMilli(1L), "TEST", "Message"));
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(testEvents);
    presenter.onViewingConfirmed();
    verify(mockView).showLogs(testEvents);
    verify(mockView, never()).showNoLogsMessage();
  }

  @Test
  public void onViewingConfirmed_whenLogsExist_showsChainVerification() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay())
        .thenReturn(ImmutableList.of(TEST_EVENT));
    when(mockAuditLogger.verifyChain()).thenReturn(INTACT_CHAIN);

    presenter.onViewingConfirmed();

    verify(mockView).showChainVerificationInProgress();
    verify(mockView).showChainVerification(INTACT_CHAIN);
  }

  @Test
  public void onViewingConfirmed_whenLogsExist_leavesChainCheckToBackgroundExecutor() {
    List<Runnable> backgroundTasks = new ArrayList<>();
    presenter =
        new CrumblesAuditLogViewerPresenter(
            mockView, mockAuditLogger, backgroundTasks::add, Runnable::run, mockSealBeforeClear);
    when(mockAuditLogger.getAllPersistedEventsForDisplay())
        .thenReturn(ImmutableList.of(TEST_EVENT));

    presenter.onViewingConfirmed();

    verify(mockView).showChainVerificationInProgress();
    verify(mockAuditLogger, never()).verifyChain();
  }

  @Test
  public void onViewingConfirmed_whenChainCheckFinishes_leavesResultToViewExecutor() {
    List<Runnable> viewTasks = new ArrayList<>();
    presenter =
        new CrumblesAuditLogViewerPresenter(
            mockView, mockAuditLogger, Runnable::run, viewTasks::add, mockSealBeforeClear);
    when(mockAuditLogger.getAllPersistedEventsForDisplay())
        .thenReturn(ImmutableList.of(TEST_EVENT));
    when(mockAuditLogger.verifyChain()).thenReturn(INTACT_CHAIN);

    presenter.onViewingConfirmed();

    verify(mockView, never()).showChainVerification(any());
  }

  @Test
  public void onViewingConfirmed_whenNoLogs_doesNotCheckChain() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(ImmutableList.of());

    presenter.onViewingConfirmed();

    verify(mockView, never()).showChainVerificationInProgress();
    verify(mockAuditLogger, never()).verifyChain();
  }

  @Test
  public void onViewingConfirmed_recordsViewingBeforeLoadingLogs() {
    presenter.onViewingConfirmed();

    InOrder inOrder = inOrder(mockAuditLogger);
    inOrder
        .verify(mockAuditLogger)
        .logEvent("AUDIT_LOG_VIEWED", "User authenticated to view the activity log.");
    inOrder.verify(mockAuditLogger).getAllPersistedEventsForDisplay();
  }

  @Test
  public void onViewingNotConfirmed_recordsFailureWithoutLoadingLogs() {
    presenter.onViewingNotConfirmed();

    verify(mockAuditLogger)
        .logEvent(
            "AUDIT_LOG_VIEW_AUTH_FAILED",
            "Activity log not shown because the user did not authenticate to view it.");
    verify(mockAuditLogger, never()).getAllPersistedEventsForDisplay();
  }

  @Test
  public void onViewingUnavailable_recordsRefusalWithoutLoadingLogs() {
    presenter.onViewingUnavailable();

    verify(mockAuditLogger)
        .logEvent(
            "AUDIT_LOG_VIEW_REFUSED",
            "Activity log not shown because no secure lock screen is set up.");
    verify(mockAuditLogger, never()).getAllPersistedEventsForDisplay();
  }

  @Test
  public void onClearLogsClicked_showsConfirmationDialog() {
    presenter.onClearLogsClicked();
    verify(mockView).showClearLogsConfirmationDialog();
  }

  @Test
  public void onClearLogsConfirmed_requestsDeviceCredentialWithoutClearing() {
    presenter.onClearLogsConfirmed();

    verify(mockView).requestDeviceCredentialConfirmation();
    verify(mockAuditLogger, never()).clearShippedLogs();
  }

  @Test
  public void onClearLogsConfirmed_recordsRequestBeforeAskingForCredential() {
    presenter.onClearLogsConfirmed();

    InOrder inOrder = inOrder(mockAuditLogger, mockView);
    inOrder
        .verify(mockAuditLogger)
        .logEvent("AUDIT_LOG_CLEAR_REQUESTED", "User asked to clear the activity log.");
    inOrder.verify(mockView).requestDeviceCredentialConfirmation();
  }

  @Test
  public void onDeviceCredentialUnavailable_recordsRefusalThenRefreshesWithoutClearing() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay())
        .thenReturn(ImmutableList.of(TEST_EVENT));

    presenter.onDeviceCredentialUnavailable();

    InOrder inOrder = inOrder(mockAuditLogger, mockView);
    inOrder
        .verify(mockAuditLogger)
        .logEvent(
            "AUDIT_LOG_CLEAR_REFUSED",
            "Activity log kept because no secure lock screen is set up.");
    inOrder.verify(mockView).showLogs(ImmutableList.of(TEST_EVENT));
    verify(mockAuditLogger, never()).clearShippedLogs();
  }

  @Test
  public void onDeviceCredentialNotConfirmed_recordsFailureThenRefreshesWithoutClearing() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay())
        .thenReturn(ImmutableList.of(TEST_EVENT));

    presenter.onDeviceCredentialNotConfirmed();

    InOrder inOrder = inOrder(mockAuditLogger, mockView);
    inOrder
        .verify(mockAuditLogger)
        .logEvent(
            "AUDIT_LOG_CLEAR_AUTH_FAILED",
            "Activity log kept because no device credential was confirmed for clearing it.");
    inOrder.verify(mockView).showLogs(ImmutableList.of(TEST_EVENT));
    verify(mockAuditLogger, never()).clearShippedLogs();
  }

  @Test
  public void onDeviceCredentialConfirmed_whenSealingSucceeds_clearsAndRefreshes() {
    when(mockSealBeforeClear.getAsInt()).thenReturn(0);
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(ImmutableList.of());

    presenter.onDeviceCredentialConfirmed();

    InOrder inOrder = inOrder(mockSealBeforeClear, mockAuditLogger, mockView);
    inOrder.verify(mockSealBeforeClear).getAsInt();
    inOrder.verify(mockAuditLogger).clearShippedLogs();
    inOrder.verify(mockAuditLogger).getAllPersistedEventsForDisplay();
    inOrder.verify(mockView).showNoLogsMessage();
  }

  @Test
  public void onDeviceCredentialConfirmed_whenSealingFails_keepsLogsRecordsRefusalAndTellsUser() {
    when(mockSealBeforeClear.getAsInt()).thenReturn(2);
    when(mockAuditLogger.getAllPersistedEventsForDisplay())
        .thenReturn(ImmutableList.of(TEST_EVENT));

    presenter.onDeviceCredentialConfirmed();

    InOrder inOrder = inOrder(mockSealBeforeClear, mockAuditLogger, mockView);
    inOrder.verify(mockSealBeforeClear).getAsInt();
    inOrder
        .verify(mockAuditLogger)
        .logEvent(
            "AUDIT_LOG_CLEAR_REFUSED",
            "Activity log kept because 2 unshipped record(s) could not be sealed into a log batch"
                + " first.");
    inOrder.verify(mockView).showClearRefused();
    inOrder.verify(mockView).showLogs(ImmutableList.of(TEST_EVENT));
    verify(mockAuditLogger, never()).clearShippedLogs();
    verify(mockAuditLogger, never()).clearAllLogs(anyInt());
  }

  @Test
  public void onDeviceCredentialConfirmed_dispatchesThroughConfiguredExecutors() {
    List<Runnable> backgroundTasks = new ArrayList<>();
    List<Runnable> viewTasks = new ArrayList<>();
    presenter =
        new CrumblesAuditLogViewerPresenter(
            mockView, mockAuditLogger, backgroundTasks::add, viewTasks::add, mockSealBeforeClear);

    presenter.onDeviceCredentialConfirmed();
    verify(mockSealBeforeClear, never()).getAsInt();
    verify(mockAuditLogger, never()).clearShippedLogs();

    backgroundTasks.get(0).run();
    verify(mockSealBeforeClear).getAsInt();
    verify(mockAuditLogger).clearShippedLogs();
    verify(mockView, never()).showNoLogsMessage();
  }
}
