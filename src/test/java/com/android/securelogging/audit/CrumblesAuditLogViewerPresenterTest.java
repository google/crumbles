package com.android.securelogging.audit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/** Tests for {@link CrumblesAuditLogViewerPresenter}. */
@RunWith(JUnit4.class)
public class CrumblesAuditLogViewerPresenterTest {

  @Mock private CrumblesAuditLogViewerContract.View mockView;
  @Mock private CrumblesAppAuditLogger mockAuditLogger;

  private CrumblesAuditLogViewerPresenter presenter;

  @Before
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    presenter = new CrumblesAuditLogViewerPresenter(mockView, mockAuditLogger);
  }

  @Test
  public void onViewCreated_whenNoLogs_showsNoLogsMessage() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(ImmutableList.of());
    presenter.onViewCreated();
    verify(mockView).showNoLogsMessage();
    verify(mockView, never()).showLogs(any());
  }

  @Test
  public void onViewCreated_whenLogsExist_displaysLogs() {
    List<CrumblesAuditEvent> testEvents = new ArrayList<>();
    testEvents.add(new CrumblesAuditEvent(Instant.ofEpochMilli(1L), "TEST", "Message"));
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(testEvents);
    presenter.onViewCreated();
    verify(mockView).showLogs(testEvents);
    verify(mockView, never()).showNoLogsMessage();
  }

  @Test
  public void onClearLogsClicked_showsConfirmationDialog() {
    presenter.onClearLogsClicked();
    verify(mockView).showClearLogsConfirmationDialog();
  }

  @Test
  public void onClearLogsConfirmed_clearsLogsAndRefreshes() {
    when(mockAuditLogger.getAllPersistedEventsForDisplay()).thenReturn(ImmutableList.of());

    presenter.onClearLogsConfirmed();

    verify(mockAuditLogger).clearAllLogs();
    verify(mockAuditLogger).getAllPersistedEventsForDisplay();
    verify(mockView).showNoLogsMessage();
  }
}
