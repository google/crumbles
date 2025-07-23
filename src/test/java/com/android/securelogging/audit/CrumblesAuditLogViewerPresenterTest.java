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
