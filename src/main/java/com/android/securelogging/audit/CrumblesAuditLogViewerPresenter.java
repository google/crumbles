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

import java.util.List;

/** Presenter for the Crumbles audit log viewer. */
public class CrumblesAuditLogViewerPresenter implements CrumblesAuditLogViewerContract.Presenter {

  private final CrumblesAuditLogViewerContract.View view;
  private final CrumblesAppAuditLogger appAuditLogger;

  public CrumblesAuditLogViewerPresenter(
      CrumblesAuditLogViewerContract.View view, CrumblesAppAuditLogger appAuditLogger) {
    this.view = view;
    this.appAuditLogger = appAuditLogger;
  }

  @Override
  public void onViewCreated() {
    loadAuditLogs();
  }

  @Override
  public void onClearLogsClicked() {
    view.showClearLogsConfirmationDialog();
  }

  @Override
  public void onClearLogsConfirmed() {
    appAuditLogger.clearAllLogs();
    loadAuditLogs();
  }

  private void loadAuditLogs() {
    List<CrumblesAuditEvent> events = appAuditLogger.getAllPersistedEventsForDisplay();
    if (events == null || events.isEmpty()) {
      view.showNoLogsMessage();
    } else {
      view.showLogs(events);
    }
  }
}
