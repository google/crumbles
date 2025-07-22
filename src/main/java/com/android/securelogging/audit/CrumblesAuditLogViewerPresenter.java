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
