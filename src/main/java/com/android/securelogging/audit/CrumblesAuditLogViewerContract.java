package com.android.securelogging.audit;

import java.util.List;

/** Contract between the view and presenter for the Crumbles audit log viewer. */
public final class CrumblesAuditLogViewerContract {
  /** The view interface for the Crumbles audit log viewer. */
  interface View {
    void showLogs(List<CrumblesAuditEvent> events);

    void showNoLogsMessage();

    void showClearLogsConfirmationDialog();
  }

  /** The presenter interface for the Crumbles audit log viewer. */
  interface Presenter {
    void onViewCreated();

    void onClearLogsClicked();

    void onClearLogsConfirmed();
  }

  private CrumblesAuditLogViewerContract() {}
}
