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

import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesChainVerification;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.function.IntSupplier;

/** Presenter for the Crumbles audit log viewer. */
public class CrumblesAuditLogViewerPresenter implements CrumblesAuditLogViewerContract.Presenter {

  private static final String AUDIT_EVENT_VIEWED = "AUDIT_LOG_VIEWED";
  private static final String AUDIT_EVENT_VIEW_REFUSED = "AUDIT_LOG_VIEW_REFUSED";
  private static final String AUDIT_EVENT_VIEW_AUTH_FAILED = "AUDIT_LOG_VIEW_AUTH_FAILED";
  private static final String AUDIT_EVENT_CLEAR_REQUESTED = "AUDIT_LOG_CLEAR_REQUESTED";
  private static final String AUDIT_EVENT_CLEAR_REFUSED = "AUDIT_LOG_CLEAR_REFUSED";
  private static final String AUDIT_EVENT_CLEAR_AUTH_FAILED = "AUDIT_LOG_CLEAR_AUTH_FAILED";

  private final CrumblesAuditLogViewerContract.View view;
  private final CrumblesAppAuditLogger appAuditLogger;
  private final Executor chainCheckExecutor;
  private final Executor viewExecutor;
  private final IntSupplier sealBeforeClear;

  /**
   * Creates a presenter that checks the activity log's hash chain and seals unshipped records
   * before clearing on {@code chainCheckExecutor}, showing results through {@code viewExecutor} on
   * the view's thread.
   */
  public CrumblesAuditLogViewerPresenter(
      CrumblesAuditLogViewerContract.View view,
      CrumblesAppAuditLogger appAuditLogger,
      Executor chainCheckExecutor,
      Executor viewExecutor,
      IntSupplier sealBeforeClear) {
    this.view = view;
    this.appAuditLogger = appAuditLogger;
    this.chainCheckExecutor = chainCheckExecutor;
    this.viewExecutor = viewExecutor;
    this.sealBeforeClear = sealBeforeClear;
  }

  @Override
  public void onViewingConfirmed() {
    // Recorded before the logs load, so that the viewer lists this viewing too.
    appAuditLogger.logEvent(AUDIT_EVENT_VIEWED, "User authenticated to view the activity log.");
    loadAuditLogs();
  }

  @Override
  public void onViewingNotConfirmed() {
    appAuditLogger.logEvent(
        AUDIT_EVENT_VIEW_AUTH_FAILED,
        "Activity log not shown because the user did not authenticate to view it.");
  }

  @Override
  public void onViewingUnavailable() {
    appAuditLogger.logEvent(
        AUDIT_EVENT_VIEW_REFUSED,
        "Activity log not shown because no secure lock screen is set up.");
  }

  @Override
  public void onClearLogsClicked() {
    view.showClearLogsConfirmationDialog();
  }

  @Override
  public void onClearLogsConfirmed() {
    // Recorded first, so that the attempt stays on record even if the prompt never returns.
    appAuditLogger.logEvent(AUDIT_EVENT_CLEAR_REQUESTED, "User asked to clear the activity log.");
    view.requestDeviceCredentialConfirmation();
  }

  @Override
  public void onDeviceCredentialConfirmed() {
    chainCheckExecutor.execute(this::sealThenClear);
  }

  /**
   * Seals the unshipped records into a log batch, then clears the logs unless that failed. The
   * clear keeps the records that are unshipped by then, such as those logged while the batch was
   * written, so that the next batch ships them.
   */
  private void sealThenClear() {
    int unsealedCount = sealBeforeClear.getAsInt();
    if (unsealedCount > 0) {
      // Clearing would erase records that no batch carries yet, with no copy left anywhere.
      appAuditLogger.logEvent(
          AUDIT_EVENT_CLEAR_REFUSED,
          "Activity log kept because "
              + unsealedCount
              + " unshipped record(s) could not be sealed into a log batch first.");
      viewExecutor.execute(
          () -> {
            view.showClearRefused();
            loadAuditLogs();
          });
      return;
    }
    appAuditLogger.clearShippedLogs();
    viewExecutor.execute(this::loadAuditLogs);
  }

  @Override
  public void onDeviceCredentialUnavailable() {
    appAuditLogger.logEvent(
        AUDIT_EVENT_CLEAR_REFUSED, "Activity log kept because no secure lock screen is set up.");
    loadAuditLogs();
  }

  @Override
  public void onDeviceCredentialNotConfirmed() {
    appAuditLogger.logEvent(
        AUDIT_EVENT_CLEAR_AUTH_FAILED,
        "Activity log kept because no device credential was confirmed for clearing it.");
    loadAuditLogs();
  }

  private void loadAuditLogs() {
    List<CrumblesAuditEvent> events = appAuditLogger.getAllPersistedEventsForDisplay();
    if (events == null || events.isEmpty()) {
      view.showNoLogsMessage();
      return;
    }
    view.showLogs(events);
    view.showChainVerificationInProgress();
    // The check costs one Keystore operation per record, far too slow for the view's thread.
    chainCheckExecutor.execute(
        () -> {
          CrumblesChainVerification verification = appAuditLogger.verifyChain();
          viewExecutor.execute(() -> view.showChainVerification(verification));
        });
  }
}
