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

/** Contract between the view and presenter for the Crumbles audit log viewer. */
public final class CrumblesAuditLogViewerContract {
  /** The view interface for the Crumbles audit log viewer. */
  interface View {
    void showLogs(List<CrumblesAuditEvent> events);

    void showNoLogsMessage();

    /** Shows that the records are being checked against the activity log's hash chain. */
    void showChainVerificationInProgress();

    /** Shows what checking the records against the activity log's hash chain found. */
    void showChainVerification(CrumblesChainVerification verification);

    void showClearLogsConfirmationDialog();

    /** Asks the user to re-enter the device credential before the logs are cleared. */
    void requestDeviceCredentialConfirmation();
  }

  /** The presenter interface for the Crumbles audit log viewer. */
  interface Presenter {
    /** Called once the user has authenticated to view the logs, which are then shown. */
    void onViewingConfirmed();

    /** Called when the user did not authenticate to view the logs, which stay hidden. */
    void onViewingNotConfirmed();

    /** Called when the logs stay hidden because no secure lock screen is set up. */
    void onViewingUnavailable();

    void onClearLogsClicked();

    void onClearLogsConfirmed();

    /** Called once the user has successfully re-entered the device credential. */
    void onDeviceCredentialConfirmed();

    /** Called when the logs cannot be cleared because no device credential can be confirmed. */
    void onDeviceCredentialUnavailable();

    /** Called when the user did not re-enter the device credential. */
    void onDeviceCredentialNotConfirmed();
  }

  private CrumblesAuditLogViewerContract() {}
}
