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

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import com.android.securelogging.CrumblesDeviceAdminReceiver;
import com.android.securelogging.CrumblesDeviceCredentialGate;
import com.android.securelogging.CrumblesWindowInsets;
import com.android.securelogging.R;
import com.android.securelogging.audit.CrumblesAppAuditLogger.CrumblesChainVerification;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Activity to display and interact with Crumbles audit logs. */
public class CrumblesAuditLogViewerActivity extends AppCompatActivity
    implements CrumblesAuditLogViewerContract.View {

  /**
   * Runs the chain checks of every viewer one at a time, so reopening the viewer does not start a
   * second check alongside one still running. Its thread ends once it has been idle for a minute.
   */
  static final ThreadPoolExecutor chainCheckExecutor =
      new ThreadPoolExecutor(
          /* corePoolSize= */ 0,
          /* maximumPoolSize= */ 1,
          /* keepAliveTime= */ 1,
          TimeUnit.MINUTES,
          new LinkedBlockingQueue<>());

  private RecyclerView rvAuditLogs;
  private CrumblesAuditLogAdapter adapter;
  private TextView tvNoAuditLogs;
  private TextView tvChainStatus;
  private Button btnClearAuditLogs;

  private CrumblesAuditLogViewerContract.Presenter presenter;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_audit_log_viewer);
    CrumblesWindowInsets.applySystemBarPadding(this);

    Context appContext = getApplicationContext();
    presenter =
        new CrumblesAuditLogViewerPresenter(
            this,
            CrumblesAppAuditLogger.getInstance(appContext),
            chainCheckExecutor,
            this::runOnUiThread,
            () -> CrumblesDeviceAdminReceiver.sealActivityLogBeforeClear(appContext));

    if (getSupportActionBar() != null) {
      getSupportActionBar().setDisplayHomeAsUpEnabled(true);
      getSupportActionBar().setTitle(getString(R.string.title_audit_log_viewer));
    }

    rvAuditLogs = findViewById(R.id.rv_audit_logs);
    tvNoAuditLogs = findViewById(R.id.tv_no_audit_logs);
    tvChainStatus = findViewById(R.id.tv_audit_chain_status);
    btnClearAuditLogs = findViewById(R.id.btn_clear_audit_logs);

    rvAuditLogs.setLayoutManager(new LinearLayoutManager(this));
    adapter = new CrumblesAuditLogAdapter(new ArrayList<>());
    rvAuditLogs.setAdapter(adapter);

    requestViewingConfirmation();
  }

  /**
   * Shows the logs, which name keys, destinations and decrypted files, only once the user confirms
   * a Class 3 biometric or the device credential, as for decrypting logs, and closes otherwise.
   * Clearing starts from the logs, so it is offered only then too.
   */
  private void requestViewingConfirmation() {
    CrumblesDeviceCredentialGate.confirmStrongCredential(
        this,
        getString(R.string.audit_log_view_auth_title),
        /* subtitle= */ null,
        () -> {
          btnClearAuditLogs.setOnClickListener(v -> presenter.onClearLogsClicked());
          presenter.onViewingConfirmed();
        },
        () -> {
          presenter.onViewingNotConfirmed();
          finish();
        },
        () -> {
          Toast.makeText(
                  this, R.string.toast_audit_log_view_requires_screen_lock, Toast.LENGTH_LONG)
              .show();
          presenter.onViewingUnavailable();
          finish();
        });
  }

  /** Closes the logs once they are out of sight, so that showing them again takes a new prompt. */
  @Override
  protected void onStop() {
    super.onStop();
    if (!isChangingConfigurations()) {
      finish();
    }
  }

  @Override
  public void showLogs(List<CrumblesAuditEvent> events) {
    tvNoAuditLogs.setVisibility(View.GONE);
    rvAuditLogs.setVisibility(View.VISIBLE);
    adapter.updateEvents(events);
  }

  @Override
  public void showNoLogsMessage() {
    tvNoAuditLogs.setVisibility(View.VISIBLE);
    rvAuditLogs.setVisibility(View.GONE);
    tvChainStatus.setVisibility(View.GONE);
  }

  @Override
  public void showChainVerificationInProgress() {
    showChainStatus(getString(R.string.audit_chain_check_running));
  }

  @Override
  public void showChainVerification(CrumblesChainVerification verification) {
    showChainStatus(describeChainVerification(verification));
  }

  private void showChainStatus(String status) {
    tvChainStatus.setText(status);
    tvChainStatus.setVisibility(View.VISIBLE);
  }

  /** Says what the chain check found, and what that does and does not prove. */
  private String describeChainVerification(CrumblesChainVerification verification) {
    if (!verification.isIntact()) {
      return getString(
          R.string.audit_chain_check_broken,
          verification.getFirstBrokenIndex() + 1,
          verification.getTotalRecords());
    }
    if (verification.getVerifiedRecords() == 0) {
      return getString(R.string.audit_chain_check_not_possible);
    }
    return getString(
        verification.getUnverifiableRecords() > 0
            ? R.string.audit_chain_check_partly_passed
            : R.string.audit_chain_check_passed);
  }

  @Override
  public void showClearLogsConfirmationDialog() {
    new AlertDialog.Builder(this)
        .setTitle(getString(R.string.dialog_title_clear_audit_logs))
        .setMessage(getString(R.string.dialog_message_clear_audit_logs_confirmation))
        .setPositiveButton(
            getString(R.string.dialog_button_clear),
            (dialog, which) -> presenter.onClearLogsConfirmed()) // Delegate to presenter.
        .setNegativeButton(android.R.string.cancel, null)
        .setIcon(android.R.drawable.ic_dialog_alert)
        .show();
  }

  @Override
  public void requestDeviceCredentialConfirmation() {
    if (getSystemService(Context.KEYGUARD_SERVICE) == null) {
      Toast.makeText(this, "Device does not support Keyguard.", Toast.LENGTH_SHORT).show();
      presenter.onDeviceCredentialUnavailable();
      return;
    }
    CrumblesDeviceCredentialGate.confirmScreenLock(
        this,
        getString(R.string.dialog_title_clear_audit_logs),
        /* subtitle= */ null,
        presenter::onDeviceCredentialConfirmed,
        () -> {
          Toast.makeText(this, "Authentication cancelled.", Toast.LENGTH_SHORT).show();
          presenter.onDeviceCredentialNotConfirmed();
        },
        () -> {
          Toast.makeText(
                  this, "Please set up a screen lock in your device settings.", Toast.LENGTH_SHORT)
              .show();
          presenter.onDeviceCredentialUnavailable();
        });
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      finish();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }
}
