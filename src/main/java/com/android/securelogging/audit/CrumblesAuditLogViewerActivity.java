package com.android.securelogging.audit;

import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import com.android.securelogging.R;
import java.util.ArrayList;
import java.util.List;

/** Activity to display and interact with Crumbles audit logs. */
public class CrumblesAuditLogViewerActivity extends AppCompatActivity
    implements CrumblesAuditLogViewerContract.View {

  private RecyclerView rvAuditLogs;
  private CrumblesAuditLogAdapter adapter;
  private TextView tvNoAuditLogs;
  private Button btnClearAuditLogs;

  private CrumblesAuditLogViewerContract.Presenter presenter;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_audit_log_viewer);

    presenter =
        new CrumblesAuditLogViewerPresenter(
            this, CrumblesAppAuditLogger.getInstance(getApplicationContext()));

    if (getSupportActionBar() != null) {
      getSupportActionBar().setDisplayHomeAsUpEnabled(true);
      getSupportActionBar().setTitle(getString(R.string.title_audit_log_viewer));
    }

    rvAuditLogs = findViewById(R.id.rv_audit_logs);
    tvNoAuditLogs = findViewById(R.id.tv_no_audit_logs);
    btnClearAuditLogs = findViewById(R.id.btn_clear_audit_logs);

    rvAuditLogs.setLayoutManager(new LinearLayoutManager(this));
    adapter = new CrumblesAuditLogAdapter(new ArrayList<>());
    rvAuditLogs.setAdapter(adapter);

    btnClearAuditLogs.setOnClickListener(v -> presenter.onClearLogsClicked());

    presenter.onViewCreated();
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
  public boolean onOptionsItemSelected(MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      finish();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }
}
