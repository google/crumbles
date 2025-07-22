package com.android.securelogging.audit;

import android.support.v7.util.DiffUtil;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import com.android.securelogging.R;
import java.util.List;
import java.util.Objects;

/** Adapter for displaying audit logs in a RecyclerView. */
public class CrumblesAuditLogAdapter
    extends RecyclerView.Adapter<CrumblesAuditLogAdapter.LogViewHolder> {

  private List<CrumblesAuditEvent> auditEvents;

  public CrumblesAuditLogAdapter(List<CrumblesAuditEvent> auditEvents) {
    this.auditEvents = auditEvents;
  }

  @NonNull
  @Override
  public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
    View view =
        LayoutInflater.from(parent.getContext())
            .inflate(R.layout.list_item_audit_log, parent, false);
    return new LogViewHolder(view);
  }

  @Override
  public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
    CrumblesAuditEvent event = auditEvents.get(position);
    holder.tvTimestamp.setText(event.getFormattedTimestamp());
    holder.tvEventType.setText(event.getEventType());
    holder.tvMessage.setText(event.getMessage());
  }

  @Override
  public int getItemCount() {
    return auditEvents.size();
  }

  static class LogViewHolder extends RecyclerView.ViewHolder {
    TextView tvTimestamp;
    TextView tvEventType;
    TextView tvMessage;

    LogViewHolder(View itemView) {
      super(itemView);
      tvTimestamp = itemView.findViewById(R.id.tv_audit_timestamp);
      tvEventType = itemView.findViewById(R.id.tv_audit_event_type);
      tvMessage = itemView.findViewById(R.id.tv_audit_message);
    }
  }

  public void updateEvents(List<CrumblesAuditEvent> newEvents) {
    // 1. Calculate the diff.
    DiffUtil.DiffResult diffResult =
        DiffUtil.calculateDiff(new CrumblesAuditLogDiffCallback(this.auditEvents, newEvents));

    // 2. Update the adapter's data list.
    this.auditEvents = newEvents;

    // 3. Dispatch the updates to the RecyclerView
    diffResult.dispatchUpdatesTo(this);
  }

  private static class CrumblesAuditLogDiffCallback extends DiffUtil.Callback {
    private final List<CrumblesAuditEvent> oldList;
    private final List<CrumblesAuditEvent> newList;

    CrumblesAuditLogDiffCallback(
        List<CrumblesAuditEvent> oldList, List<CrumblesAuditEvent> newList) {
      this.oldList = oldList;
      this.newList = newList;
    }

    @Override
    public int getOldListSize() {
      return oldList.size();
    }

    @Override
    public int getNewListSize() {
      return newList.size();
    }

    @Override
    public boolean areItemsTheSame(int oldItemPosition, int newItemPosition) {
      // Compare unique identifiers for audit items.
      // Assuming Instant with nanosecond precision is unique enough for this context.
      return oldList
          .get(oldItemPosition)
          .getTimestamp()
          .equals(newList.get(newItemPosition).getTimestamp());
    }

    @Override
    public boolean areContentsTheSame(int oldItemPosition, int newItemPosition) {
      CrumblesAuditEvent oldEvent = oldList.get(oldItemPosition);
      CrumblesAuditEvent newEvent = newList.get(newItemPosition);

      // Using Objects.equals for null-safe comparison.
      return Objects.equals(oldEvent.getTimestamp(), newEvent.getTimestamp())
          && Objects.equals(oldEvent.getEventType(), newEvent.getEventType())
          && Objects.equals(oldEvent.getMessage(), newEvent.getMessage());
    }
  }
}
