/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.securelogging.audit;

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.RecyclerView;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.R;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/** Unit tests for the {@link CrumblesAuditLogAdapter} class. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesAuditLogAdapterTest {

  private Context context;
  private List<CrumblesAuditEvent> testEvents;
  private CrumblesAuditLogAdapter adapter;

  @Before
  public void setUp() {
    // Given: A context and a list of sample audit events.
    context = ApplicationProvider.getApplicationContext();
    context.setTheme(R.style.Theme_Crumbles); // Use the application's theme.

    testEvents = new ArrayList<>();
    testEvents.add(
        new CrumblesAuditEvent(Instant.now().minusMillis(1000), "EVENT_A", "Message A."));
    testEvents.add(
        new CrumblesAuditEvent(InstantSource.system().instant(), "EVENT_B", "Message B."));

    // And: The adapter is initialized with these events.
    adapter = new CrumblesAuditLogAdapter(testEvents);
  }

  @Test
  public void getItemCount_whenAdapterInitialized_returnsCorrectSize() {
    // Given: An adapter initialized with a list of events (in setUp).

    // When: getItemCount is called.
    int count = adapter.getItemCount();

    // Then: The count should match the number of events provided.
    assertThat(count).isEqualTo(testEvents.size());
  }

  @Test
  public void onCreateViewHolder_whenCalled_returnsCorrectViewHolderType() {
    // Given: A mock ViewGroup parent.
    ViewGroup parent = new LinearLayout(context);

    // When: onCreateViewHolder is called.
    CrumblesAuditLogAdapter.LogViewHolder viewHolder = adapter.onCreateViewHolder(parent, 0);

    // Then: The returned ViewHolder should not be null and be of the correct type.
    assertThat(viewHolder).isNotNull();
    CrumblesAuditLogAdapter.LogViewHolder unused = viewHolder;
    assertThat((View) viewHolder.itemView.findViewById(R.id.tv_audit_timestamp)).isNotNull();
    assertThat((View) viewHolder.itemView.findViewById(R.id.tv_audit_event_type)).isNotNull();
    assertThat((View) viewHolder.itemView.findViewById(R.id.tv_audit_message)).isNotNull();
  }

  @Test
  public void onBindViewHolder_whenCalled_bindsDataToViewsCorrectly() {
    // Given: A ViewHolder created by inflating the item layout.
    ViewGroup parent = new LinearLayout(context);
    LayoutInflater inflater = LayoutInflater.from(context);
    View itemView = inflater.inflate(R.layout.list_item_audit_log, parent, false);
    CrumblesAuditLogAdapter.LogViewHolder holder =
        new CrumblesAuditLogAdapter.LogViewHolder(itemView);
    // And: A specific event to bind.
    CrumblesAuditEvent eventToBind = testEvents.get(0);
    int position = 0;

    // When: onBindViewHolder is called for that position.
    adapter.onBindViewHolder(holder, position);

    // Then: The TextViews in the ViewHolder should display the correct data from the event.
    assertThat(holder.tvTimestamp.getText().toString())
        .isEqualTo(eventToBind.getFormattedTimestamp());
    assertThat(holder.tvEventType.getText().toString()).isEqualTo(eventToBind.getEventType());
    assertThat(holder.tvMessage.getText().toString()).isEqualTo(eventToBind.getMessage());
  }

  @Test
  public void updateEvents_whenNewListProvided_updatesAdapterAndNotifiesChange() {
    // Given: An adapter with initial events.
    int initialCount = adapter.getItemCount();
    assertThat(initialCount).isEqualTo(2);

    // And: A new list of events.
    List<CrumblesAuditEvent> newEvents = new ArrayList<>();
    newEvents.add(new CrumblesAuditEvent(Instant.now().plusMillis(2000), "EVENT_C", "Message C."));

    // When: updateEvents is called with the new list.
    adapter.updateEvents(newEvents);

    // Then: The item count should reflect the new list size.
    assertThat(adapter.getItemCount()).isEqualTo(newEvents.size());
    // And: The adapter's internal list should now be the new list.
    ViewGroup parent = new LinearLayout(context);
    LayoutInflater inflater = LayoutInflater.from(context);
    View itemView = inflater.inflate(R.layout.list_item_audit_log, parent, false);
    CrumblesAuditLogAdapter.LogViewHolder holder =
        new CrumblesAuditLogAdapter.LogViewHolder(itemView);
    adapter.onBindViewHolder(holder, 0);

    assertThat(holder.tvEventType.getText().toString()).isEqualTo("EVENT_C");
  }
}
