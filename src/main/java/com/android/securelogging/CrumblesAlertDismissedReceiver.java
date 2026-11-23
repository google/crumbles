/*
 * Copyright 2026 Google LLC
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

package com.android.securelogging;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Receives the delete intent of an alert that the user dismissed, records the dismissal and posts
 * the alert again while the problem it reports lasts.
 *
 * <p>Since Android 14, the user can swipe away the ongoing notifications of an app that is not a
 * device or profile owner, as when Crumbles collects logs as a delegate. Crumbles cancels an alert
 * itself once its problem is solved, which sends no delete intent.
 */
public final class CrumblesAlertDismissedReceiver extends BroadcastReceiver {

  static final String EXTRA_NOTIFICATION_ID = "com.android.securelogging.extra.NOTIFICATION_ID";
  static final String EXTRA_TITLE = "com.android.securelogging.extra.ALERT_TITLE";
  static final String EXTRA_TEXT = "com.android.securelogging.extra.ALERT_TEXT";

  @Override
  public void onReceive(Context context, Intent intent) {
    String title = intent.getStringExtra(EXTRA_TITLE);
    String text = intent.getStringExtra(EXTRA_TEXT);
    if (title == null || text == null) {
      return;
    }
    CrumblesDeviceAdminReceiver.repostDismissedAlert(
        context, intent.getIntExtra(EXTRA_NOTIFICATION_ID, /* defaultValue= */ 0), title, text);
  }
}
