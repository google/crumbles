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

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.WindowManager;
import androidx.appcompat.app.AppCompatActivity;
import com.android.securelogging.audit.CrumblesAppAuditLogger;

/**
 * Tells the user what Crumbles collects, where it goes and what Crumbles never does.
 *
 * <p>{@link CrumblesMain} opens this screen instead of itself until the user acknowledges the
 * notice. The acknowledgment is persisted, so the notice is shown once per installation. Leaving
 * the screen any other way closes the app without recording an acknowledgment.
 */
public final class CrumblesSetupActivity extends AppCompatActivity {

  /**
   * Whether the user acknowledged the notice. Versioned so that a later change to what Crumbles
   * collects can ask the user to read the notice again.
   */
  private static final String PREF_NOTICE_ACKNOWLEDGED = "setupNoticeAcknowledgedV1";

  /** Returns whether the user has acknowledged the notice. */
  static boolean isAcknowledged(Context context) {
    return context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .getBoolean(PREF_NOTICE_ACKNOWLEDGED, /* defValue= */ false);
  }

  /** Records that the user has acknowledged the notice. */
  static void markAcknowledged(Context context) {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putBoolean(PREF_NOTICE_ACKNOWLEDGED, true)
        .apply();
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    CrumblesLauncherEntry.applyToTask(this);
    setContentView(R.layout.activity_setup);
    CrumblesWindowInsets.applySystemBarPadding(this);
    findViewById(R.id.btn_setup_acknowledge).setOnClickListener(v -> onAcknowledgeClicked());
  }

  private void onAcknowledgeClicked() {
    markAcknowledged(this);
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            "SETUP_NOTICE_ACKNOWLEDGED",
            "User acknowledged the notice listing what Crumbles collects.");
    startActivity(new Intent(this, CrumblesMain.class));
    finish();
  }
}
