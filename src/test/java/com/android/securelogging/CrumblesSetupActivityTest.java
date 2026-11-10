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

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.google.common.truth.Expect;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.util.ReflectionHelpers;

/** Unit tests for {@link CrumblesSetupActivity} and for {@link CrumblesMain} opening it. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesSetupActivityTest {

  @Rule public final Expect expect = Expect.create();

  private final Context context = ApplicationProvider.getApplicationContext();

  @Before
  public void setUp() {
    // Declared in the manifest, so granted at install.
    shadowOf((Application) ApplicationProvider.getApplicationContext())
        .grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
  }

  @Test
  public void manifest_doesNotExportSetupActivity() throws Exception {
    boolean exported =
        context
            .getPackageManager()
            .getActivityInfo(
                new ComponentName(context, CrumblesSetupActivity.class), /* flags= */ 0)
            .exported;

    assertThat(exported).isFalse();
  }

  @Test
  public void crumblesMain_beforeAcknowledgment_opensSetupScreenInsteadOfItself() {
    CrumblesMain mainActivity = Robolectric.buildActivity(CrumblesMain.class).create().get();

    Intent startedIntent = shadowOf(mainActivity).getNextStartedActivity();
    assertThat(startedIntent).isNotNull();
    expect
        .that(startedIntent.getComponent())
        .isEqualTo(new ComponentName(mainActivity, CrumblesSetupActivity.class));
    expect.that(mainActivity.isFinishing()).isTrue();
    expect.that((Object) mainActivity.findViewById(R.id.material_switch)).isNull();
  }

  @Test
  public void onCreate_showsWhatIsCollectedWhereItGoesAndWhatItNeverDoes() {
    CrumblesSetupActivity activity = launchSetupActivity();

    expect.that(activity.getTitle().toString()).isEqualTo("Before you start");
    expect
        .that(getText(activity, R.id.setup_collected_textview))
        .isEqualTo(activity.getString(R.string.setup_collected_body));
    expect
        .that(getText(activity, R.id.setup_destination_textview))
        .isEqualTo(activity.getString(R.string.setup_destination_body));
    expect
        .that(getText(activity, R.id.setup_never_textview))
        .isEqualTo(activity.getString(R.string.setup_never_body));
  }

  @Test
  public void onCreate_setsFlagSecure() {
    CrumblesSetupActivity activity = launchSetupActivity();

    assertThat(activity.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE)
        .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
  }

  @Test
  public void onCreate_hidesOverlayWindows() {
    assertThat(hidesOverlayWindows(launchSetupActivity())).isTrue();
  }

  @Test
  public void onCreate_withoutAcknowledgment_recordsNothingAndStaysOpen() {
    CrumblesSetupActivity activity = launchSetupActivity();

    expect.that(CrumblesSetupActivity.isAcknowledged(context)).isFalse();
    expect.that(hasAcknowledgedEvent()).isFalse();
    expect.that(shadowOf(activity).getNextStartedActivity()).isNull();
    expect.that(activity.isFinishing()).isFalse();
  }

  @Test
  public void acknowledgeButton_recordsAcknowledgmentAndOpensMainScreen() {
    CrumblesSetupActivity activity = launchSetupActivity();

    activity.findViewById(R.id.btn_setup_acknowledge).performClick();

    Intent startedIntent = shadowOf(activity).getNextStartedActivity();
    assertThat(startedIntent).isNotNull();
    expect
        .that(startedIntent.getComponent())
        .isEqualTo(new ComponentName(activity, CrumblesMain.class));
    expect.that(CrumblesSetupActivity.isAcknowledged(context)).isTrue();
    expect.that(hasAcknowledgedEvent()).isTrue();
    expect.that(activity.isFinishing()).isTrue();
  }

  private static CrumblesSetupActivity launchSetupActivity() {
    return Robolectric.buildActivity(CrumblesSetupActivity.class).setup().get();
  }

  private static String getText(Activity activity, int textViewId) {
    return activity.<TextView>findViewById(textViewId).getText().toString();
  }

  private boolean hasAcknowledgedEvent() {
    return CrumblesAppAuditLogger.getInstance(context).getMemoryCachedEvents().stream()
        .anyMatch(event -> event.getEventType().equals("SETUP_NOTICE_ACKNOWLEDGED"));
  }

  /** Returns whether {@code activity} keeps the overlay windows of other apps hidden. */
  private static boolean hidesOverlayWindows(Activity activity) {
    int hideOverlays =
        ReflectionHelpers.getStaticField(
            WindowManager.LayoutParams.class, "SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS");
    int privateFlags =
        ReflectionHelpers.getField(activity.getWindow().getAttributes(), "privateFlags");
    return (privateFlags & hideOverlays) == hideOverlays;
  }
}
