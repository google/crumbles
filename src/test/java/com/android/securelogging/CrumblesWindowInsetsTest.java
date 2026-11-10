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

package com.android.securelogging;

import static android.os.Build.VERSION_CODES.VANILLA_ICE_CREAM;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.WindowInsets;
import androidx.core.graphics.Insets;
import androidx.core.view.WindowInsetsCompat;
import androidx.test.core.app.ApplicationProvider;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.audit.CrumblesAuditLogViewerActivity;
import com.google.common.truth.Expect;
import com.google.testing.junit.testparameterinjector.TestParameter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestParameterInjector;
import org.robolectric.annotation.Config;

/** Tests that Crumbles activities keep their content clear of the system bars. */
@RunWith(RobolectricTestParameterInjector.class)
@Config(sdk = VANILLA_ICE_CREAM)
public final class CrumblesWindowInsetsTest {

  private static final int WINDOW_WIDTH = 1080;
  private static final int WINDOW_HEIGHT = 2400;
  private static final int STATUS_BAR_HEIGHT = 63;
  private static final int NAVIGATION_BAR_HEIGHT = 48;
  private static final int DISPLAY_CUTOUT_WIDTH = 30;
  private static final WindowInsets windowInsets =
      new WindowInsetsCompat.Builder()
          .setInsets(
              WindowInsetsCompat.Type.statusBars(),
              Insets.of(/* left= */ 0, STATUS_BAR_HEIGHT, /* right= */ 0, /* bottom= */ 0))
          .setInsets(
              WindowInsetsCompat.Type.navigationBars(),
              Insets.of(/* left= */ 0, /* top= */ 0, /* right= */ 0, NAVIGATION_BAR_HEIGHT))
          .setInsets(
              WindowInsetsCompat.Type.displayCutout(),
              Insets.of(DISPLAY_CUTOUT_WIDTH, /* top= */ 0, /* right= */ 0, /* bottom= */ 0))
          .build()
          .toWindowInsets();

  @Rule public final Expect expect = Expect.create();

  private enum ActivityWithoutActionBar {
    MAIN(CrumblesMain.class, /* layoutPaddingDp= */ 16),
    DECRYPTED_LOGS(CrumblesDecryptedLogsActivity.class, /* layoutPaddingDp= */ 16),
    QR_SCANNER(CrumblesQrScannerActivity.class, /* layoutPaddingDp= */ 0);

    final Class<? extends Activity> activityClass;
    final int layoutPaddingDp;

    ActivityWithoutActionBar(Class<? extends Activity> activityClass, int layoutPaddingDp) {
      this.activityClass = activityClass;
      this.layoutPaddingDp = layoutPaddingDp;
    }
  }

  private enum ActivityWithActionBar {
    MANAGE_EXTERNAL_KEYS(CrumblesManageExternalKeysActivity.class, /* layoutPaddingDp= */ 16),
    AUDIT_LOG_VIEWER(CrumblesAuditLogViewerActivity.class, /* layoutPaddingDp= */ 0),
    SETUP(CrumblesSetupActivity.class, /* layoutPaddingDp= */ 16),
    RE_ENCRYPT_KEYS(CrumblesReEncryptKeysActivity.class, /* layoutPaddingDp= */ 16);

    final Class<? extends AppCompatActivity> activityClass;
    final int layoutPaddingDp;

    ActivityWithActionBar(Class<? extends AppCompatActivity> activityClass, int layoutPaddingDp) {
      this.activityClass = activityClass;
      this.layoutPaddingDp = layoutPaddingDp;
    }
  }

  @Before
  public void setUp() {
    Context context = ApplicationProvider.getApplicationContext();
    // Declared in the manifest, so granted at install.
    shadowOf((Application) context).grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);
    WorkManagerTestInitHelper.initializeTestWorkManager(context);
    CrumblesSetupActivity.markAcknowledged(context);
  }

  @Test
  public void onCreate_withoutActionBar_padsContentClearOfSystemBars(
      @TestParameter ActivityWithoutActionBar activityWithoutActionBar) {
    Activity activity =
        Robolectric.buildActivity(activityWithoutActionBar.activityClass).setup().get();
    int layoutPadding = toPixels(activity, activityWithoutActionBar.layoutPaddingDp);

    dispatchWindowInsets(activity);

    View contentRoot = getContentRoot(activity);
    expect.that(contentRoot.getPaddingLeft()).isEqualTo(layoutPadding + DISPLAY_CUTOUT_WIDTH);
    expect.that(contentRoot.getPaddingTop()).isEqualTo(layoutPadding + STATUS_BAR_HEIGHT);
    expect.that(contentRoot.getPaddingRight()).isEqualTo(layoutPadding);
    expect.that(contentRoot.getPaddingBottom()).isEqualTo(layoutPadding + NAVIGATION_BAR_HEIGHT);
  }

  @Test
  public void onCreate_withActionBar_padsContentBelowActionBar(
      @TestParameter ActivityWithActionBar activityWithActionBar) {
    AppCompatActivity activity =
        Robolectric.buildActivity(activityWithActionBar.activityClass).setup().get();
    int layoutPadding = toPixels(activity, activityWithActionBar.layoutPaddingDp);

    dispatchWindowInsets(activity);

    View contentRoot = getContentRoot(activity);
    int actionBarHeight = activity.getSupportActionBar().getHeight();
    expect.that(actionBarHeight).isGreaterThan(STATUS_BAR_HEIGHT);
    expect.that(contentRoot.getPaddingLeft()).isEqualTo(layoutPadding + DISPLAY_CUTOUT_WIDTH);
    expect.that(contentRoot.getPaddingTop()).isEqualTo(layoutPadding + actionBarHeight);
    expect.that(contentRoot.getPaddingRight()).isEqualTo(layoutPadding);
    expect.that(contentRoot.getPaddingBottom()).isEqualTo(layoutPadding + NAVIGATION_BAR_HEIGHT);
  }

  private static int toPixels(Activity activity, int valueDp) {
    return Math.round(valueDp * activity.getResources().getDisplayMetrics().density);
  }

  private static View getContentRoot(Activity activity) {
    ViewGroup contentParent = activity.findViewById(android.R.id.content);
    return contentParent.getChildAt(0);
  }

  /**
   * Dispatches {@link #windowInsets} to the window and lays it out, as the decor action bar only
   * forwards insets to the content while it is measured.
   */
  private static void dispatchWindowInsets(Activity activity) {
    View decorView = activity.getWindow().getDecorView();
    decorView.dispatchApplyWindowInsets(windowInsets);
    decorView.measure(
        MeasureSpec.makeMeasureSpec(WINDOW_WIDTH, MeasureSpec.EXACTLY),
        MeasureSpec.makeMeasureSpec(WINDOW_HEIGHT, MeasureSpec.EXACTLY));
    decorView.layout(/* l= */ 0, /* t= */ 0, WINDOW_WIDTH, WINDOW_HEIGHT);
  }
}
