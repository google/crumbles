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

import android.app.Activity;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

/** Keeps the content of Crumbles activities clear of the system bars. */
public final class CrumblesWindowInsets {

  /**
   * Pads the root view of the activity's content by the system bar and display cutout insets, in
   * addition to the padding declared by its layout.
   *
   * <p>Apps targeting Android 15 or higher are laid out edge-to-edge, so without this padding the
   * content is drawn under the status bar and the navigation bar. When the window shows a decor
   * action bar, the action bar adds its own height to the top system bar inset it dispatches to the
   * content, so the padded content also starts below the action bar.
   *
   * <p>Must be called after {@link Activity#setContentView(int)}.
   */
  public static void applySystemBarPadding(Activity activity) {
    ViewGroup contentParent = activity.findViewById(android.R.id.content);
    View contentRoot = contentParent.getChildAt(0);
    int paddingLeft = contentRoot.getPaddingLeft();
    int paddingTop = contentRoot.getPaddingTop();
    int paddingRight = contentRoot.getPaddingRight();
    int paddingBottom = contentRoot.getPaddingBottom();
    ViewCompat.setOnApplyWindowInsetsListener(
        contentRoot,
        (view, windowInsets) -> {
          Insets insets =
              windowInsets.getInsets(
                  WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
          view.setPadding(
              paddingLeft + insets.left,
              paddingTop + insets.top,
              paddingRight + insets.right,
              paddingBottom + insets.bottom);
          return WindowInsetsCompat.CONSUMED;
        });
  }

  private CrumblesWindowInsets() {}
}
