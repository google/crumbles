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

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for {@link CrumblesCollectionScope}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesCollectionScopeTest {

  private static final Context context = ApplicationProvider.getApplicationContext();

  @Test
  public void isNetworkCollectionEnabled_whenNeverSet_returnsTrue() {
    assertThat(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
  }

  @Test
  public void isNetworkCollectionEnabled_whenDisabled_returnsFalse() {
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);

    assertThat(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isFalse();
  }

  @Test
  public void isNetworkCollectionEnabled_whenReEnabled_returnsTrue() {
    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ false);

    CrumblesCollectionScope.setNetworkCollectionEnabled(context, /* enabled= */ true);

    assertThat(CrumblesCollectionScope.isNetworkCollectionEnabled(context)).isTrue();
  }
}
