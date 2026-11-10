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

import static com.google.common.truth.Truth.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CrumblesConstants}. */
@RunWith(JUnit4.class)
public final class CrumblesConstantsTest {

  @Test
  public void notificationIds_areDistinct() {
    Set<Integer> ids = new HashSet<>();
    assertThat(ids.add(CrumblesConstants.UPLOAD_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.DEFERRED_LOGS_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.STORAGE_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.PREFERENCES_UNREADABLE_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.LOGGING_DISABLED_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.NO_SCREEN_LOCK_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.KEY_DELETED_NOTIFICATION_ID)).isTrue();
    assertThat(ids.add(CrumblesConstants.COLLECTION_PAUSED_NOTIFICATION_ID)).isTrue();
  }
}
