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
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CrumblesDecryptedLogsSession}. */
@RunWith(JUnit4.class)
public class CrumblesDecryptedLogsSessionTest {

  @After
  public void tearDown() {
    CrumblesDecryptedLogsSession.destroyActiveSession();
  }

  private static long createSession(byte[] raw) {
    return CrumblesDecryptedLogsSession.startSession(
        ImmutableList.of(new CrumblesDecryptedLogEntry("log.bin", raw)));
  }

  @Test
  public void startSession_storesEntries() {
    long sessionId = createSession("secret".getBytes(UTF_8));

    CrumblesDecryptedLogsSession session =
        CrumblesDecryptedLogsSession.getSession(sessionId).orElseThrow();
    assertThat(session.getEntries().get(0).getContent()).isEqualTo("secret");
  }

  @Test
  public void getSession_withUnknownSessionId_returnsEmpty() {
    assertThat(CrumblesDecryptedLogsSession.getSession(/* sessionId= */ 999L)).isEmpty();
  }

  @Test
  public void startSession_whenPreviousSessionExists_wipesAndReplacesPreviousSession() {
    byte[] raw1 = "secret".getBytes(UTF_8);
    long id1 = createSession(raw1);
    CrumblesDecryptedLogsSession s1 = CrumblesDecryptedLogsSession.getSession(id1).orElseThrow();

    long id2 = createSession("other".getBytes(UTF_8));

    assertThat(CrumblesDecryptedLogsSession.getSession(id1)).isEmpty();
    assertThat(s1.getEntries()).isEmpty();
    assertThat(raw1).isEqualTo(new byte[raw1.length]);
    assertThat(CrumblesDecryptedLogsSession.getSession(id2)).isPresent();
  }

  @Test
  public void destroySession_wipesAndClearsSession() {
    byte[] raw = "secret".getBytes(UTF_8);
    long sessionId = createSession(raw);

    CrumblesDecryptedLogsSession.destroySession(sessionId);

    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
    assertThat(raw).isEqualTo(new byte[raw.length]);
  }
}
