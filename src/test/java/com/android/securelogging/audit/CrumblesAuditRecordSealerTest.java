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

package com.android.securelogging.audit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.truth.Expect;
import java.io.File;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.time.Instant;
import javax.crypto.AEADBadTagException;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/** Unit tests for the {@link CrumblesAuditRecordSealer} class. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesAuditRecordSealerTest {

  private static final String CHAIN_TAG = "a1".repeat(32);
  private static final Instant TIMESTAMP = Instant.ofEpochSecond(1_760_000_000L);
  private static final String RECORD =
      new CrumblesAuditEvent(TIMESTAMP, "KEY_CHANGED", "New key.", CHAIN_TAG).toJsonString();
  private static final String MALFORMED_LINE = "{\"timestamp\": not-json";

  @Rule public final Expect expect = Expect.create();
  @Rule public final TemporaryFolder temporaryFolder = new TemporaryFolder();

  private File wrappedKeyFile;
  private CrumblesAuditRecordSealer sealer;

  @Before
  public void setUp() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.addProvider(new FakeAndroidKeyStoreProvider());
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    wrappedKeyFile = new File(temporaryFolder.getRoot(), "app_audit_log.key");
    sealer = new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(wrappedKeyFile));
  }

  @After
  public void tearDown() {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Test
  public void seal_hidesEventAndTimestampButKeepsChainTagInTheClear() throws Exception {
    String line = sealer.seal(RECORD);

    expect.that(line).doesNotContain("KEY_CHANGED");
    expect.that(line).doesNotContain("New key.");
    expect.that(line).doesNotContain(String.valueOf(TIMESTAMP.getEpochSecond()));
    expect.that(CrumblesAuditRecordSealer.sealedChainTag(line)).hasValue(CHAIN_TAG);
    expect.that(sealer.seal(RECORD)).isNotEqualTo(line);
  }

  @Test
  public void unseal_withSealerReloadedFromKeyFile_returnsRecord() throws Exception {
    String line = sealer.seal(RECORD);
    CrumblesAuditRecordSealer reloadedSealer =
        new CrumblesAuditRecordSealer(new CrumblesAuditDataKey(wrappedKeyFile));

    String record = reloadedSealer.unseal(line);

    assertThat(record).isEqualTo(RECORD);
  }

  @Test
  public void seal_whenRecordHasNoChainTag_sealsRecordWithoutTag() throws Exception {
    String untaggedRecord =
        new CrumblesAuditEvent(TIMESTAMP, "OLD_EVENT", "Written before the chain.").toJsonString();

    String line = sealer.seal(untaggedRecord);

    expect.that(CrumblesAuditRecordSealer.sealedChainTag(line)).isEmpty();
    expect.that(sealer.unseal(line)).isEqualTo(untaggedRecord);
  }

  @Test
  public void seal_whenRecordIsMalformed_sealsItAsIs() throws Exception {
    String line = sealer.seal(MALFORMED_LINE);

    assertThat(sealer.unseal(line)).isEqualTo(MALFORMED_LINE);
  }

  @Test
  public void unseal_whenLineIsNotSealed_returnsLineWithoutCreatingKey() throws Exception {
    expect.that(sealer.unseal(RECORD)).isEqualTo(RECORD);
    expect.that(sealer.unseal(MALFORMED_LINE)).isEqualTo(MALFORMED_LINE);
    expect.that(wrappedKeyFile.exists()).isFalse();
  }

  @Test
  public void sealedChainTag_whenLineIsCleartextRecord_returnsEmpty() {
    assertThat(CrumblesAuditRecordSealer.sealedChainTag(RECORD)).isEmpty();
  }

  @Test
  public void isSealed_returnsWhetherLineHoldsSealedRecord() throws Exception {
    String line = sealer.seal(RECORD);

    expect.that(CrumblesAuditRecordSealer.isSealed(line)).isTrue();
    expect.that(CrumblesAuditRecordSealer.isSealed(RECORD)).isFalse();
    expect.that(CrumblesAuditRecordSealer.isSealed(MALFORMED_LINE)).isFalse();
  }

  @Test
  public void unseal_whenChainTagReplaced_throwsAeadBadTagException() throws Exception {
    String line = sealer.seal(RECORD).replace(CHAIN_TAG, "b2".repeat(32));

    assertThrows(AEADBadTagException.class, () -> sealer.unseal(line));
  }

  @Test
  public void unseal_whenCiphertextAltered_throwsAeadBadTagException() throws Exception {
    JSONObject fields = new JSONObject(sealer.seal(RECORD));
    String sealedRecord = fields.getString("sealed");
    char replacement = sealedRecord.charAt(20) == 'A' ? 'B' : 'A';
    String line =
        fields
            .put("sealed", sealedRecord.substring(0, 20) + replacement + sealedRecord.substring(21))
            .toString();

    assertThrows(AEADBadTagException.class, () -> sealer.unseal(line));
  }

  @Test
  public void unseal_whenSealedRecordIsNotBase64_throwsGeneralSecurityException() {
    String line = "{\"tag\":\"" + CHAIN_TAG + "\",\"sealed\":\"not base64!\"}";

    assertThrows(GeneralSecurityException.class, () -> sealer.unseal(line));
  }

  @Test
  public void unseal_whenSealedRecordIsTruncated_throwsAeadBadTagException() {
    String line = "{\"tag\":\"" + CHAIN_TAG + "\",\"sealed\":\"AAAA\"}";

    assertThrows(AEADBadTagException.class, () -> sealer.unseal(line));
  }
}
