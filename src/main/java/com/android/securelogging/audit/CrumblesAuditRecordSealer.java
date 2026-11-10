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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableMap;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Optional;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Seals app audit log records at rest with AES-256-GCM under a {@link CrumblesAuditDataKey}, so
 * that a copy of the log files reveals neither the events nor their timestamps, only how many
 * records there are and roughly how long each one is.
 *
 * <p>A sealed record is a JSON line holding the ciphertext and, in the clear, the chain tag of the
 * record, which is bound to the ciphertext as associated data. The chain can thus be continued even
 * when a record cannot be unsealed. Any other line is a record written in cleartext.
 */
final class CrumblesAuditRecordSealer {
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final String CHAIN_TAG_FIELD = "tag";
  private static final String SEALED_RECORD_FIELD = "sealed";
  private static final int IV_SIZE_BYTES = 12;
  private static final int GCM_TAG_SIZE_BYTES = 16;
  private static final BaseEncoding BASE64 = BaseEncoding.base64Url();

  private final CrumblesAuditDataKey dataKey;
  private final SecureRandom random = new SecureRandom();

  /** Creates a sealer that seals records under {@code dataKey}. */
  CrumblesAuditRecordSealer(CrumblesAuditDataKey dataKey) {
    this.dataKey = dataKey;
  }

  /**
   * Returns {@code record}, a JSON audit record, sealed as a JSON line that keeps the chain tag of
   * the record, if it has one, in the clear.
   *
   * @throws GeneralSecurityException if the data key cannot be loaded from the Keystore
   * @throws IOException if the data key cannot be read or stored
   */
  String seal(String record) throws GeneralSecurityException, IOException {
    Optional<String> chainTag = parseJson(record).flatMap(CrumblesAuditRecordSealer::chainTagOf);
    byte[] iv = new byte[IV_SIZE_BYTES];
    random.nextBytes(iv);
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(
        Cipher.ENCRYPT_MODE, dataKey.load(), new GCMParameterSpec(GCM_TAG_SIZE_BYTES * 8, iv));
    cipher.updateAAD(chainTag.orElse("").getBytes(UTF_8));
    byte[] ciphertext = cipher.doFinal(record.getBytes(UTF_8));
    ImmutableMap.Builder<String, String> fields = ImmutableMap.builder();
    chainTag.ifPresent(tag -> fields.put(CHAIN_TAG_FIELD, tag));
    fields.put(
        SEALED_RECORD_FIELD,
        BASE64.encode(
            ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array()));
    return new JSONObject(fields.buildOrThrow()).toString();
  }

  /**
   * Returns the record on {@code line}, unsealing it if {@code line} holds a sealed record.
   *
   * @throws GeneralSecurityException if the sealed record fails authentication, or the data key
   *     cannot be loaded from the Keystore
   * @throws IOException if the data key cannot be read or stored
   */
  String unseal(String line) throws GeneralSecurityException, IOException {
    Optional<JSONObject> fields = parseSealedRecord(line);
    if (fields.isEmpty()) {
      return line;
    }
    byte[] sealedRecord;
    try {
      sealedRecord = BASE64.decode(fields.get().optString(SEALED_RECORD_FIELD));
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException("Sealed audit record is not base64url.", e);
    }
    if (sealedRecord.length < IV_SIZE_BYTES + GCM_TAG_SIZE_BYTES) {
      throw new AEADBadTagException("Sealed audit record is truncated.");
    }
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(
        Cipher.DECRYPT_MODE,
        dataKey.load(),
        new GCMParameterSpec(GCM_TAG_SIZE_BYTES * 8, sealedRecord, 0, IV_SIZE_BYTES));
    cipher.updateAAD(chainTagOf(fields.get()).orElse("").getBytes(UTF_8));
    return new String(
        cipher.doFinal(sealedRecord, IV_SIZE_BYTES, sealedRecord.length - IV_SIZE_BYTES), UTF_8);
  }

  /** Returns the chain tag that {@code line} keeps in the clear, if it holds a sealed record. */
  static Optional<String> sealedChainTag(String line) {
    return parseSealedRecord(line).flatMap(CrumblesAuditRecordSealer::chainTagOf);
  }

  /** Returns whether {@code line} holds a sealed record. */
  static boolean isSealed(String line) {
    return parseSealedRecord(line).isPresent();
  }

  private static Optional<JSONObject> parseSealedRecord(String line) {
    return parseJson(line).filter(fields -> fields.has(SEALED_RECORD_FIELD));
  }

  private static Optional<JSONObject> parseJson(String line) {
    try {
      return Optional.of(new JSONObject(line));
    } catch (JSONException e) {
      return Optional.empty();
    }
  }

  private static Optional<String> chainTagOf(JSONObject fields) {
    return fields.has(CHAIN_TAG_FIELD)
        ? Optional.of(fields.optString(CHAIN_TAG_FIELD))
        : Optional.empty();
  }
}
