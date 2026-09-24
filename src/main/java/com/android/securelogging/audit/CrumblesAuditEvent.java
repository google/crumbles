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

package com.android.securelogging.audit;

import static java.nio.charset.StandardCharsets.UTF_8;

import androidx.annotation.Nullable;
import com.google.common.io.BaseEncoding;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.json.JSONException;
import org.json.JSONObject;

/** Represents a Crumbles audit event. */
public class CrumblesAuditEvent {
  public static final String GENESIS_TAG = "0".repeat(64);
  private final Instant timestamp;
  private final String eventType;
  private final String message;
  @Nullable private final String tag;

  private static final ThreadLocal<SimpleDateFormat> dateFormat =
      ThreadLocal.withInitial(
          () -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()));

  public CrumblesAuditEvent(Instant timestamp, String eventType, String message) {
    this(timestamp, eventType, message, null);
  }

  public CrumblesAuditEvent(
      Instant timestamp, String eventType, String message, @Nullable String tag) {
    this.timestamp = timestamp;
    this.eventType = eventType;
    this.message = message;
    this.tag = tag;
  }

  @Nullable
  public String getTag() {
    return tag;
  }

  public CrumblesAuditEvent withTag(@Nullable String newTag) {
    return new CrumblesAuditEvent(timestamp, eventType, message, newTag);
  }

  public String computeTag(SecretKey key, String previousTag) throws GeneralSecurityException {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(key);
    String payload =
        previousTag
            + '\n'
            + (timestamp.getEpochSecond() * 1_000_000_000L + timestamp.getNano())
            + '\n'
            + eventType.length()
            + ':'
            + eventType
            + '\n'
            + message.length()
            + ':'
            + message;
    return BaseEncoding.base16().lowerCase().encode(mac.doFinal(payload.getBytes(UTF_8)));
  }

  public Instant getTimestamp() {
    return timestamp;
  }

  public String getEventType() {
    return eventType;
  }

  public String getMessage() {
    return message;
  }

  /** Returns a user-friendly, formatted date and time string. */
  @SuppressWarnings("JavaUtilDate")
  public String getFormattedTimestamp() {
    return dateFormat.get().format(Date.from(timestamp));
  }

  public String toJsonString() {
    try {
      return new JSONObject()
          .put(
              "timestamp",
              timestamp.getEpochSecond() * 1_000_000_000L
                  + timestamp.getNano()) // Store as nanoseconds.
          .put("eventType", eventType)
          .put("message", message)
          .putOpt("tag", tag)
          .toString();
    } catch (JSONException e) {
      return "{}";
    }
  }

  public static CrumblesAuditEvent fromJsonString(String json) throws JSONException {
    JSONObject jsonObject = new JSONObject(json);
    long epochNanos = jsonObject.getLong("timestamp"); // Retrieve nanoseconds.
    Instant retrievedInstant =
        Instant.ofEpochSecond(
            epochNanos / 1_000_000_000L,
            epochNanos % 1_000_000_000L); // Reconstruct with nanoseconds.

    return new CrumblesAuditEvent(
        retrievedInstant,
        jsonObject.getString("eventType"),
        jsonObject.getString("message"),
        jsonObject.has("tag") ? jsonObject.getString("tag") : null);
  }
}
