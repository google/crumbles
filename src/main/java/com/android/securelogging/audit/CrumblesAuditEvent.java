package com.android.securelogging.audit;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

/** Represents a Crumbles audit event. */
public class CrumblesAuditEvent {
  private final Instant timestamp;
  private final String eventType;
  private final String message;

  private static final ThreadLocal<SimpleDateFormat> dateFormat =
      ThreadLocal.withInitial(
          () -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()));

  public CrumblesAuditEvent(Instant timestamp, String eventType, String message) {
    this.timestamp = timestamp;
    this.eventType = eventType;
    this.message = message;
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
        retrievedInstant, jsonObject.getString("eventType"), jsonObject.getString("message"));
  }
}
