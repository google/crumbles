package com.android.securelogging.audit;

import static com.google.common.truth.Truth.assertThat;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Unit tests for the {@link CrumblesAuditEvent} class. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesAuditEventTest {

  @Test
  @SuppressWarnings("JavaUtilDate")
  public void getFormattedTimestamp_whenCalled_returnsCorrectlyFormattedDateString() {
    // Given: A specific timestamp for a predictable and repeatable test.
    long specificTimestamp = 1748548800000L; // May 29, 2025 20:00:00 PM GMT.
    Instant timestamp = Instant.ofEpochMilli(specificTimestamp);
    CrumblesAuditEvent event = new CrumblesAuditEvent(timestamp, "TEST_EVENT", "A test event.");

    // And: A SimpleDateFormat instance configured exactly like the one in the production code.
    SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
    formatter.setTimeZone(TimeZone.getTimeZone("GMT"));

    // When: We create the expected date string THE CORRECT WAY.
    String expectedDateString = formatter.format(new Date(specificTimestamp));

    // Then: The actual formatted timestamp from the event should match our expected string.
    TimeZone.setDefault(TimeZone.getTimeZone("GMT"));
    assertThat(event.getFormattedTimestamp()).isEqualTo(expectedDateString);
    assertThat(event.getFormattedTimestamp()).isEqualTo("2025-05-29 20:00:00");
  }

  @Test
  public void toJsonString_and_fromJsonString_areSymmetric() throws Exception {
    // Given.
    Instant timestamp = InstantSource.system().instant();
    String eventType = "JSON_TEST";
    String message = "This is a test message with special chars: \"'{}[]";
    CrumblesAuditEvent originalEvent = new CrumblesAuditEvent(timestamp, eventType, message);

    // When.
    String jsonString = originalEvent.toJsonString();
    CrumblesAuditEvent reconstructedEvent = CrumblesAuditEvent.fromJsonString(jsonString);

    // Then.
    assertThat(reconstructedEvent.getTimestamp()).isEqualTo(originalEvent.getTimestamp());
    assertThat(reconstructedEvent.getEventType()).isEqualTo(originalEvent.getEventType());
    assertThat(reconstructedEvent.getMessage()).isEqualTo(originalEvent.getMessage());
  }
}
