package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link CrumblesDecryptedLogEntry}. */
@RunWith(JUnit4.class)
public class CrumblesDecryptedLogEntryTest {

  private static final String TEST_FILE_NAME = "log_file_1.txt";
  private static final String TEST_CONTENT = "This is some decrypted log content.";
  private static final byte[] testRawBytes = TEST_CONTENT.getBytes(UTF_8);

  @Test
  public void constructor_withRawBytes_initializesCorrectly() {
    CrumblesDecryptedLogEntry entry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT, testRawBytes);

    assertThat(entry.getFileName()).isEqualTo(TEST_FILE_NAME);
    assertThat(entry.getContent()).isEqualTo(TEST_CONTENT);
    assertThat(entry.getRawBytes()).isEqualTo(testRawBytes);
  }

  @Test
  public void constructor_withoutRawBytes_initializesCorrectly() {
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT);

    assertThat(entry.getFileName()).isEqualTo(TEST_FILE_NAME);
    assertThat(entry.getContent()).isEqualTo(TEST_CONTENT);
    assertThat(entry.getRawBytes()).isNull(); // Raw bytes should be null initially.
  }

  @Test
  public void getFileName_returnsCorrectValue() {
    CrumblesDecryptedLogEntry entry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT, testRawBytes);
    assertThat(entry.getFileName()).isEqualTo(TEST_FILE_NAME);
  }

  @Test
  public void getContent_returnsCorrectValue() {
    CrumblesDecryptedLogEntry entry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT, testRawBytes);
    assertThat(entry.getContent()).isEqualTo(TEST_CONTENT);
  }

  @Test
  public void getRawBytes_returnsCorrectValue() {
    CrumblesDecryptedLogEntry entry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT, testRawBytes);
    assertThat(entry.getRawBytes()).isEqualTo(testRawBytes);
  }

  @Test
  public void setRawBytes_updatesRawBytesCorrectly() {
    CrumblesDecryptedLogEntry entry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT); // Start with null rawBytes.
    assertThat(entry.getRawBytes()).isNull();

    byte[] newRawBytes = "new raw data".getBytes(UTF_8);
    entry.setRawBytes(newRawBytes);

    assertThat(entry.getRawBytes()).isEqualTo(newRawBytes);
  }

  @Test
  public void serialization_deserialization_preservesData() throws Exception {
    CrumblesDecryptedLogEntry originalEntry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, TEST_CONTENT, testRawBytes);

    // Serialize
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(originalEntry);
    }
    byte[] serializedBytes = baos.toByteArray();

    // Deserialize
    ByteArrayInputStream bais = new ByteArrayInputStream(serializedBytes);
    ObjectInputStream ois = new ObjectInputStream(bais);
    CrumblesDecryptedLogEntry deserializedEntry = (CrumblesDecryptedLogEntry) ois.readObject();
    ois.close();

    // Assert
    assertThat(deserializedEntry.getFileName()).isEqualTo(originalEntry.getFileName());
    assertThat(deserializedEntry.getContent()).isEqualTo(originalEntry.getContent());
    assertThat(deserializedEntry.getRawBytes()).isEqualTo(originalEntry.getRawBytes());
  }
}
