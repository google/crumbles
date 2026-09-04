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
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, testRawBytes);

    assertThat(entry.getFileName()).isEqualTo(TEST_FILE_NAME);
    assertThat(entry.getContent()).isEqualTo(TEST_CONTENT);
    assertThat(entry.getRawBytes()).isEqualTo(testRawBytes);
  }

  @Test
  public void constructor_withoutRawBytes_initializesCorrectly() {
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, null);

    assertThat(entry.getFileName()).isEqualTo(TEST_FILE_NAME);
    assertThat(entry.getContent()).isNull();
    assertThat(entry.getRawBytes()).isNull();
    entry.setRawBytes(testRawBytes);
    assertThat(entry.getRawBytes()).isEqualTo(testRawBytes);
  }

  @Test
  public void wipe_zeroesRawBytesBuffer() {
    byte[] mutableBytes = "sensitive".getBytes(UTF_8);
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, mutableBytes);

    entry.wipe();

    assertThat(entry.getRawBytes()).isNull();
    assertThat(entry.getContent()).isNull();
    assertThat(mutableBytes).isEqualTo(new byte[mutableBytes.length]);
  }

  @Test
  public void getFileName_returnsCorrectValue() {
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, testRawBytes);
    assertThat(entry.getFileName()).isEqualTo(TEST_FILE_NAME);
  }

  @Test
  public void getContent_returnsCorrectValue() {
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, testRawBytes);
    assertThat(entry.getContent()).isEqualTo(TEST_CONTENT);
  }

  @Test
  public void getRawBytes_returnsCorrectValue() {
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, testRawBytes);
    assertThat(entry.getRawBytes()).isEqualTo(testRawBytes);
  }

  @Test
  public void setRawBytes_updatesRawBytesAndWipesPreviousBuffer() {
    byte[] initialBytes = "initial".getBytes(UTF_8);
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, initialBytes);
    byte[] newRawBytes = "new raw data".getBytes(UTF_8);

    entry.setRawBytes(newRawBytes);

    assertThat(entry.getRawBytes()).isEqualTo(newRawBytes);
    assertThat(entry.getContent()).isEqualTo("new raw data");
    assertThat(initialBytes).isEqualTo(new byte[initialBytes.length]);
  }

  @Test
  public void setRawBytes_withNull_clearsRawBytesAndWipesPreviousBuffer() {
    byte[] initialBytes = "initial".getBytes(UTF_8);
    CrumblesDecryptedLogEntry entry = new CrumblesDecryptedLogEntry(TEST_FILE_NAME, initialBytes);

    entry.setRawBytes(null);

    assertThat(entry.getRawBytes()).isNull();
    assertThat(initialBytes).isEqualTo(new byte[initialBytes.length]);
  }

  @Test
  public void serialization_deserialization_preservesData() throws Exception {
    CrumblesDecryptedLogEntry originalEntry =
        new CrumblesDecryptedLogEntry(TEST_FILE_NAME, testRawBytes);

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
