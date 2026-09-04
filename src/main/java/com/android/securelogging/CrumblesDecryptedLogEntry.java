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

import static java.nio.charset.StandardCharsets.UTF_8;

import androidx.annotation.Nullable;
import java.io.Serializable;
import java.util.Arrays;

/** Represents a decrypted log entry retaining mutable raw bytes in volatile memory. */
public class CrumblesDecryptedLogEntry implements Serializable {
  private final String fileName;
  private byte[] rawBytes;

  /** Constructs a new entry with the file name and optional mutable raw bytes buffer. */
  public CrumblesDecryptedLogEntry(String fileName, @Nullable byte[] rawBytes) {
    this.fileName = fileName;
    this.rawBytes = rawBytes;
  }

  public String getFileName() {
    return fileName;
  }

  @Nullable
  public String getContent() {
    return rawBytes != null ? new String(rawBytes, UTF_8) : null;
  }

  @Nullable
  public byte[] getRawBytes() {
    return rawBytes;
  }

  /** Sets the raw bytes buffer, securely zeroing any previous buffer if replaced. */
  public void setRawBytes(@Nullable byte[] newRawBytes) {
    if (this.rawBytes != null && !Arrays.equals(this.rawBytes, newRawBytes)) {
      Arrays.fill(this.rawBytes, (byte) 0);
    }
    this.rawBytes = newRawBytes;
  }

  /** Securely zeroes the decrypted byte buffer in memory. */
  public void wipe() {
    if (rawBytes != null) {
      Arrays.fill(rawBytes, (byte) 0);
      rawBytes = null;
    }
  }
}
