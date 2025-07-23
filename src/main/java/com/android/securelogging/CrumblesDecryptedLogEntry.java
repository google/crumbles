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

import java.io.Serializable;

/** Represents a decrypted log entry from Crumbles. */
public class CrumblesDecryptedLogEntry implements Serializable {
  private final String fileName;
  private final String content;
  private byte[] rawBytes; // Store the raw decrypted bytes for re-encryption.

  public CrumblesDecryptedLogEntry(String fileName, String content, byte[] rawBytes) {
    this.fileName = fileName;
    this.content = content;
    this.rawBytes = rawBytes;
  }

  public CrumblesDecryptedLogEntry(String fileName, String content) {
    this.fileName = fileName;
    this.content = content;
  }

  public String getFileName() {
    return fileName;
  }

  public String getContent() {
    return content;
  }

  public byte[] getRawBytes() {
    return rawBytes;
  }

  public void setRawBytes(byte[] rawBytes) {
    this.rawBytes = rawBytes;
  }
}
