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
