package com.android.securelogging.exceptions;

/** Exception thrown when there is an error encrypting the logs. */
public class CrumblesLogsEncryptionException extends RuntimeException {
  public CrumblesLogsEncryptionException(String message) {
    super(message);
  }

  public CrumblesLogsEncryptionException(String message, Throwable cause) {
    super(message, cause);
  }
}
