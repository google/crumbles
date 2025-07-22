package com.android.securelogging.exceptions;

/** Exception thrown when there is an error decrypting the logs. */
public class CrumblesLogsDecryptionException extends RuntimeException {

  public CrumblesLogsDecryptionException(String message) {
    super(message);
  }

  public CrumblesLogsDecryptionException(String message, Throwable cause) {
    super(message, cause);
  }
}
