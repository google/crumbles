package com.android.securelogging.exceptions;

/** Exception thrown when there is an error with any of the Crumbles keys handling. */
public class CrumblesKeysException extends Exception {
  public CrumblesKeysException(String message) {
    super(message);
  }

  public CrumblesKeysException(String message, Throwable cause) {
    super(message, cause);
  }
}
