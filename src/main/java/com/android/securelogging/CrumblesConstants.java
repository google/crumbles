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

import java.time.Duration;

/** Constants used by Crumbles (excluding those used for encryption and decryption). */
public final class CrumblesConstants {

  public static final String FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY = "logs";
  public static final String SENT_SUFFIX = "_sent.bin";
  public static final String PROCESSING_SUFFIX = "_processing.bin";

  /**
   * Suffix of a batch file that is still being written. Such files never end in {@code .bin}, so
   * log file listings skip them until they are atomically renamed to their final name.
   */
  public static final String TEMP_FILE_SUFFIX = ".tmp";

  public static final String NOTIFICATION_CHANNEL_ID = "email_log_channel";
  public static final String ACTION_NEEDED_NOTIFICATION_CHANNEL_ID = "action_needed_channel";
  public static final String DATA_INTEGRITY_NOTIFICATION_CHANNEL_ID = "data_integrity_channel";
  public static final Duration MAX_PROCESSING_FILE_AGE = Duration.ofDays(7);

  public static final String MARK_SENT_WORK_TAG = "mark_processing_as_sent_work";

  public static final String DELETE_WORK_TAG = "delete_sent_log_files_work";

  public static final String SEND_WORK_TAG = "send_processing_log_files_work";
  public static final Duration SEND_REPEAT_INTERVAL = Duration.ofHours(8);

  public static final String LOGGING_WATCHDOG_WORK_TAG = "logging_watchdog_work";
  public static final Duration LOGGING_WATCHDOG_REPEAT_INTERVAL = Duration.ofMinutes(15);

  /** Unique name of the one-time upload requested on top of the periodic one. */
  public static final String SEND_NOW_WORK_NAME = "send_log_files_now_work";

  public static final long MAX_LOGS_DIRECTORY_BYTES = 256L * 1024 * 1024;
  public static final long LOGS_DIRECTORY_WARN_PERCENT = 80;
  public static final long LOGS_DIRECTORY_RESERVED_PERCENT = 25;
  public static final long LOGS_DIRECTORY_SPIKE_PERCENT = 25;
  public static final Duration LOGS_DIRECTORY_SPIKE_WINDOW = Duration.ofHours(1);

  public static final String ENCRYPTED_LOGS_SUBDIRECTORY = "CrumblesEncryptedFiles";
  public static final String EXTRA_DECRYPTED_SESSION_ID = "extra_decrypted_session_id";
  public static final String FILE_PROVIDER_AUTHORITY =
      "com.android.securelogging.fileprovider"; // Matches what is defined in the Manifest.
  public static final String TEMP_RE_ENCRYPTED_DIR = "reencrypted_logs";

  /**
   * Largest file, in bytes, that decryption reads into memory.
   *
   * <p>The largest batch Crumbles produces holds one full platform security log buffer: 10,240
   * events of at most about 4 KiB each (the logd entry payload limit), roughly 40 MiB once
   * formatted and encrypted. Network log batches hold at most 1,200 events and are far smaller.
   * The limit leaves headroom above that worst case while stopping a selected file from exhausting
   * the heap.
   */
  public static final long MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES = 64L * 1024 * 1024;

  public static final String PREFS_NAME = "CrumblesPrefs";
  public static final String PREF_UPLOAD_DESTINATION_URI = "uploadDestinationUri";

  /** DataStore entry ID that the WebDAV server URL is sealed with. */
  public static final String WEBDAV_SERVER_URL_ENTRY_ID = "remote_storage_config/webdav_server_url";

  /** DataStore entry ID that the WebDAV username is sealed with. */
  public static final String WEBDAV_USERNAME_ENTRY_ID =
      "remote_storage_config/webdav_credentials/username";

  /** DataStore entry ID that the WebDAV password is sealed with. */
  public static final String WEBDAV_PASSWORD_ENTRY_ID =
      "remote_storage_config/webdav_credentials/password";

  /** DataStore entry ID that the pinned WebDAV server key digest is sealed with. */
  public static final String WEBDAV_SERVER_KEY_SHA256_ENTRY_ID =
      "remote_storage_config/webdav_server_key_sha256";

  /** Whether security logging was enabled when the logging watchdog last checked. */
  public static final String PREF_LAST_OBSERVED_LOGGING_ENABLED = "lastObservedLoggingEnabled";

  /** Whether network logging was enabled when the logging watchdog last checked. */
  public static final String PREF_LAST_OBSERVED_NETWORK_LOGGING_ENABLED =
      "lastObservedNetworkLoggingEnabled";

  /**
   * Tag of the last activity log record sealed into a stored log batch. The next batch carries the
   * activity log records written after it.
   */
  public static final String PREF_AUDIT_SHIPPED_THROUGH_TAG = "auditShippedThroughTag";

  public static final String ZXING_PACKAGE_NAME = "com.google.zxing.client.android";

  public static final int CAMERA_PERMISSION_REQUEST_CODE = 103;
  public static final String SCAN_RESULT_EXTRA = "SCAN_RESULT";
  public static final int QR_SCAN_REQUEST_CODE_PERMISSIONS = 1011;

  public static final String ARG_PRIVATE_KEY_BYTES = "private_key_bytes";
  public static final String ARG_SHOW_QR_INITIALLY = "show_qr_initially";

  public static final String CURRENT_LOG_FILE_NAME = "app_audit_log.jsonl";
  public static final String OLD_LOG_FILE_NAME = "app_audit_log.old.jsonl";
  public static final String AUDIT_LOG_KEY_FILE_NAME = "app_audit_log.key";
  public static final int MAX_MEMORY_EVENTS = 100; // Max events to keep in RAM for quick display.
  public static final long MAX_LOG_FILE_SIZE_BYTES = 1024 * 1024; // 1 MiB per file pre-rotation.

  public static final int QR_CODE_WIDTH_PX = 250;
  public static final int QR_CODE_HEIGHT_PX = 250;
  public static final int DIALOG_PADDING_LEFT_RIGHT_DP = 20;
  public static final int DIALOG_PADDING_TOP_BOTTOM_DP = 8;
  public static final int DIALOG_WARNING_TEXT_PADDING_BOTTOM_DP = 12;
  public static final int DIALOG_WARNING_TEXT_PADDING_TOP_DP = 16;

  public static final int FILE_PICKER_REQUEST_CODE =
      123; // For the file picker needed for decryption.
  public static final int FILE_TREE_REQUEST_CODE = 789; // For selecting the upload destination.
  public static final int KEYGUARD_DESTINATION_REQUEST_CODE =
      790; // For authenticating before changing the upload destination.
  public static final int KEYGUARD_DISABLE_LOGGING_REQUEST_CODE =
      791; // For authenticating before turning logging off.
  public static final int KEYGUARD_DISABLE_NETWORK_COLLECTION_REQUEST_CODE =
      792; // For authenticating before turning network collection off.
  public static final int KEYGUARD_WIPE_ANYWAY_REQUEST_CODE =
      798; // For authenticating before wiping batches that could not be uploaded.

  public static final int UPLOAD_NOTIFICATION_ID = 2001;
  public static final int DEFERRED_LOGS_NOTIFICATION_ID = 2002;
  public static final int STORAGE_NOTIFICATION_ID = 2003;
  public static final int PREFERENCES_UNREADABLE_NOTIFICATION_ID = 2004;
  public static final int LOGGING_DISABLED_NOTIFICATION_ID = 2005;
  public static final int NO_SCREEN_LOCK_NOTIFICATION_ID = 2006;
  public static final int KEY_DELETED_NOTIFICATION_ID = 2007;
  public static final int COLLECTION_PAUSED_NOTIFICATION_ID = 2008;

  private CrumblesConstants() {}
}
