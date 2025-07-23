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

/** Constants used by Crumbles (excluding those used for encryption and decryption). */
public final class CrumblesConstants {

  public static final String FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY = "logs";
  public static final String SENT_SUFFIX = "_sent.bin";
  public static final String ENCRYPTED_LOG_FILE_NAME = "crumbles_logs_encrypted_";
  public static final String PROCESSING_SUFFIX = "_processing.bin";
  public static final String NOTIFICATION_CHANNEL_ID = "email_log_channel";

  public static final String MARK_SENT_WORK_TAG = "mark_processing_as_sent_work";
  public static final long MARK_SENT_REPEAT_INTERVAL_HOURS = 8;
  public static final long MARK_SENT_INITIAL_DELAY_MINUTES_OFFSET = 10;

  public static final String DELETE_WORK_TAG = "delete_sent_log_files_work";
  public static final long DELETE_REPEAT_INTERVAL_HOURS = 24;

  public static final String SEND_WORK_TAG = "send_processing_log_files_work";
  public static final long SEND_REPEAT_INTERVAL_HOURS = 8;

  public static final String ENCRYPTED_LOGS_SUBDIRECTORY = "CrumblesEncryptedFiles";
  public static final String EXTRA_DECRYPTED_LOGS = "extra_decrypted_logs";
  public static final String FILE_PROVIDER_AUTHORITY =
      "com.android.securelogging.fileprovider"; // Matches what is defined in the Manifest.
  public static final String TEMP_RE_ENCRYPTED_DIR = "reencrypted_logs";

  public static final String PREFS_NAME = "CrumblesPrefs";
  public static final String PREF_EXTERNAL_PUBLIC_KEY_B64 = "externalPublicKeyBase64";
  public static final String PREF_RE_ENCRYPT_PUBLIC_KEY_B64 = "reEncryptPublicKeyBase64";

  public static final String ZXING_PACKAGE_NAME = "com.google.zxing.client.android";

  public static final int CAMERA_PERMISSION_REQUEST_CODE = 103;
  public static final String SCAN_RESULT_EXTRA = "SCAN_RESULT";
  public static final int QR_SCAN_REQUEST_CODE_PERMISSIONS = 1011;

  public static final String ARG_PRIVATE_KEY_BYTES = "private_key_bytes";
  public static final String ARG_SHOW_QR_INITIALLY = "show_qr_initially";

  public static final String CURRENT_LOG_FILE_NAME = "app_audit_log.jsonl";
  public static final String OLD_LOG_FILE_NAME = "app_audit_log.old.jsonl";
  public static final int MAX_MEMORY_EVENTS = 100; // Max events to keep in RAM for quick display.
  public static final long MAX_LOG_FILE_SIZE_BYTES = 512 * 1024; // 0.5 MB per file pre-rotation.

  public static final int QR_CODE_WIDTH_PX = 250;
  public static final int QR_CODE_HEIGHT_PX = 250;
  public static final int DIALOG_PADDING_LEFT_RIGHT_DP = 20;
  public static final int DIALOG_PADDING_TOP_BOTTOM_DP = 8;
  public static final int DIALOG_WARNING_TEXT_PADDING_BOTTOM_DP = 12;
  public static final int DIALOG_WARNING_TEXT_PADDING_TOP_DP = 16;

  public static final int FILE_PICKER_REQUEST_CODE =
      123; // For the file picker needed for decryption.
  public static final int KEYGUARD_REQUEST_CODE = 456; // For the lock screen prompt.

  private CrumblesConstants() {}
}
