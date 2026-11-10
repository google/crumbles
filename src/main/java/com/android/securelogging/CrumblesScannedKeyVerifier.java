/*
 * Copyright 2026 Google LLC
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

import android.app.Activity;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Toast;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import java.security.PublicKey;

/**
 * Asks the user to confirm the SHA-256 fingerprint of a public key scanned from a QR code before
 * the key is trusted.
 *
 * <p>A QR code is not an authenticated channel. Without this step, anyone who gets a single code in
 * front of the user silently becomes the recipient of every log batch encrypted to that key.
 */
final class CrumblesScannedKeyVerifier {

  private static final String TAG = "CrumblesScannedKeyVerifier";
  private static final String EVENT_KEY_IMPORT_REJECTED = "EXTERNAL_KEY_IMPORT_REJECTED";

  /**
   * The longest scanned text that is decoded as a key, in characters: more than five times the
   * Base64 encoding of the largest RSA public key that Crumbles accepts, so that a crafted QR code
   * cannot make the app decode and parse an arbitrarily large payload.
   */
  static final int MAX_SCANNED_KEY_LENGTH = 4096;

  /**
   * Decodes the public key that a QR code holds as Base64 text.
   *
   * @param scannedText the text of the scanned QR code
   * @return the key
   * @throws CrumblesKeysException if {@code scannedText} is empty, if it is longer than {@link
   *     #MAX_SCANNED_KEY_LENGTH} characters, or if it is not the Base64 encoding of a public key
   *     that Crumbles accepts
   */
  static PublicKey parseScannedKey(String scannedText) throws CrumblesKeysException {
    if (scannedText.length() > MAX_SCANNED_KEY_LENGTH) {
      throw new CrumblesKeysException(
          "Scanned text is longer than " + MAX_SCANNED_KEY_LENGTH + " characters.");
    }
    PublicKey key = CrumblesLogsEncryptor.publicKeyFromBase64(scannedText);
    if (key == null) {
      throw new CrumblesKeysException("Scanned text is empty.");
    }
    return key;
  }

  /**
   * Asks the user to compare the fingerprint of a scanned key against a value they obtained out of
   * band, and runs {@code onVerified} only if they confirm the match.
   *
   * @param activity the activity that hosts the confirmation dialog
   * @param scannedPublicKey the key that was just scanned
   * @param onVerified the action to run once the user confirms the fingerprint
   */
  static void confirmFingerprint(
      Activity activity, PublicKey scannedPublicKey, Runnable onVerified) {
    String fingerprint;
    try {
      fingerprint = CrumblesLogsEncryptor.getPublicKeyFingerprint(scannedPublicKey);
    } catch (CrumblesKeysException e) {
      Log.e(TAG, "Could not compute the fingerprint of a scanned key.", e);
      CrumblesAppAuditLogger.getInstance(activity)
          .logEvent(
              EVENT_KEY_IMPORT_REJECTED,
              "Scanned key rejected because its fingerprint could not be computed.");
      Toast.makeText(activity, R.string.toast_key_fingerprint_unavailable, Toast.LENGTH_LONG)
          .show();
      return;
    }

    AlertDialog dialog =
        new AlertDialog.Builder(activity)
            .setTitle(R.string.dialog_verify_key_fingerprint_title)
            .setMessage(
                activity.getString(R.string.dialog_verify_key_fingerprint_message, fingerprint))
            .setCancelable(false)
            .setPositiveButton(
                R.string.dialog_verify_key_fingerprint_confirm, (unused, which) -> onVerified.run())
            .setNegativeButton(
                R.string.dialog_verify_key_fingerprint_cancel,
                (unused, which) ->
                    CrumblesAppAuditLogger.getInstance(activity)
                        .logEvent(
                            EVENT_KEY_IMPORT_REJECTED,
                            "User did not confirm the fingerprint of a scanned key."))
            .create();
    Window window = dialog.getWindow();
    if (window != null) {
      // A dialog window does not inherit FLAG_SECURE from the activity window, and an app that
      // may draw over others could otherwise cover the fingerprint with the one the user expects.
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
      window.setHideOverlayWindows(true);
    }
    dialog.show();
  }

  private CrumblesScannedKeyVerifier() {}
}
