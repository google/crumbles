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

import static com.google.common.base.Strings.isNullOrEmpty;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.content.FileProvider;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.exceptions.CrumblesKeysException;
import com.google.common.collect.ImmutableList;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** An activity to display decrypted Crumbles logs and offer re-encryption and sharing options. */
public class CrumblesDecryptedLogsActivity extends Activity {
  private static final String TAG = "[CrumblesDecryptedLogsView]";
  private static final int RE_ENCRYPT_KEY_REQUEST_CODE = 42; // Unique request code.
  private static final int SHARE_REQUEST_CODE = 43;

  /** The activity this viewer started and waits for, which decides what leaving the screen does. */
  private enum AwaitedResult {
    NONE,
    KEY_SELECTION,
    SHARE
  }

  private ArrayList<CrumblesDecryptedLogEntry> decryptedLogEntries = new ArrayList<>();
  private long sessionId;
  private TextView decryptedLogsTextView;
  private AwaitedResult awaitedResult = AwaitedResult.NONE;

  private CrumblesLogsEncryptor logsEncryptor;
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private final ArrayList<File> tempReEncryptedFilesForSharing = new ArrayList<>();
  @Nullable @VisibleForTesting AlertDialog activeShareDialog;

  @SuppressWarnings("NonFinalStaticField")
  @VisibleForTesting
  static CrumblesExternalPublicKeyManager publicKeyManagerForTest = null;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_decrypted_logs);
    CrumblesWindowInsets.applySystemBarPadding(this);
    setTitle(R.string.decrypted_logs_viewer_title);
    // Any staged file belongs to an earlier share that is over by now, for instance because the
    // process was killed before onDestroy() could run.
    CrumblesReEncryptedCache.sweep(this);

    decryptedLogsTextView = findViewById(R.id.decrypted_logs_text_view);
    Button closeButton = findViewById(R.id.close_button);
    Button reEncryptAndShareButton = findViewById(R.id.reencrypt_and_share_button);

    logsEncryptor = CrumblesMain.getLogsEncryptorInstance();
    // Use the test manager if it's been injected.
    if (publicKeyManagerForTest != null) {
      publicKeyManager = publicKeyManagerForTest;
    } else {
      publicKeyManager = CrumblesExternalPublicKeyManager.getInstance(this);
    }

    if (logsEncryptor == null) {
      showToast("Error: Cryptographic service not available.");
      Log.e(TAG, "CrumblesLogsEncryptor instance is null in CrumblesDecryptedLogsActivity.");
      finish();
      return;
    }

    Intent intent = getIntent();
    sessionId =
        intent != null
            ? intent.getLongExtra(
                CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, /* defaultValue= */ -1)
            : -1;
    Optional<CrumblesDecryptedLogsSession> sessionOpt =
        CrumblesDecryptedLogsSession.getSession(sessionId);
    if (sessionOpt.isPresent()) {
      decryptedLogEntries = new ArrayList<>(sessionOpt.get().getEntries());
      if (decryptedLogEntries != null && !decryptedLogEntries.isEmpty()) {
        SpannableStringBuilder fullLogText = new SpannableStringBuilder();
        for (int i = 0; i < decryptedLogEntries.size(); i++) {
          CrumblesDecryptedLogEntry entry = decryptedLogEntries.get(i);
          String header = "--- Log: " + entry.getFileName() + " ---\n";
          fullLogText.append(header);
          if (entry.getContent() != null) {
            fullLogText.append(entry.getContent());
          } else {
            fullLogText.append("[Content Unavailable]\n");
          }
          if (i < decryptedLogEntries.size() - 1) {
            fullLogText.append("\n\n");
          }
        }
        decryptedLogsTextView.setText(fullLogText);
      } else {
        decryptedLogsTextView.setText(R.string.no_decrypted_log_content_to_display);
        reEncryptAndShareButton.setEnabled(false);
      }
    } else {
      decryptedLogsTextView.setText(R.string.error_could_not_load_decrypted_logs);
      Log.e(TAG, "Intent did not contain decrypted logs.");
      reEncryptAndShareButton.setEnabled(false);
    }

    closeButton.setOnClickListener(v -> finish());

    reEncryptAndShareButton.setOnClickListener(
        v -> {
          if (decryptedLogEntries != null && !decryptedLogEntries.isEmpty()) {
            Intent keySelectorIntent = new Intent(this, CrumblesReEncryptKeysActivity.class);
            keySelectorIntent.putExtra(CrumblesConstants.EXTRA_DECRYPTED_SESSION_ID, sessionId);
            awaitedResult = AwaitedResult.KEY_SELECTION;
            startActivityForResult(keySelectorIntent, RE_ENCRYPT_KEY_REQUEST_CODE);
          } else {
            showToast("No content to re-encrypt and share.");
          }
        });
  }

  @Override
  protected void onStart() {
    super.onStart();

  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == RE_ENCRYPT_KEY_REQUEST_CODE) {
      awaitedResult = AwaitedResult.NONE;
      if (resultCode == Activity.RESULT_OK && data != null) {
        if (CrumblesDecryptedLogsSession.getSession(sessionId).isEmpty()) {
          wipeDecryptedLogs();
          finish();
          return;
        }
        String keyIdentifier =
            data.getStringExtra(CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS);
        boolean isInternal =
            data.getBooleanExtra(
                CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_IS_INTERNAL, false);
        handleReEncryption(keyIdentifier, isInternal);
      } else if (CrumblesDecryptedLogsSession.getSession(sessionId).isEmpty()) {
        wipeDecryptedLogs();
        finish();
      } else {
        showToast("Re-encryption cancelled.");
      }
    } else if (requestCode == SHARE_REQUEST_CODE) {
      awaitedResult = AwaitedResult.NONE;
      onBackFromShare();
    }
  }

  /**
   * Deletes the staged copies once the user is back from sharing them, and leaves if the share
   * target had covered this screen, since {@link #onStop()} wiped the logs then.
   */
  private void onBackFromShare() {
    cleanUpTemporaryFiles();
    wipeDecryptedLogs();
    finish();
  }

  @VisibleForTesting
  void handleReEncryption(String keyIdentifier, boolean isInternal) {
    if (isNullOrEmpty(keyIdentifier)) {
      showToast("No key selected for re-encryption.");
      return;
    }

    PublicKey reEncryptionKey = null;
    try {
      List<PublicKey> externalKeys = publicKeyManager.getExternalReEncryptPublicKeys();
      for (PublicKey key : externalKeys) {
        try {
          if (CrumblesLogsEncryptor.getPublicKeyFingerprint(key).equals(keyIdentifier)) {
            reEncryptionKey = key;
            break;
          }
        } catch (CrumblesKeysException e) {
          // Skip only this key: the selected one can come later in the list.
          Log.e(TAG, "Error calculating fingerprint for re-encryption key", e);
        }
      }
    } catch (RuntimeException e) {
      Log.e(TAG, "Error retrieving re-encryption key with identifier: " + keyIdentifier, e);
    }

    if (reEncryptionKey == null) {
      showToast("Selected re-encryption key could not be found.");
      return;
    }

    reEncryptAndOfferToShareLogs(reEncryptionKey);
  }

  @VisibleForTesting
  void reEncryptAndOfferToShareLogs(PublicKey reEncryptionKey) {
    CrumblesReEncryptedCache.sweep(this);
    File tempDirBase = CrumblesReEncryptedCache.getDirectory(this);
    if (!tempDirBase.exists()) {
      if (!tempDirBase.mkdirs()) {
        Log.e(
            TAG,
            "Failed to create temporary directory for re-encrypted logs: "
                + tempDirBase.getAbsolutePath());
        showToast("Error creating temporary storage.");
        return;
      }
    }

    tempReEncryptedFilesForSharing.clear();
    ArrayList<Uri> reEncryptedFileUris = new ArrayList<>();
    boolean allSuccess = true;

    for (CrumblesDecryptedLogEntry entry : decryptedLogEntries) {
      if (entry.getRawBytes() == null) {
        Log.w(
            TAG,
            "Skipping re-encryption for " + entry.getFileName() + ": raw bytes not available.");
        allSuccess = false;
        continue;
      }
      try {
        LogBatch encryptedBatch = reEncryptEntry(entry, entry.getRawBytes(), reEncryptionKey);

        String sanitizedOriginalFileName = entry.getFileName().replaceAll("[^a-zA-Z0-9._-]", "_");
        String tempFileName =
            "re_encrypted_"
                + InstantSource.system().instant().toEpochMilli()
                + "_"
                + sanitizedOriginalFileName;
        if (tempFileName.length() > 100) {
          tempFileName = tempFileName.substring(0, 100);
        }
        tempFileName += ".bin";

        Path tempFilePath = logsEncryptor.serializeBytes(encryptedBatch, tempDirBase, tempFileName);

        if (tempFilePath != null) {
          File tempFile = tempFilePath.toFile();
          Uri fileUri =
              FileProvider.getUriForFile(this, CrumblesConstants.FILE_PROVIDER_AUTHORITY, tempFile);
          reEncryptedFileUris.add(fileUri);
          tempReEncryptedFilesForSharing.add(tempFile);
          Log.i(
              TAG,
              "Successfully re-encrypted and saved to temporary file: "
                  + tempFile.getAbsolutePath());
        } else {
          throw new IOException("serializeBytes returned null path for " + tempFileName);
        }

      } catch (Exception e) {
        Log.e(TAG, "Failed to re-encrypt or save content from: " + entry.getFileName(), e);
        showToast("Error re-encrypting " + entry.getFileName());
        allSuccess = false;
      }
    }

    if (!reEncryptedFileUris.isEmpty()) {
      Intent shareIntent = new Intent();
      if (reEncryptedFileUris.size() == 1) {
        shareIntent.setAction(Intent.ACTION_SEND);
        shareIntent.putExtra(Intent.EXTRA_STREAM, reEncryptedFileUris.get(0));
        shareIntent.setType("application/octet-stream");
      } else {
        shareIntent.setAction(Intent.ACTION_SEND_MULTIPLE);
        shareIntent.putParcelableArrayListExtra(Intent.EXTRA_STREAM, reEncryptedFileUris);
        shareIntent.setType("*/*");
      }
      shareIntent.setClipData(clipDataFor(reEncryptedFileUris));
      shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
      shareIntent.putExtra(Intent.EXTRA_SUBJECT, "Re-encrypted Crumbles Log(s)");

      String shareMessage =
          allSuccess
              ? "All logs re-encrypted. Choose an app to share."
              : "Some logs re-encrypted. Choose an app to share.";
      // The batches can now leave the phone, for whoever holds the key's private key.
      CrumblesAppAuditLogger.getInstance(this)
          .logEvent(
              "LOGS_RE_ENCRYPTED",
              "Re-encrypted "
                  + reEncryptedFileUris.size()
                  + " batch(es) to share them, to the key with fingerprint "
                  + fingerprintOf(reEncryptionKey)
                  + ".");
      showToast(shareMessage);
      chooseShareTarget(shareIntent);
    } else if (allSuccess && decryptedLogEntries != null && !decryptedLogEntries.isEmpty()) {
      showToast("Re-encryption seems to have produced no files to share.");
    } else if (!allSuccess) {
      showToast("Re-encryption failed for some items or no content was available.");
    } else {
      showToast("No logs were available to re-encrypt.");
    }
  }

  /**
   * Packs {@code uris} into a {@link ClipData} so {@link Intent#FLAG_GRANT_READ_URI_PERMISSION}
   * grants the chosen recipient read access to every staged file.
   */
  private static ClipData clipDataFor(List<Uri> uris) {
    ClipData clipData = ClipData.newRawUri(/* label= */ null, uris.get(0));
    for (int i = 1; i < uris.size(); i++) {
      clipData.addItem(new ClipData.Item(uris.get(i)));
    }
    return clipData;
  }

  /** Returns the fingerprint of {@code key}, or "unavailable" if it cannot be computed. */
  private static String fingerprintOf(PublicKey key) {
    try {
      return CrumblesLogsEncryptor.getPublicKeyFingerprint(key);
    } catch (CrumblesKeysException e) {
      return "unavailable";
    }
  }

  /**
   * Lists the apps that accept {@code shareIntent} for the user to pick one. Unlike the system
   * chooser, which can read the staged files as soon as it opens, no app can read them before the
   * user confirms it.
   */
  private void chooseShareTarget(Intent shareIntent) {
    PackageManager packageManager = getPackageManager();
    ImmutableList<ResolveInfo> targets =
        ImmutableList.sortedCopyOf(
            new ResolveInfo.DisplayNameComparator(packageManager),
            packageManager.queryIntentActivities(shareIntent, PackageManager.MATCH_DEFAULT_ONLY));
    if (targets.isEmpty()) {
      showToast(getString(R.string.toast_no_app_for_re_encrypted_logs));
      cleanUpTemporaryFiles();
      return;
    }
    CharSequence[] labels = targets.stream().map(this::labelOf).toArray(CharSequence[]::new);
    showSecureShareDialog(
        new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_choose_share_target)
            .setItems(
                labels, (dialog, which) -> confirmShareTarget(targets.get(which), shareIntent))
            .setOnCancelListener(dialog -> cleanUpTemporaryFiles())
            .create());
  }

  /**
   * Returns the label of {@code target}, {@link CrumblesDeviceAdminReceiver#escapeLabel escaped and
   * capped} so that line breaks, bidi controls or long runs of filler characters in it cannot hide
   * or push out of view the package name shown next to it.
   */
  private String labelOf(ResolveInfo target) {
    return getString(
        R.string.share_target_app,
        CrumblesDeviceAdminReceiver.escapeLabel(target.loadLabel(getPackageManager())),
        target.activityInfo.packageName);
  }

  /** Names the picked app and its package, and sends it the staged files once the user confirms. */
  private void confirmShareTarget(ResolveInfo target, Intent shareIntent) {
    String escapedLabel =
        CrumblesDeviceAdminReceiver.escapeLabel(target.loadLabel(getPackageManager()));
    String packageName = target.activityInfo.packageName;
    showSecureShareDialog(
        new AlertDialog.Builder(this)
            .setTitle(
                getString(R.string.dialog_title_confirm_share_target, escapedLabel, packageName))
            .setMessage(
                getString(R.string.dialog_message_confirm_share_target, escapedLabel, packageName))
            .setPositiveButton(
                R.string.dialog_button_send,
                (dialog, which) -> shareWith(target.activityInfo, shareIntent))
            .setNegativeButton(android.R.string.cancel, (dialog, which) -> cleanUpTemporaryFiles())
            .setOnCancelListener(dialog -> cleanUpTemporaryFiles())
            .create());
  }

  private void showSecureShareDialog(AlertDialog dialog) {
    activeShareDialog = dialog;
    dialog.setOnDismissListener(
        dismissed -> {
          if (Objects.equals(activeShareDialog, dismissed)) {
            activeShareDialog = null;
          }
        });
    Window window = dialog.getWindow();
    if (window != null) {
      // A dialog window does not inherit FLAG_SECURE or overlay hiding from the activity window.
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
      window.setHideOverlayWindows(true);
    }
    dialog.show();
  }

  /**
   * Sends the staged files to {@code target} only, which gets a grant to read each of them. {@link
   * CrumblesReEncryptedCache#sweep} revokes those grants when it deletes the files.
   */
  private void shareWith(ActivityInfo target, Intent shareIntent) {
    try {
      // The target's result tells this viewer that the user is back.
      startActivityForResult(
          new Intent(shareIntent).setClassName(target.packageName, target.name),
          SHARE_REQUEST_CODE);
      awaitedResult = AwaitedResult.SHARE;
    } catch (ActivityNotFoundException | SecurityException e) {
      // The app was removed, or stopped exporting the activity, after the user picked it.
      Log.e(TAG, "Failed to send the re-encrypted logs to " + target.packageName, e);
      showToast(getString(R.string.toast_no_app_for_re_encrypted_logs));
      cleanUpTemporaryFiles();
    }
  }

  private void cleanUpTemporaryFiles() {
    Log.d(TAG, "Cleaning up " + tempReEncryptedFilesForSharing.size() + " temporary share files.");
    tempReEncryptedFilesForSharing.clear();
    CrumblesReEncryptedCache.sweep(this);
  }

  private void showToast(String message) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    if (isChangingConfigurations()) {
      return; // The recreated viewer shows the same session.
    }
    cleanUpTemporaryFiles();
    wipeDecryptedLogs();
  }

  /**
   * Wipes the decrypted logs once this screen is no longer visible, so that showing them again
   * takes a new decryption, and with it a new authentication, from {@link CrumblesMain}.
   */
  @Override
  protected void onStop() {
    super.onStop();

    if (isChangingConfigurations()) {
      return; // The recreated viewer shows the same session.
    }
    switch (awaitedResult) {
      case KEY_SELECTION -> {} // The re-encryption that follows needs the decrypted bytes.
      case SHARE -> wipeDecryptedLogs(); // Stay to delete the staged copies once the user is back.
      case NONE -> {
        if (activeShareDialog != null) {
          activeShareDialog.dismiss();
        }
        cleanUpTemporaryFiles();
        wipeDecryptedLogs();
        finish();
      }
    }
  }

  /** Wipes the logs if the user leaves the app from the key picker, as no result will use them. */
  @Override
  public void onTrimMemory(int level) {
    super.onTrimMemory(level);
    if (level >= ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN
        && awaitedResult.equals(AwaitedResult.KEY_SELECTION)) {
      wipeDecryptedLogs();
      finish();
    }
  }

  /**
   * Re-encrypts {@code rawBytes} for {@code reEncryptionKey}. When {@code entry} came from a batch
   * signed by this installation, the new batch is signed again under the original sequence number,
   * attributed to this installation's device ID and sealing the attestation chain of its
   * batch-signing key.
   *
   * <p>Format version 2 batches leave the cleartext outer {@code device_id} empty, so signing a
   * re-encrypted copy stamped from {@code entry.getDeviceId()} would attest {@code unknown_device}.
   * Any other batch, including one whose signature does not verify with this installation's key, is
   * written unsigned with {@code entry.getDeviceId()}, without an attestation chain and without
   * creating a batch-signing key.
   */
  private LogBatch reEncryptEntry(
      CrumblesDecryptedLogEntry entry, byte[] rawBytes, PublicKey reEncryptionKey)
      throws CrumblesKeysException {
    LogBatch originalBatch = entry.getOriginalBatch();
    if (originalBatch == null || !originalBatch.hasSignature()) {
      return logsEncryptor.reEncryptLogBatch(rawBytes, reEncryptionKey, entry.getDeviceId());
    }
    CrumblesBatchSigner batchSigner = new CrumblesBatchSigner(this);
    if (batchSigner.isSignedByThisInstallation(originalBatch)) {
      LogBatch localBatch =
          logsEncryptor.reEncryptLogBatchForSigning(this, rawBytes, reEncryptionKey);
      try {
        return batchSigner.signAgain(originalBatch, localBatch);
      } catch (CrumblesKeysException e) {
        Log.e(TAG, "Failed to sign a re-encrypted log batch again; writing it unsigned.", e);
      }
    }
    CrumblesAppAuditLogger.getInstance(this)
        .logEvent(
            CrumblesDeviceAdminReceiver.AUDIT_EVENT_BATCH_SIGNING_FAILED,
            "Re-encrypted log batch "
                + originalBatch.getSequenceNumber()
                + " written without a signature: signing it again failed.");
    return logsEncryptor.reEncryptLogBatch(rawBytes, reEncryptionKey, entry.getDeviceId());
  }

  /**
   * Ends the session that held the decrypted logs, which zeroes the entries this viewer shares with
   * it, and clears them from the screen.
   */
  private void wipeDecryptedLogs() {
    decryptedLogEntries.clear();
    CrumblesDecryptedLogsSession.destroySession(sessionId);
    decryptedLogsTextView.setText("");
  }
}
