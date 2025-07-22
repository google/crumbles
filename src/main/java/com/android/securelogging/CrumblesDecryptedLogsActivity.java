package com.android.securelogging;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.SpannableStringBuilder;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.content.FileProvider;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** An activity to display decrypted Crumbles logs and offer re-encryption and sharing options. */
public class CrumblesDecryptedLogsActivity extends Activity {
  private static final String TAG = "[CrumblesDecryptedLogsView]";
  private static final int RE_ENCRYPT_KEY_REQUEST_CODE = 42; // Unique request code.

  private ArrayList<CrumblesDecryptedLogEntry> decryptedLogEntries;
  private CrumblesLogsEncryptor logsEncryptor;
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private ArrayList<File> tempReEncryptedFilesForSharing = new ArrayList<>();

  @SuppressWarnings("NonFinalStaticField")
  @VisibleForTesting
  static CrumblesExternalPublicKeyManager publicKeyManagerForTest = null;

  @Override
  @SuppressWarnings({
    "unchecked",
    "deprecation"
  }) // Need to use deprecated methods for compatibility
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_decrypted_logs);
    setTitle(R.string.decrypted_logs_viewer_title);

    TextView decryptedLogsTextView = findViewById(R.id.decrypted_logs_text_view);
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
    if (intent != null && intent.hasExtra(CrumblesConstants.EXTRA_DECRYPTED_LOGS)) {
      decryptedLogEntries =
          (ArrayList<CrumblesDecryptedLogEntry>)
              intent.getSerializableExtra(CrumblesConstants.EXTRA_DECRYPTED_LOGS);
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
          if (entry.getRawBytes() == null && entry.getContent() != null) {
            entry.setRawBytes(entry.getContent().getBytes(UTF_8));
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
            startActivityForResult(keySelectorIntent, RE_ENCRYPT_KEY_REQUEST_CODE);
          } else {
            showToast("No content to re-encrypt and share.");
          }
        });
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == RE_ENCRYPT_KEY_REQUEST_CODE) {
      if (resultCode == Activity.RESULT_OK && data != null) {
        String keyIdentifier =
            data.getStringExtra(CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS);
        boolean isInternal =
            data.getBooleanExtra(
                CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_IS_INTERNAL, false);
        handleReEncryption(keyIdentifier, isInternal);
      } else {
        showToast("Re-encryption cancelled.");
      }
    }
  }

  @VisibleForTesting
  void handleReEncryption(String keyIdentifier, boolean isInternal) {
    if (isNullOrEmpty(keyIdentifier)) {
      showToast("No key selected for re-encryption.");
      return;
    }

    PublicKey reEncryptionKey = null;
    try {
      if (isInternal) {
        reEncryptionKey = logsEncryptor.getPublicKey(keyIdentifier);
      } else {
        List<PublicKey> externalKeys = publicKeyManager.getExternalReEncryptPublicKeys();
        for (PublicKey key : externalKeys) {
          if (CrumblesLogsEncryptor.getPublicKeyHash(key).equals(keyIdentifier)) {
            reEncryptionKey = key;
            break;
          }
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
    File tempDirBase = new File(getCacheDir(), CrumblesConstants.TEMP_RE_ENCRYPTED_DIR);
    if (!tempDirBase.exists()) {
      if (!tempDirBase.mkdirs()) {
        Log.e(
            TAG,
            "Failed to create temporary directory for re-encrypted logs: "
                + tempDirBase.getAbsolutePath());
        showToast("Error creating temporary storage.");
        return;
      }
    } else {
      clearDirectory(tempDirBase.toPath());
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
        LogBatch encryptedBatch =
            logsEncryptor.reEncryptLogBatch(entry.getRawBytes(), reEncryptionKey);

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
      shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
      shareIntent.putExtra(Intent.EXTRA_SUBJECT, "Re-encrypted Crumbles Log(s)");

      try {
        startActivity(Intent.createChooser(shareIntent, "Share Re-encrypted Log(s) Via"));
        String shareMessage =
            allSuccess
                ? "All logs re-encrypted. Choose an app to share."
                : "Some logs re-encrypted. Choose an app to share.";
        showToast(shareMessage);
      } catch (ActivityNotFoundException ex) {
        showToast("No application can handle this share request.");
        cleanUpTemporaryFiles();
      }
    } else if (allSuccess && decryptedLogEntries != null && !decryptedLogEntries.isEmpty()) {
      showToast("Re-encryption seems to have produced no files to share.");
    } else if (!allSuccess) {
      showToast("Re-encryption failed for some items or no content was available.");
    } else {
      showToast("No logs were available to re-encrypt.");
    }
  }

  private void cleanUpTemporaryFiles() {
    if (tempReEncryptedFilesForSharing.isEmpty()) {
      Log.d(TAG, "No temporary files to clean up.");
      return;
    }
    Log.d(
        TAG, "Cleaning up " + tempReEncryptedFilesForSharing.size() + " temporary share files...");
    for (File file : tempReEncryptedFilesForSharing) {
      if (file.exists()) {
        if (file.delete()) {
          Log.d(TAG, "Deleted temporary file: " + file.getAbsolutePath());
        } else {
          Log.w(TAG, "Failed to delete temporary file: " + file.getAbsolutePath());
        }
      }
    }
    tempReEncryptedFilesForSharing.clear();

    File tempDirBase = new File(getCacheDir(), CrumblesConstants.TEMP_RE_ENCRYPTED_DIR);
    if (tempDirBase.exists() && tempDirBase.isDirectory()) {
      File[] filesInDir = tempDirBase.listFiles();
      if (filesInDir == null || filesInDir.length == 0) {
        if (tempDirBase.delete()) {
          Log.d(TAG, "Deleted empty temporary directory: " + tempDirBase.getAbsolutePath());
        } else {
          Log.w(
              TAG, "Failed to delete empty temporary directory: " + tempDirBase.getAbsolutePath());
        }
      }
    }
  }

  /* Helper method to clear a directory. */
  private void clearDirectory(Path directory) {
    if (Files.exists(directory) && Files.isDirectory(directory)) {
      try (Stream<Path> stream = Files.walk(directory)) {
        if (stream != null) {
          stream
              .sorted((path1, path2) -> path2.compareTo(path1))
              .forEach(
                  path -> {
                    try {
                      if (!path.equals(directory)) { // Don't delete the root dir itself here.
                        Files.delete(path);
                        Log.d(TAG, "Cleaned old file/dir: " + path.toFile().getAbsolutePath());
                      }
                    } catch (IOException e) {
                      Log.w(
                          TAG,
                          "Failed to delete old file/dir: " + path.toFile().getAbsolutePath(),
                          e);
                    }
                  });
        }
      } catch (IOException e) {
        Log.w(TAG, "Failed to clear directory: " + directory.toFile().getAbsolutePath(), e);
      }
    }
  }

  private void showToast(String message) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    Log.d(TAG, "onDestroy called. Cleaning up temporary files.");
    cleanUpTemporaryFiles();
  }

  /** FOR TESTING PURPOSES ONLY to allow tests to populate the list. */
  void addFileToTrackForTesting(File f) {
    if (tempReEncryptedFilesForSharing == null) {
      tempReEncryptedFilesForSharing = new ArrayList<>();
    }
    tempReEncryptedFilesForSharing.add(f);
  }

  /** FOR TESTING PURPOSES ONLY to allow tests to modify internal state. */
  @VisibleForTesting
  void setDecryptedLogEntriesForTest(List<CrumblesDecryptedLogEntry> entries) {
    this.decryptedLogEntries = new ArrayList<>(entries);
    Button reEncryptAndShareButton = findViewById(R.id.reencrypt_and_share_button);
    TextView decryptedLogsTextView = findViewById(R.id.decrypted_logs_text_view);

    if (reEncryptAndShareButton != null) {
      reEncryptAndShareButton.setEnabled(
          this.decryptedLogEntries != null && !this.decryptedLogEntries.isEmpty());
    }

    if (decryptedLogsTextView != null) {
      if (this.decryptedLogEntries == null || this.decryptedLogEntries.isEmpty()) {
        decryptedLogsTextView.setText(R.string.no_decrypted_log_content_to_display);
      }
    }
  }
}
