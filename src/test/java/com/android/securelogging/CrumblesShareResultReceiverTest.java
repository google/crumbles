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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.audit.CrumblesAppAuditLogger;
import com.android.securelogging.audit.CrumblesAuditEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/** Unit tests for {@link CrumblesShareResultReceiver}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesShareResultReceiverTest {

  private Context context;
  private File logDirectory;
  private CrumblesShareResultReceiver receiver;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    receiver = new CrumblesShareResultReceiver();
    logDirectory = new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY);
    deleteRecursive(logDirectory);
    logDirectory.mkdirs();
    CrumblesAppAuditLogger.getInstance(context).clearAllLogs();
  }

  @After
  public void tearDown() {
    deleteRecursive(logDirectory);
  }

  private void deleteRecursive(File fileOrDirectory) {
    if (fileOrDirectory.isDirectory()) {
      File[] children = fileOrDirectory.listFiles();
      if (children != null) {
        for (File child : children) {
          deleteRecursive(child);
        }
      }
    }
    fileOrDirectory.delete();
  }

  private File createFile(String name) throws IOException {
    File file = new File(logDirectory, name);
    assertTrue("Could not create test file: " + name, file.createNewFile());
    return file;
  }

  @Test
  public void onReceive_withChosenComponent_renamesProcessingFilesToSentAndLogsAudit()
      throws IOException {
    // Given: Multiple crumbles_logs_encrypted_*_processing.bin files.
    File file1 = createFile(CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "1" + CrumblesConstants.PROCESSING_SUFFIX);
    File file2 = createFile(CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "2" + CrumblesConstants.PROCESSING_SUFFIX);

    Intent intent = new Intent(context, CrumblesShareResultReceiver.class);
    intent.putExtra(
        Intent.EXTRA_CHOSEN_COMPONENT, new ComponentName("com.example.app", "ShareActivity"));
    intent.putStringArrayListExtra(
        CrumblesConstants.EXTRA_FILES,
        new ArrayList<>(Arrays.asList(file1.getName(), file2.getName())));

    // When: Receiver processes the share completion callback.
    receiver.onReceive(context, intent);

    // Then: Both files are renamed to _sent.bin.
    assertThat(file1.exists()).isFalse();
    assertThat(file2.exists()).isFalse();
    File sent1 = new File(logDirectory, CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "1" + CrumblesConstants.SENT_SUFFIX);
    File sent2 = new File(logDirectory, CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "2" + CrumblesConstants.SENT_SUFFIX);
    assertThat(sent1.exists()).isTrue();
    assertThat(sent2.exists()).isTrue();

    // And: An audit log event is recorded.
    List<CrumblesAuditEvent> events =
        CrumblesAppAuditLogger.getInstance(context).getAllPersistedEventsForDisplay();
    assertThat(events).isNotEmpty();
    assertThat(events.get(0).getEventType()).isEqualTo("LOGS_MARKED_SENT");
  }

  @Test
  public void onReceive_withoutChosenComponent_doesNotRenameFiles() throws IOException {
    // Given: A _processing.bin file and an intent lacking EXTRA_CHOSEN_COMPONENT.
    File file1 = createFile(CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "1" + CrumblesConstants.PROCESSING_SUFFIX);

    Intent intent = new Intent(context, CrumblesShareResultReceiver.class);
    intent.putStringArrayListExtra(
        CrumblesConstants.EXTRA_FILES, new ArrayList<>(Arrays.asList(file1.getName())));

    // When: Receiver receives intent without EXTRA_CHOSEN_COMPONENT.
    receiver.onReceive(context, intent);

    // Then: File remains _processing.bin.
    assertThat(file1.exists()).isTrue();
    File sent1 = new File(logDirectory, CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "1" + CrumblesConstants.SENT_SUFFIX);
    assertThat(sent1.exists()).isFalse();
  }

  @Test
  public void onReceive_onlyRenamesSpecifiedFiles() throws IOException {
    // Given: Two _processing.bin files, but only one is listed in the intent extra.
    File file1 = createFile(CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "1" + CrumblesConstants.PROCESSING_SUFFIX);
    File file2 = createFile(CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "2" + CrumblesConstants.PROCESSING_SUFFIX);

    Intent intent = new Intent(context, CrumblesShareResultReceiver.class);
    intent.putExtra(
        Intent.EXTRA_CHOSEN_COMPONENT, new ComponentName("com.example.app", "ShareActivity"));
    intent.putStringArrayListExtra(
        CrumblesConstants.EXTRA_FILES, new ArrayList<>(Arrays.asList(file1.getName())));

    // When: Receiver processes the callback.
    receiver.onReceive(context, intent);

    // Then: Only file1 is renamed to _sent.bin. file2 remains _processing.bin.
    assertThat(file1.exists()).isFalse();
    assertThat(new File(logDirectory, CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "1" + CrumblesConstants.SENT_SUFFIX).exists()).isTrue();
    assertThat(file2.exists()).isTrue();
    assertThat(new File(logDirectory, CrumblesConstants.ENCRYPTED_LOG_FILE_NAME + "2" + CrumblesConstants.SENT_SUFFIX).exists()).isFalse();
  }

  @Test
  public void onReceive_tamperedFileNames_areIgnored() throws IOException {
    // Given: An invalid prefix file and a traversal filename.
    File invalidPrefixFile = createFile("malicious_log" + CrumblesConstants.PROCESSING_SUFFIX);

    Intent intent = new Intent(context, CrumblesShareResultReceiver.class);
    intent.putExtra(
        Intent.EXTRA_CHOSEN_COMPONENT, new ComponentName("com.example.app", "ShareActivity"));
    intent.putStringArrayListExtra(
        CrumblesConstants.EXTRA_FILES,
        new ArrayList<>(Arrays.asList(invalidPrefixFile.getName(), "../../secret_processing.bin")));

    // When: Receiver processes the callback.
    receiver.onReceive(context, intent);

    // Then: Tampered file names are ignored and remain untouched.
    assertThat(invalidPrefixFile.exists()).isTrue();
    List<CrumblesAuditEvent> events =
        CrumblesAppAuditLogger.getInstance(context).getAllPersistedEventsForDisplay();
    assertThat(events).isEmpty();
  }
}
