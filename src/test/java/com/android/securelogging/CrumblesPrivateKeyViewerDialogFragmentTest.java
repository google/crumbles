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
import static java.nio.charset.StandardCharsets.UTF_8;

import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.testing.FragmentScenario;
import androidx.lifecycle.Lifecycle;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

/** Unit tests for {@link CrumblesPrivateKeyViewerDialogFragment}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesPrivateKeyViewerDialogFragmentTest {

  @Test
  public void newInstance_withValidArguments_createsFragmentWithCorrectArgs() {
    // Given: A sample byte array for the private key and the initial view state.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);
    boolean shouldShowQr = true;

    // When: The newInstance factory method is called.
    CrumblesPrivateKeyViewerDialogFragment fragment =
        CrumblesPrivateKeyViewerDialogFragment.newInstance(testKeyBytes, shouldShowQr);

    // Then: A non-null fragment instance is created.
    assertThat(fragment).isNotNull();

    // And: The fragment has a non-null arguments Bundle.
    Bundle args = fragment.getArguments();
    assertThat(args).isNotNull();

    // And: The arguments in the Bundle match the values passed to the factory method.
    assertThat(args.getByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES)).isEqualTo(testKeyBytes);
    assertThat(args.getBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY)).isTrue();
  }

  @Test
  public void onCreateDialog_whenShowQrIsFalse_showsTextViewInitially() {
    // Given: A fragment is created with arguments to show the TEXT view initially.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);
    Bundle args = new Bundle();
    args.putByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES, testKeyBytes);
    args.putBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY, false);

    // When: The fragment is launched.
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class, args, R.style.Theme_AppCompat);
    scenario.moveToState(Lifecycle.State.RESUMED);

    // Then: The text view is visible, and the QR code view is hidden.
    scenario.onFragment(
        fragment -> {
          assertThat(fragment.getDialog()).isNotNull();
          assertThat(fragment.getDialog().isShowing()).isTrue();

          View dialogView = fragment.getDialog().findViewById(R.id.private_key_text_scrollview);
          assertThat(dialogView.getVisibility()).isEqualTo(View.VISIBLE);

          View qrView = fragment.getDialog().findViewById(R.id.private_key_qr_code_imageview);
          assertThat(qrView.getVisibility()).isEqualTo(View.GONE);
        });
  }

  @Test
  public void onCreateDialog_whenShowQrIsTrue_showsQrViewInitially() {
    // Given: A fragment is created with arguments to show the QR CODE view initially.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);
    Bundle args = new Bundle();
    args.putByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES, testKeyBytes);
    args.putBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY, true);

    // When: The fragment is launched.
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class, args, R.style.Theme_AppCompat);
    scenario.moveToState(Lifecycle.State.RESUMED);

    // Then: The QR code view is visible, and the text view is hidden.
    scenario.onFragment(
        fragment -> {
          assertThat(fragment.getDialog()).isNotNull();
          assertThat(fragment.getDialog().isShowing()).isTrue();

          View dialogView = fragment.getDialog().findViewById(R.id.private_key_text_scrollview);
          assertThat(dialogView.getVisibility()).isEqualTo(View.GONE);

          View qrView = fragment.getDialog().findViewById(R.id.private_key_qr_code_imageview);
          assertThat(qrView.getVisibility()).isEqualTo(View.VISIBLE);
        });
  }

  @Test
  public void onCreateDialog_withNullArguments_doesNotCrashAndCreatesDialogObject() {
    // Given: No arguments are provided to the fragment.
    Bundle args = null;

    // When: The fragment is launched using FragmentScenario.launch().
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class, args, R.style.Theme_Crumbles);

    // Then: The app does not crash and the Dialog object is still created by the framework.
    // Our internal logic now gracefully handles the null arguments.
    scenario.onFragment(
        fragment -> {
          assertThat(fragment.getDialog()).isNotNull();
          // The dialog will show a simple error message, which is the expected behavior.
          assertThat(fragment.getDialog().isShowing()).isTrue();
        });
  }
}
