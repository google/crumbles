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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import android.app.Dialog;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentFactory;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.fragment.app.testing.FragmentScenario;
import androidx.lifecycle.Lifecycle;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.securelogging.CrumblesPrivateKeyViewerDialogFragment.KeyCustodyConfirmationListener;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLooper;

/** Unit tests for {@link CrumblesPrivateKeyViewerDialogFragment}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesPrivateKeyViewerDialogFragmentTest {

  private static FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> launchFragment(
      byte[] keyBytes, boolean showQrInitially) {
    Bundle args = new Bundle();
    args.putBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY, showQrInitially);
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class,
            args,
            R.style.Theme_AppCompat,
            new FragmentFactory() {
              @NonNull
              @Override
              public Fragment instantiate(
                  @NonNull ClassLoader classLoader, @NonNull String className) {
                if (className.equals(CrumblesPrivateKeyViewerDialogFragment.class.getName())) {
                  return CrumblesPrivateKeyViewerDialogFragment.newInstance(
                      Arrays.copyOf(keyBytes, keyBytes.length), showQrInitially);
                }
                return super.instantiate(classLoader, className);
              }
            });
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper();
    return scenario;
  }

  @Test
  public void newInstance_withValidArguments_createsFragmentWithCorrectArgs() {
    // Given: A sample byte array for the private key and the initial view state.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);
    int originalLength = testKeyBytes.length;
    boolean shouldShowQr = true;

    // When: The newInstance factory method is called.
    CrumblesPrivateKeyViewerDialogFragment fragment =
        CrumblesPrivateKeyViewerDialogFragment.newInstance(testKeyBytes, shouldShowQr);

    // Then: A non-null fragment instance is created.
    assertThat(fragment).isNotNull();

    // And: The fragment has a non-null arguments Bundle.
    Bundle args = fragment.getArguments();
    assertThat(args).isNotNull();

    // And: Key bytes are never placed in the arguments Bundle (persisted to disk by AMS).
    assertThat(args.getByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES)).isNull();
    assertThat(args.getBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY)).isTrue();

    // And: The caller's key array is immediately invalidated (zeroed).
    assertThat(testKeyBytes).isEqualTo(new byte[originalLength]);

    // And: The fragment must not retain its instance.
    assertThat(fragment.getRetainInstance()).isFalse();
  }

  @Test
  public void onCreateDialog_whenShowQrIsFalse_showsTextViewInitially() {
    // Given: A fragment is created with arguments to show the TEXT view initially.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);

    // When: The fragment is launched.
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment(testKeyBytes, false);

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

    // When: The fragment is launched.
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment(testKeyBytes, true);

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
  public void onCreateDialog_whenShowQrInitiallyNotProvided_showsTextViewByDefault() {
    // Given: A fragment is created with arguments that do not specify ARG_SHOW_QR_INITIALLY.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);

    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class,
            new Bundle(),
            R.style.Theme_AppCompat,
            new FragmentFactory() {
              @NonNull
              @Override
              public Fragment instantiate(
                  @NonNull ClassLoader classLoader, @NonNull String className) {
                if (className.equals(CrumblesPrivateKeyViewerDialogFragment.class.getName())) {
                  CrumblesPrivateKeyViewerDialogFragment fragment =
                      CrumblesPrivateKeyViewerDialogFragment.newInstance(
                          Arrays.copyOf(testKeyBytes, testKeyBytes.length), false);
                  fragment.setArguments(new Bundle());
                  return fragment;
                }
                return super.instantiate(classLoader, className);
              }
            });
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper();

    // Then: The text view is visible by default, and the QR code view is hidden.
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
  public void onCreateDialog_whenArgumentsAreNull_showsTextViewByDefault() {
    // Given: A fragment is created with key material but with null arguments.
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);

    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class,
            null,
            R.style.Theme_AppCompat,
            new FragmentFactory() {
              @NonNull
              @Override
              public Fragment instantiate(
                  @NonNull ClassLoader classLoader, @NonNull String className) {
                if (className.equals(CrumblesPrivateKeyViewerDialogFragment.class.getName())) {
                  CrumblesPrivateKeyViewerDialogFragment fragment =
                      CrumblesPrivateKeyViewerDialogFragment.newInstance(
                          Arrays.copyOf(testKeyBytes, testKeyBytes.length), false);
                  fragment.setArguments(null);
                  return fragment;
                }
                return super.instantiate(classLoader, className);
              }
            });
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper();

    // Then: The text view is visible by default without throwing NullPointerException.
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
  public void onClickDone_triggersCustodyConfirmedAndDismisses() {
    // Given: A fragment with a registered custody confirmation listener.
    KeyCustodyConfirmationListener mockListener = mock(KeyCustodyConfirmationListener.class);
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);

    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment(testKeyBytes, false);

    // When: User clicks the "Done" (OK, I Understand & Saved It) button.
    scenario.onFragment(
        fragment -> {
          fragment.setKeyCustodyConfirmationListener(mockListener);
          Button doneButton = fragment.getDialog().findViewById(R.id.btn_done);
          assertThat(doneButton).isNotNull();
          doneButton.performClick();
          fragment.onDismiss(fragment.getDialog());
        });

    // Then: onKeyCustodyConfirmed is triggered and onKeyCustodyCancelled is never called.
    verify(mockListener).onKeyCustodyConfirmed();
    verify(mockListener, never()).onKeyCustodyCancelled();
  }

  @Test
  public void onDismiss_withoutDoneClick_triggersCustodyCancelled() {
    // Given: A fragment with a registered custody confirmation listener.
    KeyCustodyConfirmationListener mockListener = mock(KeyCustodyConfirmationListener.class);
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);

    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment(testKeyBytes, false);

    // When: Dialog is dismissed without clicking the done button.
    scenario.onFragment(
        fragment -> {
          fragment.setKeyCustodyConfirmationListener(mockListener);
          fragment.onDismiss(fragment.getDialog());
        });

    // Then: onKeyCustodyCancelled is triggered and onKeyCustodyConfirmed is never called.
    verify(mockListener).onKeyCustodyCancelled();
    verify(mockListener, never()).onKeyCustodyConfirmed();
  }

  @Test
  public void onCreateDialog_withoutKey_doesNotCrashAndCreatesErrorDialog() {
    // Given: No arguments or key data are provided to the fragment.
    Bundle args = null;

    // When: The fragment is launched using FragmentScenario.launch().
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        FragmentScenario.launch(
            CrumblesPrivateKeyViewerDialogFragment.class, args, R.style.Theme_Crumbles);
    ShadowLooper.idleMainLooper();

    // Then: The app does not crash and the Dialog object is still created with FLAG_SECURE.
    scenario.onFragment(
        fragment -> {
          assertThat(fragment.getDialog()).isNotNull();
          assertThat(fragment.getDialog().isShowing()).isTrue();
          assertThat(
                  fragment.requireDialog().getWindow().getAttributes().flags
                      & WindowManager.LayoutParams.FLAG_SECURE)
              .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
        });
  }

  @Test
  public void privateKeyViewer_doesNotStoreKeyInArguments() {
    byte[] key = new byte[1190];
    new SecureRandom().nextBytes(key);
    CrumblesPrivateKeyViewerDialogFragment f =
        CrumblesPrivateKeyViewerDialogFragment.newInstance(key, /* showQrInitially= */ false);
    assertThat(f.getArguments().getByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES)).isNull();
    assertThat(f.getRetainInstance()).isFalse();
    // And the caller's array must have been zeroed:
    assertThat(key).isEqualTo(new byte[1190]);
  }

  @Test
  public void privateKeyViewer_setsFlagSecure() {
    byte[] key = new byte[1190];
    new SecureRandom().nextBytes(key);
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment(key, /* showQrInitially= */ false);
    scenario.onFragment(
        f -> {
          assertThat(
                  f.requireDialog().getWindow().getAttributes().flags
                      & WindowManager.LayoutParams.FLAG_SECURE)
              .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
          assertThat(
                  f.requireActivity().getWindow().getAttributes().flags
                      & WindowManager.LayoutParams.FLAG_SECURE)
              .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE);
        });
  }

  @Test
  public void onCreateDialog_showsKeyInTextViewThatIsNotEditableSavedOrAutofilled() {
    byte[] testKeyBytes = "a-test-private-key".getBytes(UTF_8);

    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment(testKeyBytes, /* showQrInitially= */ false);

    scenario.onFragment(
        fragment -> {
          TextView keyTextView = fragment.requireDialog().findViewById(R.id.private_key_text_view);
          assertThat(keyTextView).isNotInstanceOf(EditText.class);
          assertThat(keyTextView.getText().toString())
              .isEqualTo(Base64.getEncoder().encodeToString(testKeyBytes));
          assertThat(keyTextView.isSaveEnabled()).isFalse();
          assertThat(keyTextView.isTextSelectable()).isFalse();
          assertThat(keyTextView.getImportantForAutofill())
              .isEqualTo(View.IMPORTANT_FOR_AUTOFILL_NO);
          assertThat(keyTextView.isAccessibilityDataSensitive()).isTrue();
        });
  }

  @Test
  public void onCreateDialog_hidesKeyFromAccessibilityServicesOtherThanTools() {
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment("a-test-private-key".getBytes(UTF_8), /* showQrInitially= */ false);

    scenario.onFragment(
        fragment -> {
          TextView keyTextView = fragment.requireDialog().findViewById(R.id.private_key_text_view);
          assertThat(keyTextView.isAccessibilityDataSensitive()).isTrue();
        });
  }

  @Test
  public void onDismiss_clearsDisplayedKeyText() {
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment("a-test-private-key".getBytes(UTF_8), /* showQrInitially= */ false);
    AtomicReference<TextView> keyTextView = new AtomicReference<>();

    scenario.onFragment(
        fragment -> {
          keyTextView.set(fragment.requireDialog().findViewById(R.id.private_key_text_view));
          fragment.onDismiss(fragment.requireDialog());
        });

    assertThat(keyTextView.get().getText().toString()).isEmpty();
  }

  @Test
  public void onDismiss_detachesAndRecyclesQrBitmap() {
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment("a-test-private-key".getBytes(UTF_8), /* showQrInitially= */ true);
    AtomicReference<ImageView> qrCodeImageView = new AtomicReference<>();
    AtomicReference<Bitmap> qrBitmap = new AtomicReference<>();

    scenario.onFragment(
        fragment -> {
          ImageView imageView =
              fragment.requireDialog().findViewById(R.id.private_key_qr_code_imageview);
          qrCodeImageView.set(imageView);
          qrBitmap.set(((BitmapDrawable) imageView.getDrawable()).getBitmap());
          fragment.onDismiss(fragment.requireDialog());
        });

    assertThat(qrCodeImageView.get().getDrawable()).isNull();
    assertThat(qrBitmap.get().isRecycled()).isTrue();
  }

  @Test
  public void onDismiss_dropsEncodedKeySoQrCodeCannotBeRegenerated() {
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment("a-test-private-key".getBytes(UTF_8), /* showQrInitially= */ false);
    AtomicReference<Drawable> qrDrawableAfterSwitch = new AtomicReference<>();

    scenario.onFragment(
        fragment -> {
          Dialog dialog = fragment.requireDialog();
          ImageView qrCodeImageView = dialog.findViewById(R.id.private_key_qr_code_imageview);
          Button switchButton = dialog.findViewById(R.id.btn_switch_view);
          fragment.onDismiss(dialog);
          switchButton.performClick();
          // Read it now: the fragment removal posted by onDismiss() clears the views later.
          qrDrawableAfterSwitch.set(qrCodeImageView.getDrawable());
        });

    assertThat(qrDrawableAfterSwitch.get()).isNull();
  }

  @Test
  public void whenDestroyed_clearsDisplayedKeyText() {
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment("a-test-private-key".getBytes(UTF_8), /* showQrInitially= */ false);
    AtomicReference<TextView> keyTextView = new AtomicReference<>();
    scenario.onFragment(
        fragment ->
            keyTextView.set(fragment.requireDialog().findViewById(R.id.private_key_text_view)));

    scenario.moveToState(Lifecycle.State.DESTROYED);

    assertThat(keyTextView.get().getText().toString()).isEmpty();
  }

  @Test
  public void whenDestroyed_clearsDisplayedKeyTextBeforeDialogWindowIsRemoved() {
    FragmentScenario<CrumblesPrivateKeyViewerDialogFragment> scenario =
        launchFragment("a-test-private-key".getBytes(UTF_8), /* showQrInitially= */ false);
    AtomicReference<String> keyTextWhenWindowRemoved = new AtomicReference<>();
    scenario.onFragment(
        fragment -> {
          TextView keyTextView = fragment.requireDialog().findViewById(R.id.private_key_text_view);
          // DialogFragment calls onDismiss(), which also clears the key, right after it removes
          // the dialog window, so read the text at removal time.
          keyTextView.addOnAttachStateChangeListener(
              new View.OnAttachStateChangeListener() {
                @Override
                public void onViewAttachedToWindow(View view) {}

                @Override
                public void onViewDetachedFromWindow(View view) {
                  keyTextWhenWindowRemoved.set(keyTextView.getText().toString());
                }
              });
        });

    scenario.moveToState(Lifecycle.State.DESTROYED);

    assertThat(keyTextWhenWindowRemoved.get()).isEmpty();
  }
}
