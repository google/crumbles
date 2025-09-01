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

import android.app.Dialog;
import android.content.DialogInterface;
import android.graphics.Bitmap;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;
import androidx.appcompat.app.AlertDialog;
import android.text.method.LinkMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.Toast;
import com.google.zxing.BarcodeFormat;
import java.util.Arrays;
import java.util.Base64;

/**
 * Dialog fragment to display the private key. It fully owns the handling of sensitive data such as
 * private key bytes, makes its own copy, and immediately invalidates the data in the calling
 * Activity's scope, clearing it from memory.
 */
public class CrumblesPrivateKeyViewerDialogFragment extends DialogFragment {

  private static final String TAG = "CrumblesPrivateKeyViewerDF";

  // Hold the fragment's own secure copy.
  private byte[] privateKeyCopy;
  private Runnable cleanupCallback;

  public static CrumblesPrivateKeyViewerDialogFragment newInstance(
      byte[] privateKeyBytes, boolean showQrInitially) {
    CrumblesPrivateKeyViewerDialogFragment fragment = new CrumblesPrivateKeyViewerDialogFragment();
    Bundle args = new Bundle();
    args.putByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES, privateKeyBytes);
    args.putBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY, showQrInitially);
    fragment.setArguments(args);
    return fragment;
  }

  /** Method for the Activity to provide the cleanup task. */
  public void setCleanupCallback(Runnable callback) {
    this.cleanupCallback = callback;
  }

  @Override
  public void onCreate(@Nullable Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Bundle arguments = getArguments();
    if (arguments != null) {
      byte[] originalBytes = arguments.getByteArray(CrumblesConstants.ARG_PRIVATE_KEY_BYTES);
      if (originalBytes != null) {
        // 1. Make our own secure, defensive copy.
        this.privateKeyCopy = Arrays.copyOf(originalBytes, originalBytes.length);

        // 2. Execute the callback to tell the Activity it can now clear its key.
        if (cleanupCallback != null) {
          cleanupCallback.run();
          cleanupCallback = null; // Ensure it only runs once.
        }
      }
    }
  }

  @NonNull
  @Override
  public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
    if (privateKeyCopy == null) {
      Log.e(TAG, "Private key data was not provided to the dialog fragment.");
      return new AlertDialog.Builder(requireActivity())
          .setTitle("Error")
          .setMessage("No key data provided.")
          .setPositiveButton(android.R.string.ok, null)
          .create();
    }

    AlertDialog.Builder builder = new AlertDialog.Builder(requireActivity());
    builder
        .setTitle(R.string.dialog_title_private_key_security_warning)
        .setMessage(R.string.dialog_message_private_key_user_responsibility)
        .setView(R.layout.dialog_togglable_private_key);

    AlertDialog dialog = builder.create();

    dialog.setOnShowListener(
        d -> {
          final EditText keyTextView = dialog.findViewById(R.id.private_key_text_view);
          final ScrollView textScrollView = dialog.findViewById(R.id.private_key_text_scrollview);
          final ImageView qrCodeImageView = dialog.findViewById(R.id.private_key_qr_code_imageview);
          final Button switchButton = dialog.findViewById(R.id.btn_switch_view);
          final Button doneButton = dialog.findViewById(R.id.btn_done);

          if (textScrollView == null
              || keyTextView == null
              || qrCodeImageView == null
              || switchButton == null
              || doneButton == null) {
            Log.e(TAG, "One or more views in the dialog layout could not be found.");
            return;
          }

          final String privateKeyB64 = Base64.getEncoder().encodeToString(privateKeyCopy);
          keyTextView.setText(privateKeyB64);
          keyTextView.setMovementMethod(LinkMovementMethod.getInstance());

          boolean showQrInitially =
              getArguments().getBoolean(CrumblesConstants.ARG_SHOW_QR_INITIALLY, false);

          if (showQrInitially) {
            try {
              CrumblesBarcodeEncoder barcodeEncoder = new CrumblesBarcodeEncoder();
              Bitmap bitmap =
                  barcodeEncoder.encodeBitmap(privateKeyB64, BarcodeFormat.QR_CODE, 600, 600);
              qrCodeImageView.setImageBitmap(bitmap);
              textScrollView.setVisibility(View.GONE);
              qrCodeImageView.setVisibility(View.VISIBLE);
              switchButton.setText(R.string.dialog_button_view_as_text);
            } catch (Exception e) {
              Log.e(TAG, "Failed to generate initial QR bitmap", e);
              textScrollView.setVisibility(View.VISIBLE);
              qrCodeImageView.setVisibility(View.GONE);
              switchButton.setText(R.string.dialog_button_view_as_qr);
            }
          } else {
            textScrollView.setVisibility(View.VISIBLE);
            qrCodeImageView.setVisibility(View.GONE);
            switchButton.setText(R.string.dialog_button_view_as_qr);
          }

          doneButton.setOnClickListener(v -> dialog.dismiss());
          switchButton.setOnClickListener(
              v -> {
                boolean isQrCurrentlyVisible = qrCodeImageView.getVisibility() == View.VISIBLE;
                if (isQrCurrentlyVisible) {
                  qrCodeImageView.setVisibility(View.GONE);
                  textScrollView.setVisibility(View.VISIBLE);
                  switchButton.setText(R.string.dialog_button_view_as_qr);
                } else {
                  try {
                    if (qrCodeImageView.getDrawable() == null) {
                      CrumblesBarcodeEncoder barcodeEncoder = new CrumblesBarcodeEncoder();
                      Bitmap bitmap =
                          barcodeEncoder.encodeBitmap(
                              privateKeyB64, BarcodeFormat.QR_CODE, 600, 600);
                      qrCodeImageView.setImageBitmap(bitmap);
                    }
                    textScrollView.setVisibility(View.GONE);
                    qrCodeImageView.setVisibility(View.VISIBLE);
                    switchButton.setText(R.string.dialog_button_view_as_text);
                  } catch (Exception e) {
                    Toast.makeText(
                            getContext(),
                            R.string.toast_qr_generation_failed_for_private_key,
                            Toast.LENGTH_SHORT)
                        .show();
                    Log.e(TAG, "Failed to generate QR bitmap", e);
                  }
                }
              });
        });

    return dialog;
  }

  @Override
  public void onDismiss(@NonNull DialogInterface dialog) {
    super.onDismiss(dialog);
    // Clear the fragment's internal copy when it's done.
    if (privateKeyCopy != null) {
      Arrays.fill(privateKeyCopy, (byte) 0);
      Log.d(TAG, "Internal defensive copy cleared on dismiss.");
    }
  }
}
