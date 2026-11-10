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

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.WindowManager;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.ImageProxy.PlaneProxy;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.FormatException;
import com.google.zxing.NotFoundException;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Activity to scan QR codes. Decoding happens on the device with ZXing. */
public class CrumblesQrScannerActivity extends AppCompatActivity {

  private static final String TAG = "CrumblesQrScannerActivity";
  static final String EXTRA_END_DECRYPTED_SESSION_ON_STOP = "end_decrypted_session_on_stop";
  private static final String[] requiredPermissions = new String[] {Manifest.permission.CAMERA};

  private PreviewView previewView;
  private ExecutorService cameraExecutor;
  // Read on the camera executor and written on the main thread.
  private volatile boolean isProcessingBarcode = false;
  private boolean returningResult = false;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
    getWindow().setHideOverlayWindows(true);
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_qr_scanner);
    CrumblesWindowInsets.applySystemBarPadding(this);

    previewView = findViewById(R.id.camera_preview_view);
    cameraExecutor = Executors.newSingleThreadExecutor();

    if (allPermissionsGranted()) {
      startCamera();
    } else {
      ActivityCompat.requestPermissions(
          this, requiredPermissions, CrumblesConstants.QR_SCAN_REQUEST_CODE_PERMISSIONS);
    }
  }

  private boolean allPermissionsGranted() {
    for (String permission : requiredPermissions) {
      if (ContextCompat.checkSelfPermission(this, permission)
          != PackageManager.PERMISSION_GRANTED) {
        return false;
      }
    }
    return true;
  }

  private void startCamera() {
    ListenableFuture<ProcessCameraProvider> cameraProviderFuture =
        ProcessCameraProvider.getInstance(this);

    cameraProviderFuture.addListener(
        () -> {
          try {
            ProcessCameraProvider cameraProvider = cameraProviderFuture.get();
            bindCameraUseCases(cameraProvider);
          } catch (ExecutionException | InterruptedException e) {
            Log.e(TAG, "Error starting camera provider.", e);
            Toast.makeText(this, "Error starting camera: " + e.getMessage(), Toast.LENGTH_SHORT)
                .show();
            finishWithError();
          }
        },
        ContextCompat.getMainExecutor(this));
  }

  private void bindCameraUseCases(@NonNull ProcessCameraProvider cameraProvider) {
    Preview preview = new Preview.Builder().build();
    preview.setSurfaceProvider(previewView.getSurfaceProvider());

    CameraSelector cameraSelector =
        new CameraSelector.Builder().requireLensFacing(CameraSelector.LENS_FACING_BACK).build();

    ImageAnalysis imageAnalysis =
        new ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build();

    imageAnalysis.setAnalyzer(cameraExecutor, this::processImageProxy);

    try {
      cameraProvider.unbindAll();
      cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis);
    } catch (RuntimeException e) {
      Log.e(TAG, "Use case binding failed.", e);
      Toast.makeText(this, "Could not start camera.", Toast.LENGTH_SHORT).show();
      finishWithError();
    }
  }

  /** Decodes one camera frame and, if it shows a QR code, finishes with the code's text. */
  void processImageProxy(@NonNull ImageProxy imageProxy) {
    try {
      if (!isProcessingBarcode) {
        decodeQrCode(imageProxy).ifPresent(text -> runOnUiThread(() -> handleQrCodeFound(text)));
      }
    } finally {
      imageProxy.close();
    }
  }

  /** Returns the text of the QR code in the luminance plane of a YUV_420_888 frame, if any. */
  private static Optional<String> decodeQrCode(@NonNull ImageProxy imageProxy) {
    PlaneProxy luminancePlane = imageProxy.getPlanes()[0];
    int rowStride = luminancePlane.getRowStride();
    int height = imageProxy.getHeight();
    ByteBuffer buffer = luminancePlane.getBuffer();
    byte[] luminance = new byte[rowStride * height];
    // The last row of the plane can be shorter than the row stride.
    buffer.get(luminance, /* off= */ 0, Math.min(buffer.remaining(), luminance.length));
    PlanarYUVLuminanceSource source =
        new PlanarYUVLuminanceSource(
            luminance,
            rowStride,
            height,
            /* left= */ 0,
            /* top= */ 0,
            imageProxy.getWidth(),
            height,
            /* reverseHorizontal= */ false);
    Result result;
    try {
      result = new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(source)));
    } catch (NotFoundException | ChecksumException | FormatException e) {
      // Most frames do not contain a readable QR code, so keep scanning.
      return Optional.empty();
    }
    return Optional.of(result.getText());
  }

  private void handleQrCodeFound(@NonNull String rawValue) {
    if (isProcessingBarcode) {
      return;
    }
    isProcessingBarcode = true;

    // Never log the scanned payload: the same scanner is used to import private keys.
    Log.d(TAG, "QR Code detected, payload length: " + rawValue.length());
    returningResult = true;
    Intent resultIntent = new Intent();
    resultIntent.putExtra(CrumblesConstants.SCAN_RESULT_EXTRA, rawValue);
    setResult(Activity.RESULT_OK, resultIntent);
    finish();
  }

  @Override
  protected void onStop() {
    super.onStop();
    if (!isChangingConfigurations()
        && !isFinishing()
        && !returningResult
        && getIntent().getBooleanExtra(EXTRA_END_DECRYPTED_SESSION_ON_STOP, false)) {
      CrumblesDecryptedLogsSession.destroyActiveSession();
    }
  }

  @Override
  public void onRequestPermissionsResult(
      int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    if (requestCode == CrumblesConstants.QR_SCAN_REQUEST_CODE_PERMISSIONS) {
      if (allPermissionsGranted()) {
        startCamera();
      } else {
        Toast.makeText(this, "Camera permission is required to scan QR codes.", Toast.LENGTH_LONG)
            .show();
        finishWithError();
      }
    }
  }

  private void finishWithError() {
    setResult(Activity.RESULT_CANCELED);
    finish();
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    cameraExecutor.shutdown();
    if (isFinishing()) {
      // The camera is only needed to scan, so give the permission back. The system revokes it,
      // and kills the app, once the app is in the background and has no active components. A
      // configuration change destroys the activity without finishing it, and the scan goes on.
      getApplicationContext().revokeSelfPermissionsOnKill(Arrays.asList(requiredPermissions));
    }
  }
}
