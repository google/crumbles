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
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.media.Image;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.util.Log;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.mlkit.vision.barcode.BarcodeScanner;
import com.google.mlkit.vision.barcode.BarcodeScannerOptions;
import com.google.mlkit.vision.barcode.BarcodeScanning;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.common.InputImage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Activity to scan QR codes. */
public class CrumblesQrScannerActivity extends AppCompatActivity {

  private static final String TAG = "CrumblesQrScannerActivity";
  private static final String[] requiredPermissions = new String[] {Manifest.permission.CAMERA};

  private PreviewView previewView;
  private ExecutorService cameraExecutor;
  @VisibleForTesting BarcodeScanner barcodeScanner;
  private boolean isProcessingBarcode = false;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_qr_scanner);

    previewView = findViewById(R.id.camera_preview_view);
    cameraExecutor = Executors.newSingleThreadExecutor();

    if (allPermissionsGranted()) {
      startCamera();
    } else {
      ActivityCompat.requestPermissions(
          this, requiredPermissions, CrumblesConstants.QR_SCAN_REQUEST_CODE_PERMISSIONS);
    }
  }

  private BarcodeScanner getBarcodeScanner() {
    if (barcodeScanner == null) {
      BarcodeScannerOptions options =
          new BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build();
      barcodeScanner = BarcodeScanning.getClient(options);
    }
    return barcodeScanner;
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

  @SuppressLint("UnsafeOptInUsageError")
  void processImageProxy(@NonNull ImageProxy imageProxy) {
    if (isProcessingBarcode) {
      imageProxy.close();
      return;
    }
    Image mediaImage = imageProxy.getImage();
    if (mediaImage != null) {
      InputImage image =
          InputImage.fromMediaImage(mediaImage, imageProxy.getImageInfo().getRotationDegrees());
      processInputImage(image, imageProxy);
    } else {
      imageProxy.close();
    }
  }

  private void processInputImage(@NonNull InputImage image, @NonNull ImageProxy imageProxy) {
    getBarcodeScanner()
        .process(image)
        .addOnSuccessListener(
            barcodes -> {
              if (!barcodes.isEmpty()) {
                // When a barcode is found, call our new handler method.
                handleBarcodeFound(barcodes.get(0));
              }
            })
        .addOnFailureListener(e -> Log.e(TAG, "Barcode scanning failed.", e))
        .addOnCompleteListener(task -> imageProxy.close());
  }

  /** App's logic to facilitate testing without using framework classes. */
  @VisibleForTesting
  void handleBarcodeFound(@NonNull Barcode barcode) {
    if (isProcessingBarcode) {
      return;
    }
    isProcessingBarcode = true;

    String rawValue = barcode.getRawValue();
    if (rawValue != null) {
      Log.d(TAG, "QR Code detected: " + rawValue);
      Intent resultIntent = new Intent();
      resultIntent.putExtra(CrumblesConstants.SCAN_RESULT_EXTRA, rawValue);
      setResult(Activity.RESULT_OK, resultIntent);
    } else {
      Log.w(TAG, "QR Code detected but raw value is null.");
      setResult(Activity.RESULT_CANCELED);
    }
    finish();
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
    if (barcodeScanner != null) {
      barcodeScanner.close();
    }
  }
}
