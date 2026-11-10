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
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.graphics.ImageFormat;
import android.graphics.Rect;
import android.media.Image;
import android.view.WindowManager;
import androidx.annotation.Nullable;
import androidx.camera.core.ExperimentalGetImage;
import androidx.camera.core.ImageInfo;
import androidx.camera.core.ImageProxy;
import androidx.camera.core.ImageProxy.PlaneProxy;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.common.collect.ImmutableList;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowLooper;
import org.robolectric.util.ReflectionHelpers;

/** Unit tests for {@link CrumblesQrScannerActivity}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34, application = CrumblesQrScannerActivityTest.SelfRevokeRecordingApplication.class)
public class CrumblesQrScannerActivityTest {

  private static final int FRAME_SIZE = 200;
  private static final byte WHITE = (byte) 0xFF;
  private static final String SCANNED_TEXT = "This is a test QR value";

  private ActivityScenario<CrumblesQrScannerActivity> scenario;
  private SelfRevokeRecordingApplication appContext;

  @Before
  public void setUp() {
    // Given: Mocks are initialized for the test class.
    MockitoAnnotations.openMocks(this);
    appContext = ApplicationProvider.getApplicationContext();
    // Declared in the manifest, so granted at install.
    shadowOf(appContext).grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS);

    // And: The activity theme is set to avoid inflation errors.
    appContext.setTheme(R.style.Theme_Crumbles);
  }

  @After
  @SuppressWarnings("ActivityScenarioNoAutoClose")
  public void tearDown() {
    // Given: An activity scenario may be running.
    // When: The test is finished.
    // Then: The scenario is closed to release resources.
    if (scenario != null) {
      scenario.close();
    }
    CrumblesDecryptedLogsSession.destroyActiveSession();
  }

  private void launchActivity() {
    scenario = ActivityScenario.launch(CrumblesQrScannerActivity.class);
    // Move the activity to a resumed state to ensure onCreate and onResume are called.
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper();
  }

  /** Returns a camera frame whose luminance plane shows {@code text} as a QR code. */
  private static FakeLuminanceFrame frameShowingQrCode(String text, int rowPadding)
      throws WriterException {
    BitMatrix qrCode =
        new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, FRAME_SIZE, FRAME_SIZE);
    int rowStride = qrCode.getWidth() + rowPadding;
    // Padding bytes stay black, so a decoder that ignores the row stride fails.
    byte[] luminance = new byte[rowStride * qrCode.getHeight()];
    for (int y = 0; y < qrCode.getHeight(); y++) {
      for (int x = 0; x < qrCode.getWidth(); x++) {
        if (!qrCode.get(x, y)) {
          luminance[y * rowStride + x] = WHITE;
        }
      }
    }
    return new FakeLuminanceFrame(luminance, rowStride, qrCode.getWidth(), qrCode.getHeight());
  }

  private static FakeLuminanceFrame blankFrame() {
    byte[] luminance = new byte[FRAME_SIZE * FRAME_SIZE];
    Arrays.fill(luminance, WHITE);
    return new FakeLuminanceFrame(luminance, FRAME_SIZE, FRAME_SIZE, FRAME_SIZE);
  }

  /** A YUV_420_888 frame that only carries the luminance plane the scanner reads. */
  private static final class FakeLuminanceFrame implements ImageProxy {
    private final PlaneProxy luminancePlane;
    private final int width;
    private final int height;
    private Rect cropRect;
    private boolean closed;

    FakeLuminanceFrame(byte[] luminance, int rowStride, int width, int height) {
      this.luminancePlane = new FakeLuminancePlane(ByteBuffer.wrap(luminance), rowStride);
      this.width = width;
      this.height = height;
      this.cropRect = new Rect(0, 0, width, height);
    }

    boolean isClosed() {
      return closed;
    }

    @Override
    public void close() {
      closed = true;
    }

    @Override
    public Rect getCropRect() {
      return cropRect;
    }

    @Override
    public void setCropRect(@Nullable Rect rect) {
      cropRect = rect == null ? new Rect(0, 0, width, height) : rect;
    }

    @Override
    public int getFormat() {
      return ImageFormat.YUV_420_888;
    }

    @Override
    public int getHeight() {
      return height;
    }

    @Override
    public int getWidth() {
      return width;
    }

    @Override
    public PlaneProxy[] getPlanes() {
      return new PlaneProxy[] {luminancePlane};
    }

    @Override
    public ImageInfo getImageInfo() {
      throw new UnsupportedOperationException("The scanner does not read the image info.");
    }

    @Override
    @ExperimentalGetImage
    @Nullable
    public Image getImage() {
      return null;
    }
  }

  private static final class FakeLuminancePlane implements PlaneProxy {
    private final ByteBuffer buffer;
    private final int rowStride;

    FakeLuminancePlane(ByteBuffer buffer, int rowStride) {
      this.buffer = buffer;
      this.rowStride = rowStride;
    }

    @Override
    public int getRowStride() {
      return rowStride;
    }

    @Override
    public int getPixelStride() {
      return 1;
    }

    @Override
    public ByteBuffer getBuffer() {
      return buffer;
    }
  }

  /** Records the permissions that the app asks the system to revoke when it is killed. */
  public static final class SelfRevokeRecordingApplication extends Application {
    private final List<String> selfRevokedPermissions = new ArrayList<>();

    @Override
    public void revokeSelfPermissionsOnKill(Collection<String> permissions) {
      selfRevokedPermissions.addAll(permissions);
    }
  }

  @Test
  public void onCreate_hidesOverlayWindows() {
    shadowOf(appContext).grantPermissions(Manifest.permission.CAMERA);

    launchActivity();

    scenario.onActivity(activity -> assertThat(hidesOverlayWindows(activity)).isTrue());
  }

  @Test
  public void onCreate_setsFlagSecure() {
    shadowOf(appContext).grantPermissions(Manifest.permission.CAMERA);

    launchActivity();

    scenario.onActivity(
        activity ->
            assertThat(
                    activity.getWindow().getAttributes().flags
                        & WindowManager.LayoutParams.FLAG_SECURE)
                .isEqualTo(WindowManager.LayoutParams.FLAG_SECURE));
  }

  // --- Tests for permission handling ---

  @Test
  public void onCreate_whenAllPermissionsAreGranted_doesNotRequestPermissions() {
    // Given: The required CAMERA permission is granted.
    shadowOf(appContext).grantPermissions(Manifest.permission.CAMERA);

    // When: The activity is launched.
    launchActivity();

    // Then: The activity does not request permissions again.
    scenario.onActivity(
        activity -> {
          ShadowActivity shadowActivity = shadowOf(activity);
          assertThat(shadowActivity.getLastRequestedPermission()).isNull();
        });
  }

  @Test
  public void onCreate_whenPermissionIsMissing_requestsPermissions() {
    // Given: The required CAMERA permission is NOT granted.
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);

    // When: The activity is launched.
    launchActivity();

    // Then: The activity requests the CAMERA permission.
    scenario.onActivity(
        activity -> {
          ShadowActivity shadowActivity = shadowOf(activity);
          ShadowActivity.PermissionsRequest lastRequest =
              shadowActivity.getLastRequestedPermission();
          assertThat(lastRequest).isNotNull();
          assertThat(lastRequest.requestedPermissions)
              .asList()
              .containsExactly(Manifest.permission.CAMERA);
        });
  }

  @Test
  public void onDestroy_whenFinishing_revokesCameraPermission() {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    launchActivity();

    scenario.onActivity(activity -> activity.finish());
    scenario.moveToState(Lifecycle.State.DESTROYED);

    assertThat(appContext.selfRevokedPermissions).containsExactly(Manifest.permission.CAMERA);
  }

  @Test
  public void onDestroy_whenRecreated_doesNotRevokeCameraPermission() {
    // Robolectric has no camera, so a scanner with the permission finishes with an error. Without
    // the permission, the scanner keeps running while it waits for the user.
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    launchActivity();

    scenario.recreate();

    assertThat(appContext.selfRevokedPermissions).isEmpty();
  }

  // --- Tests for QR code decoding ---

  @Test
  public void processImageProxy_withQrCodeFrame_finishesWithScannedText() throws Exception {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    launchActivity();
    FakeLuminanceFrame frame = frameShowingQrCode(SCANNED_TEXT, /* rowPadding= */ 0);

    scenario.onActivity(
        activity -> {
          activity.processImageProxy(frame);
          ShadowLooper.idleMainLooper();

          ShadowActivity shadowActivity = shadowOf(activity);
          assertThat(shadowActivity.getResultCode()).isEqualTo(Activity.RESULT_OK);
          Intent resultIntent = shadowActivity.getResultIntent();
          assertThat(resultIntent.getStringExtra(CrumblesConstants.SCAN_RESULT_EXTRA))
              .isEqualTo(SCANNED_TEXT);
        });
  }

  @Test
  public void processImageProxy_withPaddedRows_finishesWithScannedText() throws Exception {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    launchActivity();
    FakeLuminanceFrame frame = frameShowingQrCode(SCANNED_TEXT, /* rowPadding= */ 64);

    scenario.onActivity(
        activity -> {
          activity.processImageProxy(frame);
          ShadowLooper.idleMainLooper();

          Intent resultIntent = shadowOf(activity).getResultIntent();
          assertThat(resultIntent.getStringExtra(CrumblesConstants.SCAN_RESULT_EXTRA))
              .isEqualTo(SCANNED_TEXT);
        });
  }

  @Test
  public void processImageProxy_withoutQrCode_returnsNoScanResult() {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    launchActivity();
    FakeLuminanceFrame frame = blankFrame();

    scenario.onActivity(
        activity -> {
          activity.processImageProxy(frame);
          ShadowLooper.idleMainLooper();

          assertThat(shadowOf(activity).getResultIntent()).isNull();
        });
  }

  @Test
  public void processImageProxy_closesFrame() {
    shadowOf(appContext).grantPermissions(Manifest.permission.CAMERA);
    launchActivity();
    FakeLuminanceFrame frame = blankFrame();

    scenario.onActivity(activity -> activity.processImageProxy(frame));

    assertThat(frame.isClosed()).isTrue();
  }

  @Test
  public void processImageProxy_withKeyMaterial_doesNotLogScannedPayload() throws Exception {
    shadowOf(appContext).grantPermissions(Manifest.permission.CAMERA);
    launchActivity();
    String secretMarker = "MIIBOgIBAAJBAKj";
    FakeLuminanceFrame frame =
        frameShowingQrCode(
            "-----BEGIN PRIVATE KEY-----" + secretMarker + "-----END PRIVATE KEY-----",
            /* rowPadding= */ 0);

    scenario.onActivity(
        activity -> {
          activity.processImageProxy(frame);
          ShadowLooper.idleMainLooper();

          StringBuilder loggedMessages = new StringBuilder();
          for (ShadowLog.LogItem logItem : ShadowLog.getLogs()) {
            loggedMessages.append(logItem.msg).append('\n');
          }
          assertThat(shadowOf(activity).getResultIntent()).isNotNull();
          assertThat(loggedMessages.toString()).doesNotContain(secretMarker);
        });
  }

  @Test
  public void onStop_whenStartedFromKeyPickerWithoutResult_endsDecryptedSession() {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    byte[] rawBytes = "decrypted log content".getBytes(UTF_8);
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "log.bin", rawBytes, "device-1", /* originalBatch= */ null)));
    Intent intent =
        new Intent(appContext, CrumblesQrScannerActivity.class)
            .putExtra(CrumblesQrScannerActivity.EXTRA_END_DECRYPTED_SESSION_ON_STOP, true);
    scenario = ActivityScenario.launch(intent);

    scenario.moveToState(Lifecycle.State.CREATED);

    assertThat(rawBytes).isEqualTo(new byte[rawBytes.length]);
    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isEmpty();
  }

  @Test
  public void onStop_whenStartedFromKeyPickerAndReturningResult_keepsDecryptedSession()
      throws Exception {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    byte[] expectedBytes = "decrypted log content".getBytes(UTF_8);
    byte[] rawBytes = expectedBytes.clone();
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "log.bin", rawBytes, "device-1", /* originalBatch= */ null)));
    Intent intent =
        new Intent(appContext, CrumblesQrScannerActivity.class)
            .putExtra(CrumblesQrScannerActivity.EXTRA_END_DECRYPTED_SESSION_ON_STOP, true);
    scenario = ActivityScenario.launch(intent);
    FakeLuminanceFrame frame = frameShowingQrCode(SCANNED_TEXT, /* rowPadding= */ 0);

    scenario.onActivity(
        activity -> {
          activity.processImageProxy(frame);
          ShadowLooper.idleMainLooper();
        });
    scenario.moveToState(Lifecycle.State.DESTROYED);

    assertThat(rawBytes).isEqualTo(expectedBytes);
    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isPresent();
  }

  @Test
  public void onStop_whenFinishingWithoutResult_keepsDecryptedSession() {
    shadowOf(appContext).denyPermissions(Manifest.permission.CAMERA);
    byte[] expectedBytes = "decrypted log content".getBytes(UTF_8);
    byte[] rawBytes = expectedBytes.clone();
    long sessionId =
        CrumblesDecryptedLogsSession.startSession(
            ImmutableList.of(
                new CrumblesDecryptedLogEntry(
                    "log.bin", rawBytes, "device-1", /* originalBatch= */ null)));
    Intent intent =
        new Intent(appContext, CrumblesQrScannerActivity.class)
            .putExtra(CrumblesQrScannerActivity.EXTRA_END_DECRYPTED_SESSION_ON_STOP, true);
    scenario = ActivityScenario.launch(intent);

    scenario.onActivity(Activity::finish);
    scenario.moveToState(Lifecycle.State.DESTROYED);

    assertThat(rawBytes).isEqualTo(expectedBytes);
    assertThat(CrumblesDecryptedLogsSession.getSession(sessionId)).isPresent();
  }

  /** Returns whether {@code activity} keeps the overlay windows of other apps hidden. */
  private static boolean hidesOverlayWindows(Activity activity) {
    int hideOverlays =
        ReflectionHelpers.getStaticField(
            WindowManager.LayoutParams.class, "SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS");
    int privateFlags =
        ReflectionHelpers.getField(activity.getWindow().getAttributes(), "privateFlags");
    return (privateFlags & hideOverlays) == hideOverlays;
  }
}
