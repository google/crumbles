package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.Manifest;
import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.google.mlkit.vision.barcode.common.Barcode;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;
import org.robolectric.shadows.ShadowLooper;

/** Unit tests for {@link CrumblesQrScannerActivity}. */
@RunWith(AndroidJUnit4.class)
@Config(sdk = 34)
public class CrumblesQrScannerActivityTest {

  private ActivityScenario<CrumblesQrScannerActivity> scenario;
  private Application appContext;

  @Before
  public void setUp() {
    // Given: Mocks are initialized for the test class.
    MockitoAnnotations.openMocks(this);
    appContext = ApplicationProvider.getApplicationContext();

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
  }

  private void launchActivity() {
    scenario = ActivityScenario.launch(CrumblesQrScannerActivity.class);
    // Move the activity to a resumed state to ensure onCreate and onResume are called.
    scenario.moveToState(Lifecycle.State.RESUMED);
    ShadowLooper.idleMainLooper();
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

  // --- Tests for Barcode Handling Logic ---

  @Test
  public void handleBarcodeFound_withValidBarcode_finishesWithResult() {
    // Given: The camera permission is granted and the activity is launched.
    shadowOf(appContext).grantPermissions(Manifest.permission.CAMERA);
    launchActivity();

    // And: A mock Barcode is created with a specific value.
    Barcode mockBarcode = mock(Barcode.class);
    String expectedQrValue = "This is a test QR value";
    when(mockBarcode.getRawValue()).thenReturn(expectedQrValue);

    scenario.onActivity(
        activity -> {
          // When: The activity's handler method is called directly with the mock barcode.
          activity.handleBarcodeFound(mockBarcode);
          ShadowLooper.idleMainLooper();

          // Then: The activity finishes.
          assertThat(activity.isFinishing()).isTrue();

          // And: The result is RESULT_OK.
          ShadowActivity shadowActivity = shadowOf(activity);
          assertThat(shadowActivity.getResultCode()).isEqualTo(Activity.RESULT_OK);

          // And: The result intent contains the correct scanned data.
          Intent resultIntent = shadowActivity.getResultIntent();
          assertThat(resultIntent.getStringExtra(CrumblesConstants.SCAN_RESULT_EXTRA))
              .isEqualTo(expectedQrValue);
        });
  }
}
