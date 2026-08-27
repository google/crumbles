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
import static org.mockito.Mockito.when;
import static org.robolectric.Shadows.shadowOf;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Looper;
import android.support.v7.app.ActionBar;
import android.view.View;
import android.widget.ListView;
import android.widget.TextView;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import com.google.common.collect.ImmutableList;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowActivity;

/** Unit tests for {@link CrumblesReEncryptKeysActivity}. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 34)
public class CrumblesReEncryptKeysActivityTest {

  @Mock private CrumblesExternalPublicKeyManager mockPublicKeyManager;

  private ActivityScenario<CrumblesReEncryptKeysActivity> scenario;

  @Before
  public void setUp() {
    MockitoAnnotations.openMocks(this);
    ApplicationProvider.getApplicationContext().setTheme(R.style.Theme_AppCompat);
    CrumblesReEncryptKeysActivity.publicKeyManagerForTest = mockPublicKeyManager;
  }

  @After
  public void tearDown() {
    if (scenario != null) {
      scenario.close();
    }
    CrumblesReEncryptKeysActivity.publicKeyManagerForTest = null;
  }

  private void launchActivity() {
    Context context = ApplicationProvider.getApplicationContext();
    Intent intent = new Intent(context, CrumblesReEncryptKeysActivity.class);
    scenario = ActivityScenario.launch(intent);
    shadowOf(Looper.getMainLooper()).idle();
  }

  @Test
  public void onCreate_setsUpActionBarCorrectly() {
    // Given: The activity is launched.
    launchActivity();

    // When: The activity creates and initializes the UI.
    scenario.onActivity(
        activity -> {
          // Then: The ActionBar is configured correctly.
          ActionBar actionBar = activity.getSupportActionBar();
          assertThat(actionBar).isNotNull();
          assertThat(actionBar.getTitle().toString()).isEqualTo("Select Re-encryption Key");
          int displayOptions = actionBar.getDisplayOptions();
          assertThat((displayOptions & ActionBar.DISPLAY_HOME_AS_UP)).isNotEqualTo(0);
        });
  }

  @Test
  public void onResume_keyInfoAdapter_setsCorrectText() throws Exception {
    // Given: An external key is configured in the public key manager.
    PublicKey externalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(externalKey));
    String externalKeyHash = CrumblesLogsEncryptor.getPublicKeyHash(externalKey);

    // When: The activity is launched and resumed.
    launchActivity();

    // Then: The adapter correctly displays the text for the external key.
    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          View externalKeyView = listView.getChildAt(0);
          TextView externalText1 = externalKeyView.findViewById(android.R.id.text1);
          TextView externalText2 = externalKeyView.findViewById(android.R.id.text2);
          assertThat(externalText1.getText().toString()).isEqualTo(externalKeyHash);
          assertThat(externalText2.getText().toString()).isEqualTo("External Key");
        });
  }

  @Test
  public void onListItemClick_forExternalKey_setsResultAndFinishes() throws Exception {
    // Given: An external key is configured.
    PublicKey externalKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
    when(mockPublicKeyManager.getExternalReEncryptPublicKeys())
        .thenReturn(ImmutableList.of(externalKey));
    String externalKeyHash = CrumblesLogsEncryptor.getPublicKeyHash(externalKey);

    launchActivity();
    shadowOf(Looper.getMainLooper()).idle();

    // When: The item in the list is clicked.
    scenario.onActivity(
        activity -> {
          ListView listView = activity.findViewById(R.id.re_encrypt_key_list);
          shadowOf(listView).performItemClick(0);

          // Then: The activity finishes with the correct result data.
          assertThat(shadowOf(activity).getResultCode()).isEqualTo(Activity.RESULT_OK);
          Intent resultData = shadowOf(activity).getResultIntent();
          assertThat(resultData).isNotNull();
          assertThat(
                  resultData.getStringExtra(CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_ALIAS))
              .isEqualTo(externalKeyHash);
          assertThat(
                  resultData.getBooleanExtra(
                      CrumblesReEncryptKeysActivity.EXTRA_SELECTED_KEY_IS_INTERNAL, true))
              .isFalse();
        });
  }

  @Test
  public void importExternalKey_onClick_launchesQrScanner() {
    // Given: The activity is launched.
    launchActivity();

    // When: The "Import New External Key" button is clicked.
    scenario.onActivity(
        activity -> {
          // Assume camera permission is granted for the test.
          shadowOf(activity).grantPermissions(android.Manifest.permission.CAMERA);
          activity.findViewById(R.id.btn_import_external_re_encrypt_key).performClick();
          shadowOf(Looper.getMainLooper()).idle();

          // Then: An intent to start the QR scanner activity is launched for a result.
          ShadowActivity.IntentForResult startedIntentResult =
              shadowOf(activity).peekNextStartedActivityForResult();
          assertThat(startedIntentResult).isNotNull();

          Intent startedIntent = startedIntentResult.intent;
          assertThat(shadowOf(startedIntent).getIntentClass().getName())
              .isEqualTo(CrumblesQrScannerActivity.class.getName());
        });
  }
}
