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
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.content.ContextCompat;
import com.android.securelogging.exceptions.CrumblesKeysException;
import java.security.PublicKey;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;

/** An activity to select or create a key for re-encryption. */
public class CrumblesReEncryptKeysActivity extends AppCompatActivity {

  private static final String TAG = "CrumblesReEncryptKeys";
  public static final String EXTRA_SELECTED_KEY_ALIAS = "selected_key_alias";
  public static final String EXTRA_SELECTED_KEY_IS_INTERNAL = "is_internal_key";

  private CrumblesLogsEncryptor logsEncryptor;
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private List<KeyInfo> availableKeys;
  private ArrayAdapter<KeyInfo> adapter;

  @SuppressWarnings("NonFinalStaticField")
  @VisibleForTesting
  static CrumblesExternalPublicKeyManager publicKeyManagerForTest = null;

  private final ActivityResultLauncher<Intent> qrScanLauncher =
      registerForActivityResult(
          new ActivityResultContracts.StartActivityForResult(),
          result -> {
            if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
              Intent data = result.getData();
              String scannedPublicKeyB64 = data.getStringExtra(CrumblesConstants.SCAN_RESULT_EXTRA);
              if (scannedPublicKeyB64 != null && !scannedPublicKeyB64.isEmpty()) {
                try {
                  PublicKey importedKey =
                      CrumblesLogsEncryptor.publicKeyFromBase64(scannedPublicKeyB64);
                  if (importedKey != null) {
                    publicKeyManager.saveReEncryptPublicKey(importedKey);
                    Toast.makeText(
                            this, "New external re-encryption key imported.", Toast.LENGTH_SHORT)
                        .show();
                    loadAvailableKeys(); // Refresh list.
                  }
                } catch (CrumblesKeysException e) {
                  Toast.makeText(this, "Failed to import key.", Toast.LENGTH_SHORT).show();
                  Log.e(TAG, "Failed to process imported key", e);
                }
              }
            } else {
              Toast.makeText(this, "QR Scan cancelled or failed.", Toast.LENGTH_SHORT).show();
            }
          });

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_re_encrypt_keys);
    if (getSupportActionBar() != null) {
      getSupportActionBar().setDisplayHomeAsUpEnabled(true);
      getSupportActionBar().setTitle("Select Re-encryption Key");
    }

    logsEncryptor = CrumblesMain.getLogsEncryptorInstance();
    // Use the test manager if it's been injected.
    if (publicKeyManagerForTest != null) {
      publicKeyManager = publicKeyManagerForTest;
    } else {
      publicKeyManager = CrumblesExternalPublicKeyManager.getInstance(this);
    }

    availableKeys = new ArrayList<>();

    ListView listView = findViewById(R.id.re_encrypt_key_list);
    adapter = new KeyInfoAdapter(this, availableKeys);
    listView.setAdapter(adapter);

    listView.setOnItemClickListener(
        (parent, view, position, id) -> {
          KeyInfo selectedKey = availableKeys.get(position);
          Intent resultIntent = new Intent();
          resultIntent.putExtra(EXTRA_SELECTED_KEY_ALIAS, selectedKey.getAlias());
          resultIntent.putExtra(EXTRA_SELECTED_KEY_IS_INTERNAL, selectedKey.isInternal());
          setResult(Activity.RESULT_OK, resultIntent);
          finish();
        });

    Button createInternalKey = findViewById(R.id.btn_create_internal_re_encrypt_key);
    createInternalKey.setOnClickListener(v -> createNewInternalKey());

    Button importExternalKey = findViewById(R.id.btn_import_external_re_encrypt_key);
    importExternalKey.setOnClickListener(v -> startQrScan());
  }

  @Override
  protected void onResume() {
    super.onResume();
    loadAvailableKeys();
  }

  private void loadAvailableKeys() {
    availableKeys.clear();

    // Load internal keys from Keystore
    List<PublicKey> internalKeys = logsEncryptor.getInternalReEncryptPublicKeys();
    for (PublicKey key : internalKeys) {
      String alias = CrumblesLogsEncryptor.getPublicKeyAlias(key);
      if (alias != null) {
        availableKeys.add(new KeyInfo(alias, "Keystore Key", true));
      }
    }

    // Load external keys from EncryptedSharedPreferences
    List<PublicKey> externalKeys = publicKeyManager.getExternalReEncryptPublicKeys();
    for (PublicKey key : externalKeys) {
      String hash = CrumblesLogsEncryptor.getPublicKeyHash(key);
      availableKeys.add(new KeyInfo(hash, "External Key", false));
    }

    adapter.notifyDataSetChanged();
  }

  private void createNewInternalKey() {
    try {
      String newAlias =
          CrumblesLogsEncryptor.RE_ENCRYPT_KEY_ALIAS_PREFIX
              + InstantSource.system().instant().toEpochMilli();
      logsEncryptor.generateKeyPair(newAlias, /* requireUserAuthentication= */ false);
      Toast.makeText(this, "New internal re-encryption key created.", Toast.LENGTH_SHORT).show();
      loadAvailableKeys(); // Refresh the list
    } catch (Exception e) {
      Toast.makeText(this, "Failed to create new key.", Toast.LENGTH_SHORT).show();
      Log.e(TAG, "Failed to create new internal re-encryption key", e);
    }
  }

  private void startQrScan() {
    if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
        != PackageManager.PERMISSION_GRANTED) {
      requestPermissions(
          new String[] {Manifest.permission.CAMERA},
          CrumblesConstants.CAMERA_PERMISSION_REQUEST_CODE);
      return;
    }
    Intent intent = new Intent(this, CrumblesQrScannerActivity.class);
    qrScanLauncher.launch(intent);
  }

  @Override
  public void onRequestPermissionsResult(
      int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    if (requestCode == CrumblesConstants.CAMERA_PERMISSION_REQUEST_CODE) {
      if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
        startQrScan();
      } else {
        Toast.makeText(this, "Camera permission denied.", Toast.LENGTH_SHORT).show();
      }
    }
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      setResult(Activity.RESULT_CANCELED);
      finish();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }

  // Simple data class to hold key info for the adapter.
  static class KeyInfo {
    private final String alias; // or hash
    private final String type;
    private final boolean isInternal;

    KeyInfo(String alias, String type, boolean isInternal) {
      this.alias = alias;
      this.type = type;
      this.isInternal = isInternal;
    }

    public String getAlias() {
      return alias;
    }

    public String getType() {
      return type;
    }

    public boolean isInternal() {
      return isInternal;
    }
  }

  // Custom adapter to display the key info.
  private static class KeyInfoAdapter extends ArrayAdapter<KeyInfo> {
    KeyInfoAdapter(Context context, List<KeyInfo> keys) {
      super(context, android.R.layout.simple_list_item_2, android.R.id.text1, keys);
    }

    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
      View view =
          LayoutInflater.from(getContext())
              .inflate(android.R.layout.simple_list_item_2, parent, false);
      TextView text1 = view.findViewById(android.R.id.text1);
      TextView text2 = view.findViewById(android.R.id.text2);

      KeyInfo keyInfo = getItem(position);
      if (keyInfo != null) {
        text1.setText(keyInfo.getAlias());
        text2.setText(keyInfo.getType());
      }
      return view;
    }
  }
}
