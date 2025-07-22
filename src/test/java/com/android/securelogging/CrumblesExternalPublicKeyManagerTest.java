package com.android.securelogging;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/** Unit tests for the {@link CrumblesExternalPublicKeyManager} class. */
@RunWith(AndroidJUnit4.class)
public class CrumblesExternalPublicKeyManagerTest {
  @Mock private CrumblesLogsEncryptor mockCryptoManager;
  private SharedPreferences sharedPreferences;
  private CrumblesExternalPublicKeyManager publicKeyManager;
  private PublicKey testPublicKey;
  private String testSerializedPayload;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.openMocks(this);
    Context context = ApplicationProvider.getApplicationContext();
    sharedPreferences = context.getSharedPreferences("test_prefs", Context.MODE_PRIVATE);
    sharedPreferences.edit().clear().apply();

    KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    testPublicKey = kp.getPublic();
    testSerializedPayload = "iv:key:ciphertext";

    when(mockCryptoManager.encryptDataStoreEntry(any(byte[].class)))
        .thenReturn(testSerializedPayload);
    when(mockCryptoManager.decryptData(any(String.class))).thenReturn(testPublicKey.getEncoded());

    publicKeyManager = new CrumblesExternalPublicKeyManager(sharedPreferences, mockCryptoManager);
  }

  @After
  public void tearDown() {
    sharedPreferences.edit().clear().apply();
  }

  @Test
  public void saveAndGetActiveExternalPublicKey_successfulRoundtrip() throws Exception {
    // When
    publicKeyManager.saveActiveExternalPublicKey(testPublicKey);
    PublicKey retrievedKey = publicKeyManager.getActiveExternalPublicKey();

    // Then
    assertThat(retrievedKey).isNotNull();
    assertThat(retrievedKey.getEncoded()).isEqualTo(testPublicKey.getEncoded());
    verify(mockCryptoManager).decryptData(testSerializedPayload);
  }

  @Test
  public void saveReEncryptPublicKey_andGet_successfulRoundtrip() throws Exception {
    // When
    publicKeyManager.saveReEncryptPublicKey(testPublicKey);
    List<PublicKey> retrievedKeys = publicKeyManager.getExternalReEncryptPublicKeys();

    // Then
    assertThat(retrievedKeys).hasSize(1);
    assertThat(retrievedKeys.get(0).getEncoded()).isEqualTo(testPublicKey.getEncoded());
  }
}
