package com.android.securelogging.fakes;

import java.security.Provider;

/** A fake provider to register a fake KeyStore and KeyPairGenerator for testing purposes. */
public class FakeAndroidKeyStoreProvider extends Provider {
  public static final String PROVIDER_NAME =
      "AndroidKeyStore"; // Match what CrumblesLogsEncryptor expects.

  public FakeAndroidKeyStoreProvider() {
    super(PROVIDER_NAME, "1.0", "Fake AndroidKeyStore Provider for Testing");

    // Register the KeyStoreSpi.
    put("KeyStore." + PROVIDER_NAME, FakeAndroidKeyStoreSpi.class.getName());

    // CrumblesLogsEncryptor calls: KeyPairGenerator.getInstance("RSA", "AndroidKeyStore").
    // So, our provider (named "AndroidKeyStore") needs to offer an "RSA" KeyPairGenerator.
    put("KeyPairGenerator.RSA", FakeAndroidKeyPairGeneratorSpi.class.getName());
  }
}
