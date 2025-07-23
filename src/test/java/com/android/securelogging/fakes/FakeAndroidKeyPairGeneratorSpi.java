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

package com.android.securelogging.fakes;

import static java.nio.charset.StandardCharsets.UTF_8;

import android.security.keystore.KeyGenParameterSpec;
import com.google.common.collect.ImmutableSet;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.spec.AlgorithmParameterSpec;
import java.time.InstantSource;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;
import javax.security.auth.x500.X500Principal;

/**
 * A fake implementation of {@link KeyPairGeneratorSpi} to simulate Android KeyStore's key pair
 * generation.
 */
public class FakeAndroidKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
  private KeyGenParameterSpec keyGenParameterSpec;
  private final KeyPairGenerator standardRsaGenerator;

  public FakeAndroidKeyPairGeneratorSpi() throws Exception {
    this.standardRsaGenerator = KeyPairGenerator.getInstance("RSA");
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof KeyGenParameterSpec keyGenParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported params: " + params.getClass().getName());
    }
    this.keyGenParameterSpec = keyGenParameterSpec;
    this.standardRsaGenerator.initialize(this.keyGenParameterSpec.getKeySize(), random);
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    this.standardRsaGenerator.initialize(keysize, random);
  }

  @Override
  public KeyPair generateKeyPair() {
    if (this.keyGenParameterSpec == null) {
      throw new IllegalStateException(
          "KeyPairGeneratorSpi not initialized with KeyGenParameterSpec");
    }

    KeyPair keyPair = this.standardRsaGenerator.generateKeyPair();
    String alias = this.keyGenParameterSpec.getKeystoreAlias();

    try {
      Certificate selfSignedCert = generateSelfSignedCertificate(keyPair, alias);

      // 1. Pass the spec to the FakeAndroidKeyStoreSpi so it knows what parameters to associate
      // with the key entry it's about to receive.
      FakeAndroidKeyStoreSpi.setLatestKeyGenParameterSpec(this.keyGenParameterSpec);

      // 2. Use the standard KeyStore API to set the entry. Our FakeAndroidKeyStoreSpi will
      // intercept this call and create the PrivateKeyEntry correctly using the spec from step 1.
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      keyStore.setKeyEntry(
          alias, keyPair.getPrivate(), /* password= */ null, new Certificate[] {selfSignedCert});

    } catch (Exception e) {
      throw new RuntimeException(
          "Failed to generate/store self-signed certificate for fake KeyPairGenerator", e);
    }
    return keyPair;
  }

  // Basic self-signed certificate generation (can be complex without BouncyCastle).
  // This is a very simplified version.
  @SuppressWarnings("JavaUtilDate") // Minimal implementation, not for production.
  private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String alias)
      throws Exception {
    PublicKey publicKey = keyPair.getPublic();

    // Owner and issuer are the same for self-signed certs.
    X500Principal owner = new X500Principal("CN=" + alias + ", OU=Test, O=Android, C=US");
    Date from = new Date();
    Calendar calendar = Calendar.getInstance();
    calendar.setTime(from);
    calendar.add(Calendar.YEAR, 1); // 1 year validity
    Date to = calendar.getTime();
    BigInteger serialNumber = BigInteger.valueOf(InstantSource.system().instant().toEpochMilli());

    // THIS IS NOT A CRYPTOGRAPHICALLY VALID CERTIFICATE, BUT A MOCK FOR TESTING getPublicKey().
    return new MinimalFakeX509Certificate(publicKey, owner, serialNumber, from, to);
  }

  /*
   * A very minimal fake certificate for testing purposes.
   * WARNING: This is NOT a real, secure, or fully compliant X509Certificate.
   * It's designed to be just enough for `getPublicKey()` and basic checks in tests.
   */
  @SuppressWarnings({"deprecation", "JavaUtilDate"}) // For X509Certificate methods.
  private static class MinimalFakeX509Certificate extends X509Certificate implements X509Extension {
    private final PublicKey publicKey;
    private final X500Principal subjectX500Principal;
    private final X500Principal issuerX500Principal;
    private final BigInteger serialNumber;
    private final Date notBefore;
    private final Date notAfter;
    private final byte[] encoded = "fakeEncodedData".getBytes(UTF_8); // Simple placeholder.

    MinimalFakeX509Certificate(
        PublicKey publicKey,
        X500Principal subjectAndIssuer,
        BigInteger serialNumber,
        Date notBefore,
        Date notAfter) {
      this.publicKey = publicKey;
      this.subjectX500Principal = subjectAndIssuer;
      this.issuerX500Principal = subjectAndIssuer; // Self-signed.
      this.serialNumber = serialNumber;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
    }

    @Override
    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException {
      Date now = new Date();
      if (now.before(notBefore)) {
        throw new CertificateNotYetValidException("Certificate not valid until " + notBefore);
      }
      if (now.after(notAfter)) {
        throw new CertificateExpiredException("Certificate expired on " + notAfter);
      }
    }

    @Override
    public void checkValidity(Date date)
        throws CertificateExpiredException, CertificateNotYetValidException {
      if (date == null) {
        throw new IllegalArgumentException("date is null");
      }
      if (date.before(notBefore)) {
        throw new CertificateNotYetValidException("Certificate not valid until " + notBefore);
      }
      if (date.after(notAfter)) {
        throw new CertificateExpiredException("Certificate expired on " + notAfter);
      }
    }

    @Override
    public int getVersion() {
      return 3; // X.509 v3.
    }

    @Override
    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    @Override
    public Principal getIssuerDN() {
      return issuerX500Principal;
    }

    @Override
    public Principal getSubjectDN() {
      return subjectX500Principal;
    }

    @Override
    public Date getNotBefore() {
      return (Date) notBefore.clone();
    }

    @Override
    public Date getNotAfter() {
      return (Date) notAfter.clone();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
      return "fakeTBSCertificate".getBytes(UTF_8); // Placeholder.
    }

    @Override
    public byte[] getSignature() {
      return "fakeSignature".getBytes(UTF_8); // Placeholder.
    }

    @Override
    public String getSigAlgName() {
      return "SHA256withRSA"; // Matches how it was "signed".
    }

    @Override
    public String getSigAlgOID() {
      return "1.2.840.113549.1.1.11"; // OID for SHA256withRSA.
    }

    @Override
    public byte[] getSigAlgParams() {
      return null; // Often null
    }

    @Override
    public boolean[] getIssuerUniqueID() {
      return null;
    }

    @Override
    public boolean[] getSubjectUniqueID() {
      return null;
    }

    @Override
    public boolean[] getKeyUsage() {
      // For a general RSA key used for encryption/wrapping by AndroidKeyStore:
      return new boolean[] {
        true, // digitalSignature.
        false, // nonRepudiation.
        true, // keyEncipherment.
        true, // dataEncipherment.
        false, // keyAgreement.
        false, // keyCertSign.
        false, // cRLSign.
        false, // encipherOnly.
        false // decipherOnly.
      };
    }

    @Override
    @Nullable
    public List<String> getExtendedKeyUsage() throws CertificateParsingException {
      return null;
    }

    @Override
    @Nullable
    public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
      return null;
    }

    @Override
    @Nullable
    public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
      return null;
    }

    @Override
    public X500Principal getIssuerX500Principal() {
      return issuerX500Principal;
    }

    @Override
    public X500Principal getSubjectX500Principal() {
      return subjectX500Principal;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
      // This should return the ASN.1 DER encoded form of the certificate.
      return encoded.clone(); // Return a copy for immutability.
    }

    @Override
    public void verify(PublicKey key)
        throws CertificateException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            NoSuchProviderException,
            SignatureException {
      // No-op for fake, or basic check if key matches this.publicKey.
      if (this.publicKey == null || !this.publicKey.equals(key)) {
        // This check is if 'key' is the CA's public key. For self-signed, it's our own public key.
        // For simplicity, let's assume it "verifies" if it's our own public key.
      }
    }

    @Override
    public void verify(PublicKey key, String sigProvider)
        throws CertificateException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            NoSuchProviderException,
            SignatureException {
      verify(key); // Delegate, ignore sigProvider for this fake.
    }

    @Override
    public void verify(PublicKey key, Provider sigProvider)
        throws CertificateException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {
      try {
        verify(key); // Delegate.
      } catch (NoSuchProviderException e) {
        throw new IllegalArgumentException("No such provider: " + sigProvider, e);
      }
    }

    @Override
    public String toString() {
      return "MinimalFakeX509Certificate (Subject: " + subjectX500Principal.getName() + ")";
    }

    @Override
    public int getBasicConstraints() {
      return 0;
    }

    @Override
    public PublicKey getPublicKey() {
      return publicKey;
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
      return false;
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
      return ImmutableSet.of();
    }



    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
      return ImmutableSet.of();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
      return null;
    }
  }
}
