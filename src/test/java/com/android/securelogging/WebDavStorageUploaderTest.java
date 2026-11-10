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
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;

import android.content.Context;
import androidx.documentfile.provider.DocumentFile;
import androidx.test.core.app.ApplicationProvider;
import com.android.securelogging.WebDavStorageUploader.ConnectionTestResult;
import com.google.common.net.InetAddresses;
import com.google.common.time.Sleeper;
import com.google.common.truth.Expect;
import com.google.testing.junit.testparameterinjector.TestParameter;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestParameterInjector;
import org.robolectric.shadows.ShadowLog;
import org.robolectric.shadows.ShadowSystemClock;

/** Unit tests for {@link WebDavStorageUploader}. */
@RunWith(RobolectricTestParameterInjector.class)
public final class WebDavStorageUploaderTest {

  private static final String FILE_CONTENT = "sample encrypted payload";
  private static final String USERNAME = "u";
  private static final String PASSWORD = "p";

  private static final Context context = ApplicationProvider.getApplicationContext();

  private static final HeldCertificate testRootCertificate =
      new HeldCertificate.Builder().certificateAuthority(/* maxIntermediateCas= */ 0).build();
  private static final HeldCertificate serverCertificate =
      new HeldCertificate.Builder()
          .addSubjectAlternativeName(InetAddress.getLoopbackAddress().getHostAddress())
          .signedBy(testRootCertificate)
          .build();
  private static final X509ExtendedTrustManager testRootTrustManager =
      trustManagerTrusting(testRootCertificate);

  @Rule public final Expect expect = Expect.create();

  private final AtomicReference<String> httpsRequestBody = new AtomicReference<>();
  private HttpServer server;
  private HttpsServer httpsServer;
  private String serverAuthority;
  private String serverBaseUrl;
  private File testFile;
  private WebDavStorageUploader testUploader;

  @Before
  public void setUp() throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();
    server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
    server.start();
    // toUriString() brackets IPv6 literals, so this is correct on both IPv4 and IPv6 hosts.
    serverAuthority = InetAddresses.toUriString(loopback) + ":" + server.getAddress().getPort();
    serverBaseUrl = "http://" + serverAuthority + "/webdav";
    testFile = new File(context.getFilesDir(), "test_log.bin");
    Files.writeString(testFile.toPath(), FILE_CONTENT);
    testUploader =
        new WebDavStorageUploader(
            serverBaseUrl, USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8));
  }

  @After
  public void tearDown() {
    if (testUploader != null) {
      testUploader.close();
    }
    if (server != null) {
      server.stop(0);
    }
    if (httpsServer != null) {
      httpsServer.stop(0);
    }
    if (testFile != null && testFile.exists()) {
      testFile.delete();
    }
  }

  @Test
  public void uploadFile_whenServerReturns201Created_sendsAuthenticatedPutWithFileContent() {
    AtomicReference<String> receivedMethod = new AtomicReference<>();
    AtomicReference<String> receivedAuth = new AtomicReference<>();
    AtomicReference<String> receivedUserAgent = new AtomicReference<>();
    AtomicReference<String> receivedBody = new AtomicReference<>();

    server.createContext(
        "/webdav/remote_log.bin",
        exchange -> {
          receivedMethod.set(exchange.getRequestMethod());
          receivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
          receivedUserAgent.set(exchange.getRequestHeaders().getFirst("User-Agent"));
          try {
            receivedBody.set(new String(exchange.getRequestBody().readAllBytes(), UTF_8));
            exchange.sendResponseHeaders(201, -1);
          } finally {
            exchange.close();
          }
        });

    assertThat(testUploader.uploadFile(context, testFile, "remote_log.bin")).isTrue();
    assertThat(receivedMethod.get()).isEqualTo("PUT");
    assertThat(receivedAuth.get()).startsWith("Basic ");
    assertThat(receivedBody.get()).isEqualTo(FILE_CONTENT);
  }

  @Test
  public void uploadFile_whenRemoteFileNameHasSpaces_percentEncodesPathSegment() {
    AtomicReference<String> receivedRawPath = new AtomicReference<>();
    server.createContext(
        "/webdav",
        exchange -> {
          receivedRawPath.set(exchange.getRequestURI().getRawPath());
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });

    assertThat(testUploader.uploadFile(context, testFile, "my log.bin")).isTrue();
    assertThat(receivedRawPath.get()).isEqualTo("/webdav/my%20log.bin");
  }

  @Test
  public void uploadFile_whenServerReturns200Ok_returnsTrue() {
    respondWithStatusCode("/webdav/ok.bin", 200);

    assertThat(testUploader.uploadFile(context, testFile, "ok.bin")).isTrue();
  }

  @Test
  public void uploadFile_whenServerReturns204NoContent_returnsTrue() {
    respondWithStatusCode("/webdav/nocontent.bin", 204);

    assertThat(testUploader.uploadFile(context, testFile, "nocontent.bin")).isTrue();
  }

  @Test
  public void uploadFile_whenServerReturns401Unauthorized_returnsFalse() {
    respondWithStatusCode("/webdav/unauth.bin", 401);

    assertThat(testUploader.uploadFile(context, testFile, "unauth.bin")).isFalse();
  }

  @Test
  public void uploadFile_whenServerReturns500InternalError_returnsFalseWithoutTransportFailure() {
    respondWithStatusCode("/webdav/err.bin", 500);

    boolean uploaded = testUploader.uploadFile(context, testFile, "err.bin");

    expect.that(uploaded).isFalse();
    expect.that(testUploader.transportFailed()).isFalse();
  }

  @Test
  public void uploadFile_whenServerStallsTheResponse_givesUpAtTheDeadline() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    stallRequests("/webdav/stalled.bin", new CountDownLatch(1), release);
    ExecutorService uploadThread = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> upload =
          uploadThread.submit(() -> testUploader.uploadFile(context, testFile, "stalled.bin"));

      boolean uploaded = awaitPastDeadline(upload);

      expect.that(uploaded).isFalse();
      expect.that(testUploader.transportFailed()).isTrue();
    } finally {
      release.countDown();
      uploadThread.shutdown();
    }
  }

  @Test
  public void uploadFile_givesALargerBatchMoreTimeBeforeItsDeadline() throws Exception {
    // At the slowest rate that the deadline allows for, a mebibyte takes 16 s on top of the minute.
    Files.write(testFile.toPath(), new byte[1 << 20]);
    CountDownLatch requestReceived = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    stallRequests("/webdav/large.bin", requestReceived, release);
    ExecutorService uploadThread = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> upload =
          uploadThread.submit(() -> testUploader.uploadFile(context, testFile, "large.bin"));
      assertThat(requestReceived.await(10, SECONDS)).isTrue();

      ShadowSystemClock.advanceBy(Duration.ofSeconds(70));
      Sleeper.defaultSleeper().sleep(Duration.ofMillis(500));
      boolean endedBeforeItsDeadline = upload.isDone();
      boolean uploaded = awaitPastDeadline(upload);

      expect.that(endedBeforeItsDeadline).isFalse();
      expect.that(uploaded).isFalse();
    } finally {
      release.countDown();
      uploadThread.shutdown();
    }
  }

  @Test
  public void testConnection_whenServerStallsTheResponse_givesUpAtTheDeadline() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    stallRequests("/webdav/probe", new CountDownLatch(1), release);
    ExecutorService probeThread = Executors.newSingleThreadExecutor();
    try {
      Future<ConnectionTestResult> probe =
          probeThread.submit(
              () ->
                  WebDavStorageUploader.testConnection(
                      serverBaseUrl + "/probe",
                      USERNAME.getBytes(UTF_8),
                      PASSWORD.getBytes(UTF_8)));

      ConnectionTestResult result = awaitPastDeadline(probe);

      assertThat(result).isEqualTo(ConnectionTestResult.NETWORK_ERROR);
    } finally {
      release.countDown();
      probeThread.shutdown();
    }
  }

  @Test
  public void uploadFile_sendsOctetStreamContentType() {
    assertThat(captureUploadRequestHeaders("content_type.bin").getFirst("Content-Type"))
        .isEqualTo("application/octet-stream");
  }

  @Test
  public void uploadFile_sendsCrumblesUserAgent() {
    assertThat(captureUploadRequestHeaders("user_agent.bin").getFirst("User-Agent"))
        .isEqualTo("Crumbles-Android");
  }

  @Test
  public void uploadFile_sendsContentLengthMatchingFileSize() {
    assertThat(captureUploadRequestHeaders("length.bin").getFirst("Content-Length"))
        .isEqualTo(String.valueOf(testFile.length()));
  }

  @Test
  public void uploadFile_whenServerReturns202Accepted_returnsFalse() {
    // 202 means the server has queued the request, not that the batch is stored, so it must not
    // count as success even though it is a 2xx.
    respondWithStatusCode("/webdav/accepted.bin", 202);

    assertThat(testUploader.uploadFile(context, testFile, "accepted.bin")).isFalse();
  }

  @Test
  public void uploadFile_whenPlaintextHttpToNonLoopbackHost_rejectsWithoutSendingRequest()
      throws Exception {
    InetAddress nonLoopback = findNonLoopbackLocalAddress();
    HttpServer nonLoopbackServer = HttpServer.create(new InetSocketAddress(nonLoopback, 0), 0);
    AtomicBoolean serverWasContacted = new AtomicBoolean(false);
    nonLoopbackServer.createContext(
        "/webdav/remote_log.bin",
        exchange -> {
          serverWasContacted.set(true);
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });
    nonLoopbackServer.start();
    String url =
        "http://"
            + InetAddresses.toUriString(nonLoopback)
            + ":"
            + nonLoopbackServer.getAddress().getPort()
            + "/webdav";

    try (WebDavStorageUploader uploader =
        new WebDavStorageUploader(url, USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8))) {
      assertThat(uploader.uploadFile(context, testFile, "remote_log.bin")).isFalse();
      assertThat(serverWasContacted.get()).isFalse();
    } finally {
      nonLoopbackServer.stop(0);
    }
  }
  @Test
  public void constructor_whenCallerWipesItsOwnArrays_uploaderKeepsWorkingCredentials() {
    AtomicReference<String> receivedAuth = new AtomicReference<>();
    server.createContext(
        "/webdav/defensive.bin",
        exchange -> {
          receivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });
    byte[] callerUsername = USERNAME.getBytes(UTF_8);
    byte[] callerPassword = PASSWORD.getBytes(UTF_8);

    try (WebDavStorageUploader uploader =
        new WebDavStorageUploader(serverBaseUrl, callerUsername, callerPassword)) {
      Arrays.fill(callerUsername, (byte) 0);
      Arrays.fill(callerPassword, (byte) 0);

      assertThat(uploader.uploadFile(context, testFile, "defensive.bin")).isTrue();
      assertThat(receivedAuth.get()).isEqualTo(expectedAuthHeader());
    }
  }

  @Test
  public void close_wipesCredentials_soLaterUploadsNoLongerAuthenticate() {
    // Unlike the other fakes in this file, this one checks the credentials, so that a request sent
    // with wiped credentials is rejected the way a real WebDAV server would reject it.
    server.createContext(
        "/webdav/wiped.bin",
        exchange -> {
          boolean authenticated =
              expectedAuthHeader().equals(exchange.getRequestHeaders().getFirst("Authorization"));
          exchange.sendResponseHeaders(authenticated ? 201 : 401, -1);
          exchange.close();
        });
    assertThat(testUploader.uploadFile(context, testFile, "wiped.bin")).isTrue();

    testUploader.close();

    assertThat(testUploader.uploadFile(context, testFile, "wiped.bin")).isFalse();
  }

  @Test
  public void uploadFile_whenServerUrlIsRejected_returnsFalseWithoutContactingServer(
      @TestParameter RejectedServerUrl rejectedServerUrl) {
    AtomicBoolean serverWasContacted = recordWhetherServerIsContacted();
    String url = String.format(rejectedServerUrl.format, serverAuthority);
    try (WebDavStorageUploader uploader =
        new WebDavStorageUploader(url, USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8))) {
      expect.that(uploader.uploadFile(context, testFile, "remote_log.bin")).isFalse();
      expect.that(serverWasContacted.get()).isFalse();
    }
  }

  @Test
  public void uploadFile_whenServerUrlIsRejected_logsWithoutTheUrl() {
    try (WebDavStorageUploader uploader =
        new WebDavStorageUploader(
            "http://cloud.example.com/remote.php/dav/files/alice/",
            USERNAME.getBytes(UTF_8),
            PASSWORD.getBytes(UTF_8))) {
      assertThat(uploader.uploadFile(context, testFile, "remote_log.bin")).isFalse();
    }

    var logs = ShadowLog.getLogsForTag("WebDavStorageUploader");
    assertThat(logs).hasSize(1);
    expect.that(logs.get(0).msg).isEqualTo("WebDAV server URL rejected by the transport policy");
    expect.that(logs.get(0).throwable).isNull();
  }

  @Test
  public void testConnection_whenServerReturns200Ok_returnsSuccess() {
    respondWithStatusCode("/webdav/s200", 200);

    assertThat(
            WebDavStorageUploader.testConnection(
                serverBaseUrl + "/s200", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.SUCCESS);
  }

  @Test
  public void testConnection_whenServerReturns401Unauthorized_returnsAuthFailed() {
    respondWithStatusCode("/webdav/s401", 401);

    assertThat(
            WebDavStorageUploader.testConnection(
                serverBaseUrl + "/s401", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.AUTH_FAILED);
  }

  @Test
  public void testConnection_whenServerReturns404NotFound_returnsServerNotFound() {
    respondWithStatusCode("/webdav/s404", 404);

    assertThat(
            WebDavStorageUploader.testConnection(
                serverBaseUrl + "/s404", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.SERVER_NOT_FOUND);
  }

  @Test
  public void testConnection_whenUrlIsMalformed_returnsInvalidUrl() {
    assertThat(
            WebDavStorageUploader.testConnection(
                "not-a-valid-url", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.INVALID_URL);
  }

  @Test
  public void testConnection_whenPlaintextHttpToNonLoopbackHost_returnsInvalidUrl() {
    assertThat(
            WebDavStorageUploader.testConnection(
                "http://example.com/webdav", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.INVALID_URL);
  }

  @Test
  public void testConnection_whenServerUrlIsRejected_returnsInvalidUrlWithoutContactingServer(
      @TestParameter RejectedServerUrl rejectedServerUrl) {
    AtomicBoolean serverWasContacted = recordWhetherServerIsContacted();
    String url = String.format(rejectedServerUrl.format, serverAuthority);

    ConnectionTestResult result =
        WebDavStorageUploader.testConnection(url, USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8));

    expect.that(result).isEqualTo(ConnectionTestResult.INVALID_URL);
    expect.that(serverWasContacted.get()).isFalse();
  }

  @Test
  public void testConnection_whenHttpsUrlHasNoHost_returnsInvalidUrl() {
    assertThat(
            WebDavStorageUploader.testConnection(
                "https:///webdav", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.INVALID_URL);
  }

  @Test
  public void testConnection_whenSchemeIsHttps_isNotRejectedAsInvalidUrl() {
    // The loopback server speaks plaintext HTTP, so the TLS handshake fails and the result is a
    // network error. The point of the assertion is that https passes the scheme policy instead of
    // being rejected up front as an invalid URL.
    String httpsLoopbackUrl = "https://" + serverAuthority + "/webdav";

    assertThat(
            WebDavStorageUploader.testConnection(
                httpsLoopbackUrl, USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.NETWORK_ERROR);
  }

  @Test
  public void uploadFile_whenServerRedirectsThePut_doesNotResendTheBatchToTheNewLocation() {
    // Redirects are never followed, so the batch is not sent a second time to wherever the server
    // points.
    AtomicBoolean redirectTargetWasContacted = new AtomicBoolean(false);
    server.createContext(
        "/webdav/moved.bin",
        exchange -> {
          exchange.getResponseHeaders().set("Location", serverBaseUrl + "/elsewhere.bin");
          exchange.sendResponseHeaders(302, -1);
          exchange.close();
        });
    server.createContext(
        "/webdav/elsewhere.bin",
        exchange -> {
          redirectTargetWasContacted.set(true);
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });

    assertThat(testUploader.uploadFile(context, testFile, "moved.bin")).isFalse();
    assertThat(redirectTargetWasContacted.get()).isFalse();
  }

  @Test
  public void testConnection_whenServerRedirects_returnsRedirectedWithoutFollowing() {
    AtomicBoolean redirectTargetWasContacted = new AtomicBoolean(false);
    server.createContext(
        "/webdav/moved",
        exchange -> {
          exchange.getResponseHeaders().set("Location", serverBaseUrl + "/elsewhere");
          exchange.sendResponseHeaders(301, -1);
          exchange.close();
        });
    server.createContext(
        "/webdav/elsewhere",
        exchange -> {
          redirectTargetWasContacted.set(true);
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });

    ConnectionTestResult result =
        WebDavStorageUploader.testConnection(
            serverBaseUrl + "/moved", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8));

    expect.that(result).isEqualTo(ConnectionTestResult.REDIRECTED);
    expect.that(redirectTargetWasContacted.get()).isFalse();
  }

  @Test
  public void testConnection_probesWithAuthenticatedOptionsRequest() {
    AtomicReference<String> receivedMethod = new AtomicReference<>();
    AtomicReference<String> receivedAuth = new AtomicReference<>();
    AtomicReference<String> receivedUserAgent = new AtomicReference<>();
    server.createContext(
        "/webdav/probe",
        exchange -> {
          receivedMethod.set(exchange.getRequestMethod());
          receivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
          receivedUserAgent.set(exchange.getRequestHeaders().getFirst("User-Agent"));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });

    assertThat(
            WebDavStorageUploader.testConnection(
                serverBaseUrl + "/probe", USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8)))
        .isEqualTo(ConnectionTestResult.SUCCESS);
    // OPTIONS asks only whether the server is there and accepts the credentials, so a probe must
    // never fall back to a method that could read or alter a stored batch.
    assertThat(receivedMethod.get()).isEqualTo("OPTIONS");
    assertThat(receivedAuth.get()).isEqualTo(expectedAuthHeader());
    assertThat(receivedUserAgent.get()).isEqualTo("Crumbles-Android");
  }

  @Test
  public void getStorageTypeAndDescription_returnExpectedValues() {
    assertThat(testUploader.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
    assertThat(testUploader.getDestinationDescription()).isEqualTo("WebDAV server");
    assertThat(new GoogleDriveStorageUploader(DocumentFile.fromFile(testFile)).rejectedServerKey())
        .isFalse();
  }

  @Test
  public void uploadFile_whenServerPresentsPinnedKey_uploadsOverTls() throws Exception {
    String httpsServerUrl = startHttpsServer();

    try (WebDavStorageUploader uploader =
        newUploader(
            httpsServerUrl,
            pinnedSocketFactory(serverCertificate.keyPair().getPublic(), testRootTrustManager))) {
      expect.that(uploader.uploadFile(context, testFile, "pinned.bin")).isTrue();
    }
    expect.that(httpsRequestBody.get()).isEqualTo(FILE_CONTENT);
  }

  @Test
  public void uploadFile_whenServerPresentsAnotherKey_refusesBeforeSendingTheRequest()
      throws Exception {
    String httpsServerUrl = startHttpsServer();
    PublicKey otherKey = KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic();
    X509Certificate[] chain = {serverCertificate.certificate()};
    WebDavServerKeyPin.PinningTrustManager wrongPinTm =
        WebDavServerKeyPin.ofSha256(sha256(otherKey.getEncoded()))
            .new PinningTrustManager(testRootTrustManager);
    SSLEngine engine = handshakingEngine();
    assertThrows(CertificateException.class, () -> wrongPinTm.checkServerTrusted(chain, "RSA"));
    assertThrows(
        CertificateException.class, () -> wrongPinTm.checkServerTrusted(chain, "RSA", engine));

    try (WebDavStorageUploader uploader =
        newUploader(httpsServerUrl, pinnedSocketFactory(otherKey, testRootTrustManager))) {
      expect.that(uploader.uploadFile(context, testFile, "impostor.bin")).isFalse();
      expect.that(uploader.rejectedServerKey()).isTrue();
      expect.that(uploader.transportFailed()).isFalse();
    }
    expect.that(httpsRequestBody.get()).isNull();
  }

  @Test
  public void uploadFile_whenPinnedServerChainIsUntrusted_refusesWithoutReportingKeyMismatch()
      throws Exception {
    String httpsServerUrl = startHttpsServer();
    X509ExtendedTrustManager otherRootTrustManager =
        trustManagerTrusting(
            new HeldCertificate.Builder()
                .certificateAuthority(/* maxIntermediateCas= */ 0)
                .build());
    X509Certificate[] chain = {serverCertificate.certificate()};
    WebDavServerKeyPin.PinningTrustManager untrustedTm =
        WebDavServerKeyPin.ofSha256(sha256(serverCertificate.keyPair().getPublic().getEncoded()))
            .new PinningTrustManager(otherRootTrustManager);
    SSLEngine engine = handshakingEngine();
    assertThrows(CertificateException.class, () -> untrustedTm.checkServerTrusted(chain, "RSA"));
    assertThrows(
        CertificateException.class, () -> untrustedTm.checkServerTrusted(chain, "RSA", engine));

    try (WebDavStorageUploader uploader =
        newUploader(
            httpsServerUrl,
            pinnedSocketFactory(serverCertificate.keyPair().getPublic(), otherRootTrustManager))) {
      expect.that(uploader.uploadFile(context, testFile, "untrusted.bin")).isFalse();
      expect.that(uploader.rejectedServerKey()).isFalse();
    }
    expect.that(httpsRequestBody.get()).isNull();
  }

  @Test
  public void uploadFile_whenCallerWipesPinDigest_stillAcceptsPinnedKey() throws Exception {
    String httpsServerUrl = startHttpsServer();
    byte[] pinnedKeySha256 = sha256(serverCertificate.keyPair().getPublic().getEncoded());
    WebDavServerKeyPin pin = WebDavServerKeyPin.ofSha256(pinnedKeySha256);
    Arrays.fill(pinnedKeySha256, (byte) 0);
    X509Certificate[] chain = {serverCertificate.certificate()};
    pin.new PinningTrustManager(testRootTrustManager).checkServerTrusted(chain, "RSA");
    pin.new PinningTrustManager(testRootTrustManager)
        .checkServerTrusted(chain, "RSA", handshakingEngine());

    try (WebDavStorageUploader uploader =
        newUploader(httpsServerUrl, pin.newSocketFactory(testRootTrustManager))) {
      assertThat(uploader.uploadFile(context, testFile, "copied_pin.bin")).isTrue();
    }
  }

  @Test
  public void uploadFile_whenGivenTlsSocketFactoryForPlaintextUrl_refusesWithoutContactingServer()
      throws Exception {
    AtomicBoolean serverWasContacted = recordWhetherServerIsContacted();

    try (WebDavStorageUploader uploader =
        newUploader(
            serverBaseUrl,
            pinnedSocketFactory(serverCertificate.keyPair().getPublic(), testRootTrustManager))) {
      expect.that(uploader.uploadFile(context, testFile, "plaintext.bin")).isFalse();
      expect.that(serverWasContacted.get()).isFalse();
    }
  }

  @Test
  public void serverKeyPin_whenDigestIsNot32Bytes_throws() {
    assertThrows(IllegalArgumentException.class, () -> WebDavServerKeyPin.ofSha256(new byte[31]));
  }

  @Test
  public void fetchServerKeyPin_returnsPinOfServerKeyWithoutSendingARequest() throws Exception {
    String httpsServerUrl = startHttpsServer();

    HttpsURLConnection conn =
        WebDavStorageUploader.openHttpsConnection(httpsServerUrl, testRootTrustManager);
    expect.that(conn.getConnectTimeout()).isEqualTo(15_000);
    expect.that(conn.getReadTimeout()).isEqualTo(30_000);
    WebDavServerKeyPin pin =
        WebDavStorageUploader.fetchServerKeyPin(httpsServerUrl, testRootTrustManager);

    expect.that(pin).isEqualTo(WebDavServerKeyPin.of(serverCertificate.keyPair().getPublic()));
    expect.that(httpsRequestBody.get()).isNull();
  }

  @Test
  public void fetchServerKeyPin_whenServerStallsTheHandshake_givesUpAtTheDeadline()
      throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();
    ExecutorService fetchThread = Executors.newSingleThreadExecutor();
    // The socket accepts connections, but nothing ever answers the TLS handshake on them.
    try (ServerSocket silentServer = new ServerSocket(/* port= */ 0, /* backlog= */ 1, loopback)) {
      String url =
          "https://"
              + InetAddresses.toUriString(loopback)
              + ":"
              + silentServer.getLocalPort()
              + "/webdav";
      Future<WebDavServerKeyPin> fetch =
          fetchThread.submit(
              () -> WebDavStorageUploader.fetchServerKeyPin(url, testRootTrustManager));

      ExecutionException thrown =
          assertThrows(ExecutionException.class, () -> awaitPastDeadline(fetch));

      assertThat(thrown).hasCauseThat().isInstanceOf(IOException.class);
    } finally {
      fetchThread.shutdown();
    }
  }

  @Test
  public void fetchServerKeyPin_whenChainIsUntrusted_throws() throws Exception {
    String httpsServerUrl = startHttpsServer();
    X509ExtendedTrustManager otherRootTrustManager =
        trustManagerTrusting(
            new HeldCertificate.Builder()
                .certificateAuthority(/* maxIntermediateCas= */ 0)
                .build());

    assertThrows(
        SSLHandshakeException.class,
        () -> WebDavStorageUploader.fetchServerKeyPin(httpsServerUrl, otherRootTrustManager));
  }

  @Test
  public void fetchServerKeyPin_whenUrlIsPlaintext_throws() {
    assertThrows(
        IllegalArgumentException.class,
        () -> WebDavStorageUploader.fetchServerKeyPin(serverBaseUrl, testRootTrustManager));
  }

  @Test
  public void fetchServerKeyPin_whenUrlCarriesUserInfo_throwsWithoutContactingServer()
      throws Exception {
    String httpsServerUrl = startHttpsServer().replace("https://", "https://user:secret@");

    assertThrows(
        IllegalArgumentException.class,
        () -> WebDavStorageUploader.fetchServerKeyPin(httpsServerUrl, testRootTrustManager));
    expect.that(httpsRequestBody.get()).isNull();
  }

  /**
   * Uploads {@link #testFile} to {@code remoteFileName} and returns the headers the server saw.
   *
   * <p>The headers are copied out of the exchange, because the exchange releases them once it is
   * closed.
   */
  private Headers captureUploadRequestHeaders(String remoteFileName) {
    Headers received = new Headers();
    server.createContext(
        "/webdav/" + remoteFileName,
        exchange -> {
          received.putAll(exchange.getRequestHeaders());
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });

    assertThat(testUploader.uploadFile(context, testFile, remoteFileName)).isTrue();
    return received;
  }

  /**
   * Returns an address of this machine that is not a loopback address.
   *
   * <p>Pointing the uploader at an unreachable host would prove nothing: the upload would fail for
   * lack of a connection whether or not the scheme policy exists. Showing that it is the policy
   * doing the rejecting needs a target that is genuinely reachable yet not loopback, which is what
   * a real address of one of this machine's own interfaces gives. Traffic to it would stay on the
   * machine, so the test remains hermetic.
   */
  private static InetAddress findNonLoopbackLocalAddress() throws Exception {
    for (NetworkInterface networkInterface :
        Collections.list(NetworkInterface.getNetworkInterfaces())) {
      if (!networkInterface.isUp()) {
        continue;
      }
      for (InetAddress address : Collections.list(networkInterface.getInetAddresses())) {
        if (!address.isLoopbackAddress()) {
          return address;
        }
      }
    }
    throw new AssertionError(
        "This machine has no non-loopback address on any interface that is up, so the scheme"
            + " policy cannot be exercised against a reachable host.");
  }

  /** Returns the {@code Authorization} header value the uploader sends for valid credentials. */
  private static String expectedAuthHeader() {
    return "Basic "
        + Base64.getEncoder().encodeToString((USERNAME + ":" + PASSWORD).getBytes(UTF_8));
  }

  private void respondWithStatusCode(String path, int statusCode) {
    server.createContext(
        path,
        exchange -> {
          exchange.sendResponseHeaders(statusCode, -1);
          exchange.close();
        });
  }

  /**
   * Makes the server hold each request to {@code path} unanswered until {@code release} opens, or
   * for 10 s at most. {@code received} counts down as each request arrives.
   */
  private void stallRequests(String path, CountDownLatch received, CountDownLatch release) {
    server.createContext(
        path,
        exchange -> {
          received.countDown();
          try {
            release.await(10, SECONDS);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          exchange.close();
        });
  }

  /**
   * Moves the clock past the transfer deadline, repeatedly until {@code transfer} ends, as the
   * transfer sets its deadline only once it starts, and returns its result.
   */
  private static <T> T awaitPastDeadline(Future<T> transfer) throws Exception {
    for (int attempt = 0; attempt < 100 && !transfer.isDone(); attempt++) {
      ShadowSystemClock.advanceBy(Duration.ofHours(1));
      Sleeper.defaultSleeper().sleep(Duration.ofMillis(50));
    }
    return transfer.get(/* timeout= */ 1, SECONDS);
  }

  /** Makes the server record whether any request reaches it, whatever the path. */
  private AtomicBoolean recordWhetherServerIsContacted() {
    AtomicBoolean serverWasContacted = new AtomicBoolean(false);
    server.createContext(
        "/",
        exchange -> {
          serverWasContacted.set(true);
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });
    return serverWasContacted;
  }

  /**
   * Starts a loopback HTTPS server that presents {@link #serverCertificate} and returns its WebDAV
   * base URL.
   *
   * <p>The server stores the body of any request that reaches it in {@link #httpsRequestBody}. The
   * uploader sends a request only after the TLS handshake has accepted the server.
   */
  private String startHttpsServer() throws IOException {
    InetAddress loopback = InetAddress.getLoopbackAddress();
    httpsServer = HttpsServer.create(new InetSocketAddress(loopback, 0), 0);
    httpsServer.setHttpsConfigurator(
        new HttpsConfigurator(
            new HandshakeCertificates.Builder()
                .heldCertificate(serverCertificate)
                .build()
                .sslContext()));
    httpsServer.createContext(
        "/",
        exchange -> {
          httpsRequestBody.set(new String(exchange.getRequestBody().readAllBytes(), UTF_8));
          exchange.sendResponseHeaders(201, -1);
          exchange.close();
        });
    httpsServer.start();
    return "https://"
        + InetAddresses.toUriString(loopback)
        + ":"
        + httpsServer.getAddress().getPort()
        + "/webdav";
  }

  private static WebDavStorageUploader newUploader(
      String serverUrl, SSLSocketFactory tlsSocketFactory) {
    return new WebDavStorageUploader(
        serverUrl, USERNAME.getBytes(UTF_8), PASSWORD.getBytes(UTF_8), tlsSocketFactory);
  }

  /** Returns a socket factory that also requires {@code pinnedKey} from the server. */
  private static SSLSocketFactory pinnedSocketFactory(
      PublicKey pinnedKey, X509ExtendedTrustManager trustManager) throws GeneralSecurityException {
    return WebDavServerKeyPin.ofSha256(sha256(pinnedKey.getEncoded()))
        .newSocketFactory(trustManager);
  }

  private static byte[] sha256(byte[] data) throws GeneralSecurityException {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static SSLEngine handshakingEngine() throws Exception {
    SSLEngine engine = new HandshakeCertificates.Builder().build().sslContext().createSSLEngine();
    engine.setUseClientMode(true);
    engine.beginHandshake();
    return engine;
  }

  /** Returns a trust manager that accepts the certificates {@code rootCertificate} has signed. */
  private static X509ExtendedTrustManager trustManagerTrusting(HeldCertificate rootCertificate) {
    return (X509ExtendedTrustManager)
        new HandshakeCertificates.Builder()
            .addTrustedCertificate(rootCertificate.certificate())
            .build()
            .trustManager();
  }

  /** Server URLs that the transport policy rejects, as formats that take the server authority. */
  private enum RejectedServerUrl {
    HTTP_NO_HOST("http:/webdav"),
    HTTPS_NO_HOST("https:/webdav"),
    USER_INFO("http://user:secret@%s/webdav"),
    QUERY("http://%s/webdav?folder=logs"),
    FRAGMENT("http://%s/webdav#logs");

    private final String format;

    RejectedServerUrl(String format) {
      this.format = format;
    }
  }
}
