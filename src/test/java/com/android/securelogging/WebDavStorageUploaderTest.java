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

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import com.android.securelogging.WebDavStorageUploader.ConnectionTestResult;
import com.google.common.net.InetAddresses;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link WebDavStorageUploader}. */
@RunWith(RobolectricTestRunner.class)
public final class WebDavStorageUploaderTest {

  private static final String FILE_CONTENT = "sample encrypted payload";

  private static final Context context = ApplicationProvider.getApplicationContext();

  private HttpServer server;
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
    testUploader = new WebDavStorageUploader(serverBaseUrl, "u", "p");
  }

  @After
  public void tearDown() {
    if (server != null) {
      server.stop(0);
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
  public void uploadFile_whenServerReturns500InternalError_returnsFalse() {
    respondWithStatusCode("/webdav/err.bin", 500);

    assertThat(testUploader.uploadFile(context, testFile, "err.bin")).isFalse();
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

    try {
      WebDavStorageUploader uploader = new WebDavStorageUploader(url, "u", "p");

      assertThat(uploader.uploadFile(context, testFile, "remote_log.bin")).isFalse();
      assertThat(serverWasContacted.get()).isFalse();
    } finally {
      nonLoopbackServer.stop(0);
    }
  }

  @Test
  public void testConnection_whenServerReturns200Ok_returnsSuccess() {
    respondWithStatusCode("/webdav/s200", 200);

    assertThat(WebDavStorageUploader.testConnection(serverBaseUrl + "/s200", "u", "p"))
        .isEqualTo(ConnectionTestResult.SUCCESS);
  }

  @Test
  public void testConnection_whenServerReturns401Unauthorized_returnsAuthFailed() {
    respondWithStatusCode("/webdav/s401", 401);

    assertThat(WebDavStorageUploader.testConnection(serverBaseUrl + "/s401", "u", "p"))
        .isEqualTo(ConnectionTestResult.AUTH_FAILED);
  }

  @Test
  public void testConnection_whenServerReturns404NotFound_returnsServerNotFound() {
    respondWithStatusCode("/webdav/s404", 404);

    assertThat(WebDavStorageUploader.testConnection(serverBaseUrl + "/s404", "u", "p"))
        .isEqualTo(ConnectionTestResult.SERVER_NOT_FOUND);
  }

  @Test
  public void testConnection_whenUrlIsMalformed_returnsInvalidUrl() {
    assertThat(WebDavStorageUploader.testConnection("not-a-valid-url", "u", "p"))
        .isEqualTo(ConnectionTestResult.INVALID_URL);
  }

  @Test
  public void testConnection_whenPlaintextHttpToNonLoopbackHost_returnsInvalidUrl() {
    assertThat(WebDavStorageUploader.testConnection("http://example.com/webdav", "u", "p"))
        .isEqualTo(ConnectionTestResult.INVALID_URL);
  }

  @Test
  public void testConnection_whenSchemeIsHttps_isNotRejectedAsInvalidUrl() {
    // The loopback server speaks plaintext HTTP, so the TLS handshake fails and the result is a
    // network error. The point of the assertion is that https passes the scheme policy instead of
    // being rejected up front as an invalid URL.
    String httpsLoopbackUrl = "https://" + serverAuthority + "/webdav";

    assertThat(WebDavStorageUploader.testConnection(httpsLoopbackUrl, "u", "p"))
        .isEqualTo(ConnectionTestResult.NETWORK_ERROR);
  }

  @Test
  public void uploadFile_whenServerRedirectsThePut_doesNotResendTheBatchToTheNewLocation() {
    // Streaming the body straight to the socket also means the request cannot be replayed, so a
    // redirect is reported as a failure instead of the batch being sent a second time to wherever
    // the server points. Buffering the body in memory would let the redirect be followed silently.
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

    assertThat(WebDavStorageUploader.testConnection(serverBaseUrl + "/probe", "u", "p"))
        .isEqualTo(ConnectionTestResult.SUCCESS);
    // OPTIONS asks only whether the server is there and accepts the credentials, so a probe must
    // never fall back to a method that could read or alter a stored batch.
    assertThat(receivedMethod.get()).isEqualTo("OPTIONS");
    assertThat(receivedAuth.get())
        .isEqualTo("Basic " + Base64.getEncoder().encodeToString("u:p".getBytes(UTF_8)));
    assertThat(receivedUserAgent.get()).isEqualTo("Crumbles-Android");
  }

  @Test
  public void getStorageTypeAndDescription_returnExpectedValues() {
    assertThat(testUploader.getStorageType()).isEqualTo(StorageType.STORAGE_TYPE_WEBDAV);
    assertThat(testUploader.getDestinationDescription()).contains(serverBaseUrl);
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

  private void respondWithStatusCode(String path, int statusCode) {
    server.createContext(
        path,
        exchange -> {
          exchange.sendResponseHeaders(statusCode, -1);
          exchange.close();
        });
  }
}
