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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import android.content.Context;
import android.net.Uri;
import android.security.NetworkSecurityPolicy;
import android.util.Base64;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.common.base.Ascii;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.net.InetAddresses;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * WebDAV (RFC 4918) remote storage uploader supporting TLS and HTTP Basic Authentication.
 *
 * <p>Credentials are held as byte arrays rather than strings so that {@link #close()} can overwrite
 * them; a {@code String} would stay readable in the heap until garbage collected. Use instances
 * inside a try-with-resources block.
 */
public final class WebDavStorageUploader implements RemoteStorageUploader {

  private static final String TAG = "WebDavStorageUploader";
  private static final int CONNECT_TIMEOUT_MS = 15000;
  private static final int READ_TIMEOUT_MS = 30000;

  /**
   * A common value, so that the server's access logs do not name the app. The platform default
   * would name the device and its build.
   */
  private static final String USER_AGENT = "Mozilla/5.0";

  private static final int HTTP_SUCCESS_MIN = 200;
  private static final int HTTP_SUCCESS_MAX = 299;

  /** Result status for WebDAV connection reachability and credential verification. */
  public enum ConnectionTestResult {
    SUCCESS,
    AUTH_FAILED,
    SERVER_NOT_FOUND,
    /** The server answered with a redirect, which uploads never follow. */
    REDIRECTED,
    INVALID_URL,
    NETWORK_ERROR
  }

  private final String serverUrl;
  private final byte[] username;
  private final byte[] password;
  @Nullable private final SSLSocketFactory tlsSocketFactory;
  private boolean serverKeyRejected;
  private boolean transportFailed;
  private boolean failedMidBody;

  /**
   * Creates an uploader for {@code serverUrl}.
   *
   * <p>The credential arrays are copied, so the caller stays free to wipe the arrays it passed in.
   */
  public WebDavStorageUploader(String serverUrl, byte[] username, byte[] password) {
    this(serverUrl, username, password, /* tlsSocketFactory= */ null);
  }

  /**
   * Creates an uploader for {@code serverUrl} whose TLS connections go through {@code
   * tlsSocketFactory} (refusing plaintext HTTP when set), or the platform default if {@code null}.
   */
  public WebDavStorageUploader(
      String serverUrl,
      byte[] username,
      byte[] password,
      @Nullable SSLSocketFactory tlsSocketFactory) {
    this.serverUrl = checkNotNull(serverUrl, "serverUrl cannot be null");
    this.username = checkNotNull(username, "username cannot be null").clone();
    this.password = checkNotNull(password, "password cannot be null").clone();
    this.tlsSocketFactory = tlsSocketFactory;
  }

  /**
   * Overwrites the stored credentials with zeroes.
   *
   * <p>Uploads attempted after this point authenticate with the wiped credentials and so are
   * rejected by the server.
   */
  @Override
  public void close() {
    Arrays.fill(username, (byte) 0);
    Arrays.fill(password, (byte) 0);
  }

  @Override
  public boolean uploadFile(Context context, File file, String remoteFileName) {
    transportFailed = false;
    failedMidBody = false;
    if (!isAcceptableServerUrl(serverUrl)) {
      // The URL stays out of the log, because it can name the account.
      Log.e(TAG, "WebDAV server URL rejected by the transport policy");
      return false;
    }
    String targetUrlString = buildTargetUrl(serverUrl, remoteFileName);
    HttpURLConnection conn = null;
    CrumblesTransferDeadline.Disarm deadline = CrumblesTransferDeadline.Disarm.NONE;
    boolean sendingBody = false;
    try {
      URL url = toAbsoluteUrl(targetUrlString);
      conn = openConnection(url);
      if (!routeThroughTlsSocketFactory(conn, tlsSocketFactory)) {
        Log.e(TAG, "Plaintext WebDAV URL rejected: this uploader connects only through TLS");
        return false;
      }
      CrumblesTransferDeadline.Transfer transfer =
          CrumblesTransferDeadline.arm(file.length(), conn::disconnect);
      deadline = transfer;
      conn.setInstanceFollowRedirects(false);
      conn.setRequestMethod("PUT");
      conn.setDoOutput(true);
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(READ_TIMEOUT_MS);
      sendBodyWithoutBufferingItInMemory(conn, file.length());
      conn.setRequestProperty("Content-Type", "application/octet-stream");
      conn.setRequestProperty("Authorization", buildBasicAuthHeader(username, password));
      conn.setRequestProperty("User-Agent", USER_AGENT);

      transfer.checkInTime();
      try (InputStream in = new FileInputStream(file);
          OutputStream out = conn.getOutputStream()) {
        sendingBody = true;
        @SuppressWarnings("unused")
        var unusedBytes = CrumblesTransferDeadline.copy(in, out, transfer);
        out.flush();
      }
      sendingBody = false;

      int responseCode = conn.getResponseCode();
      if (confirmsBatchIsStored(responseCode)) {
        return true;
      }
      Log.e(TAG, "WebDAV upload failed with HTTP status code: " + responseCode);
    } catch (URISyntaxException | IllegalArgumentException | MalformedURLException e) {
      // Leaves the exception out, because its message would echo the URL.
      Log.e(TAG, "Invalid WebDAV target URL");
    } catch (ProtocolException e) {
      Log.e(TAG, "Invalid HTTP protocol configuration for WebDAV", e);
    } catch (IOException | SecurityException e) {
      if (isServerKeyMismatch(e)) {
        serverKeyRejected = true;
        Log.e(TAG, "WebDAV server presented a public key other than the pinned one", e);
      } else {
        transportFailed = true;
        failedMidBody = sendingBody;
        Log.e(TAG, "I/O or network failure uploading " + remoteFileName + " to WebDAV", e);
      }
    } finally {
      deadline.close();
      if (conn != null) {
        conn.disconnect();
      }
    }
    return false;
  }

  /**
   * Opens a connection to {@code url}. A loopback server is reached directly: a proxy would take
   * the request, credentials included, off the device, in plaintext over HTTP.
   */
  private static HttpURLConnection openConnection(URL url) throws IOException {
    return (HttpURLConnection)
        (isLoopbackHost(url.getHost()) ? url.openConnection(Proxy.NO_PROXY) : url.openConnection());
  }

  /**
   * Has {@code conn} use {@code tlsSocketFactory}, if one was given.
   *
   * @return {@code false} if a factory was given but {@code conn} is plaintext HTTP, which the
   *     factory cannot secure
   */
  private static boolean routeThroughTlsSocketFactory(
      HttpURLConnection conn, @Nullable SSLSocketFactory tlsSocketFactory) {
    if (tlsSocketFactory == null) {
      return true;
    }
    if (conn instanceof HttpsURLConnection httpsConnection) {
      httpsConnection.setSSLSocketFactory(tlsSocketFactory);
      return true;
    }
    return false;
  }

  /** Returns whether {@code failure} arose because the server's key does not match the pin. */
  private static boolean isServerKeyMismatch(Throwable failure) {
    return Throwables.getCausalChain(failure).stream()
        .anyMatch(WebDavServerKeyPin.ServerKeyMismatchException.class::isInstance);
  }

  /**
   * Verifies server connectivity and authentication credentials via an HTTP test request.
   *
   * <p>A redirect is reported rather than followed. Uploads never follow one, so a probe that did
   * would vouch for a URL that every upload then fails against.
   */
  public static ConnectionTestResult testConnection(
      String serverUrl, byte[] username, byte[] password) {
    return testConnection(serverUrl, username, password, /* tlsSocketFactory= */ null);
  }

  public static ConnectionTestResult testConnection(
      String serverUrl,
      byte[] username,
      byte[] password,
      @Nullable SSLSocketFactory tlsSocketFactory) {
    if (!isAcceptableServerUrl(serverUrl)) {
      return ConnectionTestResult.INVALID_URL;
    }
    HttpURLConnection conn = null;
    CrumblesTransferDeadline.Disarm deadline = CrumblesTransferDeadline.Disarm.NONE;
    try {
      URL url = toAbsoluteUrl(serverUrl);
      conn = openConnection(url);
      if (!routeThroughTlsSocketFactory(conn, tlsSocketFactory)) {
        return ConnectionTestResult.INVALID_URL;
      }
      deadline = CrumblesTransferDeadline.arm(conn::disconnect);
      conn.setInstanceFollowRedirects(false);
      conn.setRequestMethod("OPTIONS");
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(READ_TIMEOUT_MS);
      conn.setRequestProperty("Authorization", buildBasicAuthHeader(username, password));
      conn.setRequestProperty("User-Agent", USER_AGENT);

      int responseCode = conn.getResponseCode();
      if (acceptsConnectionProbe(responseCode)) {
        return ConnectionTestResult.SUCCESS;
      }
      if (responseCode >= HttpURLConnection.HTTP_MULT_CHOICE
          && responseCode < HttpURLConnection.HTTP_BAD_REQUEST) {
        return ConnectionTestResult.REDIRECTED;
      }
      if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED
          || responseCode == HttpURLConnection.HTTP_FORBIDDEN) {
        return ConnectionTestResult.AUTH_FAILED;
      }
      if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
        return ConnectionTestResult.SERVER_NOT_FOUND;
      }
      return ConnectionTestResult.NETWORK_ERROR;
    } catch (URISyntaxException | IllegalArgumentException | MalformedURLException e) {
      return ConnectionTestResult.INVALID_URL;
    } catch (IOException | SecurityException e) {
      return ConnectionTestResult.NETWORK_ERROR;
    } finally {
      deadline.close();
      if (conn != null) {
        conn.disconnect();
      }
    }
  }

  /**
   * Connects to {@code serverUrl} without credentials and returns the pin of the public key in the
   * server's own certificate, for the user to confirm before uploads rely on it.
   *
   * <p>The certificate chain must be one that {@code trustManager} accepts, and the certificate
   * must be valid for the host. The connection carries no credentials and is closed after the TLS
   * handshake.
   *
   * @param serverUrl an HTTPS URL that {@link #isAcceptableServerUrl} accepts
   * @param trustManager decides which certificate chains to accept: {@link
   *     WebDavServerKeyPin#platformTrustManager()} outside tests
   * @throws IllegalArgumentException if {@code serverUrl} is not such an HTTPS URL
   * @throws IOException if the server cannot be reached or does not prove its identity
   * @throws GeneralSecurityException if TLS cannot be set up
   */
  static WebDavServerKeyPin fetchServerKeyPin(
      String serverUrl, X509ExtendedTrustManager trustManager)
      throws IOException, GeneralSecurityException {
    HttpsURLConnection httpsConnection = openHttpsConnection(serverUrl, trustManager);
    try (CrumblesTransferDeadline.Disarm deadline =
        CrumblesTransferDeadline.arm(httpsConnection::disconnect)) {
      httpsConnection.connect();
      return WebDavServerKeyPin.of(httpsConnection.getServerCertificates()[0].getPublicKey());
    } finally {
      httpsConnection.disconnect();
    }
  }

  static HttpsURLConnection openHttpsConnection(
      String serverUrl, X509ExtendedTrustManager trustManager)
      throws IOException, GeneralSecurityException {
    checkArgument(isAcceptableServerUrl(serverUrl), "WebDAV server URL rejected");
    URLConnection connection;
    try {
      connection = openConnection(toAbsoluteUrl(serverUrl));
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("WebDAV server URL rejected", e);
    }
    checkArgument(
        connection instanceof HttpsURLConnection, "Only an HTTPS server has a key to pin");
    HttpsURLConnection httpsConnection = (HttpsURLConnection) connection;
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(/* km= */ null, new TrustManager[] {trustManager}, /* random= */ null);
    httpsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
    httpsConnection.setConnectTimeout(CONNECT_TIMEOUT_MS);
    httpsConnection.setReadTimeout(READ_TIMEOUT_MS);
    return httpsConnection;
  }

  /**
   * Returns {@code uriString} as an absolute URL.
   *
   * @throws IllegalArgumentException if {@code uriString} is a syntactically valid URI but is not
   *     absolute, for example {@code "webdav/log.bin"}
   */
  private static URL toAbsoluteUrl(String uriString)
      throws URISyntaxException, MalformedURLException {
    return new URI(uriString).toURL();
  }

  /**
   * Configures {@code conn} to write a body of {@code contentLengthBytes} straight to the socket.
   *
   * <p>Left unset, {@link HttpURLConnection} buffers the whole batch in memory before sending any
   * of it, which a phone cannot afford for a large batch. Both paths put the same {@code
   * Content-Length} on the wire, so the difference is in memory use rather than in anything a
   * caller or a server can observe.
   */
  private static void sendBodyWithoutBufferingItInMemory(
      HttpURLConnection conn, long contentLengthBytes) {
    conn.setFixedLengthStreamingMode(contentLengthBytes);
  }

  /**
   * Returns whether {@code responseCode} asserts that the uploaded batch is now stored.
   *
   * <p>Deliberately narrower than the range {@link #acceptsConnectionProbe} takes, because the
   * caller deletes its local copy of the batch once an upload reports success. {@code 202 Accepted}
   * says only that the server has queued the request, and {@code 207 Multi-Status} reports
   * per-resource outcomes that would have to be parsed out of the body, so neither is safe to treat
   * as a durable write.
   */
  private static boolean confirmsBatchIsStored(int responseCode) {
    return responseCode == HttpURLConnection.HTTP_OK
        || responseCode == HttpURLConnection.HTTP_CREATED
        || responseCode == HttpURLConnection.HTTP_NO_CONTENT;
  }

  /**
   * Returns whether {@code responseCode} answers a reachability probe successfully.
   *
   * <p>Any 2xx answer to OPTIONS means the server is reachable and accepted the credentials; which
   * 2xx it is does not matter, as nothing is being stored yet.
   */
  private static boolean acceptsConnectionProbe(int responseCode) {
    return responseCode >= HTTP_SUCCESS_MIN && responseCode <= HTTP_SUCCESS_MAX;
  }

  private static String buildTargetUrl(String base, String fileName) {
    String encodedFileName = Uri.encode(fileName);
    return base.endsWith("/") ? base + encodedFileName : base + "/" + encodedFileName;
  }

  /**
   * Returns the {@code Authorization} header value for {@code username} and {@code password}.
   *
   * <p>The credentials are concatenated in a byte array that is wiped before returning, so no
   * plaintext {@code user:password} string is ever created. The Base64 form is unavoidably a
   * string, because that is what {@link HttpURLConnection#setRequestProperty} accepts; keeping it
   * to a per-request local at least stops it from being retained.
   */
  private static String buildBasicAuthHeader(byte[] username, byte[] password) {
    byte[] credentials = new byte[username.length + 1 + password.length];
    try {
      System.arraycopy(username, 0, credentials, 0, username.length);
      credentials[username.length] = (byte) ':';
      System.arraycopy(password, 0, credentials, username.length + 1, password.length);
      return "Basic " + Base64.encodeToString(credentials, Base64.NO_WRAP);
    } finally {
      Arrays.fill(credentials, (byte) 0);
    }
  }

  /**
   * Returns whether {@code serverUrl} is acceptable as the base URL of a WebDAV server.
   *
   * <p>On top of passing {@link #isAllowedScheme}, the URL must name a host and carry no user-info,
   * query or fragment. Credentials travel only in the {@code Authorization} header, never in a URL
   * that could end up logged or displayed. A query or fragment would swallow the file name that
   * uploads append, sending every batch to the same resource.
   */
  static boolean isAcceptableServerUrl(String serverUrl) {
    URL url;
    try {
      url = toAbsoluteUrl(serverUrl);
    } catch (URISyntaxException | IllegalArgumentException | MalformedURLException e) {
      return false;
    }
    return !Strings.isNullOrEmpty(url.getHost())
        && isAllowedScheme(url)
        && url.getUserInfo() == null
        && url.getQuery() == null
        && url.getRef() == null;
  }

  /**
   * Returns the scheme, host and port of {@code serverUrl}, to which a server key is bound, in the
   * same form however the URL spells them: {@code https://DAV.example.org/dav} and {@code
   * https://dav.example.org:443/} both give {@code https://dav.example.org:443}.
   *
   * @throws IllegalArgumentException if {@code serverUrl} is not an absolute URL
   */
  static String serverOrigin(String serverUrl) {
    URL url;
    try {
      url = toAbsoluteUrl(serverUrl);
    } catch (URISyntaxException | MalformedURLException e) {
      throw new IllegalArgumentException("Invalid WebDAV server URL", e);
    }
    int port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
    return url.getProtocol() + "://" + Ascii.toLowerCase(url.getHost()) + ":" + port;
  }

  /**
   * Returns whether {@code url} may carry WebDAV traffic.
   *
   * <p>HTTPS is always permitted. Plaintext HTTP is permitted only towards a loopback address that
   * the network security config opens to cleartext, as only debug builds do: any app can listen on
   * a loopback port while the intended server is down, and take the credentials.
   */
  private static boolean isAllowedScheme(URL url) {
    if (Objects.equals(url.getProtocol(), "https")) {
      return true;
    }
    return Objects.equals(url.getProtocol(), "http")
        && isLoopbackHost(url.getHost())
        && NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(url.getHost());
  }

  /**
   * Returns whether {@code host} designates this device.
   *
   * <p>IP literals are parsed directly rather than resolved, so this never performs a DNS lookup or
   * any other network I/O. Any host that is not an IP literal is treated as remote.
   */
  private static boolean isLoopbackHost(String host) {
    if (Ascii.equalsIgnoreCase(host, "localhost")) {
      return true;
    }
    try {
      return InetAddresses.forUriString(host).isLoopbackAddress();
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  @Override
  public StorageType getStorageType() {
    return StorageType.STORAGE_TYPE_WEBDAV;
  }

  @Override
  public boolean rejectedServerKey() {
    return serverKeyRejected;
  }

  @Override
  public boolean transportFailed() {
    return transportFailed;
  }

  @Override
  public boolean failedMidBody() {
    return failedMidBody;
  }

  /**
   * Returns a description that leaves out the server URL.
   *
   * <p>The description reaches notifications, the audit trail and logcat, whereas the URL can name
   * the account, as in {@code https://cloud.example.com/remote.php/dav/files/alice/}.
   */
  @Override
  public String getDestinationDescription() {
    return "WebDAV server";
  }
}
