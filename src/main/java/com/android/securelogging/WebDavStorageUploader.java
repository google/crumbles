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

import static com.google.common.base.Preconditions.checkNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;
import com.google.common.base.Ascii;
import com.google.common.io.ByteStreams;
import com.google.common.net.InetAddresses;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Objects;

/** WebDAV (RFC 4918) remote storage uploader supporting TLS and HTTP Basic Authentication. */
public final class WebDavStorageUploader implements RemoteStorageUploader {

  private static final String TAG = "WebDavStorageUploader";
  private static final int CONNECT_TIMEOUT_MS = 15000;
  private static final int READ_TIMEOUT_MS = 30000;
  private static final String USER_AGENT = "Crumbles-Android";

  private static final int HTTP_SUCCESS_MIN = 200;
  private static final int HTTP_SUCCESS_MAX = 299;

  /** Result status for WebDAV connection reachability and credential verification. */
  public enum ConnectionTestResult {
    SUCCESS,
    AUTH_FAILED,
    SERVER_NOT_FOUND,
    INVALID_URL,
    NETWORK_ERROR
  }

  private final String serverUrl;
  private final String username;
  private final String password;

  public WebDavStorageUploader(String serverUrl, String username, String password) {
    this.serverUrl = checkNotNull(serverUrl, "serverUrl cannot be null");
    this.username = checkNotNull(username, "username cannot be null");
    this.password = checkNotNull(password, "password cannot be null");
  }

  @Override
  public boolean uploadFile(Context context, File file, String remoteFileName) {
    String targetUrlString = buildTargetUrl(serverUrl, remoteFileName);
    HttpURLConnection conn = null;
    try {
      URL url = toAbsoluteUrl(targetUrlString);
      if (!isAllowedScheme(url)) {
        Log.e(TAG, "Insecure HTTP scheme rejected for WebDAV endpoint: " + targetUrlString);
        return false;
      }
      conn = (HttpURLConnection) url.openConnection();
      conn.setRequestMethod("PUT");
      conn.setDoOutput(true);
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(READ_TIMEOUT_MS);
      sendBodyWithoutBufferingItInMemory(conn, file.length());
      conn.setRequestProperty("Content-Type", "application/octet-stream");
      conn.setRequestProperty("Authorization", buildBasicAuthHeader(username, password));
      conn.setRequestProperty("User-Agent", USER_AGENT);

      try (InputStream in = new FileInputStream(file);
          OutputStream out = conn.getOutputStream()) {
        ByteStreams.copy(in, out);
        out.flush();
      }

      int responseCode = conn.getResponseCode();
      if (confirmsBatchIsStored(responseCode)) {
        return true;
      }
      Log.e(TAG, "WebDAV upload failed with HTTP status code: " + responseCode);
    } catch (URISyntaxException
        | IllegalArgumentException
        | MalformedURLException
        | ProtocolException e) {
      Log.e(TAG, "Invalid WebDAV URL or HTTP protocol configuration: " + targetUrlString, e);
    } catch (IOException | SecurityException e) {
      Log.e(TAG, "I/O or network failure uploading " + remoteFileName + " to WebDAV", e);
    } finally {
      if (conn != null) {
        conn.disconnect();
      }
    }
    return false;
  }

  /** Verifies server connectivity and authentication credentials via an HTTP test request. */
  public static ConnectionTestResult testConnection(
      String serverUrl, String username, String password) {
    HttpURLConnection conn = null;
    try {
      URL url = toAbsoluteUrl(serverUrl);
      if (!isAllowedScheme(url)) {
        return ConnectionTestResult.INVALID_URL;
      }
      conn = (HttpURLConnection) url.openConnection();
      conn.setRequestMethod("OPTIONS");
      conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
      conn.setReadTimeout(READ_TIMEOUT_MS);
      conn.setRequestProperty("Authorization", buildBasicAuthHeader(username, password));
      conn.setRequestProperty("User-Agent", USER_AGENT);

      int responseCode = conn.getResponseCode();
      if (acceptsConnectionProbe(responseCode)) {
        return ConnectionTestResult.SUCCESS;
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
      if (conn != null) {
        conn.disconnect();
      }
    }
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

  private static String buildBasicAuthHeader(String user, String pass) {
    String credentials = user + ":" + pass;
    String encoded = Base64.encodeToString(credentials.getBytes(UTF_8), Base64.NO_WRAP);
    return "Basic " + encoded;
  }

  /**
   * Returns whether {@code url} may carry WebDAV traffic.
   *
   * <p>HTTPS is always permitted. Plaintext HTTP is permitted only towards a loopback address,
   * because that traffic never leaves the device and so is not exposed to network interception.
   */
  private static boolean isAllowedScheme(URL url) {
    if (Objects.equals(url.getProtocol(), "https")) {
      return true;
    }
    return Objects.equals(url.getProtocol(), "http") && isLoopbackHost(url.getHost());
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
  public String getDestinationDescription() {
    return "WebDAV (" + serverUrl + ")";
  }
}
