/*
 * Copyright 2026 Google LLC
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.UserHandle;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.work.Configuration;
import androidx.work.ListenableWorker.Result;
import androidx.work.testing.SynchronousExecutor;
import androidx.work.testing.TestListenableWorkerBuilder;
import androidx.work.testing.WorkManagerTestInitHelper;
import com.android.securelogging.fakes.FakeAndroidKeyStoreProvider;
import com.android.securelogging.fakes.FakeAndroidKeyStoreSpi;
import com.google.common.collect.ImmutableList;
import com.google.common.truth.Expect;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protos.wireless_android_security_exploits_secure_logging_src_main.LogBatch;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Tests for {@link CrumblesHeartbeatWorker}. */
@RunWith(AndroidJUnit4.class)
public final class CrumblesHeartbeatWorkerTest {

  @Rule public final Expect expect = Expect.create();

  private Context context;
  private DevicePolicyManager mockDpm;
  private Context contextWithDpm;

  @BeforeClass
  public static void installFakeKeystore() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
    Security.insertProviderAt(new FakeAndroidKeyStoreProvider(), 1);
  }

  @AfterClass
  public static void removeFakeKeystore() {
    Security.removeProvider(FakeAndroidKeyStoreProvider.PROVIDER_NAME);
  }

  @Before
  public void setUp() throws Exception {
    FakeAndroidKeyStoreSpi.keystoreEntries.clear();
    context = ApplicationProvider.getApplicationContext();
    WorkManagerTestInitHelper.initializeTestWorkManager(
        context, new Configuration.Builder().setExecutor(new SynchronousExecutor()).build());
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit();
    CrumblesExternalPublicKeyManager.getInstance(context)
        .saveActiveExternalPublicKey(
            KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    mockDpm = mock(DevicePolicyManager.class);
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(true);
    when(mockDpm.isSecurityLoggingEnabled(any())).thenReturn(true);
    contextWithDpm =
        new ContextWrapper(context) {
          @Override
          public Object getSystemService(String name) {
            return name.equals(Context.DEVICE_POLICY_SERVICE)
                ? mockDpm
                : super.getSystemService(name);
          }
        };
  }

  @After
  public void tearDown() throws Exception {
    CrumblesExternalPublicKeyManager.getInstance(context).clearActiveExternalPublicKey();
  }

  @Test
  public void doWork_whenNoBatchWasEverSigned_writesSignedBatch() throws Exception {
    CrumblesBatchSigner signer = new CrumblesBatchSigner(context);
    assertThat(signer.lastSignedAt()).isEmpty();

    Result result = runWorker();

    ImmutableList<LogBatch> batches = writtenBatches();
    assertThat(batches).hasSize(1);
    expect.that(result).isEqualTo(Result.success());
    expect.that(batches.get(0).hasSignature()).isTrue();
    expect.that(batches.get(0).getSequenceNumber()).isEqualTo(1);
    // The batch is padded to the minimum 4096-byte bucket plus the 16-byte AES-GCM authentication
    // tag.
    expect.that(batches.get(0).getMetadata().getBlobSize()).isEqualTo(4096 + 16);
    expect.that(signer.lastSignedAt()).isPresent();
  }

  @Test
  public void doWork_afterBatchWasJustSigned_writesNothing() throws Exception {
    var unused = new CrumblesBatchSigner(context).sign(LogBatch.getDefaultInstance());

    runWorker();

    assertThat(writtenBatches()).isEmpty();
  }

  @Test
  public void doWork_whenLastBatchIsOlderThanInterval_writesNextNumberedBatch() throws Exception {
    context
        .getSharedPreferences(CrumblesConstants.PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putLong(CrumblesBatchSigner.PREF_LAST_SEQUENCE_NUMBER, 7)
        .putLong(
            CrumblesBatchSigner.PREF_LAST_SIGNED_AT_MILLIS,
            Instant.now().minus(Duration.ofHours(25)).toEpochMilli())
        .commit();

    runWorker();

    ImmutableList<LogBatch> batches = writtenBatches();
    assertThat(batches).hasSize(1);
    assertThat(batches.get(0).getSequenceNumber()).isEqualTo(8);
  }

  @Test
  public void doWork_whenNeitherDeviceOwnerNorDelegate_writesNothing() throws Exception {
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);
    when(mockDpm.isNetworkLoggingEnabled(any())).thenReturn(true);

    runWorker();

    assertThat(writtenBatches()).isEmpty();
  }

  @Test
  public void doWork_whenOnlyNetworkLoggingIsDelegatedAndOn_writesSignedBatch() throws Exception {
    delegateOnlyNetworkLogging();
    when(mockDpm.isNetworkLoggingEnabled(isNull())).thenReturn(true);

    Result result = runWorker();

    ImmutableList<LogBatch> batches = writtenBatches();
    assertThat(batches).hasSize(1);
    expect.that(result).isEqualTo(Result.success());
    expect.that(batches.get(0).hasSignature()).isTrue();
  }

  @Test
  public void doWork_whenDelegatedNetworkLoggingIsOff_writesNothing() throws Exception {
    delegateOnlyNetworkLogging();
    when(mockDpm.isNetworkLoggingEnabled(isNull())).thenReturn(false);

    runWorker();

    assertThat(writtenBatches()).isEmpty();
  }

  @Test
  public void doWork_whenDevicePolicyManagerIsNull_writesNothing() throws Exception {
    mockDpm = null;

    runWorker();

    assertThat(writtenBatches()).isEmpty();
  }

  @Test
  public void doWork_whenSecurityAndNetworkLoggingAreOff_writesNothing() throws Exception {
    when(mockDpm.isSecurityLoggingEnabled(any())).thenReturn(false);
    when(mockDpm.isNetworkLoggingEnabled(any())).thenReturn(false);

    runWorker();

    assertThat(writtenBatches()).isEmpty();
  }

  @Test
  public void doWork_withoutEncryptionKey_writesNothing() throws Exception {
    CrumblesExternalPublicKeyManager.getInstance(context).clearActiveExternalPublicKey();

    Result result = runWorker();

    expect.that(result).isEqualTo(Result.success());
    expect.that(writtenBatches()).isEmpty();
  }

  @Test
  public void doWork_skipsWhenSecondaryUserPresentOrDelegatedCheckThrows() throws Exception {
    when(mockDpm.getSecondaryUsers(any(ComponentName.class)))
        .thenReturn(ImmutableList.of(UserHandle.getUserHandleForUid(1000000)));
    runWorker();
    expect.that(writtenBatches()).hasSize(1);
    ageLastSignedAt();
    runWorker();
    expect.that(writtenBatches()).hasSize(1);

    when(mockDpm.getSecondaryUsers(any(ComponentName.class)))
        .thenThrow(new SecurityException("Lost DO"));
    runWorker();
    expect.that(writtenBatches()).hasSize(2);

    ageLastSignedAt();
    String pkg = context.getPackageName();
    ImmutableList<String> sec = ImmutableList.of(DevicePolicyManager.DELEGATION_SECURITY_LOGGING);
    when(mockDpm.isDeviceOwnerApp(pkg)).thenReturn(false);
    when(mockDpm.getDelegatedScopes(null, pkg)).thenReturn(sec, sec, ImmutableList.of());
    when(mockDpm.isSecurityLoggingEnabled(isNull())).thenReturn(true);
    when(mockDpm.retrievePreRebootSecurityLogs(isNull()))
        .thenThrow(new SecurityException("Blocked"));
    runWorker();
    expect.that(writtenBatches()).hasSize(2);
    when(mockDpm.getDelegatedScopes(null, pkg)).thenReturn(sec);
    runWorker();
    expect.that(writtenBatches()).hasSize(3);
    ageLastSignedAt();
    runWorker();
    expect.that(writtenBatches()).hasSize(3);
    doReturn(null).when(mockDpm).retrievePreRebootSecurityLogs(isNull());
    runWorker();
    expect.that(writtenBatches()).hasSize(4);

    ageLastSignedAt();
    delegateOnlyNetworkLogging();
    ImmutableList<String> net = ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING);
    when(mockDpm.isNetworkLoggingEnabled(isNull())).thenReturn(true);
    when(mockDpm.retrieveNetworkLogs(isNull(), eq(Long.MIN_VALUE)))
        .thenThrow(new SecurityException("Blocked"));
    when(mockDpm.getDelegatedScopes(null, pkg)).thenReturn(net, net, net, net, ImmutableList.of());
    runWorker();
    expect.that(writtenBatches()).hasSize(4);
    when(mockDpm.getDelegatedScopes(null, pkg)).thenReturn(net);
    runWorker();
    expect.that(writtenBatches()).hasSize(5);
    ageLastSignedAt();
    runWorker();
    expect.that(writtenBatches()).hasSize(5);
    doReturn(null).when(mockDpm).retrieveNetworkLogs(isNull(), eq(Long.MIN_VALUE));
    when(mockDpm.isNetworkLoggingEnabled(isNull())).thenThrow(new SecurityException("Revoked"));
    runWorker();
    expect.that(writtenBatches()).hasSize(5);
  }

  private void ageLastSignedAt() {
    CrumblesDeviceAdminReceiver.prefs(context)
        .edit()
        .putLong(CrumblesBatchSigner.PREF_LAST_SIGNED_AT_MILLIS, 0L)
        .commit();
  }

  @CanIgnoreReturnValue
  private Result runWorker() {
    return TestListenableWorkerBuilder.from(contextWithDpm, CrumblesHeartbeatWorker.class)
        .build()
        .doWork();
  }

  /**
   * Makes Crumbles the delegate of network logging only, which the platform does not tell whether
   * security logging is on.
   */
  private void delegateOnlyNetworkLogging() {
    when(mockDpm.isDeviceOwnerApp(context.getPackageName())).thenReturn(false);
    when(mockDpm.getDelegatedScopes(/* admin= */ null, context.getPackageName()))
        .thenReturn(ImmutableList.of(DevicePolicyManager.DELEGATION_NETWORK_LOGGING));
    when(mockDpm.isSecurityLoggingEnabled(any()))
        .thenThrow(new SecurityException("Not the security logging delegate"));
  }

  private ImmutableList<LogBatch> writtenBatches() throws IOException {
    File[] files =
        new File(context.getFilesDir(), CrumblesConstants.FILEPROVIDER_COMPATIBLE_LOGS_SUBDIRECTORY)
            .listFiles((directory, name) -> name.endsWith(".bin"));
    ImmutableList.Builder<LogBatch> batches = ImmutableList.builder();
    for (File file : files == null ? new File[0] : files) {
      batches.add(
          LogBatch.parseFrom(
              Files.readAllBytes(file.toPath()), ExtensionRegistryLite.getEmptyRegistry()));
    }
    return batches.build();
  }
}
