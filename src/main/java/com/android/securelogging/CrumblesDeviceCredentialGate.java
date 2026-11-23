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

import android.app.KeyguardManager;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.biometric.BiometricManager.Authenticators;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

/** Prompts for strong authentication via {@link BiometricPrompt}, rejecting Class 2 unlock. */
public final class CrumblesDeviceCredentialGate {

  private CrumblesDeviceCredentialGate() {}

  /** Confirms the device screen lock via {@link BiometricPrompt}. */
  public static void confirmScreenLock(
      FragmentActivity activity,
      CharSequence title,
      @Nullable CharSequence subtitle,
      Runnable onConfirmed,
      Runnable onCancelled,
      Runnable onUnavailable) {
    confirm(
        activity,
        title,
        subtitle,
        Authenticators.DEVICE_CREDENTIAL,
        onConfirmed,
        onCancelled,
        onUnavailable);
  }

  /** Confirms Class 3 strong biometric or device screen lock while rejecting Class 2 biometrics. */
  public static void confirmStrongCredential(
      FragmentActivity activity,
      CharSequence title,
      @Nullable CharSequence subtitle,
      Runnable onConfirmed,
      Runnable onCancelled,
      Runnable onUnavailable) {
    confirm(
        activity,
        title,
        subtitle,
        Authenticators.BIOMETRIC_STRONG | Authenticators.DEVICE_CREDENTIAL,
        onConfirmed,
        onCancelled,
        onUnavailable);
  }

  private static void confirm(
      FragmentActivity activity,
      CharSequence title,
      @Nullable CharSequence subtitle,
      int authenticators,
      Runnable onConfirmed,
      Runnable onCancelled,
      Runnable onUnavailable) {
    KeyguardManager keyguardManager = activity.getSystemService(KeyguardManager.class);
    if (keyguardManager == null || !keyguardManager.isDeviceSecure()) {
      onUnavailable.run();
      return;
    }
    if (activity.getSupportFragmentManager().isStateSaved()) {
      postIfActive(activity, onCancelled);
      return;
    }
    PromptInfo promptInfo = buildPromptInfo(title, subtitle, authenticators);
    new BiometricPrompt(
            activity,
            new BiometricPrompt.AuthenticationCallback() {
              @Override
              public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                postIfActive(activity, onConfirmed);
              }

              @Override
              public void onAuthenticationError(int errorCode, CharSequence errString) {
                postIfActive(activity, onCancelled);
              }
            })
        .authenticate(promptInfo);
  }

  @VisibleForTesting
  static PromptInfo buildPromptInfo(
      CharSequence title, @Nullable CharSequence subtitle, int authenticators) {
    return new PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setAllowedAuthenticators(authenticators)
        .build();
  }

  private static void postIfActive(FragmentActivity activity, Runnable callback) {
    activity
        .getMainExecutor()
        .execute(
            () -> {
              if (!activity.isFinishing() && !activity.isDestroyed()) {
                callback.run();
              }
            });
  }
}
