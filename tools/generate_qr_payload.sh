#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Helper script to generate Android Enterprise QR Code provisioning JSON payload for Crumbles.
# Calculates the URL-safe base64 SHA-256 checksum required by Android DevicePolicyManager.

set -euo pipefail

APK_PATH="${1:-}"
DOWNLOAD_URL="${2:-https://github.com/google/crumbles/releases/latest/download/CrumblesApp.apk}"
ENABLE_LOGGING="${3:-true}"

if [ -z "$APK_PATH" ] || [ ! -f "$APK_PATH" ]; then
  echo "Usage: $0 <path_to_crumbles_apk> [download_url] [enable_logging (true|false)]"
  echo "Example: $0 ./CrumblesApp.apk https://example.com/CrumblesApp.apk true"
  exit 1
fi

# Calculate URL-safe Base64 SHA-256 checksum of the APK file
CHECKSUM=$(openssl dgst -sha256 -binary "$APK_PATH" | openssl base64 | tr '+/' '-_' | tr -d '=')

cat <<EOF
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.android.securelogging/.CrumblesDeviceAdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": "$DOWNLOAD_URL",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM": "$CHECKSUM",
  "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": true,
  "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
    "enable_logging": $ENABLE_LOGGING
  }
}
EOF
