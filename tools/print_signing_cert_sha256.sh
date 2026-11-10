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

# Verifies an APK with apksigner and prints the signing certificate SHA-256
# fingerprint as 32 colon-separated uppercase hexadecimal octets (matching the
# "App signing certificate (SHA-256):" footer on the Crumbles main screen).

set -euo pipefail

APK_PATH="${1:-}"

if [[ -z "${APK_PATH}" || ! -f "${APK_PATH}" ]]; then
  echo "Usage: $0 <path_to_crumbles_apk>" >&2
  exit 1
fi

if ! command -v apksigner >/dev/null 2>&1; then
  echo "ERROR: apksigner not found on PATH." >&2
  echo "Install Android SDK Build-Tools and add apksigner to PATH." >&2
  exit 1
fi

APKSIGNER_OUTPUT="$(apksigner verify --print-certs "${APK_PATH}")"

CERT_HEX="$(printf '%s\n' "${APKSIGNER_OUTPUT}" \
  | awk -F': ' '/Signer #1 certificate SHA-256 digest/ {print $2; exit}' \
  | tr -d ':[:space:]' \
  | tr '[:lower:]' '[:upper:]')"

if [[ ! "${CERT_HEX}" =~ ^[0-9A-F]{64}$ ]]; then
  echo "ERROR: Could not parse SHA-256 certificate digest from apksigner." >&2
  exit 1
fi

FINGERPRINT="$(printf '%s' "${CERT_HEX}" | sed 's/../&:/g; s/:$//')"
printf '%s\n' "${FINGERPRINT}"
