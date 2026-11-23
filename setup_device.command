#!/bin/bash

set -euo pipefail

# The SHA-256 fingerprint of the certificate that signs Crumbles releases, from
# --expected-cert-sha256 or CRUMBLES_EXPECTED_CERT_SHA256, or else asked for
# below. Get it from your organization or another source that you trust: the
# release notes are on the same site as the APK.
EXPECTED_CERT="${CRUMBLES_EXPECTED_CERT_SHA256:-}"
if [[ "${1:-}" == "--expected-cert-sha256" ]]; then
    EXPECTED_CERT="${2:-}"
fi

# Run from the folder that holds this script, so that ./adb and ./apksigner
# are that folder's, whichever folder the script was started from.
cd -- "$(dirname -- "$0")"

# Prefer the adb and apksigner of this folder, then the ones on PATH.
if [[ -x ./adb ]]; then
    ADB_BIN="./adb"
else
    ADB_BIN="$(command -v adb || true)"
fi
if [[ -x ./apksigner ]]; then
    APKSIGNER_BIN="./apksigner"
else
    APKSIGNER_BIN="$(command -v apksigner || true)"
fi

# Download into a new private folder, never over files of the user.
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
APK_FILE="$WORK_DIR/CrumblesApp.apk"
SHA_FILE="$WORK_DIR/CrumblesApp.apk.sha256"

# Clears the screen for a clean look
clear || true

echo ""
echo "=============================================================="
echo "    Crumbles App - FULLY AUTOMATED INSTALL AND SETUP (macOS)"
echo "=============================================================="
echo ""
echo "This script will:"
echo "  1. Download the latest Crumbles app (.apk) and check its signer."
echo "  2. Install it on your phone."
echo "  3. Set it as the device owner."
echo ""
echo "BEFORE YOU CONTINUE:"
echo "  - The Android device must be FACTORY RESET with NO accounts."
echo "  - 'USB Debugging' must be enabled in Developer Options."
echo "  - The device MUST be plugged into this computer."
echo "  - apksigner (Android SDK Build-Tools) must be on your PATH or in this folder."
echo ""
echo "=============================================================="
echo ""
read -p "Press [Enter] to continue..."
clear || true

echo ""
echo "--> Step 1 of 4: Looking for your device..."
if [[ -z "$ADB_BIN" ]]; then
    echo ""
    echo "ERROR: adb was not found. Put this script in the Android Platform-Tools"
    echo "folder, or add adb to your PATH."
    read -p "Press [Enter] to exit."
    exit 1
fi
"$ADB_BIN" wait-for-device
echo "Device found!"
echo ""

echo "--> Step 2 of 4: Downloading the Crumbles APK..."
APK_URL="https://github.com/google/crumbles/releases/download/v1.0/CrumblesApp.apk"
if ! curl --proto '=https' --tlsv1.2 -fsSL -o "$APK_FILE" "$APK_URL"; then
    echo ""
    echo "ERROR: Failed to download the APK. Please check your internet connection."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Download complete!"
echo ""

echo "Verifying APK integrity..."
if ! curl --proto '=https' --tlsv1.2 -fsSL -o "$SHA_FILE" "${APK_URL}.sha256" \
    || [ ! -s "$SHA_FILE" ]; then
    echo ""
    echo "ERROR: Failed to download the APK checksum. Please check your internet connection."
    read -p "Press [Enter] to exit."
    exit 1
fi

EXPECTED_HASH="$(awk '{ sub(/\r$/, ""); print tolower($1); exit }' "$SHA_FILE")"
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_HASH="$(sha256sum "$APK_FILE" | awk '{ print tolower($1) }')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_HASH="$(shasum -a 256 "$APK_FILE" | awk '{ print tolower($1) }')"
else
    echo ""
    echo "ERROR: Neither sha256sum nor shasum found on PATH to verify APK checksum."
    read -p "Press [Enter] to exit."
    exit 1
fi

# Require a well-formed expected hash and an exact match with the APK hash.
if [[ ! "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] \
    || [[ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]]; then
    echo ""
    echo "ERROR: APK checksum verification failed! Download may be corrupted or compromised."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Integrity verification successful!"
echo ""

echo "Verifying the APK signing certificate..."
if [[ -z "$APKSIGNER_BIN" ]]; then
    echo ""
    echo "ERROR: apksigner was not found. Install Android SDK Build-Tools and add"
    echo "apksigner to your PATH, or set up the device with a QR code (see HOW_TO.md)."
    read -p "Press [Enter] to exit."
    exit 1
fi
if [[ -z "$EXPECTED_CERT" ]]; then
    echo "Enter the SHA-256 fingerprint of the Crumbles signing certificate"
    echo "(AA:BB:CC:... or 64 hexadecimal digits), as your organization gave it:"
    read -r EXPECTED_CERT || EXPECTED_CERT=""
fi
EXPECTED_CERT="$(printf '%s' "$EXPECTED_CERT" | tr -d ':[:space:]' | tr '[:upper:]' '[:lower:]')"
# Every signer of the APK must be the expected certificate.
# Split on the digest label itself: signer labels such as "V3.0 Signer: (...)"
# contain ": " too.
ACTUAL_CERTS="$("$APKSIGNER_BIN" verify --print-certs "$APK_FILE" 2>/dev/null \
    | awk -F'certificate SHA-256 digest: ' 'NF == 2 { print tolower($2) }' | sort -u)" \
    || ACTUAL_CERTS=""
if [[ ! "$EXPECTED_CERT" =~ ^[0-9a-f]{64}$ ]] || [[ "$ACTUAL_CERTS" != "$EXPECTED_CERT" ]]; then
    echo ""
    echo "ERROR: The APK is not signed with the expected certificate, so it was not installed."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Signing certificate verified!"
echo ""

echo "--> Step 3 of 4: Installing the Crumbles APK..."
if ! "$ADB_BIN" install -r "$APK_FILE"; then
    echo ""
    echo "ERROR: Failed to install the APK. Please check the connection to your device."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Installation successful!"
echo ""

echo "--> Step 4 of 4: Attempting to set device owner..."
DPM_STATUS=0
DPM_OUTPUT="$("$ADB_BIN" shell dpm set-device-owner \
    com.android.securelogging/.CrumblesDeviceAdminReceiver 2>&1)" || DPM_STATUS=$?
echo "$DPM_OUTPUT"
if [[ "$DPM_STATUS" -ne 0 || "$DPM_OUTPUT" != *"Success"* ]]; then
    echo ""
    echo "ERROR: Failed to set Crumbles as the device owner. See the output above."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo ""

echo "=============================================================="
echo ""
echo "SETUP COMPLETE!"
echo ""
echo "Crumbles has been set as the device owner."
echo "You can unplug your device after answering the question below."
echo ""
echo "=============================================================="
echo ""

echo "SECURITY REMINDER: USB debugging should be turned off once setup is done."
# Pressing Enter disables USB debugging: only "n" or "no" leaves it on.
read -r -p "Disable USB debugging on the device now? [Y/n] " DISABLE_ADB || DISABLE_ADB=""
if [[ "$DISABLE_ADB" =~ ^[Nn]([Oo])?$ ]]; then
    echo "Please remember to turn off USB debugging in Developer Options."
elif "$ADB_BIN" shell settings put global adb_enabled 0; then
    echo "USB debugging has been disabled."
else
    echo "WARNING: Could not disable USB debugging. Please turn it off in Developer Options."
fi
echo ""

read -p "Press [Enter] to exit."
