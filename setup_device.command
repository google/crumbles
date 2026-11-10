#!/bin/bash

set -euo pipefail

# Clears the screen for a clean look
clear || true

echo ""
echo "=============================================================="
echo "    Crumbles App - FULLY AUTOMATED INSTALL AND SETUP (macOS)"
echo "=============================================================="
echo ""
echo "This script will:"
echo "  1. Download the latest Crumbles app (.apk)."
echo "  2. Install it on your phone."
echo "  3. Set it as the device owner."
echo ""
echo "BEFORE YOU CONTINUE:"
echo "  - The Android device must be FACTORY RESET with NO accounts."
echo "  - 'USB Debugging' must be enabled in Developer Options."
echo "  - The device MUST be plugged into this computer."
echo ""
echo "=============================================================="
echo ""
read -p "Press [Enter] to continue..."
clear || true

echo ""
echo "--> Step 1 of 4: Looking for your device..."
./adb wait-for-device
echo "Device found!"
echo ""

echo "--> Step 2 of 4: Downloading the Crumbles APK..."
APK_URL="https://github.com/google/crumbles/releases/download/v1.0/CrumblesApp.apk"
if ! curl --proto '=https' --tlsv1.2 -fsSL -o CrumblesApp.apk "$APK_URL"; then
    echo ""
    echo "ERROR: Failed to download the APK. Please check your internet connection."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Download complete!"
echo ""

echo "Verifying APK integrity..."
if ! curl --proto '=https' --tlsv1.2 -fsSL -o CrumblesApp.apk.sha256 "${APK_URL}.sha256" \
    || [ ! -s CrumblesApp.apk.sha256 ]; then
    echo ""
    echo "ERROR: Failed to download the APK checksum. Please check your internet connection."
    rm -f CrumblesApp.apk CrumblesApp.apk.sha256
    read -p "Press [Enter] to exit."
    exit 1
fi

EXPECTED_HASH="$(awk '{ sub(/\r$/, ""); print tolower($1); exit }' CrumblesApp.apk.sha256)"
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_HASH="$(sha256sum CrumblesApp.apk | awk '{ print tolower($1) }')"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_HASH="$(shasum -a 256 CrumblesApp.apk | awk '{ print tolower($1) }')"
else
    echo ""
    echo "ERROR: Neither sha256sum nor shasum found on PATH to verify APK checksum."
    rm -f CrumblesApp.apk CrumblesApp.apk.sha256
    read -p "Press [Enter] to exit."
    exit 1
fi

# Require a well-formed expected hash and an exact match with the APK hash.
if [[ ! "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] \
    || [[ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]]; then
    echo ""
    echo "ERROR: APK checksum verification failed! Download may be corrupted or compromised."
    rm -f CrumblesApp.apk CrumblesApp.apk.sha256
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Integrity verification successful!"
echo ""

echo "--> Step 3 of 4: Installing the Crumbles APK..."
if ! ./adb install -r CrumblesApp.apk; then
    echo ""
    echo "ERROR: Failed to install the APK. Please check the connection to your device."
    rm -f CrumblesApp.apk CrumblesApp.apk.sha256
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Installation successful!"
echo ""

echo "--> Step 4 of 4: Attempting to set device owner..."
DPM_STATUS=0
DPM_OUTPUT="$(./adb shell dpm set-device-owner \
    com.android.securelogging/.CrumblesDeviceAdminReceiver 2>&1)" || DPM_STATUS=$?
echo "$DPM_OUTPUT"
if [[ "$DPM_STATUS" -ne 0 || "$DPM_OUTPUT" != *"Success"* ]]; then
    echo ""
    echo "ERROR: Failed to set Crumbles as the device owner. See the output above."
    rm -f CrumblesApp.apk CrumblesApp.apk.sha256
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

# Clean up the downloaded files
rm -f CrumblesApp.apk CrumblesApp.apk.sha256

echo "SECURITY REMINDER: USB debugging should be turned off once setup is done."
# Pressing Enter disables USB debugging: only "n" or "no" leaves it on.
read -r -p "Disable USB debugging on the device now? [Y/n] " DISABLE_ADB || DISABLE_ADB=""
if [[ "$DISABLE_ADB" =~ ^[Nn]([Oo])?$ ]]; then
    echo "Please remember to turn off USB debugging in Developer Options."
elif ./adb shell settings put global adb_enabled 0; then
    echo "USB debugging has been disabled."
else
    echo "WARNING: Could not disable USB debugging. Please turn it off in Developer Options."
fi
echo ""

read -p "Press [Enter] to exit."
