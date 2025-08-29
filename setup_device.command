#!/bin/bash

# Clears the screen for a clean look
clear

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
clear

echo ""
echo "--> Step 1 of 4: Looking for your device..."
./adb wait-for-device
echo "Device found!"
echo ""

echo "--> Step 2 of 4: Downloading the Crumbles APK..."
APK_URL="https://github.com/google/crumbles/releases/v1.0/CrumblesApp.apk"
curl -L -o CrumblesApp.apk "$APK_URL"
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Failed to download the APK. Please check your internet connection."
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Download complete!"
echo ""

echo "--> Step 3 of 4: Installing the Crumbles APK..."
./adb install -r CrumblesApp.apk
if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Failed to install the APK. Please check the connection to your device."
    rm CrumblesApp.apk
    read -p "Press [Enter] to exit."
    exit 1
fi
echo "Installation successful!"
echo ""

echo "--> Step 4 of 4: Attempting to set device owner..."
./adb shell dpm set-device-owner com.android.securelogging/.CrumblesDeviceAdminReceiver
echo ""

echo "=============================================================="
echo ""
echo "SETUP COMPLETE!"
echo ""
echo "If you see 'Success' messages above, it worked!"
echo "You can now unplug your device."
echo ""
echo "=============================================================="
echo ""

# Clean up the downloaded file
rm CrumblesApp.apk

read -p "Press [Enter] to exit."
