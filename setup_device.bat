@echo off
setlocal
title Crumbles Device Setup

:: Run the Windows tools by their full path: cmd.exe looks in the current folder first, so a bare
:: name would run a curl.exe, powershell.exe or findstr.exe planted next to this script instead.
set "CURL_EXE=%SystemRoot%\System32\curl.exe"
set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "FINDSTR_EXE=%SystemRoot%\System32\findstr.exe"
for %%T in ("%CURL_EXE%" "%POWERSHELL_EXE%" "%FINDSTR_EXE%") do (
    if not exist "%%~T" (
        echo  ERROR: %%~T was not found. This script needs Windows 10 version 1803 or later.
        pause
        exit /b 1
    )
)

cls
echo.
echo  ==============================================================
echo      Crumbles App - FULLY AUTOMATED INSTALL AND SETUP
echo  ==============================================================
echo.
echo  This script will:
echo    1. Download the latest Crumbles app (.apk).
echo    2. Install it on your phone.
echo    3. Set it as the device owner.
echo.
echo  BEFORE YOU CONTINUE:
echo    - The Android device must be FACTORY RESET with NO accounts.
echo    - 'USB Debugging' must be enabled in Developer Options.
echo    - The device MUST be plugged into this computer.
echo.
echo  ==============================================================
echo.
pause
cls

echo.
echo  --> Step 1 of 4: Looking for your device...
echo.
adb.exe wait-for-device
echo  Device found!
echo.

echo  --> Step 2 of 4: Downloading the Crumbles APK...
set "APK_URL=https://github.com/google/crumbles/releases/download/v1.0/CrumblesApp.apk"
"%CURL_EXE%" --proto "=https" --tlsv1.2 -fsSL -o CrumblesApp.apk "%APK_URL%"
if errorlevel 1 (
    echo.
    echo  ERROR: Failed to download the APK. Please check your internet connection.
    pause
    exit /b 1
)
echo  Download complete!
echo.

echo  Verifying APK integrity...
"%CURL_EXE%" --proto "=https" --tlsv1.2 -fsSL -o CrumblesApp.apk.sha256 "%APK_URL%.sha256"
if errorlevel 1 (
    echo.
    echo  ERROR: Failed to download the APK checksum. Please check your internet connection.
    del CrumblesApp.apk
    pause
    exit /b 1
)

:: Require a well-formed expected hash and an exact match with the APK hash.
"%POWERSHELL_EXE%" -NoProfile -Command "$expected = (Get-Content CrumblesApp.apk.sha256 | Select-Object -First 1).Split()[0].Trim().ToLower(); $actual = (Get-FileHash CrumblesApp.apk -Algorithm SHA256).Hash.ToLower(); if (($expected -notmatch '^[0-9a-f]{64}$') -or ($actual -ne $expected)) { Write-Error 'Checksum mismatch'; exit 1 }"
if errorlevel 1 (
    echo.
    echo  ERROR: APK checksum verification failed! Download may be corrupted or compromised.
    del CrumblesApp.apk CrumblesApp.apk.sha256
    pause
    exit /b 1
)
echo  Integrity verification successful!
echo.

echo  --> Step 3 of 4: Installing the Crumbles APK...
adb.exe install -r CrumblesApp.apk
if errorlevel 1 (
    echo.
    echo  ERROR: Failed to install the APK. Please check the connection to your device.
    del CrumblesApp.apk CrumblesApp.apk.sha256
    pause
    exit /b 1
)
echo  Installation successful!
echo.

echo  --> Step 4 of 4: Attempting to set device owner...
adb.exe shell dpm set-device-owner com.android.securelogging/.CrumblesDeviceAdminReceiver > dpm_output.txt 2>&1
type dpm_output.txt
"%FINDSTR_EXE%" /C:"Success" dpm_output.txt >nul
if errorlevel 1 (
    echo.
    echo  ERROR: Failed to set Crumbles as the device owner. See the output above.
    del CrumblesApp.apk CrumblesApp.apk.sha256 dpm_output.txt
    pause
    exit /b 1
)
echo.

echo  ==============================================================
echo.
echo  SETUP COMPLETE!
echo.
echo  Crumbles has been set as the device owner.
echo  You can unplug your device after answering the question below.
echo.
echo  ==============================================================
echo.

:: Clean up the downloaded files
del CrumblesApp.apk CrumblesApp.apk.sha256 dpm_output.txt

echo  SECURITY REMINDER: USB debugging should be turned off once setup is done.
:: Pressing Enter disables USB debugging: only "n" or "no" leaves it on.
set "DISABLE_ADB=y"
set /p "DISABLE_ADB=Disable USB debugging on the device now? [Y/n] "
set "KEEP_ADB="
if /i "%DISABLE_ADB%"=="n" set "KEEP_ADB=1"
if /i "%DISABLE_ADB%"=="no" set "KEEP_ADB=1"
if defined KEEP_ADB (
    echo  Please remember to turn off USB debugging in Developer Options.
) else (
    adb.exe shell settings put global adb_enabled 0
    if errorlevel 1 (
        echo  WARNING: Could not disable USB debugging. Please turn it off in Developer Options.
    ) else (
        echo  USB debugging has been disabled.
    )
)

echo.
pause
