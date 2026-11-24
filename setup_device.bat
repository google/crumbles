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
:: Likewise, run the adb.exe of the Platform-Tools folder that holds this script.
set "ADB_EXE=%~dp0adb.exe"
if not exist "%ADB_EXE%" (
    echo  ERROR: adb.exe was not found. Put this script in the Platform-Tools folder.
    pause
    exit /b 1
)

:: The SHA-256 fingerprint of the certificate that signs Crumbles releases, from
:: --expected-cert-sha256 or CRUMBLES_EXPECTED_CERT_SHA256, or else asked for below. Get it
:: from your organization or another source that you trust: the release notes are on the same
:: site as the APK.
set "EXPECTED_CERT=%CRUMBLES_EXPECTED_CERT_SHA256%"
if /i "%~1"=="--expected-cert-sha256" set "EXPECTED_CERT=%~2"

cls
echo.
echo  ==============================================================
echo      Crumbles App - FULLY AUTOMATED INSTALL AND SETUP
echo  ==============================================================
echo.
echo  This script will:
echo    1. Download the latest Crumbles app (.apk) and check its signer.
echo    2. Install it on your phone.
echo    3. Set it as the device owner.
echo.
echo  BEFORE YOU CONTINUE:
echo    - The Android device must be FACTORY RESET with NO accounts.
echo    - 'USB Debugging' must be enabled in Developer Options.
echo    - The device MUST be plugged into this computer.
echo    - apksigner (Android SDK Build-Tools) must be on your PATH.
echo.
echo  ==============================================================
echo.
pause
cls

echo.
echo  --> Step 1 of 4: Looking for your device...
echo.
"%ADB_EXE%" wait-for-device
echo  Device found!
echo.

echo  --> Step 2 of 4: Downloading the Crumbles APK...
set "APK_URL=https://github.com/google/crumbles/releases/download/v2.0/CrumblesApp.apk"
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

echo  Verifying the APK signing certificate...
:: PowerShell looks for apksigner on PATH only, not in the current folder.
"%POWERSHELL_EXE%" -NoProfile -Command "if (-not (Get-Command apksigner -CommandType Application -ErrorAction SilentlyContinue)) { exit 1 }"
if errorlevel 1 (
    echo.
    echo  ERROR: apksigner was not found. Install Android SDK Build-Tools and add
    echo  apksigner to your PATH, or set up the device with a QR code ^(see HOW_TO.md^).
    del CrumblesApp.apk CrumblesApp.apk.sha256
    pause
    exit /b 1
)
if not defined EXPECTED_CERT (
    echo  Enter the SHA-256 fingerprint of the Crumbles signing certificate
    echo  ^(AA:BB:CC:... or 64 hexadecimal digits^), as your organization gave it:
    set /p "EXPECTED_CERT="
)
:: Every signer of the APK must be the expected certificate.
"%POWERSHELL_EXE%" -NoProfile -Command "$expected = ([string]$env:EXPECTED_CERT -replace '[:\s]', '').ToLower(); $apksigner = (Get-Command apksigner -CommandType Application | Select-Object -First 1).Source; $output = & $apksigner verify --print-certs CrumblesApp.apk 2>$null; if ($LASTEXITCODE -ne 0) { exit 1 }; $actual = @($output | Select-String 'certificate SHA-256 digest: ([0-9a-fA-F]+)' | ForEach-Object { $_.Matches[0].Groups[1].Value.ToLower() } | Sort-Object -Unique); if (($expected -notmatch '^[0-9a-f]{64}$') -or ($actual.Count -ne 1) -or ($actual[0] -ne $expected)) { exit 1 }"
if errorlevel 1 (
    echo.
    echo  ERROR: The APK is not signed with the expected certificate, so it was not installed.
    del CrumblesApp.apk CrumblesApp.apk.sha256
    pause
    exit /b 1
)
echo  Signing certificate verified!
echo.

echo  --> Step 3 of 4: Installing the Crumbles APK...
"%ADB_EXE%" install -r CrumblesApp.apk
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
"%ADB_EXE%" shell dpm set-device-owner com.android.securelogging/.CrumblesDeviceAdminReceiver > dpm_output.txt 2>&1
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
    "%ADB_EXE%" shell settings put global adb_enabled 0
    if errorlevel 1 (
        echo  WARNING: Could not disable USB debugging. Please turn it off in Developer Options.
    ) else (
        echo  USB debugging has been disabled.
    )
)

echo.
pause
