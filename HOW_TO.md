# Crumbles User & Administrator Guide

## What is Crumbles?
Crumbles is a privacy-first Android security application designed for high-risk individuals, journalists, human rights defenders, and security teams. It continuously records Android **Security Logs** (system events, authentication attempts) and **Network Logs** (connection activity) to help detect mobile exploits and suspicious behavior.

To protect your privacy, Crumbles automatically encrypts all logs on your phone before they are stored or transmitted. You can securely upload these encrypted log files to your preferred storage provider (e.g., Google Drive, Email) or share them with trusted forensic analysts.

---

## Installation & Setup Options

Setting up Crumbles requires granting it **Device Owner** permissions so it can access Android system audit logs. There are two ways to set up Crumbles on your phone:

### Option 1: Zero-Touch / QR Code Provisioning (Recommended)
This automated method sets up Crumbles during initial phone setup without requiring a computer.

**Steps:**
1. **Back up your phone**: [Back up your data](https://support.google.com/android/answer/2819582).
2. **Factory reset your phone**: [Factory reset your phone](https://support.google.com/android/answer/6088915).
3. **Trigger built-in QR scanner**: On the initial "Welcome" setup screen (before connecting to Wi-Fi), tap any blank area on the screen **6 times continuously**.
4. **Scan the Provisioning QR Code**: The built-in Android QR code reader will launch. Point your phone camera directly at the official release provisioning QR code below (or scan the custom QR code provided by your organization).

![Official Release Provisioning QR Code](documentation_images/provisioning_qr.png)

5. **Connect to Wi-Fi**: Follow the prompts to connect to Wi-Fi. Android Enterprise will automatically verify the APK checksum, install Crumbles, set permissions, and enable background logging automatically!

*(Note: Custom server deployments and helpdesks can generate custom QR code payloads using `./tools/generate_qr_payload.sh <path_to_apk>`.)*

---

### Option 2: Manual Computer / ADB Setup
If you prefer installing Crumbles manually using a desktop or laptop computer:

1. **Back up your data** and **Factory reset your phone** without adding a Google Account yet.
2. **Enable USB Debugging** on your phone ([Setup Guide](https://developer.android.com/studio/debug/dev-options)).
3. Plug your phone into your computer via USB cable and tap **Allow USB Debugging** on your phone screen.
4. Download the [Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools) and the latest [Crumbles APK](https://github.com/google/crumbles/releases).
5. Run the setup script for your computer's OS:
   * **Windows**: Double-click `setup_device.bat`
   * **Mac**: Double-click `setup_device.command`
   * **Linux**: Run `./setup_device.sh`
   * *(Terminal alternative: `adb install -r CrumblesApp.apk` followed by `adb shell dpm set-device-owner com.android.securelogging/.CrumblesDeviceAdminReceiver`)*

---

## Managing Encryption Keys in Crumbles

Once installed, open the Crumbles app, enable the logging toggle, and select your preferred encryption key management strategy:

* **Option A: Built-in Hardware Keystore (Recommended)**
  * Crumbles stores your encryption keys securely inside your phone's hardware security module (TEE/StrongBox).
  * **In-App Decryption**: You can view and decrypt your logs directly inside the app.
  * **Re-Encrypt & Share**: You can re-encrypt selected logs using a trusted 3rd-party's public key QR code to safely share them via Email or Drive.
* **Option B: Generate Private Key & Keep Externally**
  * Crumbles generates an encryption key pair, but displays the private key for you to save in an offline, secure location (e.g., password manager). Crumbles does not store the private key on the phone.
* **Option C: Import External Public Key (For Organizations & NGOs)**
  * Scan a public key QR code provided by a trusted organization or NGO. All logs will be encrypted using their public key so only their analysts can decrypt the logs.

---

## Daily Log Sharing & Upload

Once configured, Crumbles operates automatically in the background:
1. At periodic background intervals (default: 8 hours), Crumbles gathers and encrypts accumulated audit logs into `.bin` payload files.
2. Crumbles displays a daily notification: *"Encrypted logs ready to be shared"*.
3. Tap the notification to open the standard Android share menu and upload your encrypted logs to any app installed on your phone (e.g., Google Drive, Gmail, Signal, Dropbox).

---

## Building from Source (Developers)

Developers can build Crumbles locally using Gradle:
1. Clone the repository: `git clone https://github.com/google/crumbles.git`
2. Build with Gradle: `./gradlew build`
3. Install to connected device: `adb install -r <path_to_apk>`

---

## How to Uninstall
Because Crumbles operates as a Device Owner app to protect security log integrity, Android security policy requires a **Factory Reset** to completely uninstall Crumbles and remove Device Owner status.
