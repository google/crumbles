# Crumbles: Privacy-Preserving Security & Network Logging for Android

Crumbles is an open-source Android application designed for high-risk individuals, journalists, human rights defenders, and security teams. It collects system-level **Security** and **Network logs**—data typically reserved for enterprise environments—to detect potential mobile exploits while ensuring strict cryptographic user privacy.

---

## Key Implemented Features

* 🔒 **Hybrid Envelope Encryption**: All log batches are encrypted symmetrically with AES-256-GCM and asymmetric RSA-2048 key encapsulation.
* 🛠️ **Zero-Touch Provisioning**: Automated QR Code onboarding via Android Enterprise that installs the app, sets Device Owner permissions, and schedules background tasks automatically.
* 🔑 **Flexible Key Management**:
  * **Android Keystore (Hardware-backed)**: Generates and locks keys inside TEE/StrongBox hardware. Supports in-app log decryption and re-encryption.
  * **External Private Key**: Displays generated private keys for offline storage. The phone only keeps the public key.
  * **Import External Public Key**: Scan an NGO or organization's QR code to encrypt logs using their public key.
* 📤 **Automated Upload & Transmission**: Periodic background workers batch logs and trigger native Android system sharing notifications to upload encrypted files via any installed app (Google Drive, Gmail, Signal, etc.).

---

## Quick Setup Overview

| Setup Method | Prerequisites | Steps Summary |
| :--- | :--- | :--- |
| **Zero-Touch QR Provisioning** *(Recommended)* | Factory-reset phone, Wi-Fi | 1. Tap welcome screen 6 times<br>2. Scan provisioning QR code<br>3. Connect to Wi-Fi to auto-install |
| **Manual USB / ADB Setup** | Computer, USB cable, Platform-Tools | 1. Enable USB Debugging<br>2. Plug into computer<br>3. Run `setup_device.bat` / `.command` / `.sh` |

For full setup details, step-by-step guides, and developer build instructions, read the **[HOW_TO.md Guide](HOW_TO.md)**.

---

## Technical Architecture & Protobuf Specifications

Log batches are output as encrypted `.bin` files containing three structured sections defined in [src/main/logs.proto](src/main/logs.proto):

1. **LogData**: AES-256-GCM encrypted audit log payload bytes.
2. **LogKey**: Asymmetrically wrapped symmetric key and 12-byte initialization vector (IV).
3. **LogMetadata**: Payload size, timestamp, device identifier, and encryption type flags.

### Re-Encrypt & Share Flow
For users storing keys in Android Keystore, Crumbles provides an in-app **Re-encrypt and Share** feature. This allows users to decrypt logs locally and re-encrypt them using a forensic analyst's public key QR code, enabling safe sharing with trusted third parties without exposing master keys.

---

## Uninstallation Notice
Due to Android security policies protecting Device Owner apps against unauthorized tampering, uninstalling Crumbles requires a **Factory Reset**.
