# Crumbles: Privacy-Preserving Security & Network Logging for Android

Crumbles is an open-source Android application designed for high-risk individuals, journalists, human rights defenders, and security teams. It collects system-level **Security** and **Network logs**—data typically reserved for enterprise environments—to detect potential mobile exploits while ensuring strict cryptographic user privacy.

---

## Key Implemented Features

* 🔒 **Hybrid Envelope Encryption**: All log batches are encrypted
  symmetrically with AES-256-GCM, and their keys with RSA: 3072-bit keys made
  on the phone (2048-bit in StrongBox), or an imported public key of 2048 to
  4096 bits.
* 🛠️ **Zero-Touch Provisioning**: Automated QR Code onboarding via Android Enterprise that installs the app, sets Device Owner permissions, and schedules background tasks automatically.
* 🔑 **Flexible Key Management**:
  * **Android Keystore (Hardware-backed)**: Generates and locks keys inside TEE/StrongBox hardware. Supports in-app log decryption and re-encryption.
  * **External Private Key**: Displays generated private keys for offline storage. The phone only keeps the public key.
  * **Import External Public Key**: Scan an NGO or organization's QR code to encrypt logs using their public key.
* 📤 **Automated Upload & Transmission**: Periodic background workers upload
  the encrypted batches to a folder that you pick with the Android file picker
  (such as a Google Drive folder), or to a WebDAV server whose key you
  confirmed.

---

## Quick Setup Overview

| Setup Method | Prerequisites | Steps Summary |
| :--- | :--- | :--- |
| **Zero-Touch QR Provisioning** *(Recommended)* | Factory-reset phone, Wi-Fi | 1. Tap welcome screen 6 times<br>2. Scan provisioning QR code<br>3. Connect to Wi-Fi to auto-install |
| **Manual USB / ADB Setup** | Computer, USB cable, Platform-Tools | 1. Enable USB Debugging<br>2. Plug into computer<br>3. Run `setup_device.bat` / `.command` / `.sh` |

For full setup details, step-by-step guides, and developer build instructions, read the **[HOW_TO.md Guide](HOW_TO.md)**.

### Multi-User & Profile Requirements (Affiliated Users)

* **Android Platform Requirement (`DevicePolicyManagerService`
  `maybePauseDeviceWideLoggingLocked` /
  `areAllUsersAffiliatedWithDeviceLocked`)**: Android pauses device-wide
  [Security Logging][dpc-security-logging] (`mSecurityLogMonitor.pause()`) and
  [Network Logging][dpc-network-logging] (`mNetworkLogger.pause()`)—and throws
  `SecurityException` on `retrieveSecurityLogs()`,
  `retrievePreRebootSecurityLogs()`, and `retrieveNetworkLogs()`—whenever
  **any** [unaffiliated][dpc-affiliated-users] secondary user or profile exists
  on the device, even while `isSecurityLoggingEnabled()` and
  `isNetworkLoggingEnabled()` continue to return `true` (see the Android
  Enterprise [Security Logging][dpc-security-logging],
  [Network Logging][dpc-network-logging], and
  [Affiliated Users][dpc-affiliated-users] documentation).
* **Standalone Device Owner Mode**: Because Crumbles does not act as a Profile
  Owner on secondary users or profiles or configure
  [`DevicePolicyManager.setAffiliationIds()`][dpm-set-affiliation-ids], the
  device **must remain single-user with no secondary users or profiles** (no
  Work Profile, Guest/Secondary user, Android 14+ Clone profile, or Android 15+
  Private Space). While security logging is on, Crumbles applies
  `DISALLOW_ADD_USER`, `DISALLOW_ADD_MANAGED_PROFILE`,
  `DISALLOW_ADD_CLONE_PROFILE`, and `DISALLOW_ADD_PRIVATE_PROFILE` itself
  (Android already sets the last three for any device owner, and removes an
  existing Private Space when its restriction takes effect).
* **Delegated Mode (`DELEGATION_SECURITY_LOGGING` /
  `DELEGATION_NETWORK_LOGGING`)**: If the delegating Device Owner DPC allows
  secondary users or managed profiles on the device, the DPC **must** install
  an affiliated Profile Owner on every secondary user or profile and set
  matching affiliation IDs via
  [`DevicePolicyManager.setAffiliationIds()`][dpm-set-affiliation-ids] on both
  the Device Owner (`USER_SYSTEM`) and each Profile Owner. Profiles that
  cannot have a Profile Owner (such as Android 14+ Clone profiles, Android 15+
  Private Space, or unmanaged secondary/guest users) cannot be affiliated and
  must be disallowed; otherwise logging stops until they are removed.
  Removing an unaffiliated user or profile makes
  `discardDeviceWideLogsLocked()` discard the logs buffered in memory, but
  the security logs kept across the next restart can still include events
  from that time.

[dpc-security-logging]: https://developer.android.com/work/dpc/security#log-enterprise
[dpc-network-logging]: https://developer.android.com/work/dpc/logging#availability
[dpc-affiliated-users]: https://developer.android.com/work/dpc/dedicated-devices/multiple-users#affiliated-users
[dpm-set-affiliation-ids]: https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setAffiliationIds(android.content.ComponentName,%20java.util.Set%3Cjava.lang.String%3E)

A provisioning QR code grants Device Owner rights to whichever app it names, so
before scanning a code handed to you by someone else, work through
**[Verifying a provisioning QR code before you scan it][verify-qr]**. That
section is also explicit about what such verification cannot establish.

[verify-qr]: HOW_TO.md#verifying-a-provisioning-qr-code-before-you-scan-it

### Verify your download

Each GitHub release publishes both the APK file checksum
(`CrumblesApp.apk.sha256`, which changes on every build) and the **signing
certificate SHA-256 fingerprint** (32 colon-separated uppercase hex octets,
which stays the same across releases signed by the same key).

Before installing a downloaded APK, verify its signature and print its signing
certificate SHA-256 fingerprint:

```bash
./tools/print_signing_cert_sha256.sh CrumblesApp.apk
```

Compare the output against the signing certificate SHA-256 fingerprint in the
GitHub release notes (obtained over an independent channel). The footer at the
bottom of the Crumbles main screen (`App signing certificate (SHA-256): ...`)
is drawn by the installed app itself, so a look-alike app can show any value.
To check the app that is installed, copy it off the phone and verify it:

```bash
adb shell pm path com.android.securelogging  # Prints package:<path>.
adb pull <path> installed.apk
./tools/print_signing_cert_sha256.sh installed.apk
```

See **[RELEASING.md](RELEASING.md)** for the full release signing and
verification process.

---

## Technical Architecture & Protobuf Specifications

Log batches are output as encrypted `.bin` files containing three structured sections defined in [src/main/logs.proto](src/main/logs.proto):

1. **LogData**: AES-256-GCM encrypted audit log payload bytes. With the encryption type `LOG_ENCRYPTION_TYPE_AES_GCM_PADDED`, the decrypted payload is the length of the logs as a 4-byte big-endian integer, the logs, then zero bytes up to the next power of two of at least 4 KiB, so that the file size reveals only that size bucket. Format version 2 batches (`LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA`), which Crumbles writes, pad a serialized `SealedLogs` instead: the timestamp and device identifier of the batch, its logs, and the key attestation chain of the key that signs it, which older batches carry in clear in their signature.
2. **LogKey**: Asymmetrically wrapped symmetric key and 12-byte initialization vector (IV).
3. **LogMetadata**: Payload size and encryption type, authenticated as AES-GCM associated data. For format version 2, the associated data starts with the label `crumbles/v2/batch` and ends with the SHA-256 digest of the recipient's public key (its DER SubjectPublicKeyInfo). Older batches also carry their timestamp and device identifier here, in clear.

### Re-Encrypt & Share Flow
For users storing keys in Android Keystore, Crumbles provides an in-app **Re-encrypt and Share** feature. This allows users to decrypt logs locally and re-encrypt them using a forensic analyst's public key QR code, enabling safe sharing with trusted third parties without exposing master keys.

---

## Uninstallation Notice
When Crumbles is the Device Owner, Android protects it against tampering, so
uninstalling it requires a **Factory Reset**. In delegate mode, anyone holding
the unlocked phone can uninstall Crumbles without a reset, after deactivating
its device admin if it has one (see
**[What delegate mode does not protect](HOW_TO.md#what-delegate-mode-does-not-protect)**).

The reset erases every log batch that has not been uploaded yet, and the
built-in Keystore key: batches encrypted to that key, even those already
uploaded, can then no longer be decrypted by anyone. Read
**[How to Uninstall](HOW_TO.md#how-to-uninstall)** before you reset.

---

## Security

The architecture, assets, trust boundaries, and implemented security controls
are documented in the **[Threat Model](THREAT_MODEL.md)**. Please read it before
making security-relevant changes; it ends with a review checklist for
contributors.
