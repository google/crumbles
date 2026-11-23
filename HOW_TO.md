# Crumbles User & Administrator Guide
<!-- disableFinding(LINE_OVER_80) -->

<!-- disableFinding(LINE_OVER_80) -->

## What is Crumbles?
Crumbles is a privacy-first Android security application designed for high-risk individuals, journalists, human rights defenders, and security teams. It continuously records Android **Security Logs** (system events, authentication attempts) and **Network Logs** (connection activity) to help detect mobile exploits and suspicious behavior.

To protect your privacy, Crumbles automatically encrypts all logs on your phone before they are stored or transmitted. You can securely upload these encrypted log files to your preferred storage provider (e.g., Google Drive, Email) or share them with trusted forensic analysts.

---

## What Crumbles Protects, and What It Cannot

Crumbles protects your logs from the moment Android hands them to it. What
happens before that depends on the integrity of your phone's operating system,
bootloader and secure hardware, which no app can check by itself.

Crumbles guarantees that:

* **Only the recipient you chose can read your logs.** Each batch is encrypted
  on the phone with a new AES-256-GCM key, which is wrapped with the
  recipient's RSA public key. A key scanned from a QR code is only used after
  you confirm its fingerprint.
* **Unencrypted logs are never stored or uploaded.** Decrypted logs are only
  shown on the phone after you unlock it, in windows that screenshots and
  screen recordings can't capture.
* **Tampering is detected.** The details stored next to each encrypted batch
  (its time, device and format) are authenticated together with the logs, so a
  change to either makes decryption fail.

No app can protect against the following, so they are out of scope:

* **A compromised operating system, kernel, hypervisor or secure hardware.**
  An attacker who controls them, for example through an exploit, can hide,
  change or invent events before they reach Crumbles, read them before they
  are encrypted, and make the phone's own security checks report that all is
  well. Keep your phone updated and its bootloader locked.
* **Root access**, for example through an unlocked bootloader: logs can be read
  or changed before Crumbles encrypts them.
* **Events that Android doesn't log.** Crumbles only sees what Android's
  security and network logs record.
* **Batches that never leave the phone.** If the phone is destroyed, seized or
  kept offline before an upload, the batches on it are lost. Upload often.
* **A tampered clock.** Batch times come from the phone's clock, which an
  attacker who controls the phone can change.
* **A compromised recipient key.** Whoever has the private key can read every
  batch encrypted to it. Keep it offline, and change it if it leaks.
* **Stopping the logs.** An attacker who controls the phone or its network can
  stop the logging or the uploads. Crumbles can't bring back logs that were
  never recorded or sent. A restart can also lose recent security events;
  Crumbles records when it may have. Before the first unlock after a restart,
  Crumbles collects security logs only if it encrypts them to an external key.
* **Hiding that Crumbles is installed.** The neutral launcher entry also names
  the app neutrally in Recents, but Settings, notification headers and the
  Quick Settings tile editor still show the name Crumbles.

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

5. **Connect to Wi-Fi**: Follow the prompts to connect to Wi-Fi. Android Enterprise will automatically verify the APK's signing certificate checksum (`android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`), install Crumbles, set permissions, and enable background logging automatically!

**What the embedded checksum does and does not prove**:
The QR payload carries a SHA-256 checksum of a signing certificate
(`android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`). Android
refuses to install the downloaded APK unless it is signed by a key matching
that checksum, so nobody can substitute a different binary at the download URL.

The checksum binds the installation to whatever key *the QR code itself names*.
It does not tell you that the QR code is the genuine Crumbles one. A
substituted QR code can name a different download URL, a different package and
a different signing key, and Android will install that app as Device Owner just
as willingly. A QR code is therefore only as trustworthy as the channel you
received it from.

*(Note: Custom server deployments and helpdesks can generate custom QR code payloads using `./tools/generate_qr_payload.sh <path_to_apk>`.)*

---

### Verifying a provisioning QR code before you scan it

Scanning a provisioning QR code grants the app it names **Device Owner**
rights: near-total control of the phone, removable only by a factory reset.
Anyone can print a code that looks exactly like the official one. If a
helpline, clinic, NGO or anyone else hands you a code, check it before you
scan it.

1. **Decode it without acting on it.** Using a *second* device, not the one you
   are about to provision, scan the code with an ordinary QR reader that simply
   displays the decoded text. You should see a JSON payload. Only the Android
   setup wizard acts on such a payload; a normal QR reader just shows it to
   you.
2. **Check the app it names.**
   `android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` must read
   exactly `com.android.securelogging/.CrumblesDeviceAdminReceiver`.
3. **Check where it downloads from.**
   `android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION` must
   be an `https://github.com/google/crumbles/releases/...` URL. Treat link
   shorteners, bare IP addresses and look-alike domains as a reason to stop.
4. **Check the signing key it pins.** Compare
   `android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`, character
   for character, with the checksum published for the official release. It is
   the URL-safe base64 SHA-256 of the signing certificate.
5. **Obtain the expected values from somewhere else.** Steps 2 to 4 are worth
   something only if you get the official values over a channel that is *not*
   the channel that gave you the QR code: a different network or device, a
   printed handout you already trust, or a second organisation. If your only
   source for the "official" values is the same person or site that gave you
   the code, these checks prove nothing.
6. **Check what was actually installed.** The bottom of the Crumbles main
   screen shows a SHA-256 certificate fingerprint, but the installed app draws
   it, so a look-alike app can show the expected value. To check the app that
   is really on your phone, copy it to a computer over USB debugging and verify
   its signer there: `adb shell pm path com.android.securelogging` prints the
   path of the installed APK, `adb pull <that path> installed.apk` copies it,
   and `apksigner verify --print-certs installed.apk` prints the fingerprint to
   compare with the one published for the release. This check also applies to
   the manual install in Option 2, and you can repeat it at any later time.

**Be honest with yourself about what this gives you.** These steps let you
detect a QR code that points at a different app, a different download location
or a different signing key than the published official ones. They do **not**
give you an independent trust root. Every check reduces to "does this match
what the official release says?", so an attacker who also controls the channel
through which you learned the official values — the page you visited, the
network you used, the device you checked on — will pass the comparison.
Neither do these steps protect you against a helper who provisions the phone
for you and hands it over already set up: there you are trusting that person,
not the cryptography. If you cannot verify a code, do not scan it. Waiting
costs you nothing; a wrongly provisioned phone cannot be cleaned up without a
factory reset.

---

### Option 2: Manual Computer / ADB Setup
If you prefer installing Crumbles manually using a desktop or laptop computer:

1. **Back up your data** and **Factory reset your phone** without adding a Google Account yet.
2. **Enable USB Debugging** on your phone ([Setup Guide](https://developer.android.com/studio/debug/dev-options)).
3. Plug your phone into your computer via USB cable and tap **Allow USB Debugging** on your phone screen.
4. Download the [Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools) and the latest [Crumbles APK](https://github.com/google/crumbles/releases).
5. Run the setup script for your computer's OS. A checksum from the release
   site only proves that the download is complete, so each script installs the
   APK only if its SHA-256 checksum matches `CrumblesApp.apk.sha256` **and**
   `apksigner` (Android SDK Build-Tools) finds that it is signed with the
   release certificate whose SHA-256 fingerprint you give it: with
   `--expected-cert-sha256`, in `CRUMBLES_EXPECTED_CERT_SHA256`, or typed in
   when the script asks. Get that fingerprint from your organization or
   another channel you trust, not from the site that serves the APK.
   * **Windows**: Double-click `setup_device.bat`
   * **Mac**: Double-click `setup_device.command`
   * **Linux**: Run `./setup_device.sh`
   * Terminal alternative: download `CrumblesApp.apk` and
     `CrumblesApp.apk.sha256`, and check both the checksum and the signer
     before you install. The second command must print the fingerprint from
     that trusted channel (`apksigner verify --print-certs CrumblesApp.apk`
     shows it too):

     ```bash
     sha256sum -c CrumblesApp.apk.sha256
     ./tools/print_signing_cert_sha256.sh CrumblesApp.apk
     adb install -r CrumblesApp.apk
     adb shell dpm set-device-owner com.android.securelogging/.CrumblesDeviceAdminReceiver
     ```

---

### Multi-User, Profiles & Delegated Mode Requirements (Affiliated Users)

Android enforces strict multi-user privacy rules for device-wide logging
(`DevicePolicyManagerService.maybePauseDeviceWideLoggingLocked` and
`areAllUsersAffiliatedWithDeviceLocked`):

* **Android Platform Requirement**: Android pauses device-wide
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
  phone **must remain single-user with no secondary users or profiles** (no
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
* **Troubleshooting Paused Logging**: If log collection stops while the logging
  toggle still appears enabled, check whether a secondary user, Work Profile,
  Android 14+ Clone profile, or Android 15+ Private Space exists on the phone.
  Removing an unaffiliated user or profile resumes logging, but causes
  `discardDeviceWideLogsLocked()` to discard the device-wide logs buffered in
  memory. The security logs kept across the next restart can still include
  events from that time.

[dpc-security-logging]: https://developer.android.com/work/dpc/security#log-enterprise
[dpc-network-logging]: https://developer.android.com/work/dpc/logging#availability
[dpc-affiliated-users]: https://developer.android.com/work/dpc/dedicated-devices/multiple-users#affiliated-users
[dpm-set-affiliation-ids]: https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setAffiliationIds(android.content.ComponentName,%20java.util.Set%3Cjava.lang.String%3E)

---

### What delegate mode does not protect

Your organization's device management app can stay the Device Owner and
delegate security or network logging to Crumbles instead. Android then lets
anyone holding the unlocked phone clear Crumbles' storage, force stop it or
uninstall it, which erases the batches not uploaded yet, the activity log, the
settings and the keys. To block this, tap **Activate Device Admin** on the main
screen. Even then:

* **Anyone holding the unlocked phone can deactivate the admin** in Settings,
  without your PIN, pattern or password, and then clear the storage or
  uninstall Crumbles.
* **Crumbles can't stop the deactivation.** It records it in the activity log
  and starts an upload at once, but the batches still on the phone are lost if
  the phone is offline, or if someone clears the storage or uninstalls Crumbles
  before the upload ends.

---

## Managing Encryption Keys in Crumbles

Once installed, open the Crumbles app, enable the logging toggle, and select your preferred encryption key management strategy:

* **Option A: Built-in Hardware Keystore (Recommended)**
  * Crumbles stores your encryption keys securely inside your phone's hardware security module (TEE/StrongBox).
  * **In-App Decryption**: You can view and decrypt your logs directly inside the app. Decryption asks for your PIN, pattern or password, never your fingerprint or face, which someone could force onto the sensor.
  * **Re-Encrypt & Share**: You can re-encrypt selected logs using a trusted 3rd-party's public key QR code to safely share them via Email or Drive.
* **Option B: Generate Private Key & Keep Externally**
  * Crumbles generates an encryption key pair, but displays the private key for you to save in an offline, secure location (e.g., password manager). Crumbles does not store the private key on the phone.
* **Option C: Import External Public Key (For Organizations & NGOs)**
  * Scan a public key QR code provided by a trusted organization or NGO. All logs will be encrypted using their public key so only their analysts can decrypt the logs.

---

## Daily Log Sharing & Upload

Once configured, Crumbles operates automatically in the background:
1. Tap **Select Upload Folder** on the main screen. Unlocking device credentials is required to prevent unauthorized redirection.
2. Choose where logs are uploaded:
   * **Folder (Google Drive or another storage app)**: Pick any folder via the Android Document Tree Picker with persistent write permissions.
   * **WebDAV Server**: Configure an RFC 4918-compliant WebDAV server (e.g., Nextcloud, ownCloud, mailbox.org, Apache).
     * Requirements: HTTPS is strictly enforced (except loopback during local testing). The server URL, username and password are encrypted at rest under a key held in Android Keystore.
     * Enter the final address of your WebDAV folder: redirects are not followed, and URLs that contain credentials, a query or a fragment are rejected.
     * Saved settings are never shown again, so enter all three to change any of them. Choosing a folder later deletes the saved WebDAV settings.
     * Tap **Test Connection** to check the server URL and credentials before saving.
     * When you save, Crumbles shows the fingerprint of the server's public key. Ask the server's operator for that fingerprint and save only if they match. From then on, uploads go only to a server that presents this key. If the key changes, sync pauses until you check with the operator and enter the server again to confirm its new key. A server saved before Crumbles asked you to confirm its key has no confirmed key, so sync to it pauses until you enter it again.
3. At periodic background intervals (default: 8 hours), Crumbles gathers and encrypts accumulated audit logs into `.bin` payload files.
4. Encrypted logs are streamed directly to your configured storage destination. Logs are only marked as sent on-device after verified stream write completion to prevent data loss.

---

## Decrypting and Checking Log Batches (Recipients)

If Crumbles encrypts logs to your key (Option B or C above), decrypt the `.bin`
batch files on a computer with `tools/analyst/crumbles_analyst.py`. It needs
Python 3.10 or later and the two packages in `tools/analyst/requirements.txt`.
Those packages run in the same process as your private key, so install exactly
the versions whose hashes you pinned, in a virtual environment of their own
(`pip-compile` comes with `pip-tools`):

```
# Once, on a computer you trust: pin the versions and hashes, and review them.
pip-compile --generate-hashes --output-file requirements.lock tools/analyst/requirements.txt

python3 -m venv analyst-env
analyst-env/bin/pip install --require-hashes -r requirements.lock
analyst-env/bin/python tools/analyst/crumbles_analyst.py --key key.txt --out decrypted batches
```

* `--key` is your RSA private key: a PEM file, or a text file with the Base64
  text that Crumbles showed when it generated the key pair. If the PEM key is
  encrypted, the script asks for its passphrase. Repeat it for each key that
  batches may be encrypted to, such as your keys before and after a key change.
* `--out` is optional. Without it, the script only checks the batches. With it,
  the decrypted logs are written to new files `decrypted/<batch name>.txt`,
  readable only by you. Existing files are never overwritten. Batches with a
  missing or bad signature, whose signer fails `--app-cert` or `--boot-key`, or
  from a device with more than one signer go to
  `decrypted/unverified/<batch name>.txt` instead.
* `--app-cert` is optional, and can be repeated: the SHA-256 fingerprint of a
  certificate that Crumbles may be signed with, as the release notes and the
  bottom of the Crumbles main screen show it, or as `apksigner` prints it.
  Give the certificate of the build you trust: the official release, the build
  of a custom ROM, or your own.
* `--boot-key` is optional, and can be repeated: a verified boot key that you
  trust, in hex, such as one that CalyxOS or GrapheneOS publishes or the
  verified boot key reported for a phone running its maker's OS. Required for
  custom ROMs (`SelfSigned`). When given, it applies to all boot states
  (including `Verified`), so include the verified boot keys of any stock-OS
  phones you check in the same run.
* `--attestation-status` is optional, and can be repeated: a copy of Google's
  list of revoked attestation keys, as the script does not use the network.
  Download it shortly before you check the batches, for example with
  `curl -o status.json https://android.googleapis.com/attestation/status`.
  Keep every copy you download under its own name, and give them all: Google
  can drop a revoked key from the list once its certificate expires, and a
  certificate on any of them fails. The report shows the number of listed
  certificates and the date of the newest list file.
* `--allow-unsigned` is optional: allow batches without a signature to advance
  the trailer chain. Their decrypted logs are still written to
  `decrypted/unverified/<batch name>.txt`.
* `--max-age` is optional: the maximum allowed age in hours of the newest
  batch for each device. Older devices are flagged. A re-encrypted copy of a
  batch keeps the time the batch was written, so sharing old logs again does
  not make a device look recent.
* `--device` is optional, and can be repeated: the ID of a device whose batches
  you expect, as the report prints it ("by device ..."). Each device you give
  must have a trusted batch, and batches of any other device are flagged and go
  to `unverified/`. Give it whenever a folder can hold batches of several
  phones: without it, someone who can write to the folder can delete every
  batch of one phone, or replace them with another phone's batches, and the
  check still passes.
* `--signer` is optional, and can be repeated: the SHA-256 fingerprint of a
  phone's batch-signing key, as the report prints it ("signed by TEE key ...").
  Note it from the first report after you enroll a phone, and give it in every
  later run: batches that another key signed are then flagged, even if that key
  was attested for the same device ID.
* `--min-patch-level` is optional: the oldest patch level (`YYYYMM`) of the OS,
  vendor and boot images when a phone made its signing key. The report shows
  the OS version and the patch levels that the attestation gives for each key.
* The last arguments are batch files, or folders of `.bin` files.

For each batch, the script prints when and by which device it was written,
any problem it found, and any notices (such as log rotation). Batches from
newer versions of Crumbles hold the time, the device and the attestation chain
of their signing key in encrypted form, so the script shows the time and the
device only if it can decrypt the batch. It exits with status 1 if there was a
problem:

* **cannot unwrap the AES key**: the batch was encrypted to another key, for
  example to the key you used before a key change.
* **AES-GCM authentication failed**: the batch or its metadata was altered, or
  the batch was encrypted to another key and its AES key then wrapped again
  for yours.
* **no attestation certificates**: the batch carries no attestation chain, or
  it is a newer batch that no `--key` decrypts, whose chain is encrypted with
  its logs. If a key that another batch attests signed it, this is replaced by
  a notice, and the batch still counts for the sequence numbers of the device.
* **format version 2 batch with attestation certificates in clear**: newer
  batches carry the attestation chain only encrypted with their logs, so
  someone added these certificates to the batch, where its signature does not
  cover them.
* **the padded logs declare more bytes than they hold**, or **malformed sealed
  logs**: the batch was encrypted to your key, but not by Crumbles.
* **activity log break**: each batch ends with the app's activity log records
  since the previous batch. The script orders the batches by the time they
  were written, and a break means that a batch in between is missing (deleted,
  never uploaded, or encrypted to another key), or that the app was reinstalled
  in between.
* **unsigned batch**: older versions of Crumbles didn't sign batches. From
  supported versions, it means that signing failed on the phone, or that
  someone else made the batch.
* **tamper-evidence event: BATCH_SIGNING_FAILED**: the phone wrote a batch
  without a signature or sequence number, so the numbering can't show if that
  batch is deleted later. Check that you have it: it is reported as an unsigned
  batch. A re-encrypted copy that could not be signed again is only a notice.
* **bad signature**, or a problem with the attestation certificates: the batch
  was altered, or it was not signed by a hardware key of an Android device.
* **the key was attested for another device ID**, or another problem with
  what the attestation says: the batch was not signed by Crumbles on the
  phone with the device ID of the batch.
* **the batches numbered N to M are missing**, or **repeated sequence number**:
  each phone numbers the batches it signs 1, 2, 3, and so on. The numbers need
  not start at 1, so you can check recent batches on their own, but the ones
  you check must have no gaps or repeats.
* **signed with another key**, or **signed by an app with other
  certificates**: all batches of a device must be signed by the same key, made
  by the same app.
* **signed by an app with none of the certificates of --app-cert**: a build of
  Crumbles that you did not give, or another app with the same package name,
  signed the batch.
* **the key was made while the bootloader was unlocked**, or **by an OS that
  verified boot rejected**: the phone's OS may have been altered, and such an
  OS could make up logs. Phones with a custom ROM such as CalyxOS or
  GrapheneOS pass if their bootloader is locked: the report then shows the
  verified boot state SelfSigned, and the verified boot key to compare with
  the one that the ROM publishes.
* **signed on a custom ROM but no --boot-key was given**, or **signed with none
  of the verified boot keys of --boot-key**: anyone can sign a custom ROM and
  lock the bootloader again, or sign batches on a phone whose OS is not one you
  pinned. Phones of the same model running their maker's OS share a verified
  boot key, so use `--device` to tell such phones apart.
* **signed with none of the keys of --signer**, or **the key's OS, vendor or
  boot patch level is below --min-patch-level** (or missing): a key you did
  not pin signed the batch, or a phone lacked the patches that you require.
* **device X was not given with --device**: the batch comes from a phone that
  you did not list.
* **attestation certificate N is REVOKED**, or **SUSPENDED**: Google revoked
  a key of the attestation chain, for example because it leaked, and whoever
  has a leaked key can attest anything.

A notice that **the batch time is outside the validity of attestation
certificate 0** means that the phone's clock was wrong, or was changed, when it
wrote the batch: the signature still counts. A batch **collected before the
first unlock** has no activity log records: the phone cannot read them then.

Anyone who has your public key can create a batch that decrypts, so only a
valid signature shows that Crumbles wrote it: the script checks that the key
is in the phone's TEE or StrongBox, belongs to com.android.securelogging and
was made for the device ID of the batch, on a phone with a locked bootloader
and an OS that verified boot accepted. Anyone can build an app with that
name, so the script also prints the SHA-256 fingerprint of each certificate
that signs the app: compare it with the one you expect, or give that one with
`--app-cert`. It checks Google's list of revoked attestation keys only with
`--attestation-status`.

---

## Building from Source (Developers)

Build Crumbles with the Gradle wrapper from a clone of the repository. You need
JDK 17 or newer and the Android SDK with the Android 15 (API level 35)
platform: point Gradle to the SDK with the `ANDROID_HOME` environment variable
or with `sdk.dir` in `local.properties`. Then run the unit tests and build the
release APK:

```bash
./gradlew test assembleRelease
```

Gradle writes the unsigned APK to
`build/outputs/apk/release/crumbles-release-unsigned.apk`. It checks every
plugin and library that it downloads against the SHA-256 checksums in
`gradle/verification-metadata.xml`, and fails the build if one is missing or
differs: [RELEASING.md](RELEASING.md) describes how to update them when a
dependency changes. Of the build tools that depend on the platform, the
checksums cover only those for Linux on x86-64, aapt2 and protoc: to build on
another platform, first add the checksums of its own tools with
`./gradlew --write-verification-metadata sha256 build`, and check the new
entries as RELEASING.md describes.

---

## How to Uninstall
When Crumbles is the Device Owner, Android security policy requires a **Factory Reset** to uninstall it and remove its Device Owner status. In delegate mode, no reset is needed: anyone holding the unlocked phone can uninstall Crumbles, after deactivating its device admin if it has one (see [What delegate mode does not protect](#what-delegate-mode-does-not-protect)).

**A factory reset erases everything Crumbles keeps on the phone:**

* **Batches not uploaded yet are lost.** Nothing can recover them after the
  reset.
* **The built-in Keystore key is destroyed.** Batches encrypted to it can no
  longer be decrypted by anyone, including the ones you already uploaded. An
  external key whose private key you saved, or an organization's public key,
  is not affected.

Removing the screen lock also destroys the built-in Keystore key: batches
encrypted to it can no longer be decrypted, and new logs wait on the phone
until a new key is generated. Changing an existing PIN, pattern or password to
another one (without removing the screen lock) keeps the built-in Keystore key
and all previous batches decryptable.

Before you reset:

1. Upload the batches still on the phone with the **Sync now** tile or
   **Upload now and wipe** rather than waiting for the next scheduled upload,
   then check that they arrived at your upload destination.
2. If you use the built-in Keystore key, decrypt the uploaded batches you still
   need, or re-encrypt them to a trusted public key with **Re-Encrypt & Share**.
