# Crumbles Operator & Incident Responder Runbook

<!-- The event tables below are wider than 80 columns by necessity. -->
<!-- disableFinding(LINE_OVER_80) -->

This runbook guides NGO digital helpline operators, administrators, and device
owners through onboarding, operational incidents, and interpreting Crumbles
activity-log (audit) events. Step-by-step installation instructions live in
**[HOW_TO.md](HOW_TO.md)**.

---

## 1. Onboarding & Provisioning Checklist

1. **Verify the provisioning QR code or APK before installation**:
   * Follow **[Verifying a provisioning QR code before you scan it][verify-qr]**
     on a separate device to confirm:
     * `PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` is
       `com.android.securelogging/.CrumblesDeviceAdminReceiver`.
     * `PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION` points to an
       official `https://github.com/google/crumbles/releases/...` asset.
     * `PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM` matches the URL-safe
       Base64 signing certificate digest published for the release over an
       independent channel.
   * After installation, check the app that is really installed. The footer
     on the main screen (`App signing certificate (SHA-256): ...`) is drawn by
     the installed app itself, so it is no check on its own. Copy the APK to a
     computer (`adb shell pm path com.android.securelogging`, then `adb pull`)
     and compare the fingerprint that `apksigner verify --print-certs` prints
     with the one published in the GitHub release notes (see
     **[RELEASING.md](RELEASING.md)**).
2. **Verify a screen lock is set**:
   * Ensure a PIN, pattern, or password is configured before generating keys or
     changing upload settings.
3. **Configure the encryption key**:
   * **Helpline / NGO-managed devices**: Import the organization's external
     public key QR code (`Import External Public Key`) and verify the displayed
     SHA-256 key fingerprint out of band before confirming.
   * **Self-managed devices**: Generate either a hardware-backed Android
     Keystore key (`Built-in Hardware Keystore`) or an exportable key pair
     whose private key is stored offline (`Generate Private Key & Keep
     Externally`).
4. **Configure the upload destination and collection scope**:
   * Select the upload folder (Storage Access Framework) or configure WebDAV,
     and confirm whether **Network collection** (device-wide DNS and connection
     events) should be enabled alongside **Security logging**.
   * For a WebDAV server, save the server key that Crumbles shows only if its
     fingerprint matches the one that the server's operator gave you.

[verify-qr]: HOW_TO.md#verifying-a-provisioning-qr-code-before-you-scan-it

---

## 2. Incident Playbooks

### 2.1 When Log Uploads Stop or Are Deferred

Even a quiet phone writes an empty, signed heartbeat batch once it has signed
none for 24 hours. A destination that receives nothing for more than a day or
two therefore means that something stops the batches: collection was turned
off, the app was removed, or uploads are blocked.

1. **Check the in-app Activity Log and active notifications**:
   * **No usable encryption key (`LOGS_UPLOAD_DEFERRED_NO_KEY`, `LOGS_STAGED`,
     `EXTERNAL_KEY_UNAVAILABLE`, `KEYSTORE_KEY_INVALIDATED`)**:
     * Without a usable key, Crumbles keeps retrieving logs into a sealed
       staging area of 16 MiB and encrypts them once a key is set. When the
       staging area is full, new batches are lost (`LOGS_STAGING_FULL`,
       `LOGS_LOST`), so set up a key promptly.
     * If an external key was selected but could not be read
       (`EXTERNAL_KEY_UNAVAILABLE`), Crumbles fails closed and refuses to fall
       back to another key. Re-import the expected external public key and
       confirm its fingerprint.
     * If the built-in key was invalidated (`KEYSTORE_KEY_INVALIDATED`), for
       example because the screen lock was removed, set a screen lock and
       generate a new key.
     * If `KEY_PREFERENCES_ALTERED` or `KEY_PREFERENCES_UNREADABLE` was logged,
       `user_key_prefs.pb` failed its integrity check or could not be parsed,
       and was preserved as `user_key_prefs.pb.corrupt`. Treat this as
       potential tampering and re-import the recipient key.
   * **Destination unconfigured or permission lost
     (`UPLOAD_DESTINATION_NOT_CONFIGURED`,
     `UPLOAD_DESTINATION_PERMISSION_REVOKED`, `UPLOAD_DESTINATION_INVALID`,
     `UPLOAD_CREDENTIALS_DECRYPTION_FAILED`)**:
     * Re-select the upload folder on the main screen (requires device
       credential confirmation) or re-enter the WebDAV credentials.
   * **WebDAV server key not confirmed or changed
     (`UPLOAD_SERVER_KEY_NOT_CONFIRMED`, `UPLOAD_SERVER_KEY_REJECTED`)**:
     * Crumbles uploads only to an HTTPS server whose key was confirmed, and
       stops when the server presents another key. A certificate renewal can
       change the key, but so can someone intercepting the connection. Before
       you enter the server again and save its new key, check the fingerprint
       with the server's operator over an independent channel.
   * **Transient upload failure (`LOGS_UPLOAD_FAILED`,
     `LOGS_UPLOAD_RECOVERED_PROCESSING`)**:
     * Failed `.bin` batches stay on disk (or are recovered from
       `_processing.bin` on the next worker run) and are retried automatically
       every 8 hours. The **Sync now** tile uploads them at once, and then
       deletes the uploaded batches from the phone.
   * **On-device storage pressure (`LOGS_STORAGE_CAP_APPROACHING`,
     `LOGS_STORAGE_CAP_REACHED`, `LOGS_COLLECTION_STOPPED`,
     `NETWORK_LOGS_COLLECTION_STOPPED`, `LOG_RETRIEVAL_DEFERRED`)**:
     * Crumbles caps the encrypted logs directory at 256 MiB, and lets network
       batches fill only 75% of it, so that security logs keep the rest. At the
       cap, it reclaims only already-uploaded `_sent.bin` files outside the
       oldest 25% of the cap (`LOGS_STORAGE_CAP_REACHED`). If un-uploaded
       `.bin` batches fill the cap, Crumbles stops admitting new batches rather
       than evicting un-uploaded evidence (`LOGS_COLLECTION_STOPPED`). Restore
       uploads immediately so pending `.bin` files transition to `_sent.bin`.
     * `LOG_RETRIEVAL_DEFERRED` means that Crumbles postponed retrieving logs,
       usually because the phone's free storage was too low. Logs that the
       platform drops in the meantime are lost (`LOGS_LOST`). Free up storage.
     * Storage that fills up unexpectedly, or a stop record that mentions a
       burst (25% of the cap within an hour), can be an attempt to make
       Crumbles lose logs: find out what filled the storage.
   * **Logging turned off or access lost (`SECURITY_LOGGING_DISABLED`,
     `NETWORK_LOGGING_DISABLED`, `SECURITY_LOGGING_ACCESS_LOST`,
     `NETWORK_LOGGING_ACCESS_LOST`)**:
     * Re-enable the logging switch on the main screen and inspect the
       activity log for unauthorized configuration changes.
     * Access is lost when Crumbles stops being the Device Owner or the Device
       Owner app withdraws its logging delegation. See section 2.4.
   * **Alerts turned off (`NOTIFICATIONS_BLOCKED`)**:
     * Crumbles can no longer alert the user when collection stops, and its
       main screen says so. Turn its notifications back on in Settings.

### 2.2 When an Encryption Key Is Lost, Compromised, or Refused

1. **External or exportable private key lost or compromised**:
   * Open **Manage Encryption Keys**, import or generate a replacement key, and
     verify its SHA-256 fingerprint.
   * Because the phone holds only the public key in external-key mode, pending
     batches already encrypted to the old external key cannot be decrypted on
     the phone. Choose **Keep Queued for Upload** to have them uploaded, still
     encrypted to the old key, to the configured destination, where whoever
     holds the old private key (for example an archiving system) can decrypt
     them, or **Discard Logs** to delete them.
2. **Built-in Android Keystore key rotated or unavailable**:
   * When rotating away from an internal Keystore key while pending `.bin`
     files exist, authenticate with the device credential and select
     **Re-encrypt** to re-encrypt pending batches to the new key.
   * If `PRIMARY_KEY_REPLACED` appears in the activity log, the Android
     Keystore permanently refused the settings-encryption key and Crumbles
     generated a new one; re-enter any saved upload credentials or keys.

### 2.3 When the Phone Is Seized, Compromised, or Must Be Factory Reset

1. **If the phone is seized or suspected of physical compromise**:
   * Immediately revoke the device's upload credentials or folder write access
     on the destination server (Google Drive folder permissions or WebDAV
     account) so an attacker holding the phone cannot overwrite, delete, or
     enumerate previously uploaded `.bin` batches.
   * Preserve all already-uploaded `.bin` batches and their activity-log
     records on the analyst side for forensic review.
2. **Before intentionally factory-resetting or retiring a phone**:
   * When Crumbles is the **Device Owner**, uninstalling it requires a
     **Factory Reset**. In delegate mode, anyone holding the unlocked phone can
     uninstall Crumbles without a reset, after deactivating its device admin
     if it has one (see [What delegate mode does not protect][delegate]).
   * A factory reset permanently destroys:
     * All un-uploaded `.bin` log batches still on the device.
     * The hardware-bound Android Keystore private key, which makes **even
       already-uploaded batches** encrypted to the built-in Keystore key
       permanently undecryptable.
   * Before resetting: upload pending batches with the **Sync now** tile or
     **Upload now and wipe** and check that they arrived, and if the built-in
     Keystore key was used, decrypt or **Re-Encrypt & Share** any needed
     batches to an external analyst public key first.

[delegate]: HOW_TO.md#what-delegate-mode-does-not-protect

### 2.4 When the Activity Log Shows Possible Tampering

`crumbles_analyst.py` reports the events marked **Problem** in section 3 as
`PROBLEM: tamper-evidence event`. None of them proves an attack, but each one
means that logs were lost or deleted, that collection stopped, or that someone
changed what Crumbles does. Ask the phone's owner whether they did it, and
check the events around it:

* **Logs lost (`LOGS_LOST`, `STAGED_LOGS_UNREADABLE`,
  `LOGS_COLLECTION_STOPPED`, `NETWORK_LOGS_COLLECTION_STOPPED`)**: events are
  missing from the trail. Look for the cause around it: full storage (section
  2.1), a restart or a lowered boot count, or a staged batch that was altered.
* **Collection paused (`COLLECTION_PAUSED_SECONDARY_USER`,
  `COLLECTION_RESUMED_SINGLE_USER`)**: while a secondary user, guest or profile
  exists, Android withholds logs from Crumbles, and it discards them when that
  user is removed. Events from that time are missing, although some can still
  arrive with the logs kept across the next restart. Find out who added the
  user. In delegate mode, `USER_ADDITION_ALLOWED` means that the Device Owner
  app lets users be added, which can happen unseen between two checks: ask
  its administrator to disallow it.
* **Protection removed (`DEVICE_ADMIN_DISABLED`,
  `SECURITY_LOGGING_ACCESS_LOST`, `NETWORK_LOGGING_ACCESS_LOST`)**: Crumbles
  was deactivated as device admin, so its storage can be cleared and it can be
  uninstalled, or it lost its Device Owner status or logging delegation.
* **Batches or records deleted (`UPLOAD_AND_WIPE_FORCED`, `LOGS_DISCARDED`,
  `AUDIT_LOG_CLEAR_REQUESTED`, `AUDIT_LOG_CLEARED`,
  `AUDIT_LOG_CLEAR_SEAL_FAILED`)**: someone who knew the device credential
  deleted batches that were not uploaded, or cleared the activity log.
  `AUDIT_LOG_CLEAR_SEAL_FAILED` means that the records not yet shipped could
  not be sealed into a batch first, so the activity log was kept.
* **Keys or settings lost (`KEY_PREFERENCES_ALTERED`,
  `KEY_PREFERENCES_UNREADABLE`, `KEYSTORE_KEY_INVALIDATED`,
  `AUDIT_LOG_KEY_REPLACED`, `RE_ENCRYPT_FAILED`, `KEY_HANDOVER_NOT_SEALED`,
  `DESTINATION_HANDOVER_NOT_SEALED`)**: stored keys or settings were changed,
  lost or replaced, or the holder of the external key was not told about a
  change. Re-import the recipient key and confirm its fingerprint.
* **Destination changed without a confirmed notice
  (`DESTINATION_HANDOVER_UPLOAD_FAILED`,
  `DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED`,
  `DESTINATION_HANDOVER_UPLOADED_OFFLINE`,
  `DESTINATION_CHANGED_WITHOUT_HANDOVER`)**: the outgoing destination may have
  missed the notice that names the new one. Look there for the sealed notices
  (`NOTICE: upload destination change`). A storage app can take a notice and
  keep it on the phone without ever syncing it, for example while a firewall,
  Data Saver or its own settings keep it offline, or until its data is
  cleared, so only a notice found in the folder confirms the hand-over. If
  none is there, the records of the change reach you only in the batches
  uploaded to the new destination.
* **WebDAV server key changed (`UPLOAD_SERVER_KEY_REJECTED`)**: see section
  2.1.
* **Trail incomplete (`AUDIT_RECORDS_DROPPED`, `AUDIT_EVENTS_RATE_LIMITED`,
  `FINAL_BATCH_FAILED`, `PAUSE_BATCH_FAILED`, `BATCH_SIGNING_FAILED`)**:
  records could not be written, more than 60 events of one type arrived within
  an hour, or a notice or signed batch is missing.

---

## 3. Activity-Log (Audit) Event Catalog

`CrumblesAppAuditLogger` writes JSON-lines records to no-backup storage. Each
record is sealed with AES-256-GCM under a data key that a non-exportable
Android Keystore key wraps, and the records are chained with HMAC-SHA256 under
the Android Keystore key `crumbles_audit_chain_hmac_key` starting from
`CrumblesAuditEvent.GENESIS_TAG` (64 zeroes). The tables below list every event
type that this version records. **Analyst** is how
`tools/analyst/crumbles_analyst.py` reports the event when it finds it in the
activity records that uploaded batches carry: **Problem** (tamper evidence, see
section 2.4), **Notice**, or **Routine** (not reported).

Records from versions before 1.0 can also contain `OAEP_UNSUPPORTED`: a faulty
capability probe created the device key for PKCS#1 v1.5 padding. That key keeps
receiving PKCS#1 v1.5 wraps until a new built-in key replaces it.

### 3.1 Logging State & Collection

| Event | Analyst | Written when |
| :-- | :-- | :-- |
| `SECURITY_LOGGING_ENABLED` | Routine | Security logging was turned on with the switch or at provisioning, or the watchdog (every 15 minutes) found it on. |
| `SECURITY_LOGGING_DISABLED` | Notice | The watchdog found security logging turned off, and alerted the user. |
| `NETWORK_LOGGING_ENABLED` | Notice | Network logging was turned on with the switch or at provisioning, or the watchdog found it on. |
| `NETWORK_LOGGING_DISABLED` | Notice | The watchdog found network logging turned off while network collection is on, and alerted the user. |
| `SECURITY_LOGGING_ACCESS_LOST` | Problem | Crumbles can no longer read security logs: it is no longer the Device Owner, or the delegation was withdrawn. |
| `NETWORK_LOGGING_ACCESS_LOST` | Problem | The same, for network logs. |
| `LOGGING_DISABLE_REQUESTED` | Notice | The user asked to turn off logging. |
| `LOGGING_DISABLED` | Notice | The user confirmed the device credential and turned off logging. |
| `LOGGING_DISABLE_AUTH_FAILED` | Notice | Logging stayed on: the device credential was not confirmed. |
| `LOGGING_DISABLE_REFUSED` | Notice | Logging stayed on: no secure lock screen is set. |
| `LOGGING_DISABLE_FAILED` | Notice | Logging stayed on: Crumbles is no longer the Device Owner or logging delegate. |
| `FINAL_BATCH_SEALED` | Notice | Logging was turned off and its final batch sealed, while staged batches are still pending. |
| `FINAL_BATCH_FAILED` | Problem | Logging was turned off, but no final batch could be sealed. |
| `NETWORK_COLLECTION_SCOPE_CHANGED` | Notice | Network collection (device-wide DNS and connection events) was turned on or off. |
| `NETWORK_COLLECTION_DISABLE_REQUESTED` | Notice | The user asked to turn off network collection. |
| `NETWORK_COLLECTION_DISABLE_AUTH_FAILED` | Notice | Network collection stayed on: the device credential was not confirmed. |
| `NETWORK_COLLECTION_DISABLE_REFUSED` | Notice | Network collection stayed on: no secure lock screen is set. |
| `NETWORK_COLLECTION_OFF` | Notice | Android offered network logs while network collection was off; they were not retrieved. |
| `COLLECTION_PAUSED_SECONDARY_USER` | Problem | A secondary or guest user or a profile exists, so Android withholds logs. |
| `COLLECTION_RESUMED_SINGLE_USER` | Problem | Collection resumed after the other users were removed; Android discarded the logs it held in memory meanwhile. |
| `PAUSE_BATCH_FAILED` | Problem | Collection paused, but no batch recording the pause could be sealed. |
| `DEVICE_ADMIN_DISABLED` | Problem | Crumbles was deactivated as device admin, so clearing its storage, force stopping and uninstalling it are no longer blocked. |
| `NOTIFICATIONS_BLOCKED` | Notice | Notifications or the action-needed alerts were turned off, so the user is no longer alerted when collection stops. |
| `NOTIFICATIONS_RESTORED` | Routine | Notifications and the action-needed alerts were turned back on. |
| `ALERT_DISMISSED` | Notice | An action-needed alert was dismissed while its problem lasted, so Crumbles posted it again. |
| `USER_ADDITION_ALLOWED` | Notice | In delegate mode, the Device Owner app lets users be added, so a user added and removed between two checks would pause collection without a record. |
| `USER_ADDITION_BLOCKED` | Routine | Users can no longer be added unseen: the Device Owner app disallows it, or Crumbles no longer collects as a delegate. |
| `DEVICE_POLICY_MANAGER_NOT_AVAILABLE` | Notice | `DevicePolicyManager` was unavailable when the app started. |
| `SETUP_NOTICE_ACKNOWLEDGED` | Notice | The user acknowledged the notice listing what Crumbles collects. |

### 3.2 Retrieval, Storage & Loss

| Event | Analyst | Written when |
| :-- | :-- | :-- |
| `LOG_RETRIEVAL_DEFERRED` | Notice | Retrieval was postponed: free storage was too low, the logs folder could not be created, or the logs kept from before a restart were refused, as while another user exists, or could be neither saved nor staged. |
| `LOGS_STAGED` | Routine | A batch was kept in sealed staging, to be encrypted later: no key was usable, or encrypting or saving it failed. |
| `LOGS_STAGING_FULL` | Notice | The 16 MiB staging area was full, so a batch was refused. |
| `STAGED_LOGS_UNREADABLE` | Problem | A staged batch failed authentication and was deleted: it was altered, or its device key is gone. |
| `LOGS_LOST` | Problem | Logs were lost: retrieval failed, a gap or reset in the platform's numbering showed dropped logs, a restart lost logs or the phone kept none from before it, the phone restarted again before retrieval, the boot count did not grow, a deferred network batch was lost, or a batch could be neither saved nor staged. |
| `ENCRYPT_FAILED` | Notice | Encrypting a retrieved batch failed. |
| `BATCH_WRAP_FAILED` | Notice | A batch was written without its batch-wrapped key, so reading it on the phone needs its own authentication. |
| `BATCH_SIGNING_FAILED` | Problem, or Notice for a re-encrypted copy | A batch was written without a signature or sequence number, or a re-encrypted copy without a new signature, because signing failed or the signing key's attestation chain could not be read. |
| `LOGS_STORAGE_CAP_APPROACHING` | Notice | Batches that cannot be reclaimed reached 80% of their cap. |
| `LOGS_STORAGE_CAP_REACHED` | Notice | Uploaded copies were reclaimed to admit a new batch; the record lists them. |
| `LOGS_COLLECTION_STOPPED` | Problem | Batches that cannot be reclaimed filled the 256 MiB cap, so a security batch was refused. |
| `NETWORK_LOGS_COLLECTION_STOPPED` | Problem | The same for a network batch, whose cap is 75% of 256 MiB. |

### 3.3 Key Management & Integrity

| Event | Analyst | Written when |
| :-- | :-- | :-- |
| `KEY_CHANGE_REQUESTED` | Notice | The user asked to change the encryption key; the record says how. |
| `KEY_CHANGE_AUTH_FAILED` | Notice | Key unchanged: the device credential was not confirmed, or the pending logs were not decrypted. |
| `KEY_CHANGE_ABANDONED` | Notice | Key unchanged: the screen was left before the change was confirmed. |
| `KEY_CHANGE_REFUSED` | Notice | Key unchanged: no secure lock screen is set, new logs arrived during the change, the decrypted logs were cleared, or storage was too low. |
| `KEY_INTERNAL_GENERATED` | Routine | A new built-in Keystore key pair was made active; the record gives its fingerprint. |
| `KEY_INTERNAL_GENERATION_FAILED` | Notice | Generating or switching to a built-in key pair failed, or no screen lock is set. |
| `KEYSTORE_KEY_STORAGE` | Routine | A built-in key pair was created in StrongBox (RSA-2048) or in the TEE (RSA-3072). |
| `KEYSTORE_KEY_INVALIDATED` | Problem | The Keystore permanently invalidated the built-in key pair, as when the screen lock is removed; logs are staged until a new key pair is set. |
| `KEY_EXPORTABLE_GENERATED` | Routine | A new exportable key pair was made active after the user confirmed offline custody. |
| `EXTERNAL_KEY_IMPORTED` | Routine | A scanned public key was confirmed by fingerprint and made active. |
| `EXTERNAL_KEY_IMPORT_REJECTED` | Notice | A scanned QR code was not a valid public key, its fingerprint could not be computed, or the user did not confirm it. |
| `EXTERNAL_KEY_IMPORT_FAILED` | Notice | A confirmed public key could not be saved, or a scanned re-encryption key could not be read. |
| `EXTERNAL_KEY_IMPORT_CANCELLED` | Notice | The device credential prompt for saving a re-encryption key was cancelled. |
| `EXTERNAL_KEY_IMPORT_REFUSED` | Notice | A re-encryption key was not saved: no secure lock screen is set. |
| `EXTERNAL_KEY_CLEARED` | Notice | The active external key was cleared. |
| `EXTERNAL_KEY_UNAVAILABLE` | Notice | The selected external key could not be read; the logs were not encrypted to any other key. |
| `KEY_PREFERENCES_ALTERED` | Problem | `user_key_prefs.pb` failed its integrity check, or was deleted after it had been written, and was replaced by an empty store. |
| `KEY_PREFERENCES_UNREADABLE` | Problem | `user_key_prefs.pb` could not be read, was kept as `user_key_prefs.pb.corrupt`, and was replaced by an empty store. |
| `PRIMARY_KEY_REPLACED` | Notice | The Keystore key protecting saved settings could no longer decrypt and was replaced; settings may need to be entered again. |
| `LOGS_DISCARDED` | Problem | The user discarded pending batches during a key change. |
| `LOGS_COPIED_BEFORE_KEY_CHANGE` | Routine | Pending batches were copied to a chosen folder before a key change. |
| `LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE` | Routine | Before a key change, pending batches that this phone could not decrypt were kept queued for upload, still encrypted to their original key. |
| `LOGS_COPY_BEFORE_KEY_CHANGE_FAILED` | Notice | Some pending batches could not be copied before a key change and stay on the phone. |
| `RE_ENCRYPT_FAILED` | Problem | Pending batches could not be re-encrypted after a key change. |
| `KEY_HANDOVER_NOT_NEEDED` | Routine | A key change needed no hand-over record, because no external key was active. |
| `KEY_HANDOVER_UPLOADED` | Routine | A record of the key change was uploaded for the holder of the outgoing key. |
| `KEY_HANDOVER_KEPT_ON_DEVICE` | Routine | No upload destination is set, so the hand-over record waits for background sync. |
| `KEY_HANDOVER_UPLOAD_FAILED` | Notice | The hand-over record could not be uploaded and waits for background sync. |
| `KEY_HANDOVER_NOT_SEALED` | Problem | The hand-over record could not be created, so the holder of the outgoing key is not told. |
| `RE_ENCRYPT_KEY_IMPORTED` | Routine | A re-encryption key was imported; the record gives its fingerprint. |
| `RE_ENCRYPT_KEY_REMOVED` | Notice | A re-encryption key was removed. |
| `RE_ENCRYPT_KEY_REMOVE_REFUSED` | Notice | A re-encryption key was kept: no secure lock screen is set. |
| `RE_ENCRYPT_KEY_REMOVE_AUTH_FAILED` | Notice | A re-encryption key was kept: the device credential was not confirmed for removing it. |
| `BATCH_SIGNING_KEY_ROTATED` | Notice | The device identifier changed, so the next batch is signed with a new attested key. |
| `BATCH_SIGNING_KEY_KEPT` | Notice | Hardware attribution changed, but the device identifier did not, so the batch-signing key was kept. |
| `BATCH_SIGNING_KEY_ROTATION_FAILED` | Notice | The device identifier changed, but the old signing key could not be deleted, so batches fail the attestation challenge check. |

### 3.4 Upload, Wipe & Decryption

| Event | Analyst | Written when |
| :-- | :-- | :-- |
| `UPLOAD_DESTINATION_CONFIGURED` | Routine | An upload folder (with a verified write grant) or a WebDAV destination was configured. |
| `UPLOAD_DESTINATION_AUTH_FAILED` | Notice | Destination unchanged: the device credential was not confirmed. |
| `UPLOAD_DESTINATION_REFUSED` | Notice | Destination unchanged: no secure lock screen is set. |
| `UPLOAD_DESTINATION_ABANDONED` | Notice | Destination unchanged: the app left the screen before a new one was chosen or while a notice of the change was sent, or the user kept the destination after a notice that it did not confirm (the record gives the hand-over outcome). |
| `DESTINATION_HANDOVER_NOT_NEEDED` | Routine | A destination change needed no notice, because no external key is active. |
| `DESTINATION_HANDOVER_UPLOADED` | Routine | Before the destination changed, a notice of the change, sealed to the external key, was uploaded to the outgoing WebDAV server, which confirmed it. |
| `DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED` | Problem | The storage app of the outgoing upload folder took the notice of the destination change. It can keep the notice on the phone without ever syncing it, and nothing shows whether it did, so the change needed the user's confirmation. |
| `DESTINATION_HANDOVER_UPLOADED_OFFLINE` | Problem | The same, while the phone had no validated internet connection. |
| `DESTINATION_HANDOVER_KEPT_ON_DEVICE` | Routine | No upload destination was set, so the notice of the destination change waits for background sync. |
| `DESTINATION_HANDOVER_UPLOAD_FAILED` | Problem | The notice of the destination change could not be uploaded to the outgoing destination, or the user stopped waiting before its upload began, so the change needed the user's confirmation. The notice waits for background sync, which sends it to the destination set by then. |
| `DESTINATION_HANDOVER_NOT_SEALED` | Problem | The notice of the destination change could not be created, so the holder of the external key is not told. |
| `DESTINATION_CHANGED_WITHOUT_HANDOVER` | Problem | The user changed the destination although the outgoing destination did not confirm the notice (the record gives the hand-over outcome, `UPLOAD_FAILED` also when the user stopped waiting for it). A second notice is then sealed, so that the next notice sealed carries this record, and sent to the outgoing destination before the change, with its own `DESTINATION_HANDOVER_*` record. If the user does not wait for it, it waits for background sync to the new destination. |
| `UPLOAD_DESTINATION_NOT_CONFIGURED` | Notice | Upload deferred: no upload folder, or no WebDAV server or credentials, are configured. |
| `UPLOAD_DESTINATION_PERMISSION_REVOKED` | Notice | Upload failed: the write grant for the upload folder is missing or was revoked. |
| `UPLOAD_DESTINATION_INVALID` | Notice | Upload deferred: the upload folder is inaccessible or not writable. |
| `UPLOAD_CREDENTIALS_DECRYPTION_FAILED` | Notice | Upload deferred: the saved WebDAV credentials could not be decrypted. |
| `UPLOAD_SERVER_KEY_NOT_CONFIRMED` | Notice | Upload refused: no key was confirmed for the HTTPS WebDAV server. |
| `UPLOAD_SERVER_KEY_REJECTED` | Problem | Upload refused: the WebDAV server presented a key other than the confirmed one. |
| `LOGS_UPLOAD_DEFERRED_NO_KEY` | Notice | Upload deferred: no encryption key is usable. |
| `LOGS_UPLOAD_SUCCESS` | Routine | Batches were uploaded and marked `_sent.bin`. |
| `LOGS_UPLOAD_FAILED` | Notice | Batches failed to upload and stay on the phone for retry. |
| `LOGS_UPLOAD_RECOVERED_PROCESSING` | Routine | Batches left by an interrupted upload run were recovered for retry. |
| `KEPT_COPIES_DELETED` | Routine | Uploaded copies were deleted 7 days after their upload. |
| `KEPT_COPY_RESENT` | Notice | Uploaded copies missing from the upload folder were sent again. |
| `UPLOAD_AND_WIPE_REQUESTED` | Routine | **Upload now and wipe** or the **Sync now** tile asked to upload and delete every pending batch. |
| `UPLOAD_AND_WIPE_SENT_KEPT` | Routine | Uploaded batches were kept on the phone because Google Drive may still be syncing them. |
| `UPLOAD_AND_WIPE_FINISHED` | Routine | Uploaded batches were deleted; the record counts the batches that could not be uploaded. |
| `UPLOAD_AND_WIPE_FORCED` | Problem | **Wipe anyway** deleted batches, including ones that were not uploaded, after the device credential was confirmed. |
| `UPLOAD_AND_WIPE_FORCED_AUTH_FAILED` | Notice | **Wipe anyway** was cancelled: the device credential was not confirmed. |
| `UPLOAD_AND_WIPE_FORCED_REFUSED` | Notice | **Wipe anyway** was refused: no screen lock is set. |
| `DECRYPTION_SUCCESS` | Routine | The user decrypted a batch in the app. |
| `DECRYPTION_FAILURE` | Notice | In-app decryption of a batch failed. |
| `LOGS_RE_ENCRYPTED` | Routine | Decrypted batches were re-encrypted to a chosen key, to share them; the record gives its fingerprint. |

### 3.5 Activity Log

| Event | Analyst | Written when |
| :-- | :-- | :-- |
| `AUDIT_LOG_VIEWED` | Routine | The user authenticated and opened the activity log. |
| `AUDIT_LOG_VIEW_AUTH_FAILED` | Notice | The activity log was not shown: the user did not authenticate. |
| `AUDIT_LOG_VIEW_REFUSED` | Notice | The activity log was not shown: no secure lock screen is set. |
| `AUDIT_LOG_CLEAR_REQUESTED` | Problem | The user asked to clear the activity log. |
| `AUDIT_LOG_CLEAR_AUTH_FAILED` | Notice | The activity log was kept: the device credential was not confirmed. |
| `AUDIT_LOG_CLEAR_REFUSED` | Notice | The activity log was kept: no secure lock screen is set, or the records not yet shipped could not be sealed into a batch first. |
| `AUDIT_LOG_CLEAR_SEAL_FAILED` | Problem | The records not yet shipped could not be sealed into a batch before clearing, so the activity log was kept. |
| `AUDIT_LOG_CLEARED` | Problem | First record after the activity log was cleared; it counts the removed records. |
| `AUDIT_LOG_ROTATED` | Notice | The activity log file reached 1 MiB and was rotated; the record names the last tag of the old file. |
| `AUDIT_LOG_KEY_REPLACED` | Problem | The key that seals the activity log could not be recovered and was replaced; earlier records can no longer be read. |
| `AUDIT_RECORDS_DROPPED` | Problem | Records could not be written; the record counts them and gives the time span. |
| `AUDIT_EVENTS_RATE_LIMITED` | Problem if it names a Problem event, otherwise Notice | More than 60 events of one type arrived within an hour; the rest were counted instead of recorded. |
