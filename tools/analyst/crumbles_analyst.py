# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Decrypts Crumbles log batches with the recipient's RSA private key.

Crumbles encrypts each batch with AES-256-GCM under a fresh key, which it wraps
with the recipient's RSA public key (see src/main/logs.proto and
CrumblesLogsEncryptor). Needs Python 3.10 or later and the packages in
requirements.txt: `pip install -r requirements.txt`.

Newer batches pad the logs to hide their size. Format version 2 batches also
encrypt the timestamp and the device ID of the batch, and the attestation chain
of the key that signs it, with the logs, and bind them to the recipient's key.

Usage: python3 crumbles_analyst.py --key KEY_FILE... [--out DIR]
    [--app-cert SHA256]... [--boot-key SHA256]...
    [--attestation-status STATUS_FILE]... BATCH_OR_DIR...

KEY_FILE holds the RSA private key: PEM, or the Base64 text that Crumbles shows
for a key pair it generated. Directories are searched for .bin files. A batch
file must be a regular file of at most 64 MiB, and is not read through a
symbolic link. With --out, the decrypted logs are written to DIR (or
DIR/unverified when a batch is unsigned, fails signature checks, or fails
--app-cert or --boot-key). The exit status is 1 if a batch cannot be decrypted
or fails a check.

The logs of each batch end with a trailer from the app's activity log: the tag
of the last activity record sent in the previous batch, the new records, and
the tag of the newest record (the chain head). In the order the batches were
written, each batch must start at the chain head of the one before.

Crumbles also signs each batch with a hardware key, which a chain of
certificates attests up to a Google hardware attestation root. The script
checks the signature and the chain, which a format version 2 batch encrypts:
until it is decrypted, only a key that another batch attests can check it. It
also checks what the attestation says about the key, that each device signs
with one key, and that the sequence numbers of each device have no gaps or
repeats. They need not start at 1: a set of recent batches can be checked on
its own.

Anyone can build an app named com.android.securelogging, so the script also
prints the SHA-256 digests of the certificates that sign the app that made the
key, which must not change for a device. With --app-cert, which can be
repeated, that app must be signed by one of the given certificates: that of
the official release, or of a build of your own or of a custom ROM.

An altered OS could make up logs, and the package and certificates that it
reports for the app. So the attestation must also say that the bootloader was
locked and that verified boot accepted the OS: signed with the device maker's
key ("Verified"), or with that of a custom ROM such as CalyxOS ("SelfSigned").
The report shows the state and the verified boot key. Anyone can sign a custom
ROM, so a custom ROM requires --boot-key, which can be repeated; when
--boot-key is given, every device's verified boot key (whether SelfSigned or
Verified) must be one of the given keys.

Google revokes attestation keys that leaked, as anyone who has one can attest
anything, and lists them at https://android.googleapis.com/attestation/status.
The script works offline: with --attestation-status, no certificate of an
attestation chain may be in STATUS_FILE, a downloaded copy of that list. Keep
every copy, as later ones may drop expired keys, and give each of them.
"""

import argparse
import base64
import collections
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
import dataclasses
import datetime
import getpass
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import types

from cryptography import exceptions
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import aead
from google.protobuf import descriptor_pb2
from google.protobuf import descriptor_pool
from google.protobuf import message
from google.protobuf import message_factory

# The fields of src/main/logs.proto that batch files use, as (name, number,
# type) for each message, so that this script needs no generated code. Enums
# are read as int32 and strings as bytes, which have the same wire encoding, so
# that every value survives parsing unchanged.
# LINT.IfChange
LOGS_PROTO = {
    # As in google/protobuf/timestamp.proto. Crumbles never writes the zero
    # values that proto3 would drop.
    "Timestamp": [("seconds", 1, "int64"), ("nanos", 2, "int32")],
    "DeviceId": [("device_id", 1, "bytes")],
    "LogData": [("log_blob", 1, "bytes")],
    "LogMetadata": [
        ("blob_size", 1, "uint32"),
        ("timestamp", 2, "Timestamp"),
        ("device", 3, "DeviceId"),
        ("encryption_type", 4, "int32"),
    ],
    "LogKey": [
        ("key_encryption_type", 1, "int32"),
        ("encrypted_symmetric_key", 2, "bytes"),
        ("iv", 3, "bytes"),
    ],
    "LogBatch": [
        ("data", 1, "LogData"),
        ("key", 2, "LogKey"),
        ("metadata", 3, "LogMetadata"),
        ("sequence_number", 4, "int64"),
        ("signature", 5, "BatchSignature"),
    ],
    "BatchSignature": [
        ("signature", 1, "bytes"),
        ("attestation_chain", 2, "repeated bytes"),
    ],
    # What a format version 2 batch pads and encrypts.
    "SealedLogs": [
        ("metadata", 1, "LogMetadata"),
        ("logs", 2, "bytes"),
        ("attestation_chain", 3, "repeated bytes"),
    ],
}
# The LogEncryptionType values of the batches that pad what they encrypt: the
# logs, or a SealedLogs (format version 2). Other batches encrypt the logs.
LOG_ENCRYPTION_TYPE_AES_GCM_PADDED = 2
LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA = 3
# The KeyEncryptionType values of the batches that this script decrypts.
KEY_ENCRYPTION_TYPE_ASYMMETRIC = 1  # RSA with PKCS#1 v1.5 padding.
KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256 = 4
# LINT.ThenChange(../../src/main/logs.proto)

# How each KeyEncryptionType wraps the AES key.
_KEY_WRAPS = {
    KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256: padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
        label=None),
    KEY_ENCRYPTION_TYPE_ASYMMETRIC: padding.PKCS1v15(),
}
# The name of each KeyEncryptionType in reports.
_KEY_WRAP_NAMES = {
    KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256: "RSA-OAEP-SHA256",
    KEY_ENCRYPTION_TYPE_ASYMMETRIC: "RSA-PKCS1v1.5 (legacy)",
}
_AES_KEY_BYTES = 32
_GCM_IV_BYTES = 12
# The associated data of a format version 2 batch starts with this label.
_V2_LABEL = b"crumbles/v2/batch"
# A padded plaintext starts with the size of what it pads, as a big-endian
# integer of this many bytes.
_LENGTH_BYTES = 4
# The tag of LogKey.key_encryption_type: field 1, varint wire type.
_KEY_ENCRYPTION_TYPE_TAG = b"\x08"
# The package of the message classes made from LOGS_PROTO.
_PACKAGE = "crumbles"
# How LOGS_PROTO marks repeated fields.
_REPEATED = "repeated "
# The fields that every batch has.
_BATCH_PARTS = ("data", "key", "metadata")
_PEM_MARKER = b"-----BEGIN"
# Only the user can read the decrypted logs.
_LOGS_DIRECTORY_MODE = 0o700
_LOGS_FILE_MODE = 0o600
# The largest batch file that is read, as the app limits the files that it
# decrypts (MAX_DECRYPTION_INPUT_FILE_SIZE_BYTES in CrumblesConstants), so that
# a huge or endless file cannot exhaust memory.
_MAX_BATCH_FILE_SIZE = 64 * 1024 * 1024

# The activity log trailer at the end of the logs, as CrumblesAuditExcerpt
# writes it: the tag of the previous batch's last record, a marker line if the
# device no longer has that record, the new records (JSON objects, one per
# line), and the tag of the newest record. Tags are HMAC-SHA256 values in lower
# case hex, or "none". Groups: since tag, marker, records, head tag.
# Matches (from the last "since record" line to the end of the logs):
#   --- Crumbles activity log since record none ---
#   {"timestamp":1760000000000000000,"eventType":"KEY_VIEWED",...}
#   --- Crumbles activity log chain head: <64 lower case hex digits> ---
# Does not match: tags in upper case or of another length, record lines that
# do not start with "{", or anything after the chain head line.
_SINCE_PREFIX = b"\n--- Crumbles activity log since record "
_TRAILER = re.compile(
    re.escape(_SINCE_PREFIX) + rb"([0-9a-f]{64}|none) ---\n"
    rb"(--- The previous batch's last activity record is no longer on this "
    rb"device ---\n)?"
    rb"((?:\{[^\n]*\n)*)"
    rb"--- Crumbles activity log chain head: ([0-9a-f]{64}|none) ---\n")

# SHA-256 of the SubjectPublicKeyInfo of the Google hardware attestation roots
# published at https://android.googleapis.com/attestation/root: the RSA key of
# all the "f92009e853b6b045" roots, and the EC key of Key Attestation CA1.
GOOGLE_ROOT_KEYS = frozenset([
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
])
# The statuses of attestation certificates when there is no status list.
_NO_STATUSES: Mapping[str, str] = types.MappingProxyType({})
# The curve of batch-signing keys.
_SIGNING_CURVE = "secp256r1"
# The problem of a signed batch whose attestation chain is missing, or sealed
# with logs that no key decrypts.
_NO_CHAIN = "no attestation certificates"
# Protobuf field tags hold the field number above a 3-bit wire type. These are
# the wire types of batch files, and the sizes of the fixed-size ones.
_FIELD_NUMBER_SHIFT = 3
_WIRE_TYPE_MASK = 0b111
_VARINT = 0
_LENGTH_DELIMITED = 2
_FIXED_SIZES = {1: 8, 5: 4}  # I64 and I32, by wire type.
# How many hex digits of the SHA-256 of a signing key identify it in reports.
_FINGERPRINT_DIGITS = 16
# The Android key attestation extension of the signing key's certificate. It
# holds a KeyDescription: a SEQUENCE whose fields are read by position.
_ATTESTATION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
# The ProvisioningInfoMap extension on RKP intermediate certificates.
_PROVISIONING_INFO_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")
_ATTESTATION_SECURITY_LEVEL = 1
_KEYMINT_SECURITY_LEVEL = 3
_ATTESTATION_CHALLENGE = 4
_SOFTWARE_ENFORCED = 6
_HARDWARE_ENFORCED = 7
# The identifier octets of creationDateTime ([701] EXPLICIT) and origin ([702]
# EXPLICIT), and KeyOrigin KM_ORIGIN_GENERATED (0).
_CREATION_DATETIME_TAG = b"\xbf\x85\x3d"
_ORIGIN_TAG = b"\xbf\x85\x3e"
_ORIGIN_GENERATED = b"\x00"
# The identifier octets of attestationApplicationId, which is [709] EXPLICIT.
_APPLICATION_ID_TAG = b"\xbf\x85\x45"
_PACKAGE_NAME = b"com.android.securelogging"
# The identifier octets of rootOfTrust, which is [704] EXPLICIT.
_ROOT_OF_TRUST_TAG = b"\xbf\x85\x40"
# The VerifiedBootState values (ENUMERATED contents) of an OS that verified
# boot accepted: signed with the device maker's key, or with a key that the
# user installed with a custom ROM such as CalyxOS or GrapheneOS.
_SELF_SIGNED = "SelfSigned"
_BOOT_STATES = {b"\x00": "Verified", b"\x01": _SELF_SIGNED}
# The SecurityLevel values (ENUMERATED contents) of keys in secure hardware.
_SECURITY_LEVELS = {b"\x01": "TEE", b"\x02": "StrongBox"}


def _message_classes() -> dict[str, type[message.Message]]:
  """Makes a message class for each message of LOGS_PROTO.

  Returns:
    The message classes, by message name.
  """
  field_type = descriptor_pb2.FieldDescriptorProto
  file_proto = descriptor_pb2.FileDescriptorProto(
      name="crumbles_analyst_logs.proto", package=_PACKAGE)

  for message_name, fields in LOGS_PROTO.items():
    message_proto = file_proto.message_type.add(name=message_name)
    for field_name, number, type_name in fields:
      label = field_type.LABEL_OPTIONAL
      if type_name.startswith(_REPEATED):
        label = field_type.LABEL_REPEATED
        type_name = type_name.removeprefix(_REPEATED)
      field = message_proto.field.add(
          name=field_name, number=number, label=label)
      if type_name in LOGS_PROTO:
        field.type = field_type.TYPE_MESSAGE
        field.type_name = f".{_PACKAGE}.{type_name}"
      else:
        field.type = field_type.Type.Value(f"TYPE_{type_name.upper()}")

  pool = descriptor_pool.DescriptorPool()
  pool.AddSerializedFile(file_proto.SerializeToString())
  return {
      name: message_factory.GetMessageClass(
          pool.FindMessageTypeByName(f"{_PACKAGE}.{name}"))
      for name in LOGS_PROTO
  }


_MESSAGE_CLASSES = _message_classes()
# The class of batch files.
LogBatch = _MESSAGE_CLASSES["LogBatch"]
# The class of what a format version 2 batch pads and encrypts.
SealedLogs = _MESSAGE_CLASSES["SealedLogs"]
# The number of the LogBatch field that holds the signature.
_SIGNATURE_FIELD = LogBatch.DESCRIPTOR.fields_by_name["signature"].number


class BatchError(Exception):
  """A batch cannot be read, or fails a check."""


@dataclasses.dataclass(frozen=True, kw_only=True)
class DecryptedBatch:
  """What a batch holds, decrypted.

  Attributes:
    metadata: The LogMetadata of the batch. That of a format version 2 batch
      includes the timestamp and the device ID sealed in the batch.
    logs: The logs, without padding.
    attestation_chain: The DER attestation certificates of the key that signs a
      format version 2 batch, leaf first, as sealed in the batch. Empty if the
      batch seals none, as batches of other formats.
  """

  metadata: message.Message
  logs: bytes
  attestation_chain: tuple[bytes, ...] = ()


@dataclasses.dataclass(frozen=True, kw_only=True)
class Trailer:
  """The activity log trailer of the logs of a batch.

  Attributes:
    since: The tag of the previous batch's last record, or "none".
    head: The tag of the newest record, the chain head, or "none".
    records: The number of new records.
    previous_record_missing: Whether the device no longer had the previous
      batch's last record.
    first_seq: The sequence number of the first new record.
    last_seq: The sequence number of the last new record.
    problems: Problems found in the trailer records.
    notices: Notices found in the trailer records.
    leading_sealed: The number of sealed records before first_seq.
  """

  since: str
  head: str
  records: int
  previous_record_missing: bool
  first_seq: int | None
  last_seq: int | None
  problems: tuple[str, ...]
  notices: tuple[str, ...] = ()
  leading_sealed: int = 0


@dataclasses.dataclass(frozen=True, kw_only=True)
class Signer:
  """The key that signed a batch.

  Attributes:
    key: The DER SubjectPublicKeyInfo of the key.
    security_level: Where the key lives: "TEE" or "StrongBox".
    app_certificates: The SHA-256 digests of the certificates that sign the
      app that made the key, as its attestation names them.
    boot_state: How verified boot checked the OS that made the key:
      "Verified" with the device maker's key, or "SelfSigned" with a key that
      the user installed, such as that of a custom ROM.
    boot_key: The verified boot key of the attestation: a digest of the key
      that the OS is signed with.
    device_id: The device ID from the key's attestation challenge.
  """

  key: bytes
  security_level: str
  app_certificates: tuple[bytes, ...]
  boot_state: str
  boot_key: bytes
  device_id: bytes


@dataclasses.dataclass(frozen=True, kw_only=True)
class Result:
  """What was found in one batch file.

  Attributes:
    path: The batch file.
    batch: The LogBatch in the file, or an empty one if the file holds none.
    metadata: The LogMetadata of the batch. If a format version 2 batch was
      decrypted, it includes the timestamp and the device ID sealed in it.
    plaintext: The decrypted logs, or None if the batch was not decrypted.
    trailer: The activity log trailer of the logs, or None if it was not read.
    signer: The key that signed the batch, or None if the signature is bad.
    signer_trusted: Whether the batch has a valid signer that satisfies
      --app-cert and --boot-key.
    out_path: The file that the decrypted logs were written to, or None.
    problems: What is wrong with the batch.
    notices: Informational notices about the batch.
    signed_digest: The SHA-256 digest of what the signature of a format version
      2 batch that no key decrypted covers, or None.
  """

  path: pathlib.Path
  batch: message.Message
  metadata: message.Message
  plaintext: bytes | None = None
  trailer: Trailer | None = None
  signer: Signer | None = None
  signer_trusted: bool = False
  out_path: pathlib.Path | None = None
  problems: tuple[str, ...] = ()
  notices: tuple[str, ...] = ()
  signed_digest: bytes | None = None


def load_private_key(
    key_data: bytes,
    ask_password: Callable[[str], str] = getpass.getpass,
) -> rsa.RSAPrivateKey:
  """Loads an RSA private key from PEM, or from Base64 PKCS#8 DER.

  Args:
    key_data: The contents of the key file.
    ask_password: Called with a prompt to get the passphrase of an encrypted
      key.

  Returns:
    The RSA private key.

  Raises:
    ValueError: If key_data does not hold an RSA private key.
  """
  if _PEM_MARKER in key_data:
    load = serialization.load_pem_private_key
  else:  # Base64 decoding skips the line breaks of a copied key.
    load = serialization.load_der_private_key
    key_data = base64.b64decode(key_data)

  try:
    key = load(key_data, password=None)
  except TypeError:  # The key is encrypted.
    key = load(key_data, password=ask_password("Key passphrase: ").encode())

  if not isinstance(key, rsa.RSAPrivateKey):
    raise ValueError("not an RSA private key")

  return key


def load_attestation_status(status_data: bytes) -> dict[str, str]:
  """Reads Google's list of revoked and suspended attestation certificates.

  Args:
    status_data: A copy of https://android.googleapis.com/attestation/status:
      JSON whose "entries" map serial numbers, in lower case hex, to the status
      of a certificate and maybe a reason.

  Returns:
    The status and reason of each listed certificate, by serial number.

  Raises:
    ValueError: If status_data is not such a list, or lists no certificate.
  """
  statuses = {}
  try:
    for serial, entry in json.loads(status_data)["entries"].items():
      try:
        normalized_serial = f"{int(serial, 16):x}"
      except ValueError:
        continue
      reason = entry.get("reason")
      statuses[normalized_serial] = (
          f"{entry['status']} ({reason})" if reason else entry["status"])
  except (AttributeError, KeyError, TypeError) as e:
    raise ValueError(f"not an attestation status list: {e!r}") from None
  if not statuses:  # Google's list is never empty.
    raise ValueError("the attestation status list has no entries")
  return statuses


def parse_batch(data: bytes) -> message.Message:
  """Parses a batch file.

  Args:
    data: The contents of the batch file.

  Returns:
    The LogBatch in data.

  Raises:
    BatchError: If data does not hold a LogBatch with data, a key and metadata.
  """
  batch = LogBatch()
  try:
    batch.ParseFromString(data)
  except message.DecodeError as e:
    raise BatchError("not a Crumbles log batch") from e

  missing = [part for part in _BATCH_PARTS if not batch.HasField(part)]
  if missing:
    raise BatchError(f"not a Crumbles log batch: no {', '.join(missing)}")

  return batch


def associated_data(
    metadata: message.Message,
    key_encryption_type: int,
    recipient_public_key_der: bytes = b"",
) -> bytes:
  """Computes what CrumblesLogsEncryptor.computeAssociatedData computes.

  That is the serialization of the metadata (deterministic, as LogMetadata has
  no maps), followed by the key encryption type as an untagged int32 varint.
  For a format version 2 batch, a label comes first, and the SHA-256 digest of
  the recipient's public key comes last, which binds the batch to the key that
  its AES key is wrapped with.

  Args:
    metadata: The cleartext LogMetadata of the batch.
    key_encryption_type: The KeyEncryptionType number of the batch.
    recipient_public_key_der: The DER SubjectPublicKeyInfo of the recipient's
      public key. Only format version 2 batches bind it, so it may be empty for
      the batches of earlier formats.

  Returns:
    The associated data that AES-GCM authenticates along with the logs.

  Raises:
    ValueError: If metadata is that of a format version 2 batch and
      recipient_public_key_der is empty.
  """
  log_key = _MESSAGE_CLASSES["LogKey"](key_encryption_type=key_encryption_type)
  untagged_type = log_key.SerializeToString().removeprefix(
      _KEY_ENCRYPTION_TYPE_TAG)
  if metadata.encryption_type != LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA:
    return metadata.SerializeToString() + untagged_type
  if not recipient_public_key_der:
    raise ValueError("a format version 2 batch is bound to its recipient")
  return (
      _V2_LABEL
      + metadata.SerializeToString()
      + untagged_type
      + hashlib.sha256(recipient_public_key_der).digest()
  )


def decrypt_batch(
    batch: message.Message,
    private_key: rsa.RSAPrivateKey,
    allow_pkcs1: bool = False,
) -> DecryptedBatch:
  """Decrypts the logs of a batch, and the metadata sealed with them.

  Args:
    batch: The LogBatch to decrypt.
    private_key: The recipient's RSA private key.
    allow_pkcs1: Whether to accept the legacy RSA-PKCS1v1.5 key wrap.

  Returns:
    The logs, the metadata and the sealed attestation chain of the batch.

  Raises:
    BatchError: If the batch cannot be decrypted with private_key, its logs or
      metadata were altered, it is a format version 2 batch bound to another
      recipient, or what it encrypts is malformed.
  """
  key_type = batch.key.key_encryption_type
  if key_type == KEY_ENCRYPTION_TYPE_ASYMMETRIC and not allow_pkcs1:
    raise BatchError(
        "key wrap RSA-PKCS1v1.5 (legacy) is refused unless --allow-pkcs1 is "
        "given"
    )
  if key_type not in _KEY_WRAPS:
    raise BatchError(f"unsupported key encryption type {key_type}")

  if len(batch.key.iv) != _GCM_IV_BYTES:
    raise BatchError(
        f"the IV has {len(batch.key.iv)} bytes instead of {_GCM_IV_BYTES}")

  try:
    aes_key = private_key.decrypt(
        batch.key.encrypted_symmetric_key, _KEY_WRAPS[key_type])
  except ValueError:  # Reported below, with keys of the wrong size.
    aes_key = b""
  if len(aes_key) != _AES_KEY_BYTES:
    raise BatchError("cannot unwrap the AES key: the batch was encrypted to "
                     "another key, or it is corrupt")

  recipient_der = private_key.public_key().public_bytes(
      serialization.Encoding.DER,
      serialization.PublicFormat.SubjectPublicKeyInfo,
  )
  aad = associated_data(batch.metadata, key_type, recipient_der)
  try:
    plaintext = aead.AESGCM(aes_key).decrypt(
        batch.key.iv, batch.data.log_blob, aad)
  except exceptions.InvalidTag:
    raise BatchError(
        "AES-GCM authentication failed: the logs or the metadata were "
        "altered, or the batch is bound to another recipient"
    ) from None
  return _unpack(batch.metadata, plaintext)


def _decrypt(
    batch: message.Message,
    private_keys: Iterable[rsa.RSAPrivateKey],
    allow_pkcs1: bool,
) -> DecryptedBatch:
  """Runs decrypt_batch with each key in turn, until one decrypts batch."""
  errors = []
  for private_key in private_keys:
    try:
      return decrypt_batch(batch, private_key, allow_pkcs1)
    except BatchError as e:
      errors.append(str(e))
  raise BatchError("; ".join(dict.fromkeys(errors)))


def _strip_padding(padded: bytes) -> bytes:
  """Removes the padding from the plaintext of a padded batch.

  The plaintext starts with the size of what it pads, as a 4-byte big-endian
  integer, and zero bytes follow up to the size bucket of the batch. Like
  Crumbles, this does not check the zero bytes, which AES-GCM authenticates.

  Args:
    padded: The plaintext of a padded batch.

  Returns:
    What padded pads.

  Raises:
    BatchError: If padded declares more bytes than it holds.
  """
  length = int.from_bytes(padded[:_LENGTH_BYTES], "big")
  if length > len(padded) - _LENGTH_BYTES:
    raise BatchError("the padded logs declare more bytes than they hold")
  return padded[_LENGTH_BYTES:_LENGTH_BYTES + length]


def _unpack(metadata: message.Message, plaintext: bytes) -> DecryptedBatch:
  """Finds the logs and the metadata in the plaintext of a batch.

  As in CrumblesLogsEncryptor.decryptedLogBatch: a padded batch pads its logs,
  and a format version 2 batch pads a SealedLogs, which holds the logs with the
  timestamp and the device ID that its cleartext metadata leaves out, and the
  attestation chain that its signature leaves out. Other batches encrypt the
  logs alone.

  Args:
    metadata: The cleartext LogMetadata of the batch.
    plaintext: What the batch encrypts.

  Returns:
    The logs, the metadata and the sealed attestation chain of the batch.

  Raises:
    BatchError: If plaintext does not have the layout that the encryption type
      of the batch announces.
  """
  if metadata.encryption_type not in (
      LOG_ENCRYPTION_TYPE_AES_GCM_PADDED,
      LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA):
    return DecryptedBatch(metadata=metadata, logs=plaintext)
  contents = _strip_padding(plaintext)
  if metadata.encryption_type == LOG_ENCRYPTION_TYPE_AES_GCM_PADDED:
    return DecryptedBatch(metadata=metadata, logs=contents)
  sealed_logs = SealedLogs()
  try:
    sealed_logs.ParseFromString(contents)
  except message.DecodeError:
    raise BatchError("malformed sealed logs") from None
  unsealed = _MESSAGE_CLASSES["LogMetadata"]()
  unsealed.CopyFrom(metadata)
  if sealed_logs.metadata.HasField("timestamp"):
    unsealed.timestamp.CopyFrom(sealed_logs.metadata.timestamp)
  if sealed_logs.metadata.HasField("device"):
    unsealed.device.CopyFrom(sealed_logs.metadata.device)
  return DecryptedBatch(
      metadata=unsealed,
      logs=sealed_logs.logs,
      attestation_chain=tuple(sealed_logs.attestation_chain),
  )


_TAMPER_EVENTS = frozenset([
    "AUDIT_LOG_CLEARED",
    "AUDIT_LOG_CLEAR_REQUESTED",
    "AUDIT_LOG_CLEAR_SEAL_FAILED",
    "AUDIT_LOG_KEY_REPLACED",
    "AUDIT_RECORDS_DROPPED",
    "COLLECTION_PAUSED_SECONDARY_USER",
    "DESTINATION_HANDOVER_NOT_SEALED",
    "DEVICE_ADMIN_DISABLED",
    "FINAL_BATCH_FAILED",
    "KEYSTORE_KEY_INVALIDATED",
    "KEY_HANDOVER_NOT_SEALED",
    "KEY_PREFERENCES_ALTERED",
    "KEY_PREFERENCES_UNREADABLE",
    "LOGS_COLLECTION_STOPPED",
    "LOGS_DISCARDED",
    "LOGS_LOST",
    "NETWORK_LOGGING_ACCESS_LOST",
    "NETWORK_LOGS_COLLECTION_STOPPED",
    "PAUSE_BATCH_FAILED",
    "RE_ENCRYPT_FAILED",
    "SECURITY_LOGGING_ACCESS_LOST",
    "STAGED_LOGS_UNREADABLE",
    "UPLOAD_AND_WIPE_FORCED",
    "UPLOAD_SERVER_KEY_REJECTED",
])
# The app rate-limits every event type, tamper ones included; the record saying
# so names the type, which decides whether it hides tamper evidence.
_TAMPER_EVENT_NAMES = re.compile(
    r"\b(?:" + "|".join(map(re.escape, sorted(_TAMPER_EVENTS))) + r")\b")
# A batch that the app writes unsigned has no sequence number, so deleting it
# leaves no gap: only a re-encrypted copy that could not be signed again (as
# the app words it below) makes BATCH_SIGNING_FAILED a notice.
_RESIGNING_FAILED_PREFIX = "Re-encrypted log batch "
# Known notice events include AUDIT_LOG_ROTATED,
# COLLECTION_PAUSED, EXTERNAL_KEY_UNAVAILABLE, LOGS_STORAGE_CAP_REACHED,
# LOG_RETRIEVAL_DEFERRED, NETWORK_COLLECTION_SCOPE_CHANGED,
# NETWORK_LOGGING_DISABLED, SECURITY_LOGGING_DISABLED; any non-routine event
# outside _ROUTINE_AUDIT_EVENTS surfaces as a notice.
_ROUTINE_AUDIT_EVENTS = frozenset([
    "AUDIT_LOG_VIEWED",
    "DECRYPTION_SUCCESS",
    "DESTINATION_HANDOVER_KEPT_ON_DEVICE",
    "DESTINATION_HANDOVER_NOT_NEEDED",
    "DESTINATION_HANDOVER_UPLOADED",
    "EXTERNAL_KEY_IMPORTED",
    "KEYSTORE_KEY_STORAGE",
    "KEY_EXPORTABLE_GENERATED",
    "KEY_HANDOVER_KEPT_ON_DEVICE",
    "KEY_HANDOVER_NOT_NEEDED",
    "KEY_HANDOVER_UPLOADED",
    "KEY_INTERNAL_GENERATED",
    "KEPT_COPIES_DELETED",
    "LOGS_COPIED_BEFORE_KEY_CHANGE",
    "LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE",
    "LOGS_RE_ENCRYPTED",
    "LOGS_STAGED",
    "LOGS_UPLOAD_RECOVERED_PROCESSING",
    "LOGS_UPLOAD_SUCCESS",
    "NOTIFICATIONS_RESTORED",
    "RE_ENCRYPT_KEY_IMPORTED",
    "SECURITY_LOGGING_ENABLED",
    "UPLOAD_AND_WIPE_FINISHED",
    "UPLOAD_AND_WIPE_REQUESTED",
    "UPLOAD_AND_WIPE_SENT_KEPT",
    "UPLOAD_DESTINATION_CONFIGURED",
    "USER_ADDITION_BLOCKED",
])
_CLEAR_LOSS_TERMS = ("sealed", "unpersisted", "dropped")
_PAUSE_BATCH_PREFIXES = (
    b"Crumbles: Collection paused: secondary or guest user present",
    b"Collection paused: secondary or guest user present",
)


def _message_mentions(record_msg: object, terms: tuple[str, ...]) -> bool:
  """Returns whether record_msg is a string mentioning any term in terms."""
  if not isinstance(record_msg, str):
    return False
  lowered = record_msg.lower()
  return any(term in lowered for term in terms)


def parse_trailer(plaintext: bytes) -> Trailer:
  """Parses the activity log trailer at the end of the logs of a batch.

  The logs before the trailer can contain attacker-controlled text, so the
  trailer starts at the last line that starts like one.

  Args:
    plaintext: The decrypted logs of a batch.

  Returns:
    The trailer.

  Raises:
    BatchError: If the logs have no trailer, or it is malformed.
  """
  start = plaintext.rfind(_SINCE_PREFIX)
  if start < 0:
    raise BatchError("no activity log trailer")
  trailer_match = _TRAILER.fullmatch(plaintext, start)
  if not trailer_match:
    raise BatchError("malformed activity log trailer")
  since, marker, records_bytes, head = trailer_match.groups()

  problems = []
  notices = []
  first_seq = None
  last_seq = None
  leading_sealed = 0
  num_records = 0
  last_record_tag = None

  for line in records_bytes.strip().split(b"\n"):
    if not line:
      continue
    num_records += 1
    try:
      record = json.loads(line)
      seq = record.get("sequenceNumber")
      if record.get("sealed"):
        problems.append("could not be unsealed on the device")
        if last_seq is not None:
          last_seq += 1
        else:
          leading_sealed += 1
      else:
        if isinstance(seq, int) and not isinstance(seq, bool):
          if seq < 1:
            problems.append(f"activity log sequence number < 1: {seq}")
          if first_seq is None:
            first_seq = seq
          if last_seq is not None and seq != last_seq + 1:
            problems.append(f"activity log sequence gap: {last_seq} to {seq}")
          last_seq = seq
        else:
          problems.append("activity log record missing sequenceNumber")

      last_record_tag = record.get("tag")
      event_type = record.get("eventType")
      record_msg = record.get("message")
      if event_type in _TAMPER_EVENTS:
        if event_type == "AUDIT_LOG_CLEARED" and _message_mentions(
            record_msg, _CLEAR_LOSS_TERMS
        ):
          problems.append(f"tamper-evidence event: {event_type} ({record_msg})")
        else:
          problems.append(f"tamper-evidence event: {event_type}")
      elif event_type == "COLLECTION_RESUMED_SINGLE_USER":
        if _message_mentions(record_msg, ("discarded",)):
          problems.append(f"tamper-evidence event: {event_type} ({record_msg})")
        else:
          notices.append(f"activity log event: {event_type}")
      elif event_type == "AUDIT_EVENTS_RATE_LIMITED" and isinstance(
          record_msg, str
      ):
        if _TAMPER_EVENT_NAMES.search(record_msg):
          problems.append(f"tamper-evidence event: {event_type} ({record_msg})")
        else:
          notices.append(f"activity log event: {event_type} ({record_msg})")
      elif event_type == "BATCH_SIGNING_FAILED":
        if not isinstance(record_msg, str):
          problems.append(f"tamper-evidence event: {event_type}")
        elif record_msg.startswith(_RESIGNING_FAILED_PREFIX):
          notices.append(f"activity log event: {event_type} ({record_msg})")
        else:
          problems.append(f"tamper-evidence event: {event_type} ({record_msg})")
      elif event_type and event_type not in _ROUTINE_AUDIT_EVENTS:
        if (
            event_type == "LOGS_STORAGE_CAP_REACHED"
            and _message_mentions(record_msg, ("reclaimed",))
        ) or (
            event_type == "NETWORK_COLLECTION_SCOPE_CHANGED"
            and isinstance(record_msg, str)
            and record_msg
        ):
          notices.append(f"activity log event: {event_type} ({record_msg})")
        else:
          notices.append(f"activity log event: {event_type}")
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
      problems.append("malformed JSON in activity log record")

  if num_records == 0 and marker is None and head != since:
    problems.append("0 records and no marker but head does not equal since")
  if (num_records > 0 and last_record_tag is not None and
      last_record_tag != head.decode()):
    problems.append("last record's tag does not equal chain head")

  return Trailer(
      since=since.decode(),
      head=head.decode(),
      records=num_records,
      previous_record_missing=marker is not None,
      first_seq=first_seq,
      last_seq=last_seq,
      problems=tuple(problems),
      notices=tuple(notices),
      leading_sealed=leading_sealed,
  )


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
  """Reads a protobuf varint.

  Args:
    data: Protobuf wire format data.
    pos: Where the varint starts in data.

  Returns:
    The value of the varint, and where it ends in data.

  Raises:
    IndexError: If data ends inside the varint.
  """
  value = shift = 0
  while data[pos] & 0x80:  # More bytes follow.
    value |= (data[pos] & 0x7F) << shift
    pos += 1
    shift += 7
  return value | data[pos] << shift, pos + 1


def _signed_bytes(data: bytes) -> bytes:
  """Removes the signature field from a batch file.

  The signature covers exactly the remaining bytes, so its field is cut out of
  the file rather than the batch re-serialized.

  Args:
    data: A batch file that parses as a LogBatch.

  Returns:
    The bytes that the signature covers.

  Raises:
    BatchError: If data holds a group, which batches never do.
  """
  kept = []
  pos = 0
  while pos < len(data):
    start = pos
    tag, pos = _read_varint(data, pos)
    wire_type = tag & _WIRE_TYPE_MASK
    if wire_type == _VARINT:
      _, pos = _read_varint(data, pos)
    elif wire_type == _LENGTH_DELIMITED:
      length, pos = _read_varint(data, pos)
      pos += length
    elif wire_type in _FIXED_SIZES:
      pos += _FIXED_SIZES[wire_type]
    else:
      raise BatchError(f"unexpected wire type {wire_type} in the batch")
    if tag >> _FIELD_NUMBER_SHIFT != _SIGNATURE_FIELD:
      kept.append(data[start:pos])
  return b"".join(kept)


def _public_key_der(certificate: x509.Certificate) -> bytes:
  """Encodes the public key of a certificate.

  Args:
    certificate: An X.509 certificate.

  Returns:
    The DER SubjectPublicKeyInfo of the key.
  """
  return certificate.public_key().public_bytes(
      serialization.Encoding.DER,
      serialization.PublicFormat.SubjectPublicKeyInfo)


def _issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
  """Checks whether the key of issuer signed certificate.

  Args:
    certificate: The certificate whose signature is checked.
    issuer: The certificate that should have signed it.

  Returns:
    Whether the signature of certificate verifies with the key of issuer.
  """
  key = issuer.public_key()
  digest = certificate.signature_hash_algorithm
  if isinstance(key, rsa.RSAPublicKey):
    verify_args = (padding.PKCS1v15(), digest)
  elif isinstance(key, ec.EllipticCurvePublicKey):
    verify_args = (ec.ECDSA(digest),)
  else:  # Attestation keys are RSA or EC keys.
    return False
  try:
    key.verify(
        certificate.signature, certificate.tbs_certificate_bytes, *verify_args)
  except exceptions.InvalidSignature:
    return False
  return True


def _is_rkp_chain(chain: Sequence[x509.Certificate]) -> bool:
  """Checks whether an attestation chain is remotely provisioned (RKP)."""
  for certificate in chain[1:]:
    for extension in certificate.extensions:
      if extension.oid == _PROVISIONING_INFO_OID:
        return True
  return False


def _check_chain(
    chain: Sequence[x509.Certificate],
    root_keys: Collection[str],
    batch_time: datetime.datetime | None = None,
) -> None:
  """Checks that each certificate is signed by the next, up to a trusted root.

  Args:
    chain: Attestation certificates, leaf first.
    root_keys: The SHA-256 hashes, in hex, of the SubjectPublicKeyInfo of the
      trusted roots.
    batch_time: The time the batch was written.

  Raises:
    BatchError: If a certificate is not signed by the next one, if it is signed
      by the attested key of an app (whose certificate holds an attestation
      extension) rather than by a device or Google certificate, if an issuer is
      not a valid CA or was not valid when the attested key was created, if the
      leaf certificate was not valid at batch_time, or if the last certificate
      does not hold a self-signed trusted root key.
  """
  if batch_time is not None:
    batch_dt = batch_time.replace(tzinfo=None)
    if (chain[0].not_valid_before > batch_dt or
        chain[0].not_valid_after < batch_dt):
      raise BatchError(
          "attestation certificate 0 was not valid at the batch time")

  for i, (certificate, issuer) in enumerate(zip(chain, chain[1:])):
    if not _issued_by(certificate, issuer):
      raise BatchError(f"attestation certificate {i + 1} did not sign {i}")
    if any(extension.oid == _ATTESTATION_OID
           for extension in issuer.extensions):
      raise BatchError(f"attestation certificate {i + 1} is that of an app's "
                       f"key, which cannot certify {i}")

    try:
      basic_constraints = issuer.extensions.get_extension_for_class(
          x509.BasicConstraints).value
      if not basic_constraints.ca:
        raise BatchError(f"attestation certificate {i + 1} is not a CA")
      if (basic_constraints.path_length is not None and
          basic_constraints.path_length < i):
        raise BatchError(
            f"attestation certificate {i + 1} exceeds path length")
    except x509.ExtensionNotFound:
      raise BatchError(
          f"attestation certificate {i + 1} is not a CA") from None

    try:
      key_usage = issuer.extensions.get_extension_for_class(
          x509.KeyUsage).value
      if not key_usage.key_cert_sign:
        raise BatchError(
            f"attestation certificate {i + 1} cannot sign certificates")
    except x509.ExtensionNotFound:
      raise BatchError(
          f"attestation certificate {i + 1} cannot sign certificates"
      ) from None

  if not _issued_by(chain[-1], chain[-1]):
    raise BatchError("the root certificate is not self-signed")

  if hashlib.sha256(_public_key_der(chain[-1])).hexdigest() not in root_keys:
    raise BatchError("the attestation certificates do not lead to a Google "
                     "hardware attestation root")

  _, software_enforced, hardware_enforced = _key_description_fields(chain[0])
  try:
    creation_dt = _creation_datetime(hardware_enforced + software_enforced)
  except (IndexError, OverflowError, ValueError):
    raise BatchError("malformed key attestation") from None

  rkp = _is_rkp_chain(chain)
  if rkp and creation_dt is None:
    raise BatchError("the attestation has no creationDateTime")
  if creation_dt is not None:
    for i, issuer in enumerate(chain[1:]):
      if issuer.not_valid_before > creation_dt or (
          rkp and issuer.not_valid_after < creation_dt
      ):
        raise BatchError(
            f"attestation certificate {i + 1} was not valid when the key was "
            "created"
        )


def _der(data: bytes) -> list[tuple[bytes, bytes]]:
  """Splits DER data into its elements.

  Args:
    data: DER elements, one after the other.

  Returns:
    The identifier octets and the contents of each element.

  Raises:
    IndexError: If data ends inside the identifier or length octets of an
      element.
    ValueError: If data ends inside the contents of an element.
  """
  elements = []
  pos = 0
  while pos < len(data):
    end = pos + 1
    if data[pos] & 0x1F == 0x1F:  # The tag number follows, in base 128.
      while data[end] & 0x80:
        end += 1
      end += 1
    tag = data[pos:end]
    length = data[end]
    pos = end + 1
    if length & 0x80:  # The length is in the next length & 0x7F bytes.
      size = length & 0x7F
      length = int.from_bytes(data[pos:pos + size], "big")
      pos += size
    if pos + length > len(data):
      raise ValueError("truncated DER element")
    elements.append((tag, data[pos:pos + length]))
    pos += length
  return elements


def _first_contents(data: bytes) -> bytes:
  """Returns the contents of the first DER element in data.

  Args:
    data: DER elements, one after the other.

  Returns:
    The contents of the first element.

  Raises:
    IndexError: If data holds no element, or ends inside the identifier or
      length octets of one.
    ValueError: If data ends inside the contents of an element.
  """
  return _der(data)[0][1]


def _attested_application(
    authorizations: Iterable[tuple[bytes, bytes]],
) -> tuple[list[bytes], list[bytes]]:
  """Finds the packages and signing certificates in the attestation of a key.

  Args:
    authorizations: The DER elements of the AuthorizationLists of a
      KeyDescription.

  Returns:
    The package names, and the SHA-256 digests of the certificates that sign
    them. Both are empty if there is no attestation application ID.

  Raises:
    IndexError: If the attestation application ID is truncated.
    ValueError: If the attestation application ID is malformed.
  """
  packages = []
  certificates = []
  for tag, contents in authorizations:
    if tag != _APPLICATION_ID_TAG:
      continue
    # An OCTET STRING holding an AttestationApplicationId: a SEQUENCE of a SET
    # of AttestationPackageInfo and a SET of signing certificate digests.
    application_id = _first_contents(_first_contents(contents))
    package_infos, digests = [elements for _, elements in _der(application_id)]
    # Each AttestationPackageInfo is a SEQUENCE of a package name and version.
    packages += [_first_contents(info) for _, info in _der(package_infos)]
    certificates += [digest for _, digest in _der(digests)]
  return packages, certificates


def _root_of_trust(
    authorizations: Iterable[tuple[bytes, bytes]],
) -> tuple[bytes, bool, bytes]:
  """Finds the RootOfTrust in the attestation of a key.

  Args:
    authorizations: The DER elements of a hardware-enforced AuthorizationList.
      The OS writes the software-enforced one, so its RootOfTrust could lie.

  Returns:
    The verified boot key, whether the bootloader was locked, and the
    VerifiedBootState (ENUMERATED contents).

  Raises:
    IndexError: If the RootOfTrust is truncated.
    ValueError: If there is no RootOfTrust, or it is malformed.
  """
  for tag, contents in authorizations:
    if tag == _ROOT_OF_TRUST_TAG:
      # A SEQUENCE of verifiedBootKey, deviceLocked, verifiedBootState and,
      # in newer versions, verifiedBootHash.
      boot_key, locked, state, *_ = [
          elements for _, elements in _der(_first_contents(contents))]
      return boot_key, locked[0] != 0, state
  raise ValueError("no RootOfTrust")


def _creation_datetime(
    authorizations: Iterable[tuple[bytes, bytes]],
) -> datetime.datetime | None:
  """Finds creationDateTime in the attestation of a key."""
  for tag, contents in authorizations:
    if tag == _CREATION_DATETIME_TAG:
      millis = int.from_bytes(_first_contents(contents), "big", signed=True)
      return (
          datetime.datetime(1970, 1, 1)
          + datetime.timedelta(milliseconds=millis)
      )
  return None


def _key_description_fields(
    certificate: x509.Certificate,
) -> tuple[list[bytes], list[tuple[bytes, bytes]], list[tuple[bytes, bytes]]]:
  """Reads the fields and AuthorizationLists of a KeyDescription.

  Args:
    certificate: The leaf certificate of an attestation chain.

  Returns:
    The DER element contents of the KeyDescription, the DER elements of its
    softwareEnforced AuthorizationList, and those of its hardwareEnforced
    AuthorizationList.

  Raises:
    BatchError: If the attestation extension is missing or malformed.
  """
  try:
    extension = certificate.extensions.get_extension_for_oid(_ATTESTATION_OID)
    key_description = _first_contents(extension.value.value)
    fields = [contents for _, contents in _der(key_description)]
    return (
        fields,
        _der(fields[_SOFTWARE_ENFORCED]),
        _der(fields[_HARDWARE_ENFORCED]),
    )
  except (IndexError, ValueError, x509.ExtensionNotFound):
    raise BatchError("malformed key attestation") from None


def _check_attestation(
    certificate: x509.Certificate, device_id: bytes
) -> Signer:
  """Checks what the attestation of a certificate says about its key.

  The attestation extension holds a KeyDescription, as described in the Android
  key attestation documentation.

  Args:
    certificate: The leaf certificate of an attestation chain.
    device_id: The device ID of the batch that the key signed.

  Returns:
    The signer: the key, where it lives, the certificates that sign the app
    that made it, and how verified boot checked the OS.

  Raises:
    BatchError: If the attestation is missing or malformed, or if it does not
      say that the key was made for device_id in a TEE or StrongBox, by
      com.android.securelogging signed with at least one certificate, on a
      device with a locked bootloader and an OS that verified boot accepted.
  """
  fields, software_enforced, hardware_enforced = _key_description_fields(
      certificate)
  try:
    packages, app_certificates = _attested_application(
        software_enforced + hardware_enforced)
    boot_key, device_locked, boot_state = _root_of_trust(hardware_enforced)
    origin_ok = any(
        tag == _ORIGIN_TAG and _first_contents(contents) == _ORIGIN_GENERATED
        for tag, contents in hardware_enforced
    )
  except (IndexError, ValueError):
    raise BatchError("malformed key attestation") from None
  if not origin_ok:
    raise BatchError("the key was not generated on the device in hardware")

  challenge = fields[_ATTESTATION_CHALLENGE]
  if not challenge:
    raise BatchError("the key's attestation challenge is empty")
  if device_id and challenge != device_id:
    raise BatchError("the key was attested for another device ID")
  if _PACKAGE_NAME not in packages:
    raise BatchError("the key does not belong to com.android.securelogging")
  if not app_certificates:
    raise BatchError("the attestation names no signing certificate of the app")
  levels = {
      fields[_ATTESTATION_SECURITY_LEVEL], fields[_KEYMINT_SECURITY_LEVEL]}
  if not levels <= _SECURITY_LEVELS.keys():
    raise BatchError("the key is not in a TEE or StrongBox")

  # Otherwise the OS may have been altered, and Keystore takes the package and
  # its certificates from the OS.
  if not device_locked:
    raise BatchError("the key was made while the bootloader was unlocked")
  if boot_state not in _BOOT_STATES:
    raise BatchError("the key was made by an OS that verified boot rejected")
  return Signer(
      key=_public_key_der(certificate),
      security_level=_SECURITY_LEVELS[fields[_KEYMINT_SECURITY_LEVEL]],
      app_certificates=tuple(app_certificates),
      boot_state=_BOOT_STATES[boot_state],
      boot_key=boot_key,
      device_id=challenge)


_CERT_PARSE_ERRORS = (
    exceptions.UnsupportedAlgorithm,
    IndexError,
    TypeError,
    ValueError,
    x509.DuplicateExtension,
    x509.ExtensionNotFound,
    x509.InvalidVersion,
    x509.UnsupportedGeneralNameType,
)


def _vouching_chain(
    batch: message.Message, sealed_chain: Sequence[bytes]
) -> Sequence[bytes]:
  """Returns the attestation chain that vouches for the signature of a batch.

  The signature does not cover the signature field of the batch, where a batch
  of an earlier format carries the chain. A format version 2 batch seals its
  chain with its logs instead, where AES-GCM authenticates it, so only that
  chain counts for such a batch.

  Args:
    batch: A signed LogBatch.
    sealed_chain: The DER attestation certificates sealed in batch, if it is a
      format version 2 batch that was decrypted.

  Returns:
    The DER attestation certificates of the key that signed batch, leaf first.
  """
  if (
      batch.metadata.encryption_type
      == LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA
  ):
    return sealed_chain
  return batch.signature.attestation_chain


def check_signature(
    data: bytes,
    batch: message.Message,
    device_id: bytes,
    root_keys: Collection[str] = GOOGLE_ROOT_KEYS,
    certificate_statuses: Mapping[str, str] = _NO_STATUSES,
    batch_time: datetime.datetime | None = None,
    attestation_chain: Sequence[bytes] = (),
) -> Signer:
  """Checks the signature of a batch and the attestation of its key.

  Args:
    data: The batch file.
    batch: The LogBatch in data.
    device_id: The device ID of the batch: that of its cleartext metadata, or
      the one sealed in a format version 2 batch.
    root_keys: The SHA-256 hashes, in hex, of the SubjectPublicKeyInfo of the
      trusted attestation roots.
    certificate_statuses: The status of each revoked or suspended attestation
      certificate, by serial number in lower case hex.
    batch_time: The time the batch was written.
    attestation_chain: The attestation chain sealed in a format version 2 batch,
      the only one that counts for such a batch. Batches of earlier formats
      carry their chain in their signature instead.

  Returns:
    The key that signed the batch.

  Raises:
    BatchError: If the batch is unsigned, if it is a format version 2 batch
      whose signature carries attestation certificates, or if a check fails.
  """
  if not batch.HasField("signature"):
    raise BatchError("unsigned batch")
  if (
      batch.metadata.encryption_type
      == LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA
      and batch.signature.attestation_chain
  ):
    # Anyone who handled the batch could have added them, unauthenticated.
    raise BatchError(
        "format version 2 batch with attestation certificates in clear"
    )
  try:
    chain = []
    for certificate_der in _vouching_chain(batch, attestation_chain):
      certificate = x509.load_der_x509_certificate(certificate_der)
      _ = certificate.extensions
      chain.append(certificate)
  except (ValueError, x509.InvalidVersion, x509.DuplicateExtension) as e:
    raise BatchError(
        f"malformed attestation certificate ({type(e).__name__})"
    ) from None
  if not chain:
    raise BatchError(_NO_CHAIN)

  try:
    key = chain[0].public_key()
    if (not isinstance(key, ec.EllipticCurvePublicKey)
        or key.curve.name != _SIGNING_CURVE):
      raise BatchError("the signing key is not an EC P-256 key")
    signed_bytes = _signed_bytes(data)
    key.verify(
        batch.signature.signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
    _check_chain(chain, root_keys, batch_time)
    for i, certificate in enumerate(chain):
      status = certificate_statuses.get(f"{certificate.serial_number:x}")
      if status:
        raise BatchError(f"attestation certificate {i} is {status}")
    return _check_attestation(chain[0], device_id)
  except _CERT_PARSE_ERRORS as e:
    raise BatchError(f"malformed attestation: {e}") from None
  except exceptions.InvalidSignature:
    raise BatchError("bad signature") from None


def _time_key(result: Result) -> tuple[int, int, str]:
  """Returns the chronological sort key of a Result."""
  return (
      result.metadata.timestamp.seconds,
      result.metadata.timestamp.nanos,
      result.path.name,
  )


def _link_unsigned_runs(unsigned: Sequence[Result]) -> list[list[Result]]:
  """Links unsigned batches into contiguous runs by trailer since and head."""
  edges: list[Result] = []
  loops: dict[str, list[Result]] = collections.defaultdict(list)
  unlinked: list[list[Result]] = []
  for u in unsigned:
    if u.trailer is None:
      unlinked.append([u])
    elif u.trailer.since != u.trailer.head:
      edges.append(u)
    elif u.trailer.since == "none":
      unlinked.append([u])
    else:
      loops[u.trailer.since].append(u)

  chains: list[list[Result]] = []
  for u in edges:
    current = None
    if u.trailer.since != "none":
      for chain in chains:
        if chain[-1].trailer.head == u.trailer.since:
          chain.append(u)
          current = chain
          break
    if current is None:
      current = [u]
      chains.append(current)
    if u.trailer.head != "none":
      for chain in chains:
        if chain is not current and chain[0].trailer.since == u.trailer.head:
          current.extend(chain)
          chains.remove(chain)
          break

  runs: list[list[Result]] = []
  for chain in chains:
    run: list[Result] = [*loops.pop(chain[0].trailer.since, ())]
    for u in chain:
      run.append(u)
      run.extend(loops.pop(u.trailer.head, ()))
    runs.append(run)
  runs.extend(loops.values())
  runs.extend(unlinked)
  return runs


def _signed_by(signer: Signer, result: Result) -> bool:
  """Checks whether signer signed an undecrypted format version 2 batch."""
  key = serialization.load_der_public_key(signer.key)
  try:
    key.verify(
        result.batch.signature.signature,
        result.signed_digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
  except exceptions.InvalidSignature:
    return False
  return True


def _attribute_sealed_batches(results: Sequence[Result]) -> list[Result]:
  """Finds the signers of the format version 2 batches that no key decrypted.

  Such a batch seals its attestation chain, but if the key of another batch
  signed it, it counts for the sequence numbers, though it has no logs to trust.

  Args:
    results: The Results of the batch files of a run.

  Returns:
    The results, with the signers found.
  """
  signers = {r.signer.key: r.signer for r in results if r.signer}
  attributed = []
  for result in results:
    matches = [
        signer
        for signer in signers.values()
        if result.signed_digest and _signed_by(signer, result)
    ]
    if not matches:
      attributed.append(result)
      continue
    attributed.append(
        dataclasses.replace(
            result,
            signer=matches[0],
            signer_trusted=True,
            problems=tuple(p for p in result.problems if p != _NO_CHAIN),
            notices=(
                *result.notices,
                (
                    "signed by a key that other batches attest: no --key"
                    " decrypts the attestation chain that it seals"
                ),
            ),
        )
    )
  return attributed


def check_batches(
    paths: Iterable[pathlib.Path],
    private_key: rsa.RSAPrivateKey | Sequence[rsa.RSAPrivateKey],
    root_keys: Collection[str] = GOOGLE_ROOT_KEYS,
    app_certificates: frozenset[bytes] = frozenset(),
    boot_keys: frozenset[bytes] = frozenset(),
    certificate_statuses: Mapping[str, str] = _NO_STATUSES,
    allow_unsigned: bool = False,
    allow_pkcs1: bool = False,
) -> list[Result]:
  """Decrypts batch files, and checks their trailers and signatures.

  Args:
    paths: The batch files.
    private_key: The recipient's RSA private key, or those of each recipient
      that the batches may be encrypted to, tried in turn.
    root_keys: The SHA-256 hashes, in hex, of the SubjectPublicKeyInfo of the
      trusted attestation roots.
    app_certificates: The SHA-256 digests of the certificates that the app that
      made a signing key may be signed with, or none to accept any.
    boot_keys: The verified boot keys that may make signing keys, or none to
      accept any Verified OS.
    certificate_statuses: The status of each revoked or suspended attestation
      certificate, by serial number in lower case hex.
    allow_unsigned: Whether to allow unsigned batches to advance trailer chains.
    allow_pkcs1: Whether to allow legacy PKCS1v1.5 encryption.

  Returns:
    A Result for each path, grouped by device and ordered.
  """
  private_keys = (
      [private_key]
      if isinstance(private_key, rsa.RSAPrivateKey)
      else private_key
  )
  results = []
  for path in paths:
    try:
      results.append(
          _check_batch(
              path, private_keys, root_keys, certificate_statuses, allow_pkcs1
          )
      )
    except Exception as exc:  # pylint: disable=broad-exception-caught
      empty = LogBatch()
      results.append(
          Result(
              path=path,
              batch=empty,
              metadata=empty.metadata,
              problems=(f"unexpected error ({type(exc).__name__}): {exc}",),
          )
      )
  results = _attribute_sealed_batches(results)

  groups = collections.defaultdict(list)
  for result in results:
    device_id = (
        result.signer.device_id
        if result.signer
        else result.metadata.device.device_id
    )
    groups[device_id].append(result)

  final_results = []
  for device_results in groups.values():
    signed = [r for r in device_results if r.signer is not None]
    signed.sort(key=lambda r: (r.batch.sequence_number, *_time_key(r)))
    signed = _check_sequences(signed, app_certificates, boot_keys)

    if not allow_unsigned:
      unverified = [r for r in device_results if r.signer is None]
      unverified.sort(key=_time_key)
      group_results = signed + unverified
    else:
      unsigned = [
          r for r in device_results if not r.batch.HasField("signature")
      ]
      unsigned.sort(key=lambda r: (r.trailer is None, *_time_key(r)))
      group_results = list(signed)
      for run in _link_unsigned_runs(unsigned):
        first_u = run[0]
        last_u = run[-1]
        insert_idx = None
        if first_u.trailer and first_u.trailer.since != "none":
          for i, r in reversed(list(enumerate(group_results))):
            if (
                r.signer_trusted
                and r.trailer
                and r.trailer.head == first_u.trailer.since
            ):
              insert_idx = i + 1
              break
        if (
            insert_idx is None
            and last_u.trailer
            and last_u.trailer.head != "none"
        ):
          for i, r in enumerate(group_results):
            if (
                r.signer_trusted
                and r.trailer
                and r.trailer.since == last_u.trailer.head
            ):
              insert_idx = i
              break
        if insert_idx is None:
          insert_idx = len(group_results)
          for i, r in enumerate(group_results):
            if _time_key(r) > _time_key(first_u):
              insert_idx = i
              break
        group_results[insert_idx:insert_idx] = run
      failed_signed = [
          r
          for r in device_results
          if r.signer is None and r.batch.HasField("signature")
      ]
      failed_signed.sort(key=_time_key)
      group_results.extend(failed_signed)

    for i, r in enumerate(group_results):
      extra_probs = []
      if (
          r.batch.HasField("metadata")
          and not r.metadata.device.device_id
          and (
              r.metadata.encryption_type
              != LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA
              or r.plaintext is not None
          )
      ):
        extra_probs.append("empty device ID")
      if extra_probs:
        group_results[i] = _with_problems(r, extra_probs)

    group_results = _check_trailer_chain(group_results, allow_unsigned)
    final_results.extend(group_results)

  return final_results


def _trailer_findings(
    trailer: Trailer | None, verified: bool
) -> tuple[tuple[str, ...], tuple[str, ...]]:
  """Returns intra-batch problems and notices from trailer."""
  if trailer is None:
    return (), ()
  probs = []
  if trailer.previous_record_missing:
    probs.append(
        "the device no longer had the previous batch's last activity "
        "record, so records written in between may have been deleted"
    )
  probs.extend(trailer.problems)
  suffix = "" if verified else " (unverified)"
  return (
      tuple(f"{p}{suffix}" for p in probs),
      tuple(f"{n}{suffix}" for n in trailer.notices),
  )


def _read_batch_file(path: pathlib.Path) -> bytes:
  """Reads a batch file that is a regular file of at most 64 MiB.

  The file is opened without following a symbolic link and without waiting for
  a writer to a FIFO, and checked through the open file, so that it cannot be
  replaced between the check and the read.

  Args:
    path: The batch file.

  Returns:
    The content of the file.

  Raises:
    OSError: If the file cannot be opened or read, or if it is a symbolic link.
    BatchError: If the file is not a regular file, or if it is larger than
      _MAX_BATCH_FILE_SIZE bytes.
  """
  flags = (
      os.O_RDONLY
      | getattr(os, "O_NOFOLLOW", 0)
      | getattr(os, "O_NONBLOCK", 0)
      | getattr(os, "O_BINARY", 0)
  )
  file_descriptor = os.open(path, flags)
  try:
    if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
      raise BatchError("not a regular file")
    with os.fdopen(file_descriptor, "rb", closefd=False) as batch_file:
      # One byte past the limit shows that the file is too large, even one
      # that grows while it is read.
      data = batch_file.read(_MAX_BATCH_FILE_SIZE + 1)
  finally:
    os.close(file_descriptor)
  if len(data) > _MAX_BATCH_FILE_SIZE:
    raise BatchError(f"larger than {_MAX_BATCH_FILE_SIZE} bytes")
  return data


def _check_batch(
    path: pathlib.Path,
    private_keys: Sequence[rsa.RSAPrivateKey],
    root_keys: Collection[str],
    certificate_statuses: Mapping[str, str],
    allow_pkcs1: bool = False,
) -> Result:
  """Reads and decrypts one batch file, and checks its trailer and signature.

  Args:
    path: The batch file.
    private_keys: The private keys of the recipients, tried in turn.
    root_keys: The SHA-256 hashes, in hex, of the SubjectPublicKeyInfo of the
      trusted attestation roots.
    certificate_statuses: The status of each revoked or suspended attestation
      certificate, by serial number in lower case hex.
    allow_pkcs1: Whether to allow legacy PKCS1v1.5 encryption.

  Returns:
    The Result for the file, with the problems found.
  """
  try:
    data = _read_batch_file(path)
    batch = parse_batch(data)
  except (OSError, BatchError) as e:
    empty = LogBatch()
    return Result(path=path, batch=empty, metadata=empty.metadata,
                  problems=(str(e),))
  problems = []
  metadata = batch.metadata
  plaintext = trailer = signer = decrypted = None

  batch_time = None
  try:
    if metadata.HasField("timestamp"):
      batch_time = datetime.datetime.fromtimestamp(
          metadata.timestamp.seconds, datetime.timezone.utc)
  except (OverflowError, OSError, ValueError):
    pass

  try:
    decrypted = _decrypt(batch, private_keys, allow_pkcs1)
    metadata, plaintext = decrypted.metadata, decrypted.logs
    if metadata.HasField("timestamp"):
      try:
        batch_time = datetime.datetime.fromtimestamp(
            metadata.timestamp.seconds, datetime.timezone.utc)
      except (OverflowError, OSError, ValueError):
        problems.append("invalid batch timestamp")
        batch_time = None
    else:
      problems.append("missing batch timestamp")
      batch_time = None
    trailer = parse_trailer(plaintext)
  except BatchError as e:
    problems.append(str(e))
  # A format version 2 batch seals the attestation chain with its logs.
  sealed_chain = decrypted.attestation_chain if decrypted is not None else ()
  signed_digest = None
  if (
      decrypted is None
      and batch.HasField("signature")
      and metadata.encryption_type
      == LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA
  ):
    # The key of another batch may have signed it.
    try:
      signed_digest = hashlib.sha256(_signed_bytes(data)).digest()
    except BatchError as e:
      problems.append(str(e))
  try:
    signer = check_signature(
        data,
        batch,
        metadata.device.device_id,
        root_keys,
        certificate_statuses,
        batch_time,
        attestation_chain=sealed_chain,
    )
  except BatchError as e:
    problems.append(str(e))

  notices = []
  if batch.HasField("signature"):
    try:
      chain = [
          x509.load_der_x509_certificate(cert_der)
          for cert_der in _vouching_chain(batch, sealed_chain)
      ]
      if not _is_rkp_chain(chain):
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        for i, cert in enumerate(chain):
          if cert.not_valid_after < now:
            notices.append(
                f"attestation certificate {i} is expired at analysis time")
    except _CERT_PARSE_ERRORS:
      pass

  trailer_problems, trailer_notices = _trailer_findings(
      trailer, signer is not None
  )
  problems.extend(trailer_problems)
  notices.extend(trailer_notices)

  return Result(
      path=path,
      batch=batch,
      metadata=metadata,
      plaintext=plaintext,
      trailer=trailer,
      signer=signer,
      signer_trusted=(signer is not None),
      problems=tuple(problems),
      notices=tuple(notices),
      signed_digest=signed_digest,
  )


def _with_problems(result: Result, problems: Iterable[str]) -> Result:
  """Adds problems to a Result.

  Args:
    result: The Result of a batch file.
    problems: The problems to add.

  Returns:
    A copy of result with the problems added.
  """
  return dataclasses.replace(result, problems=(*result.problems, *problems))


def _check_trailer_chain(
    results: Sequence[Result],
    allow_unsigned: bool = False,
) -> list[Result]:
  """Checks that each trailer starts at the chain head of the one before.

  Args:
    results: The Results of batch files, in the order they were written.
    allow_unsigned: Whether unsigned batches advance the trailer chain.

  Returns:
    The Results, with the breaks in the chain added to their problems.
  """
  checked = []
  previous = None  # The last Result linked in the chain.
  last_seq = None
  for result in results:
    chain_linked = result.signer_trusted or (
        allow_unsigned and not result.batch.HasField("signature")
    )
    if result.trailer is None or not chain_linked:
      checked.append(result)
      continue
    problems = []
    if previous and result.trailer.since != previous.trailer.head:
      problems.append(
          f"activity log break: this batch starts after record "
          f"{result.trailer.since}, but {previous.path.name} ends at "
          f"{previous.trailer.head}. A batch in between is missing, or the "
          "key changed or the app was reinstalled in between")
    if last_seq is not None:
      last_seq += result.trailer.leading_sealed
      if (result.trailer.first_seq is not None and
          result.trailer.first_seq != last_seq + 1):
        problems.append(
            "activity log sequence gap between batches: "
            f"{last_seq} to {result.trailer.first_seq}")

    if result.trailer.last_seq is not None:
      last_seq = result.trailer.last_seq

    checked.append(_with_problems(result, problems))
    previous = result
  return checked


def _signer_id(
    signer: Signer,
) -> tuple[bytes, tuple[bytes, ...], str, bytes]:
  """Returns the identity tuple of a Signer."""
  return (
      signer.key,
      signer.app_certificates,
      signer.boot_state,
      signer.boot_key,
  )


def _check_sequences(
    results: Sequence[Result],
    app_certificates: frozenset[bytes],
    boot_keys: frozenset[bytes],
) -> list[Result]:
  """Checks the signers and sequence numbers of each device's signed batches.

  Args:
    results: The Results of signed batch files.
    app_certificates: The SHA-256 digests of the certificates that the app
      that made a signing key may be signed with, or none to accept any.
    boot_keys: The verified boot keys that may make signing keys, or none to
      accept any Verified OS.

  Returns:
    The Results, in the same order, with signer changes, gaps, repeats, and
    apps or verified boot keys failing policy added to their problems.
  """
  if not results:
    return []

  policy_problems: list[list[str]] = []
  passing_signers: dict[
      tuple[bytes, tuple[bytes, ...], str, bytes], str
  ] = {}
  first = None
  for result in results:
    signer = result.signer
    probs = []
    if (
        app_certificates
        and app_certificates.isdisjoint(signer.app_certificates)
    ):
      probs.append(
          "signed by an app with none of the certificates of --app-cert"
      )
    if signer.boot_state == _SELF_SIGNED and not boot_keys:
      probs.append("signed on a custom ROM but no --boot-key was given")
    elif boot_keys and signer.boot_key not in boot_keys:
      probs.append(
          "signed with none of the verified boot keys of --boot-key"
      )
    if not probs and result.batch.sequence_number >= 1:
      if first is None:
        first = result
      passing_signers.setdefault(_signer_id(signer), result.path.name)
    policy_problems.append(probs)

  multi_signer_problem = None
  if len(passing_signers) > 1:
    names = ", ".join(passing_signers.values())
    multi_signer_problem = (
        f"batches from {len(passing_signers)} signers ({names}); "
        "pass --app-cert/--boot-key"
    )

  checked = []
  expected = None

  for result, probs in zip(results, policy_problems):
    problems = []
    notices = []
    signer = result.signer

    if first is not None:
      if signer.key != first.signer.key:
        problems.append(f"signed with another key than {first.path.name}")
      if signer.app_certificates != first.signer.app_certificates:
        problems.append(
            f"signed by an app with other certificates than {first.path.name}"
        )
      if signer.boot_state != first.signer.boot_state:
        problems.append(
            f"signed with another verified boot state than {first.path.name}"
        )
      if signer.boot_key != first.signer.boot_key:
        problems.append(
            f"signed with another verified boot key than {first.path.name}"
        )

    problems.extend(probs)
    if multi_signer_problem:
      problems.append(multi_signer_problem)

    number = result.batch.sequence_number
    signer_trusted = not probs and not multi_signer_problem and number >= 1
    if number < 1:
      problems.append(f"invalid non-positive sequence number {number}")
    elif signer_trusted:
      if expected is None:
        expected = number
        if number > 1:
          notices.append(f"missing sequence numbers 1-{number - 1}")

      if number < expected:
        problems.append(f"repeated sequence number {number}")
      elif number > expected:
        if number == expected + 1:
          problems.append(f"missing sequence number {expected}")
        else:
          problems.append(f"missing sequence numbers {expected}-{number - 1}")

      if number >= expected:
        expected = number + 1

    if result.trailer:
      is_seq_1 = (number == 1)
      is_since_none = (result.trailer.since == "none")
      if is_seq_1 and not is_since_none:
        notices.append("sequence number 1 but since is not none")
      elif not is_seq_1 and is_since_none:
        notices.append("since is none but sequence number is not 1")

    base_problems = result.problems
    base_notices = result.notices
    if not signer_trusted:
      unverified_probs, unverified_notices = _trailer_findings(
          result.trailer, False
      )
      base_problems = (
          *base_problems[: len(base_problems) - len(unverified_probs)],
          *unverified_probs,
      )
      base_notices = (
          *base_notices[: len(base_notices) - len(unverified_notices)],
          *unverified_notices,
      )

    checked.append(
        dataclasses.replace(
            result,
            signer_trusted=signer_trusted,
            problems=(*base_problems, *problems),
            notices=(*base_notices, *notices),
        )
    )
  return checked


def _printable(text: str) -> str:
  """Escapes the characters of text that are not printable.

  Batch files can come from anywhere, and a file name with control characters
  such as terminal escape sequences could rewrite the report on the screen.

  Args:
    text: A line of the report.

  Returns:
    text, with each character that is not printable written as a Python
    escape sequence.
  """
  return "".join(
      char if char.isprintable() else char.encode("unicode_escape").decode()
      for char in text)


def _describe(result: Result) -> list[str]:
  """Describes what was found in a batch file.

  Args:
    result: The Result of the batch file.

  Returns:
    The lines of the report about the file, which hold only printable
    characters.
  """
  lines = [str(result.path)]

  if result.batch.HasField("metadata"):
    metadata = result.metadata
    try:
      written = datetime.datetime.fromtimestamp(
          metadata.timestamp.seconds, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
      written = f"{metadata.timestamp.seconds} seconds after 1970"

    key_type = result.batch.key.key_encryption_type
    key_wrap = _KEY_WRAP_NAMES.get(key_type, f"type {key_type}")
    device_id = metadata.device.device_id.decode("utf-8", "replace")
    origin = f"written {written} by device {device_id!r}"
    if (result.plaintext is None and metadata.encryption_type
        == LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA):
      origin = "time and device encrypted with the logs"
    lines.append(f"  {origin}, key wrap {key_wrap}")

  if result.plaintext is not None:
    lines.append(f"  decrypted {len(result.plaintext)} bytes of logs")
  if result.trailer:
    lines.append(
        f"  activity log: since record {result.trailer.since}, "
        f"{result.trailer.records} new records, chain head "
        f"{result.trailer.head}")
  if result.signer:
    fingerprint = hashlib.sha256(result.signer.key).hexdigest()
    lines.append(
        f"  batch {result.batch.sequence_number}, signed by "
        f"{result.signer.security_level} key "
        f"{fingerprint[:_FINGERPRINT_DIGITS]}")
    # As the Crumbles main screen and the release notes show them.
    lines.extend(
        f"  app signing certificate (SHA-256): {digest.hex(':').upper()}"
        for digest in result.signer.app_certificates)
    lines.append(
        f"  bootloader locked, verified boot state {result.signer.boot_state}"
        f", verified boot key {result.signer.boot_key.hex()}")
  if result.out_path:
    lines.append(f"  written to {result.out_path}")

  if result.plaintext:
    if result.plaintext.startswith(b"Crumbles: logging was turned off"):
      lines.append("  NOTICE: logging was turned off")
    if result.plaintext.startswith(b"Crumbles key handover"):
      lines.append("  NOTICE: key handover")
    if result.plaintext.startswith(b"Crumbles upload destination change"):
      lines.append("  NOTICE: upload destination change")
    if result.plaintext.startswith(_PAUSE_BATCH_PREFIXES):
      lines.append(
          "  NOTICE: collection paused: secondary or guest user present"
      )

  lines.extend(f"  NOTICE: {notice}" for notice in result.notices)
  lines.extend(f"  PROBLEM: {problem}" for problem in result.problems)
  return [_printable(line) for line in lines]


def _write_logs(result: Result, out_dir: pathlib.Path) -> Result:
  """Writes the decrypted logs of a batch to a new file.

  Only the user can read the file. An existing file is not overwritten.

  Args:
    result: The Result of a batch file.
    out_dir: The directory to write the logs to.

  Returns:
    result with the path of the new file, or with a problem if the file
    already exists or cannot be written. result itself if the batch was not
    decrypted.
  """
  if result.plaintext is None:
    return result

  out_path = out_dir / f"{result.path.name}.txt"
  try:
    file_descriptor = os.open(
        out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _LOGS_FILE_MODE)
    with os.fdopen(file_descriptor, "wb") as out_file:
      out_file.write(result.plaintext)
  except FileExistsError:
    return _with_problems(
        result, [f"{out_path} already exists, so it was not overwritten"])
  except OSError as e:
    return _with_problems(result, [f"cannot write {out_path}: {e}"])

  return dataclasses.replace(result, out_path=out_path)


def _sha256_digest(text: str) -> bytes:
  """Reads a SHA-256 digest, in hex.

  Args:
    text: 64 hex digits, with or without a colon between each pair, as
      apksigner, the Crumbles main screen, release notes and custom ROMs write
      them.

  Returns:
    The digest.

  Raises:
    argparse.ArgumentTypeError: If text is not such a digest.
  """
  hex_digits = text.replace(":", "")
  if not re.fullmatch(r"[0-9a-fA-F]{64}", hex_digits):
    raise argparse.ArgumentTypeError(f"not a SHA-256 digest in hex: {text}")
  return bytes.fromhex(hex_digits)


def _check_devices(
    results: Sequence[Result], devices: Collection[str]
) -> list[Result]:
  """Flags the batches of devices that --device does not name.

  Args:
    results: The checked batches.
    devices: The device IDs given with --device.

  Returns:
    The results, where each batch of another device is untrusted and has a
    problem.
  """
  checked = []
  for result in results:
    device_id = (
        result.signer.device_id
        if result.signer
        else result.metadata.device.device_id
    ).decode("utf-8", "replace")
    if device_id in devices:
      checked.append(result)
    else:
      checked.append(dataclasses.replace(
          _with_problems(
              result, (f"device {device_id!r} was not given with --device",)),
          signer_trusted=False))
  return checked


def main(
    argv: Sequence[str] | None = None,
    root_keys: Collection[str] = GOOGLE_ROOT_KEYS,
) -> int:
  """Decrypts and checks the batches named on the command line.

  Args:
    argv: The command line arguments, or None for those of the process.
    root_keys: The SHA-256 hashes, in hex, of the SubjectPublicKeyInfo of the
      trusted attestation roots.

  Returns:
    The exit status: 1 if a batch has a problem, or else 0.
  """
  # argparse rather than absl flags, so that the script needs nothing but the
  # packages in requirements.txt.
  parser = argparse.ArgumentParser(
      description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument(
      "--key",
      action="append",
      required=True,
      type=pathlib.Path,
      help="an RSA private key file of a recipient; can be repeated",
  )
  parser.add_argument("--out", type=pathlib.Path,
                      help="directory to write the decrypted logs to")
  parser.add_argument(
      "--app-cert", action="append", default=[], type=_sha256_digest,
      help="SHA-256 digest of a certificate that the app may be signed with, "
           "in hex; can be repeated")
  parser.add_argument(
      "--boot-key", action="append", default=[], type=_sha256_digest,
      help="verified boot key that may make signing keys, in hex; required "
           "for custom ROMs and checked for all boot states when given; can "
           "be repeated")
  parser.add_argument("--allow-pkcs1", action="store_true",
                      help="allow legacy RSA-PKCS1v1.5 key wrap")
  parser.add_argument("--allow-unsigned", action="store_true",
                      help="allow unsigned batches to advance trailer chain")
  parser.add_argument("--max-age", type=int,
                      help="max allowed age of the newest batch in hours")
  parser.add_argument(
      "--device", action="append", default=[],
      help="ID of a device whose batches are expected: each must have a "
           "trusted batch, and batches of other devices are problems; can be "
           "repeated")
  parser.add_argument(
      "--attestation-status",
      action="append",
      default=[],
      type=pathlib.Path,
      help=(
          "a copy of Google's list of revoked attestation certificates, from "
          "https://android.googleapis.com/attestation/status; can be "
          "repeated, and no certificate may be on any of them"
      ),
  )
  parser.add_argument("batches", nargs="+", type=pathlib.Path,
                      help="batch files, or directories of .bin files")
  args = parser.parse_args(argv)

  if not args.app_cert:
    print("WARNING: No --app-cert given. The app signing certificate "
          "will not be verified.", file=sys.stderr)
  if not args.attestation_status:
    print("WARNING: No --attestation-status given. Certificates will not "
          "be checked against a revocation list.", file=sys.stderr)

  try:
    private_keys = [load_private_key(path.read_bytes()) for path in args.key]
  except (OSError, ValueError) as e:
    parser.error(f"cannot load the private key: {e}")

  certificate_statuses = {}
  for status_path in args.attestation_status:
    try:
      certificate_statuses.update(
          load_attestation_status(status_path.read_bytes())
      )
    except (OSError, ValueError) as e:
      parser.error(f"cannot load the attestation status list: {e}")
  paths = []
  for path in args.batches:
    paths.extend(sorted(path.glob("*.bin")) if path.is_dir() else [path])

  results = check_batches(
      paths,
      private_keys,
      root_keys,
      frozenset(args.app_cert),
      frozenset(args.boot_key),
      certificate_statuses,
      args.allow_unsigned,
      args.allow_pkcs1,
  )
  if not results:
    print("WARNING: No batches found.", file=sys.stderr)
    return 1
  if args.device:
    results = _check_devices(results, frozenset(args.device))
  if args.out:
    args.out.mkdir(mode=_LOGS_DIRECTORY_MODE, parents=True, exist_ok=True)
    new_results = []
    for result in results:
      if result.signer_trusted:
        new_results.append(_write_logs(result, args.out))
      elif result.plaintext is not None:
        unverified_dir = args.out / "unverified"
        unverified_dir.mkdir(mode=_LOGS_DIRECTORY_MODE, exist_ok=True)
        new_results.append(_write_logs(result, unverified_dir))
      else:
        new_results.append(result)
    results = new_results

  for result in results:
    print("\n".join(_describe(result)))

  failed = sum(1 for result in results if result.problems)

  now = datetime.datetime.now(datetime.timezone.utc)
  device_stats = {}
  for result in results:
    if result.signer_trusted and result.signer.device_id:
      dev = result.signer.device_id.decode("utf-8", "replace")
      seq = result.batch.sequence_number
      time_val = None
      if result.metadata.HasField("timestamp"):
        time_val = result.metadata.timestamp.seconds

      if dev not in device_stats:
        device_stats[dev] = {
            "min_seq": seq, "max_seq": seq,
            "min_time": time_val, "max_time": time_val,
            "latest_seq_time": time_val
        }
      else:
        stats = device_stats[dev]
        stats["min_seq"] = min(stats["min_seq"], seq)
        if seq > stats["max_seq"]:
          stats["max_seq"] = seq
          stats["latest_seq_time"] = time_val
        if time_val is not None:
          if stats["min_time"] is None or time_val < stats["min_time"]:
            stats["min_time"] = time_val
          if stats["max_time"] is None or time_val > stats["max_time"]:
            stats["max_time"] = time_val

  for dev, stats in device_stats.items():
    try:
      min_t = (datetime.datetime.fromtimestamp(
          stats["min_time"], datetime.timezone.utc).isoformat()
               if stats["min_time"] is not None else "unknown")
    except (OverflowError, OSError, ValueError):
      min_t = "invalid"
    try:
      max_t = (datetime.datetime.fromtimestamp(
          stats["max_time"], datetime.timezone.utc).isoformat()
               if stats["max_time"] is not None else "unknown")
    except (OverflowError, OSError, ValueError):
      max_t = "invalid"

    safe_dev = _printable(dev)
    print(f"Device '{safe_dev}': sequences {stats['min_seq']} to "
          f"{stats['max_seq']}, times {min_t} to {max_t}")
    if args.max_age is not None:
      latest_time = stats["latest_seq_time"]
      if latest_time is None:
        print(f"WARNING: device '{safe_dev}' has no timestamp on its newest "
              "batch!")
        failed += 1
      else:
        age_hours = (now.timestamp() - latest_time) / 3600
        if age_hours < 0:
          print(f"WARNING: device '{safe_dev}' newest batch is from the "
                "future!")
          failed += 1
        elif age_hours > args.max_age:
          print(f"WARNING: device '{safe_dev}' newest batch is "
                f"{age_hours:.1f} hours old, exceeding --max-age "
                f"{args.max_age}!")
          failed += 1

  for dev in args.device:
    if dev not in device_stats:
      print(f"WARNING: device '{_printable(dev)}' given with --device has no "
            "trusted batch!")
      failed += 1

  if args.attestation_status:
    newest = datetime.datetime.fromtimestamp(
        max(path.stat().st_mtime for path in args.attestation_status),
        datetime.timezone.utc,
    )
    print(
        f"{len(certificate_statuses)} revoked or suspended attestation "
        f"certificates in {len(args.attestation_status)} status lists, the "
        f"newest from {newest.isoformat(timespec='minutes')}"
    )
  print(f"{len(results)} batches, {failed} with problems.")
  return 1 if failed else 0


if __name__ == "__main__":
  sys.exit(main())
