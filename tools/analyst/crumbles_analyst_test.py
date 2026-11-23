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
"""Tests crumbles_analyst with keys and batches that the test makes itself.

Outside this repository, the test needs absl-py besides the packages in
requirements.txt.
"""

import base64
from collections.abc import Callable, Collection, Sequence
import contextlib
import datetime
import hashlib
import io
import json
import os
import pathlib
import sys
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.x509 import oid
from google.protobuf import message

# The script runs on its own rather than as part of a package, so the test
# imports it from its directory.
sys.path.insert(0, str(pathlib.Path(__file__).absolute().parent))
# pylint: disable=g-bad-import-order,g-import-not-at-top
import crumbles_analyst

_OAEP = padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_AES_KEY_BYTES = 32
_GCM_IV_BYTES = 12
_GCM_TAG_BYTES = 16
_LOG_ENCRYPTION_TYPE_AES_GCM = 1
# The other LogEncryptionType values.
_PADDED = crumbles_analyst.LOG_ENCRYPTION_TYPE_AES_GCM_PADDED
_SEALED_METADATA = crumbles_analyst.LOG_ENCRYPTION_TYPE_AES_GCM_SEALED_METADATA
# How CrumblesLogsEncryptor pads: the size of what it pads in 4 bytes, then
# zero bytes up to a power of two of at least 4096 bytes.
_LENGTH_BYTES = 4
_MIN_PADDED_BYTES = 4096
# Tags of activity log records.
_TAG_A, _TAG_B, _TAG_C = "a" * 64, "b" * 64, "c" * 64
# Made once, as key generation is slow.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_DER_KEY = _KEY.private_bytes(serialization.Encoding.DER,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
_OTHER_DER_KEY = _OTHER_KEY.private_bytes(
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
_LEAF_KEY = ec.generate_private_key(ec.SECP256R1())
_INTERMEDIATE_KEY = ec.generate_private_key(ec.SECP256R1())
_P384_KEY = ec.generate_private_key(ec.SECP384R1())
_ED25519_KEY = ed25519.Ed25519PrivateKey.generate()
# A key outside any TEE, which an attacker certifies with _LEAF_KEY.
_FORGED_LEAF_KEY = ec.generate_private_key(ec.SECP256R1())
# What the attestation of a batch-signing key holds.
_ATTESTATION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
_PROVISIONING_INFO_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.30")
_PACKAGE_NAME = b"com.android.securelogging"
# SHA-256 digests of app signing certificates.
_APP_CERTIFICATE = hashlib.sha256(b"app certificate").digest()
_OTHER_APP_CERTIFICATE = hashlib.sha256(b"other app certificate").digest()
# Verified boot keys, and VerifiedBootState values.
_BOOT_KEY = hashlib.sha256(b"boot key").digest()
_OTHER_BOOT_KEY = hashlib.sha256(b"other boot key").digest()
_VERIFIED, _SELF_SIGNED, _UNVERIFIED, _FAILED = (
    b"\x00", b"\x01", b"\x02", b"\x03")
_SOFTWARE, _TEE, _STRONGBOX = b"\x00", b"\x01", b"\x02"
# DER identifier octets, and BOOLEAN contents.
_INTEGER, _OCTET_STRING, _ENUMERATED = b"\x02", b"\x04", b"\x0a"
_BOOLEAN, _TRUE, _FALSE = b"\x01", b"\xff", b"\x00"
_SEQUENCE, _SET = b"\x30", b"\x31"
_CREATION_DATETIME = b"\xbf\x85\x3d"  # [701] EXPLICIT
_ORIGIN = b"\xbf\x85\x3e"  # [702] EXPLICIT
_ROOT_OF_TRUST = b"\xbf\x85\x40"  # [704] EXPLICIT
_APPLICATION_ID = b"\xbf\x85\x45"  # [709] EXPLICIT
_OS_VERSION = b"\xbf\x85\x41"  # [705] EXPLICIT
_OS_PATCH_LEVEL = b"\xbf\x85\x42"  # [706] EXPLICIT
_VENDOR_PATCH_LEVEL = b"\xbf\x85\x4e"  # [718] EXPLICIT
_BOOT_PATCH_LEVEL = b"\xbf\x85\x4f"  # [719] EXPLICIT

_PrivateKey = (
    ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey)


def _pad(contents: bytes) -> bytes:
  """Pads contents as CrumblesLogsEncryptor.padToSizeBucket does."""
  size = _MIN_PADDED_BYTES
  while size < _LENGTH_BYTES + len(contents):
    size *= 2
  length = len(contents).to_bytes(_LENGTH_BYTES, "big")
  return (length + contents).ljust(size, b"\x00")


def _encrypt(
    logs: bytes,
    public_key: rsa.RSAPublicKey = _KEY.public_key(),
    key_type: int = crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
    aes_key_bytes: int = _AES_KEY_BYTES,
    iv_bytes: int = _GCM_IV_BYTES,
    seconds: int | None = 1,
    device_id: bytes = b"device-1",
    log_type: int = _LOG_ENCRYPTION_TYPE_AES_GCM,
    plaintext: bytes | None = None,
    attestation_chain: Sequence[bytes] = (),
    bound_recipient: rsa.RSAPublicKey | None = None,
) -> message.Message:
  """Returns a LogBatch as CrumblesLogsEncryptor makes it."""
  # The batch has the LogEncryptionType log_type. AES-GCM encrypts plaintext if
  # given, or else what log_type says: the logs, padded or not, or a padded
  # SealedLogs that holds the logs, seconds, device_id and attestation_chain.
  # Only a format version 2 batch seals attestation_chain. With seconds None,
  # the metadata has no timestamp. The associated data of a format version 2
  # batch binds bound_recipient, or else public_key.
  sealed_logs = crumbles_analyst.SealedLogs(
      logs=logs, attestation_chain=attestation_chain
  )
  if seconds is not None:
    sealed_logs.metadata.timestamp.seconds = seconds
  sealed_logs.metadata.device.device_id = device_id
  batch = crumbles_analyst.LogBatch()
  if log_type == _SEALED_METADATA:
    contents = sealed_logs.SerializeToString()
  else:
    batch.metadata.MergeFrom(sealed_logs.metadata)
    contents = logs
  if plaintext is None:
    padded = log_type != _LOG_ENCRYPTION_TYPE_AES_GCM
    plaintext = _pad(contents) if padded else contents
  batch.metadata.blob_size = len(plaintext) + _GCM_TAG_BYTES
  batch.metadata.encryption_type = log_type
  aes_key = os.urandom(aes_key_bytes)
  wrap = (padding.PKCS1v15()
          if key_type == crumbles_analyst.KEY_ENCRYPTION_TYPE_ASYMMETRIC
          else _OAEP)
  batch.key.key_encryption_type = key_type
  batch.key.encrypted_symmetric_key = public_key.encrypt(aes_key, wrap)
  batch.key.iv = os.urandom(iv_bytes)
  recipient = public_key if bound_recipient is None else bound_recipient
  aad = crumbles_analyst.associated_data(
      batch.metadata,
      key_type,
      recipient.public_bytes(
          serialization.Encoding.DER,
          serialization.PublicFormat.SubjectPublicKeyInfo,
      ),
  )
  batch.data.log_blob = aead.AESGCM(aes_key).encrypt(
      batch.key.iv, plaintext, aad)
  return batch


def _claim_other_device(batch: message.Message) -> message.Message:
  """Alters the metadata of batch, as an attacker could."""
  batch.metadata.device.device_id = b"device-2"
  return batch


def _trailer(
    since: str,
    head: str,
    records: Sequence[str] | None = None,
    previous_record_missing: bool = False,
) -> bytes:
  """Returns a trailer as CrumblesAuditExcerpt.toBytes writes it."""
  if records is None:
    records = ('{"sequenceNumber": 1}',)
  lines = [f"\n--- Crumbles activity log since record {since} ---"]
  if previous_record_missing:
    lines.append("--- The previous batch's last activity record is no longer "
                 "on this device ---")
  lines += [*records, f"--- Crumbles activity log chain head: {head} ---"]
  return ("\n".join(lines) + "\n").encode()


def _der(tag: bytes, *contents: bytes) -> bytes:
  """Returns a DER element with the identifier octets tag."""
  body = b"".join(contents)
  if len(body) < 0x80:
    return tag + bytes([len(body)]) + body
  size = (len(body).bit_length() + 7) // 8
  return tag + bytes([0x80 | size]) + len(body).to_bytes(size, "big") + body


def _der_int(value: int) -> bytes:
  """Returns a DER INTEGER for value."""
  length = max(1, (value.bit_length() + 8) // 8)
  return _der(_INTEGER, value.to_bytes(length, "big", signed=True))


def _minimal_cert_der(version: int = 2, extensions: bytes = b"") -> bytes:
  """Returns a minimal keyless X.509 DER certificate for parser error tests."""
  alg = _der(
      _SEQUENCE, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"
  )
  name = _der(_SEQUENCE)
  time_utc = b"\x17\x0d260101000000Z"
  validity = _der(_SEQUENCE, time_utc, time_utc)
  spki = _der(_SEQUENCE, alg, b"\x03\x02\x00\x00")
  ext_field = _der(b"\xa3", _der(_SEQUENCE, extensions)) if extensions else b""
  tbs = _der(
      _SEQUENCE,
      _der(b"\xa0", _der(_INTEGER, bytes([version]))),
      _der(_INTEGER, b"\x01"),
      alg,
      name,
      validity,
      name,
      spki,
      ext_field,
  )
  return _der(_SEQUENCE, tbs, alg, b"\x03\x02\x00\x00")


def _key_description(
    challenge: bytes = b"device-1",
    level: bytes = _TEE,
    package: bytes = _PACKAGE_NAME,
    app_certificates: Sequence[bytes] = (_APP_CERTIFICATE,),
    locked: bytes = _TRUE,
    boot_state: bytes = _VERIFIED,
    boot_key: bytes = _BOOT_KEY,
    software_root_of_trust: bool = False,
    creation_millis: int | None = 1000,
    hardware_creation_time: bool = False,
    origin: bytes | None = b"\x00",
    extra_software_tags: Sequence[bytes] = (),
    extra_hardware_tags: Sequence[bytes] = (),
) -> bytes:
  """Returns a KeyDescription as Android key attestation writes it."""
  package_info = _der(_SEQUENCE, _der(_OCTET_STRING, package),
                      _der(_INTEGER, b"\x01"))
  digests = [_der(_OCTET_STRING, digest) for digest in app_certificates]
  application_id = _der(_SEQUENCE, _der(_SET, package_info),
                        _der(_SET, *digests))
  root_of_trust = _der(_ROOT_OF_TRUST, _der(
      _SEQUENCE, _der(_OCTET_STRING, boot_key), _der(_BOOLEAN, locked),
      _der(_ENUMERATED, boot_state), _der(_OCTET_STRING, bytes(32))))
  software_enforced = [
      _der(_APPLICATION_ID, _der(_OCTET_STRING, application_id)),
      *extra_software_tags,
  ]
  hardware_enforced = [*extra_hardware_tags]
  if origin is not None:
    hardware_enforced.append(_der(_ORIGIN, _der(_INTEGER, origin)))
  if creation_millis is not None:
    creation_tag = _der(_CREATION_DATETIME, _der_int(creation_millis))
    if hardware_creation_time:
      hardware_enforced.append(creation_tag)
    else:
      software_enforced.append(creation_tag)
  if software_root_of_trust:  # As an altered OS could write it.
    software_enforced.insert(0, root_of_trust)
  else:
    hardware_enforced.append(root_of_trust)
  return _der(
      _SEQUENCE, _der(_INTEGER, b"\x64"), _der(_ENUMERATED, level),
      _der(_INTEGER, b"\x64"), _der(_ENUMERATED, level),
      _der(_OCTET_STRING, challenge),
      # A uniqueId long enough to need a long-form length.
      _der(_OCTET_STRING, bytes(200)),
      _der(_SEQUENCE, *software_enforced),
      _der(_SEQUENCE, *hardware_enforced))


def _certificate(
    subject_key: _PrivateKey,
    issuer_key: _PrivateKey,
    key_description: bytes | None = None,
    serial_number: int = 1,
    not_valid_before: datetime.datetime = datetime.datetime(1970, 1, 1),
    not_valid_after: datetime.datetime = datetime.datetime(2036, 1, 1),
    ca: bool | None = None,
    path_length: int | None = None,
    include_basic_constraints: bool = True,
    key_cert_sign: bool = True,
    include_key_usage: bool | None = None,
    rkp: bool = False,
) -> bytes:
  """Returns a DER certificate of subject_key, signed by issuer_key."""
  name = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "Test")])
  builder = (
      x509.CertificateBuilder().subject_name(name).issuer_name(name)
      .public_key(subject_key.public_key()).serial_number(serial_number)
      .not_valid_before(not_valid_before)
      .not_valid_after(not_valid_after))
  is_ca = (key_description is None) if ca is None else ca
  if include_basic_constraints:
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length),
        critical=True)
  add_key_usage = (
      (key_description is None)
      if include_key_usage is None
      else include_key_usage
  )
  if add_key_usage:
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=key_cert_sign, crl_sign=False,
            encipher_only=False, decipher_only=False),
        critical=True)
  if rkp:
    builder = builder.add_extension(
        x509.UnrecognizedExtension(_PROVISIONING_INFO_OID, _der(_SEQUENCE)),
        critical=False)
  if key_description is not None:
    builder = builder.add_extension(
        x509.UnrecognizedExtension(_ATTESTATION_OID, key_description),
        critical=False)
  algorithm = (
      None if isinstance(issuer_key, ed25519.Ed25519PrivateKey)
      else hashes.SHA256())
  certificate = builder.sign(issuer_key, algorithm)
  return certificate.public_bytes(serialization.Encoding.DER)


def _public_key_der(key: _PrivateKey) -> bytes:
  """Returns the DER SubjectPublicKeyInfo of the public key of key."""
  return key.public_key().public_bytes(
      serialization.Encoding.DER,
      serialization.PublicFormat.SubjectPublicKeyInfo)


def _attestation_chain(
    leaf_key: ec.EllipticCurvePrivateKey = _LEAF_KEY,
    chain_tail: Sequence[bytes] | None = None,
    key_description: bytes | None = _key_description(),
) -> list[bytes]:
  """Returns the attestation chain of leaf_key, leaf first."""
  leaf = _certificate(leaf_key, _INTERMEDIATE_KEY, key_description)
  return [leaf, *(_CHAIN_TAIL if chain_tail is None else chain_tail)]


def _sign(
    batch: message.Message,
    number: int,
    leaf_key: ec.EllipticCurvePrivateKey = _LEAF_KEY,
    chain_tail: Sequence[bytes] | None = None,
    key_description: bytes | None = _key_description(),
) -> message.Message:
  """Numbers and signs batch as CrumblesBatchSigner does."""
  # Like CrumblesBatchSigner, this leaves the attestation chain out of the
  # signature of a format version 2 batch, which must seal it instead: pass the
  # chain to _encrypt.
  batch.sequence_number = number
  batch.ClearField("signature")
  batch.signature.signature = leaf_key.sign(
      batch.SerializeToString(), ec.ECDSA(hashes.SHA256()))
  if batch.metadata.encryption_type != _SEALED_METADATA:
    batch.signature.attestation_chain.extend(
        _attestation_chain(leaf_key, chain_tail, key_description)
    )
  return batch


def _with_chain(
    batch: message.Message, chain: Sequence[bytes]) -> message.Message:
  """Replaces the attestation chain of batch, keeping its signature."""
  del batch.signature.attestation_chain[:]
  batch.signature.attestation_chain.extend(chain)
  return batch


def _sealed(
    number: int,
    recipient: rsa.RSAPrivateKey,
    logs: bytes = _trailer(_TAG_A, _TAG_A, []),
) -> message.Message:
  """Returns the format version 2 batch number, encrypted to recipient."""
  return _sign(
      _encrypt(
          logs,
          recipient.public_key(),
          log_type=_SEALED_METADATA,
          attestation_chain=_attestation_chain(),
      ),
      number,
  )


def _signature_first(batch: message.Message) -> bytes:
  """Serializes batch with its signature first rather than last."""
  signature = crumbles_analyst.LogBatch(
      signature=batch.signature).SerializeToString()
  return signature + batch.SerializeToString().removesuffix(signature)


def _write_batches(
    batch_dir: pathlib.Path, batches: dict[str, message.Message]) -> None:
  """Writes each batch to a file of batch_dir, by file name."""
  for name, batch in batches.items():
    (batch_dir / name).write_bytes(batch.SerializeToString())


def _run_main(*args: object) -> tuple[int, str]:
  """Runs the script with args, and returns its exit status and output."""
  stdout = io.StringIO()
  with contextlib.redirect_stdout(stdout):
    status = crumbles_analyst.main([str(arg) for arg in args], _ROOT_KEYS)
  return status, stdout.getvalue()


# The attestation chain of _LEAF_KEY after its own certificate: the
# certificate of _INTERMEDIATE_KEY, and that of _KEY as the root.
_INTERMEDIATE_SERIAL_NUMBER = 0x2c8cdddfd5e03bfc
_ROOT = _certificate(_KEY, _KEY)
_CHAIN_TAIL = (
    _certificate(_INTERMEDIATE_KEY, _KEY,
                 serial_number=_INTERMEDIATE_SERIAL_NUMBER),
    _ROOT)
_ROOT_KEYS = frozenset([hashlib.sha256(_public_key_der(_KEY)).hexdigest()])
_CANNOT_UNWRAP = (
    "cannot unwrap the AES key: the batch was encrypted to another key, or it "
    "is corrupt"
)


class CrumblesAnalystTest(parameterized.TestCase):

  def setUp(self) -> None:
    super().setUp()
    self.temp_dir = pathlib.Path(self.create_tempdir().full_path)
    self.key_file = self.temp_dir / "key.txt"
    self.key_file.write_bytes(base64.b64encode(_DER_KEY))
    self.batch_dir = self.temp_dir / "batches"
    self.batch_dir.mkdir()
    self.out_dir = self.temp_dir / "out"

  def test_associated_data_matches_the_wire_format(self) -> None:
    metadata = crumbles_analyst.LogBatch().metadata
    metadata.blob_size = 300
    metadata.timestamp.seconds = 1760000000
    metadata.timestamp.nanos = 5
    metadata.device.device_id = b"dev"
    metadata.encryption_type = _LOG_ENCRYPTION_TYPE_AES_GCM
    aad = crumbles_analyst.associated_data(
        metadata, crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256)
    # The four metadata fields in order, then the key encryption type 4.
    self.assertEqual(
        aad.hex(), "08ac02" "12080880f09dc7061005" "1a050a03646576" "2001" "04")

  def test_version_2_associated_data_has_a_label_and_the_recipient_fingerprint(
      self,
  ) -> None:
    metadata = crumbles_analyst.LogBatch().metadata
    metadata.blob_size = 4112
    metadata.encryption_type = _SEALED_METADATA
    recipient_der = _public_key_der(_KEY)
    aad = crumbles_analyst.associated_data(
        metadata,
        crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
        recipient_der,
    )
    # The label, the two cleartext metadata fields, the key encryption type 4,
    # then the SHA-256 digest of the recipient's public key.
    self.assertEqual(
        aad,
        b"crumbles/v2/batch"
        + bytes.fromhex("089020 2003 04")
        + hashlib.sha256(recipient_der).digest(),
    )

  def test_version_2_associated_data_requires_the_recipient(self) -> None:
    metadata = crumbles_analyst.LogBatch().metadata
    metadata.encryption_type = _SEALED_METADATA
    with self.assertRaisesWithLiteralMatch(
        ValueError, "a format version 2 batch is bound to its recipient"
    ):
      crumbles_analyst.associated_data(
          metadata, crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256
      )

  @parameterized.named_parameters(
      dict(testcase_name="version_1", log_type=_LOG_ENCRYPTION_TYPE_AES_GCM),
      dict(testcase_name="padded", log_type=_PADDED),
  )
  def test_older_associated_data_binds_no_recipient(
      self, log_type: int
  ) -> None:
    metadata = crumbles_analyst.LogBatch().metadata
    metadata.blob_size = 300
    metadata.encryption_type = log_type
    key_type = crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256
    self.assertEqual(
        crumbles_analyst.associated_data(
            metadata, key_type, _public_key_der(_KEY)
        ),
        crumbles_analyst.associated_data(metadata, key_type),
    )

  @parameterized.named_parameters(
      dict(testcase_name="oaep",
           key_type=crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256),
      dict(testcase_name="legacy_pkcs1",
           key_type=crumbles_analyst.KEY_ENCRYPTION_TYPE_ASYMMETRIC),
      dict(testcase_name="padded", log_type=_PADDED),
      dict(testcase_name="padded_without_zeros", log_type=_PADDED,
           plaintext=b"\x00\x00\x00\x04logs"),
      dict(testcase_name="sealed_metadata", log_type=_SEALED_METADATA),
  )
  def test_decrypts_batch(
      self,
      key_type: int = crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256,
      log_type: int = _LOG_ENCRYPTION_TYPE_AES_GCM,
      plaintext: bytes | None = None,
  ) -> None:
    data = _encrypt(b"logs", key_type=key_type, seconds=7, device_id=b"phone",
                    log_type=log_type, plaintext=plaintext).SerializeToString()
    batch = crumbles_analyst.parse_batch(data)
    decrypted = crumbles_analyst.decrypt_batch(
        batch, _KEY,
        allow_pkcs1=(
            key_type == crumbles_analyst.KEY_ENCRYPTION_TYPE_ASYMMETRIC))
    metadata = decrypted.metadata
    self.assertEqual(
        (decrypted.logs, metadata.blob_size, metadata.timestamp.seconds,
         metadata.device.device_id, metadata.encryption_type),
        (b"logs", batch.metadata.blob_size, 7, b"phone", log_type))

  def test_decrypts_the_attestation_chain_sealed_in_a_version_2_batch(
      self,
  ) -> None:
    chain = _attestation_chain()
    batch = _encrypt(
        b"logs", log_type=_SEALED_METADATA, attestation_chain=chain
    )

    decrypted = crumbles_analyst.decrypt_batch(batch, _KEY)

    self.assertEqual(decrypted.attestation_chain, tuple(chain))

  @parameterized.named_parameters(
      dict(testcase_name="other_recipient",
           batch=_encrypt(b"logs", _OTHER_KEY.public_key()),
           error="cannot unwrap"),
      dict(testcase_name="short_aes_key",
           batch=_encrypt(b"logs", aes_key_bytes=16),
           error="cannot unwrap"),
      dict(testcase_name="unsupported_key_type",
           batch=_encrypt(b"logs", key_type=2),
           error="unsupported key encryption type 2"),
      dict(testcase_name="long_iv",
           batch=_encrypt(b"logs", iv_bytes=16),
           error="the IV has 16 bytes instead of 12"),
      dict(testcase_name="altered_metadata",
           batch=_claim_other_device(_encrypt(b"logs")),
           error="AES-GCM authentication failed"),
      dict(testcase_name="padding_shorter_than_declared",
           batch=_encrypt(b"logs", log_type=_PADDED,
                          plaintext=b"\x00\x00\x00\x05logs"),
           error="the padded logs declare more bytes than they hold"),
      dict(testcase_name="no_padding",
           batch=_encrypt(b"logs", log_type=_PADDED, plaintext=b""),
           error="the padded logs declare more bytes than they hold"),
      dict(testcase_name="malformed_sealed_logs",
           batch=_encrypt(b"logs", log_type=_SEALED_METADATA,
                          plaintext=_pad(b"\xff")),
           error="malformed sealed logs"),
  )
  def test_rejects_batch_it_cannot_decrypt(
      self, batch: message.Message, error: str) -> None:
    with self.assertRaisesRegex(crumbles_analyst.BatchError, error):
      crumbles_analyst.decrypt_batch(batch, _KEY)

  def test_rejects_version_2_batch_bound_to_another_recipient(self) -> None:
    # Its AES key is wrapped to _KEY, but it is bound to _OTHER_KEY, as when
    # someone wraps the key of a batch for _OTHER_KEY again for _KEY.
    batch = _encrypt(
        b"logs",
        log_type=_SEALED_METADATA,
        bound_recipient=_OTHER_KEY.public_key(),
    )

    with self.assertRaisesRegex(
        crumbles_analyst.BatchError, "AES-GCM authentication failed"
    ):
      crumbles_analyst.decrypt_batch(batch, _KEY)

  @parameterized.named_parameters(
      dict(testcase_name="not_protobuf",
           data=b"\xff",
           error="not a Crumbles log batch"),
      dict(testcase_name="empty",
           data=b"",
           error="not a Crumbles log batch: no data, key, metadata"),
      dict(testcase_name="no_metadata",
           data=crumbles_analyst.LogBatch(
               data={"log_blob": b"logs"}, key={"iv": b"iv"}
           ).SerializeToString(),
           error="not a Crumbles log batch: no metadata"),
  )
  def test_rejects_file_that_is_not_a_batch(
      self, data: bytes, error: str) -> None:
    with self.assertRaisesWithLiteralMatch(crumbles_analyst.BatchError, error):
      crumbles_analyst.parse_batch(data)

  @parameterized.named_parameters(
      dict(testcase_name="encrypted_pem",
           key_data=_KEY.private_bytes(
               serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
               serialization.BestAvailableEncryption(b"secret"))),
      dict(testcase_name="base64", key_data=base64.b64encode(_DER_KEY)),
      dict(testcase_name="base64_with_line_breaks",
           key_data=base64.encodebytes(_DER_KEY)),
  )
  def test_loads_private_key(self, key_data: bytes) -> None:
    key = crumbles_analyst.load_private_key(key_data, lambda prompt: "secret")
    self.assertEqual(key.private_numbers(), _KEY.private_numbers())

  def test_rejects_private_key_that_is_not_rsa(self) -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    with self.assertRaisesWithLiteralMatch(
        ValueError, "not an RSA private key"):
      crumbles_analyst.load_private_key(ec_key)

  def test_loads_attestation_status(self) -> None:
    status_data = json.dumps({"entries": {
        "2c8cdddfd5e03bfc": {"status": "REVOKED", "reason": "KEY_COMPROMISE",
                             "comment": "Key stored on unsecure system"},
        "c8966fcb2fbb0d7a": {"status": "SUSPENDED"},
    }}).encode()
    self.assertEqual(
        crumbles_analyst.load_attestation_status(status_data),
        {"2c8cdddfd5e03bfc": "REVOKED (KEY_COMPROMISE)",
         "c8966fcb2fbb0d7a": "SUSPENDED"})

  @parameterized.named_parameters(
      dict(testcase_name="not_json", status_data=b"junk"),
      dict(testcase_name="no_entries", status_data=b"{}"),
      dict(testcase_name="empty_entries", status_data=b'{"entries": {}}'),
      dict(testcase_name="entries_not_a_map", status_data=b'{"entries": []}'),
      dict(
          testcase_name="entry_without_status",
          status_data=b'{"entries": {"1": {}}}',
      ),
      dict(
          testcase_name="entry_with_an_empty_status",
          status_data=b'{"entries": {"1": {"status": ""}}}',
      ),
      dict(
          testcase_name="entry_not_a_map",
          status_data=b'{"entries": {"1": "REVOKED"}}',
      ),
  )
  def test_rejects_attestation_status_that_is_not_a_status_list(
      self, status_data: bytes) -> None:
    with self.assertRaises(ValueError):
      crumbles_analyst.load_attestation_status(status_data)

  @parameterized.named_parameters(
      dict(testcase_name="last_of_two",
           plaintext=(b"logs" + _trailer(_TAG_C, _TAG_C) + b"more logs\n"
                      + _trailer("none", _TAG_A, ['{"a": 1}', '{"b": 2}'],
                                 previous_record_missing=True)),
           expected=crumbles_analyst.Trailer(
               since="none", head=_TAG_A, records=2,
               previous_record_missing=True,
               first_seq=None, last_seq=None,
               problems=(
                   "activity log record missing sequenceNumber",
                   "activity log record missing sequenceNumber"))),
      dict(testcase_name="no_records",
           plaintext=_trailer(_TAG_A, _TAG_B, []),
           expected=crumbles_analyst.Trailer(
               since=_TAG_A, head=_TAG_B, records=0,
               previous_record_missing=False,
               first_seq=None, last_seq=None,
               problems=(
                   "0 records and no marker but head does not equal since",))),
  )
  def test_parses_last_trailer(
      self, plaintext: bytes, expected: crumbles_analyst.Trailer) -> None:
    self.assertEqual(crumbles_analyst.parse_trailer(plaintext), expected)

  @parameterized.named_parameters(
      dict(testcase_name="no_trailer",
           plaintext=b"logs\n",
           error="no activity log trailer"),
      dict(testcase_name="logs_after_trailer",
           plaintext=_trailer(_TAG_A, _TAG_B) + b"logs\n",
           error="malformed activity log trailer"),
      dict(testcase_name="record_not_json",
           plaintext=_trailer(_TAG_A, _TAG_B, ["not json"]),
           error="malformed activity log trailer"),
      dict(testcase_name="no_final_line_break",
           plaintext=_trailer(_TAG_A, _TAG_B).removesuffix(b"\n"),
           error="malformed activity log trailer"),
      dict(testcase_name="upper_case_tag",
           plaintext=_trailer(_TAG_A.upper(), _TAG_B),
           error="malformed activity log trailer"),
  )
  def test_rejects_missing_or_malformed_trailer(
      self, plaintext: bytes, error: str) -> None:
    with self.assertRaisesWithLiteralMatch(crumbles_analyst.BatchError, error):
      crumbles_analyst.parse_trailer(plaintext)

  @parameterized.named_parameters(
      dict(testcase_name="tee_signature_last",
           level=_TEE,
           boot_state=_VERIFIED,
           serialize=crumbles_analyst.LogBatch.SerializeToString,
           security_level="TEE",
           boot_state_name="Verified"),
      dict(testcase_name="strongbox_custom_rom_signature_first",
           level=_STRONGBOX,
           boot_state=_SELF_SIGNED,
           serialize=_signature_first,
           security_level="StrongBox",
           boot_state_name="SelfSigned"),
  )
  def test_checks_signature(
      self,
      level: bytes,
      boot_state: bytes,
      serialize: Callable[[message.Message], bytes],
      security_level: str,
      boot_state_name: str,
  ) -> None:
    batch = _sign(_encrypt(b"logs"), 1, key_description=_key_description(
        level=level, boot_state=boot_state))
    self.assertEqual(
        crumbles_analyst.check_signature(
            serialize(batch), batch, b"device-1", _ROOT_KEYS),
        crumbles_analyst.Signer(
            key=_public_key_der(_LEAF_KEY), security_level=security_level,
            app_certificates=(_APP_CERTIFICATE,), boot_state=boot_state_name,
            boot_key=_BOOT_KEY, device_id=b"device-1"))

  @parameterized.named_parameters(
      dict(testcase_name="unsigned",
           batch=_encrypt(b"logs"),
           error="unsigned batch"),
      dict(testcase_name="altered",
           batch=_claim_other_device(_sign(_encrypt(b"logs"), 1)),
           error="bad signature"),
      dict(testcase_name="no_certificates",
           batch=_with_chain(_sign(_encrypt(b"logs"), 1), []),
           error="no attestation certificates"),
      dict(testcase_name="malformed_certificate",
           batch=_with_chain(_sign(_encrypt(b"logs"), 1), [b"junk"]),
           error="malformed attestation certificate"),
      dict(testcase_name="p384_key",
           batch=_sign(_encrypt(b"logs"), 1, leaf_key=_P384_KEY),
           error="the signing key is not an EC P-256 key"),
      dict(testcase_name="leaf_from_another_issuer",
           batch=_sign(_encrypt(b"logs"), 1,
                       chain_tail=[_certificate(_LEAF_KEY, _KEY), _ROOT]),
           error="attestation certificate 1 did not sign 0"),
      dict(testcase_name="intermediate_from_another_issuer",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _LEAF_KEY), _ROOT]),
           error="attestation certificate 2 did not sign 1"),
      dict(testcase_name="intermediate_with_ed25519_key",
           batch=_sign(_encrypt(b"logs"), 1,
                       chain_tail=[_certificate(_ED25519_KEY, _KEY), _ROOT]),
           error="attestation certificate 1 did not sign 0"),
      dict(testcase_name="leaf_signed_with_ed25519",
           batch=_with_chain(
               _sign(_encrypt(b"logs"), 1),
               [_certificate(_LEAF_KEY, _ED25519_KEY, _key_description()),
                *_CHAIN_TAIL]),
           error="malformed attestation"),
      # A made-up leaf for a key outside any TEE, which an app certified with
      # its attested key: the chain is valid up to the root.
      dict(testcase_name="leaf_from_an_attested_app_key",
           batch=_with_chain(
               _sign(_encrypt(b"logs"), 1, leaf_key=_FORGED_LEAF_KEY), [
                   _certificate(_FORGED_LEAF_KEY, _LEAF_KEY,
                                _key_description()),
                   _certificate(_LEAF_KEY, _INTERMEDIATE_KEY,
                                _key_description(challenge=b"phone")),
                   *_CHAIN_TAIL]),
           error="attestation certificate 1 is that of an app's key"),
      dict(testcase_name="untrusted_root",
           batch=_sign(_encrypt(b"logs"), 1),
           root_keys=crumbles_analyst.GOOGLE_ROOT_KEYS,
           error="do not lead to a Google hardware attestation root"),
      dict(testcase_name="no_attestation",
           batch=_sign(_encrypt(b"logs"), 1, key_description=None),
           error="malformed key attestation"),
      dict(testcase_name="attestation_without_length",
           batch=_sign(_encrypt(b"logs"), 1, key_description=_SEQUENCE),
           error="malformed key attestation"),
      dict(testcase_name="truncated_attestation",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_SEQUENCE + b"\x05" + b"junk"),
           error="malformed key attestation"),
      dict(testcase_name="other_device",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(challenge=b"phone")),
           error="the key was attested for another device ID"),
      dict(testcase_name="other_package",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(package=b"com.ex")),
           error="the key does not belong to com.android.securelogging"),
      dict(testcase_name="no_app_certificate",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(app_certificates=())),
           error="the attestation names no signing certificate of the app"),
      dict(testcase_name="software_key",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(level=_SOFTWARE)),
           error="the key is not in a TEE or StrongBox"),
      dict(testcase_name="unlocked_bootloader",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(locked=_FALSE)),
           error="the key was made while the bootloader was unlocked"),
      dict(testcase_name="unverified_os",
           batch=_sign(
               _encrypt(b"logs"), 1,
               key_description=_key_description(boot_state=_UNVERIFIED)),
           error="the key was made by an OS that verified boot rejected"),
      dict(testcase_name="os_that_failed_verified_boot",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(boot_state=_FAILED)),
           error="the key was made by an OS that verified boot rejected"),
      dict(testcase_name="root_of_trust_from_the_os",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(
                           software_root_of_trust=True)),
           error="malformed key attestation"),
      dict(testcase_name="invalid_version_certificate",
           batch=_with_chain(
               _sign(_encrypt(b"logs"), 1), [_minimal_cert_der(version=1)]),
           error=r"malformed attestation certificate \(InvalidVersion\)"),
      dict(testcase_name="duplicate_extension_certificate",
           batch=_with_chain(
               _sign(_encrypt(b"logs"), 1),
               [_minimal_cert_der(
                   version=2,
                   extensions=_der(
                       _SEQUENCE, b"\x06\x03\x55\x1d\x13",
                       _der(_OCTET_STRING, _der(_SEQUENCE))) * 2)]),
           error=r"malformed attestation certificate \(DuplicateExtension\)"),
      dict(testcase_name="intermediate_not_a_ca",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _KEY, ca=False), _ROOT]),
           error="attestation certificate 1 is not a CA"),
      dict(testcase_name="intermediate_without_basic_constraints",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _KEY,
                            include_basic_constraints=False), _ROOT]),
           error="attestation certificate 1 is not a CA"),
      dict(testcase_name="root_exceeds_path_length",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _KEY),
               _certificate(_KEY, _KEY, path_length=0)]),
           error="attestation certificate 2 exceeds path length"),
      dict(testcase_name="intermediate_without_cert_sign",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _KEY, key_cert_sign=False),
               _ROOT]),
           error="attestation certificate 1 cannot sign certificates"),
      dict(testcase_name="intermediate_without_key_usage",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _KEY, include_key_usage=False),
               _ROOT]),
           error="attestation certificate 1 cannot sign certificates"),
      dict(testcase_name="root_not_self_signed",
           batch=_sign(_encrypt(b"logs"), 1, chain_tail=[
               _certificate(_INTERMEDIATE_KEY, _KEY),
               _certificate(_KEY, _OTHER_KEY)]),
           error="the root certificate is not self-signed"),
      dict(testcase_name="missing_origin",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(origin=None)),
           error="the key was not generated on the device in hardware"),
      dict(testcase_name="imported_key",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(origin=b"\x02")),
           error="the key was not generated on the device in hardware"),
      dict(testcase_name="empty_challenge",
           batch=_sign(_encrypt(b"logs"), 1,
                       key_description=_key_description(challenge=b"")),
           error="the key's attestation challenge is empty"),
      dict(testcase_name="rkp_missing_creation_time",
           batch=_sign(
               _encrypt(b"logs"), 1,
               chain_tail=[_certificate(_INTERMEDIATE_KEY, _KEY, rkp=True),
                           _ROOT],
               key_description=_key_description(creation_millis=None)),
           error="the attestation has no creationDateTime"),
      dict(testcase_name="rkp_expired_at_key_creation",
           batch=_sign(
               _encrypt(b"logs"), 1,
               chain_tail=[
                   _certificate(
                       _INTERMEDIATE_KEY, _KEY, rkp=True,
                       not_valid_before=datetime.datetime(2026, 1, 1),
                       not_valid_after=datetime.datetime(2026, 1, 10)),
                   _ROOT],
               key_description=_key_description(
                   creation_millis=int(datetime.datetime(
                       2026, 1, 11, tzinfo=datetime.timezone.utc
                   ).timestamp() * 1000))),
           error=("attestation certificate 1 was not valid when the key was "
                  "created")),
      dict(testcase_name="rkp_not_yet_valid_at_key_creation",
           batch=_sign(
               _encrypt(b"logs"), 1,
               chain_tail=[
                   _certificate(
                       _INTERMEDIATE_KEY, _KEY, rkp=True,
                       not_valid_before=datetime.datetime(2026, 1, 5),
                       not_valid_after=datetime.datetime(2026, 1, 14)),
                   _ROOT],
               key_description=_key_description(
                   creation_millis=int(datetime.datetime(
                       2026, 1, 4, tzinfo=datetime.timezone.utc
                   ).timestamp() * 1000))),
           error=("attestation certificate 1 was not valid when the key was "
                  "created")),
      dict(testcase_name="factory_not_yet_valid_at_key_creation",
           batch=_sign(
               _encrypt(b"logs"), 1,
               chain_tail=[
                   _certificate(
                       _INTERMEDIATE_KEY, _KEY,
                       not_valid_before=datetime.datetime(2026, 1, 5)),
                   _ROOT],
               key_description=_key_description(
                   creation_millis=int(datetime.datetime(
                       2026, 1, 4, tzinfo=datetime.timezone.utc
                   ).timestamp() * 1000))),
           error=("attestation certificate 1 was not valid when the key was "
                  "created")),
      dict(testcase_name="malformed_creation_time",
           batch=_sign(
               _encrypt(b"logs"), 1,
               key_description=_key_description(
                   creation_millis=None,
                   extra_software_tags=[_der(_CREATION_DATETIME, b"\x02")])),
           error="malformed key attestation"),
      dict(testcase_name="overflow_creation_time",
           batch=_sign(
               _encrypt(b"logs"), 1,
               key_description=_key_description(
                   creation_millis=None,
                   extra_software_tags=[
                       _der(_CREATION_DATETIME, _der_int(10**20))
                   ])),
           error="malformed key attestation"),
      dict(testcase_name="negative_creation_time_before_issuer_start",
           batch=_sign(
               _encrypt(b"logs"), 1,
               key_description=_key_description(creation_millis=-1000)),
           error=("attestation certificate 1 was not valid when the key was "
                  "created")),
      dict(testcase_name="rkp_hardware_creation_time_precedes_software",
           batch=_sign(
               _encrypt(b"logs"), 1,
               chain_tail=[
                   _certificate(
                       _INTERMEDIATE_KEY, _KEY, rkp=True,
                       not_valid_before=datetime.datetime(2026, 1, 1),
                       not_valid_after=datetime.datetime(2026, 1, 10)),
                   _ROOT],
               key_description=_key_description(
                   creation_millis=int(datetime.datetime(
                       2026, 1, 11, tzinfo=datetime.timezone.utc
                   ).timestamp() * 1000),
                   hardware_creation_time=True,
                   extra_software_tags=[
                       _der(_CREATION_DATETIME, _der_int(int(datetime.datetime(
                           2026, 1, 5, tzinfo=datetime.timezone.utc
                       ).timestamp() * 1000)))
                   ])),
           error=("attestation certificate 1 was not valid when the key was "
                  "created")),
      dict(testcase_name="non_ec_key",
           batch=_with_chain(
               _sign(_encrypt(b"logs"), 1),
               [_certificate(_KEY, _INTERMEDIATE_KEY, _key_description()),
                *_CHAIN_TAIL]),
           error="the signing key is not an EC P-256 key"),
      dict(testcase_name="wrong_curve",
           batch=_with_chain(
               _sign(_encrypt(b"logs"), 1),
               [_certificate(_P384_KEY, _INTERMEDIATE_KEY, _key_description()),
                *_CHAIN_TAIL]),
           error="the signing key is not an EC P-256 key"),
  )
  def test_rejects_bad_signature(
      self,
      batch: message.Message,
      error: str,
      root_keys: Collection[str] = _ROOT_KEYS,
  ) -> None:
    with self.assertRaisesRegex(crumbles_analyst.BatchError, error):
      crumbles_analyst.check_signature(
          batch.SerializeToString(), batch, b"device-1", root_keys
      )

  def test_rejects_signature_of_a_revoked_attestation_key(self) -> None:
    batch = _sign(_encrypt(b"logs"), 1)
    with self.assertRaisesWithLiteralMatch(
        crumbles_analyst.BatchError,
        "attestation certificate 1 is REVOKED (KEY_COMPROMISE)"):
      crumbles_analyst.check_signature(
          batch.SerializeToString(), batch, b"device-1", _ROOT_KEYS,
          {f"{_INTERMEDIATE_SERIAL_NUMBER:x}": "REVOKED (KEY_COMPROMISE)"})

  def test_checks_signature_with_the_sealed_attestation_chain(self) -> None:
    chain = _attestation_chain()
    batch = _sign(
        _encrypt(b"logs", log_type=_SEALED_METADATA, attestation_chain=chain), 1
    )

    signer = crumbles_analyst.check_signature(
        batch.SerializeToString(),
        batch,
        b"device-1",
        _ROOT_KEYS,
        attestation_chain=chain,
    )

    self.assertEqual(
        (signer.key, signer.device_id),
        (_public_key_der(_LEAF_KEY), b"device-1"),
    )

  @parameterized.named_parameters(
      dict(testcase_name="nothing_sealed", sealed=False),
      dict(testcase_name="also_sealed", sealed=True),
  )
  def test_rejects_version_2_batch_with_attestation_chain_in_clear(
      self, sealed: bool
  ) -> None:
    # The signature does not cover a chain in clear, so anyone could add one.
    chain = _attestation_chain()
    sealed_chain = chain if sealed else []
    batch = _with_chain(
        _sign(
            _encrypt(
                b"logs",
                log_type=_SEALED_METADATA,
                attestation_chain=sealed_chain,
            ),
            1,
        ),
        chain,
    )

    with self.assertRaisesWithLiteralMatch(
        crumbles_analyst.BatchError,
        "format version 2 batch with attestation certificates in clear",
    ):
      crumbles_analyst.check_signature(
          batch.SerializeToString(),
          batch,
          b"device-1",
          _ROOT_KEYS,
          attestation_chain=sealed_chain,
      )

  def test_checks_batches_in_the_order_they_were_written(self) -> None:
    _write_batches(self.batch_dir, {
        "a.bin": _encrypt(b"later logs", seconds=2),
        "b.bin": _encrypt(b"logs", seconds=1),
        "c.bin": _encrypt(b"logs", _OTHER_KEY.public_key(), seconds=1),
    })
    names = ["a.bin", "b.bin", "c.bin", "missing.bin"]
    results = crumbles_analyst.check_batches(
        [self.batch_dir / name for name in names], _KEY)
    self.assertEqual(
        [(result.path.name, result.plaintext) for result in results],
        [("b.bin", b"logs"), ("c.bin", None),
         ("a.bin", b"later logs"), ("missing.bin", None)])
    self.assertIn("No such file", results[3].problems[0])
    self.assertIn("cannot unwrap", results[1].problems[0])

  def test_reports_batch_files_that_are_too_large_or_not_regular(self) -> None:
    limit = 64 * 1024 * 1024
    _write_batches(self.batch_dir, {"valid.bin": _encrypt(b"logs")})
    (self.batch_dir / "link.bin").symlink_to(self.batch_dir / "valid.bin")
    os.mkfifo(self.batch_dir / "fifo.bin")
    (self.batch_dir / "directory.bin").mkdir()
    for name, size in (("at_limit.bin", limit), ("over_limit.bin", limit + 1)):
      with open(self.batch_dir / name, "wb") as sparse_file:
        sparse_file.truncate(size)

    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY
    )

    by_name = {result.path.name: result for result in results}
    self.assertEqual(by_name["valid.bin"].plaintext, b"logs")
    self.assertEqual(
        by_name["over_limit.bin"].problems[0], f"larger than {limit} bytes"
    )
    self.assertNotIn("larger than", by_name["at_limit.bin"].problems[0])
    self.assertEqual(by_name["fifo.bin"].problems[0], "not a regular file")
    self.assertEqual(by_name["directory.bin"].problems[0], "not a regular file")
    self.assertIn("symbolic links", by_name["link.bin"].problems[0])
    self.assertIsNone(by_name["link.bin"].plaintext)

  def test_checks_the_activity_log_chain(self) -> None:
    _write_batches(self.batch_dir, {
        "d.bin": _encrypt(
            _trailer("none", _TAG_A, records=('{"sequenceNumber": 1}',)),
            seconds=1),
        "c.bin": _encrypt(b"logs", _OTHER_KEY.public_key(), seconds=2),
        "b.bin": _encrypt(
            _trailer(_TAG_A, _TAG_B, records=('{"sequenceNumber": 2}',)),
            seconds=3),
        "a.bin": _encrypt(
            _trailer(_TAG_C, _TAG_C, records=('{"sequenceNumber": 3}',)),
            seconds=4),
        "e.bin": _encrypt(
            _trailer(_TAG_C, _TAG_C, records=('{"sequenceNumber": 4}',),
                     previous_record_missing=True),
            seconds=5),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, allow_unsigned=True)
    problems = {
        result.path.name: " ".join(result.problems) for result in results}
    self.assertEqual(list(problems),
                     ["d.bin", "c.bin", "b.bin", "a.bin", "e.bin"])
    self.assertNotIn("activity log break", problems["d.bin"])
    self.assertNotIn("activity log break", problems["b.bin"])
    self.assertIn(f"starts after record {_TAG_C}, but b.bin ends at {_TAG_B}",
                  problems["a.bin"])
    self.assertIn("no longer had the previous batch's last activity record",
                  problems["e.bin"])

  def test_checks_the_signers_and_sequence_numbers_of_each_device(self) -> None:
    other_leaf_key = ec.generate_private_key(ec.SECP256R1())
    logs = _trailer(_TAG_A, _TAG_A, [])
    _write_batches(self.batch_dir, {
        "b0.bin": _sign(_encrypt(logs, seconds=1), 1),
        "b1.bin": _sign(_encrypt(logs, seconds=2), 2),
        "b2.bin": _sign(_encrypt(logs, seconds=3), 2),
        "b3.bin": _sign(_encrypt(logs, seconds=4), 5),
        "b4.bin": _sign(
            _encrypt(logs, seconds=5, device_id=b"device-3"), 6,
            key_description=_key_description(challenge=b"device-3")),
        "b5.bin": _sign(
            _encrypt(logs, seconds=6, device_id=b"device-3"), 7,
            leaf_key=other_leaf_key,
            key_description=_key_description(
                challenge=b"device-3",
                app_certificates=[_OTHER_APP_CERTIFICATE])),
        "b6.bin": _encrypt(logs, seconds=7),
        "b7.bin": _sign(
            _encrypt(logs, seconds=8, device_id=b"device-2"), 41,
            key_description=_key_description(challenge=b"device-2")),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS)
    self.assertEqual(
        [" ".join(result.problems) for result in results],
        [
            "",
            "",
            "repeated sequence number 2",
            "missing sequence numbers 3-4",
            "unsigned batch",
            "batches from 2 signers (b4.bin, b5.bin); "
            + "pass --app-cert/--boot-key",
            "signed with another key than b4.bin "
            + "signed by an app with other certificates than b4.bin "
            + "batches from 2 signers (b4.bin, b5.bin); "
            + "pass --app-cert/--boot-key",
            "",
        ])
    self.assertEqual(
        results[0].notices, ("sequence number 1 but since is not none",)
    )
    self.assertEqual(results[5].notices, ())
    self.assertEqual(results[7].notices, ("missing sequence numbers 1-40",))
    since_none_seq2 = crumbles_analyst.check_batches(
        [self.batch_dir / "b0.bin"],
        _KEY,
        _ROOT_KEYS,
    )
    self.assertEqual(
        since_none_seq2[0].notices,
        ("sequence number 1 but since is not none",),
    )
    seq2_none_path = self.temp_dir / "seq2_none.bin"
    seq2_none_path.write_bytes(
        _sign(
            _encrypt(_trailer("none", _TAG_A, []), seconds=9), 2
        ).SerializeToString()
    )
    seq2_none_res = crumbles_analyst.check_batches(
        [seq2_none_path], _KEY, _ROOT_KEYS
    )
    self.assertEqual(
        seq2_none_res[0].notices,
        (
            "missing sequence numbers 1-1",
            "since is none but sequence number is not 1",
        ),
    )

  def test_checks_batches_of_every_format_by_their_metadata(self) -> None:
    logs = _trailer(_TAG_A, _TAG_A, [])
    _write_batches(
        self.batch_dir,
        {
            "a.bin": _sign(
                _encrypt(
                    logs,
                    seconds=3,
                    log_type=_SEALED_METADATA,
                    attestation_chain=_attestation_chain(),
                ),
                3,
            ),
            "b.bin": _sign(_encrypt(logs, seconds=2, log_type=_PADDED), 2),
            "c.bin": _sign(_encrypt(logs, seconds=1), 1),
            "d.bin": _sign(
                _encrypt(
                    logs,
                    _OTHER_KEY.public_key(),
                    seconds=4,
                    log_type=_SEALED_METADATA,
                    attestation_chain=_attestation_chain(),
                ),
                4,
            ),
        },
    )
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS)
    # d.bin hides its time, device and attestation chain, but the key of a.bin
    # signed it.
    self.assertEqual(
        [(result.path.name, " ".join(result.problems)) for result in results],
        [
            ("c.bin", ""),
            ("b.bin", ""),
            ("a.bin", ""),
            (
                "d.bin",
                "cannot unwrap the AES key: the batch was encrypted to "
                + "another key, or it is corrupt",
            ),
        ],
    )

  def test_checks_the_signature_of_a_batch_that_seals_its_chain(self) -> None:
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": _sign(
                _encrypt(
                    _trailer("none", _TAG_A),
                    log_type=_SEALED_METADATA,
                    attestation_chain=_attestation_chain(),
                ),
                1,
            ),
        },
    )

    [result] = crumbles_analyst.check_batches(
        [self.batch_dir / "b1.bin"], _KEY, _ROOT_KEYS
    )

    self.assertEqual(result.problems, ())
    self.assertTrue(result.signer_trusted)
    self.assertEqual(result.signer.key, _public_key_der(_LEAF_KEY))

  def test_does_not_trust_undecryptable_version_2_batch_with_chain_in_clear(
      self,
  ) -> None:
    # Its cleartext metadata has no device ID for the attestation to match, and
    # someone added a valid chain to its signature, which does not cover it.
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": _with_chain(
                _sign(
                    _encrypt(
                        _trailer("none", _TAG_A),
                        _OTHER_KEY.public_key(),
                        log_type=_SEALED_METADATA,
                    ),
                    1,
                ),
                _attestation_chain(),
            ),
        },
    )

    [result] = crumbles_analyst.check_batches(
        [self.batch_dir / "b1.bin"], _KEY, _ROOT_KEYS
    )

    self.assertEqual(
        result.problems,
        (
            (
                "cannot unwrap the AES key: the batch was encrypted to another"
                " key, or it is corrupt"
            ),
            "format version 2 batch with attestation certificates in clear",
        ),
    )
    self.assertIsNone(result.signer)
    self.assertFalse(result.signer_trusted)

  @parameterized.named_parameters(
      dict(
          testcase_name="batch_deleted_before_a_key_change",
          recipients={1: _OTHER_KEY, 2: _OTHER_KEY, 4: _OTHER_KEY, 5: _KEY},
          problems={
              "b1.bin": (_CANNOT_UNWRAP,),
              "b2.bin": (_CANNOT_UNWRAP,),
              "b4.bin": (_CANNOT_UNWRAP, "missing sequence number 3"),
              "b5.bin": (),
          },
      ),
      dict(
          testcase_name="handover_batch_for_the_outgoing_key",
          recipients={1: _KEY, 2: _OTHER_KEY, 3: _KEY},
          problems={"b1.bin": (), "b2.bin": (_CANNOT_UNWRAP,), "b3.bin": ()},
      ),
  )
  def test_numbers_the_batches_of_a_known_signer_that_no_key_decrypts(
      self,
      recipients: dict[int, rsa.RSAPrivateKey],
      problems: dict[str, tuple[str, ...]],
  ) -> None:
    batches = {
        f"b{number}.bin": _sealed(number, recipient)
        for number, recipient in recipients.items()
    }
    _write_batches(self.batch_dir, batches)

    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS
    )

    by_name = {result.path.name: result for result in results}
    self.assertEqual(
        {name: result.problems for name, result in by_name.items()}, problems
    )
    self.assertEqual(by_name["b2.bin"].signer.key, _public_key_der(_LEAF_KEY))
    self.assertIn(
        "signed by a key that other batches attest: no --key decrypts the "
        "attestation chain that it seals",
        by_name["b2.bin"].notices,
    )

  def test_does_not_number_an_undecryptable_batch_that_another_key_signed(
      self,
  ) -> None:
    # A batch that fills the gap left by a deleted one, which only a key that
    # no batch attests signed.
    logs = _trailer(_TAG_A, _TAG_A, [])
    forged = _encrypt(logs, _OTHER_KEY.public_key(), log_type=_SEALED_METADATA)
    batches = {
        "b1.bin": _sealed(1, _KEY),
        "b2.bin": _sign(forged, 2, leaf_key=_FORGED_LEAF_KEY),
        "b3.bin": _sealed(3, _KEY),
    }
    _write_batches(self.batch_dir, batches)

    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS
    )

    self.assertEqual(
        {result.path.name: result.problems for result in results},
        {
            "b1.bin": (),
            "b2.bin": (_CANNOT_UNWRAP, "no attestation certificates"),
            "b3.bin": ("missing sequence number 2",),
        },
    )

  def test_checks_the_chain_across_batches_without_a_trailer(self) -> None:
    before_unlock = b"Crumbles: security logs collected before the first unlock"
    batches = {
        "b1.bin": _sealed(1, _KEY),
        "b2.bin": _sealed(2, _KEY, before_unlock),
        "b3.bin": _sealed(3, _KEY),
        "b4.bin": _sealed(4, _OTHER_KEY, _trailer(_TAG_A, _TAG_B)),
        "b5.bin": _sealed(5, _KEY, _trailer(_TAG_B, _TAG_B, [])),
        "unsigned.bin": _encrypt(before_unlock),
    }
    _write_batches(self.batch_dir, batches)

    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS
    )

    problems = [result.problems for result in results]
    self.assertEqual(problems[:5], [(), (), (), (_CANNOT_UNWRAP,), ()])
    self.assertEqual(problems[5], ("no activity log trailer", "unsigned batch"))
    self.assertIn(
        "collected before the first unlock: no activity log records",
        results[1].notices,
    )

  def test_main_decrypts_each_batch_with_the_key_it_was_encrypted_to(
      self,
  ) -> None:
    other_key_file = self.temp_dir / "other_key.txt"
    other_key_file.write_bytes(base64.b64encode(_OTHER_DER_KEY))
    batches = {"b1.bin": _sealed(1, _OTHER_KEY), "b2.bin": _sealed(2, _KEY)}
    _write_batches(self.batch_dir, batches)

    status, report = _run_main(
        "--key", other_key_file, "--key", self.key_file, self.batch_dir
    )

    self.assertEqual(status, 0)
    self.assertEqual(report.count("  decrypted "), 2)

  def test_notices_an_expired_certificate_of_a_sealed_chain(self) -> None:
    expired_intermediate = _certificate(
        _INTERMEDIATE_KEY,
        _KEY,
        not_valid_before=datetime.datetime(1970, 1, 1),
        not_valid_after=datetime.datetime(2020, 1, 1),
    )
    chain = _attestation_chain(chain_tail=[expired_intermediate, _ROOT])
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": _sign(
                _encrypt(
                    _trailer("none", _TAG_A),
                    log_type=_SEALED_METADATA,
                    attestation_chain=chain,
                ),
                1,
            ),
        },
    )

    [result] = crumbles_analyst.check_batches(
        [self.batch_dir / "b1.bin"], _KEY, _ROOT_KEYS
    )

    self.assertEqual(result.problems, ())
    self.assertEqual(
        result.notices,
        ("attestation certificate 1 is expired at analysis time",),
    )

  def test_rejects_more_than_10_attestation_certificates(self) -> None:
    batch = _with_chain(_sign(_encrypt(b"logs"), 1), [_ROOT] * 11)

    with self.assertRaisesWithLiteralMatch(
        crumbles_analyst.BatchError, "more than 10 attestation certificates"
    ):
      crumbles_analyst.check_signature(
          batch.SerializeToString(), batch, b"device-1", _ROOT_KEYS
      )

  @parameterized.named_parameters(
      dict(
          testcase_name="clock_set_past_the_default_validity",
          not_valid_after=datetime.datetime(2048, 1, 1),
          batch_time=datetime.datetime(2050, 1, 1),
      ),
      dict(
          testcase_name="rkp_leaf_that_ends_with_its_issuer",
          not_valid_after=datetime.datetime(2026, 1, 10),
          batch_time=datetime.datetime(2026, 1, 31),
      ),
      dict(
          testcase_name="key_made_after_the_leaf_expired",
          not_valid_after=datetime.datetime(2026, 1, 2),
          batch_time=datetime.datetime(2026, 1, 6),
      ),
  )
  def test_keeps_the_signer_of_a_batch_written_outside_the_leaf_validity(
      self, not_valid_after: datetime.datetime, batch_time: datetime.datetime
  ) -> None:
    rkp_issuer = _certificate(
        _INTERMEDIATE_KEY,
        _KEY,
        not_valid_before=datetime.datetime(2026, 1, 1),
        not_valid_after=datetime.datetime(2026, 1, 10),
        path_length=0,
        rkp=True,
    )
    # Made on 2026-01-05, when the issuer was valid.
    key_description = _key_description(creation_millis=1767571200000)
    leaf = _certificate(
        _LEAF_KEY,
        _INTERMEDIATE_KEY,
        key_description,
        not_valid_after=not_valid_after,
    )
    seconds = int(batch_time.replace(tzinfo=datetime.timezone.utc).timestamp())
    batch = _sign(_encrypt(_trailer("none", _TAG_A), seconds=seconds), 1)
    chain = [leaf, rkp_issuer, _ROOT]
    _write_batches(self.batch_dir, {"b1.bin": _with_chain(batch, chain)})

    [result] = crumbles_analyst.check_batches(
        [self.batch_dir / "b1.bin"], _KEY, _ROOT_KEYS
    )

    self.assertEqual((result.signer_trusted, result.problems), (True, ()))
    [notice] = result.notices
    self.assertEqual(
        notice,
        "the batch time is outside the validity of attestation certificate 0:"
        " the device clock may have been changed",
    )
    self.assertEqual(result.batch.data.log_blob, b"")

  @parameterized.named_parameters(
      dict(
          testcase_name="patch_levels_too_old_or_missing",
          args=("--min-patch-level", "201802"),
          problems=[
              "the key's OS patch level is below --min-patch-level",
              "the key's boot patch level is below --min-patch-level",
              "the key has no attested OS patch level",
              "the key has no attested vendor patch level",
              "the key has no attested boot patch level",
          ],
      ),
      dict(
          testcase_name="other_signing_key",
          args=(
              "--signer",
              hashlib.sha256(_public_key_der(_LEAF_KEY)).hexdigest(),
          ),
          problems=[
              "signed with another key than b1.bin",
              "signed with none of the keys of --signer",
          ],
      ),
  )
  def test_main_checks_the_patch_levels_and_the_signing_key(
      self, args: Sequence[str], problems: Sequence[str]
  ) -> None:
    levels = {
        _OS_VERSION: 150000,
        _OS_PATCH_LEVEL: 201801,
        _VENDOR_PATCH_LEVEL: 20180205,
        _BOOT_PATCH_LEVEL: 20180105,
    }
    tags = [_der(tag, _der_int(level)) for tag, level in levels.items()]
    key_description = _key_description(extra_hardware_tags=tags)
    other_leaf_key = ec.generate_private_key(ec.SECP256R1())
    logs = _trailer(_TAG_A, _TAG_A, [])
    batches = {
        "b1.bin": _sign(_encrypt(logs), 1, key_description=key_description),
        "b2.bin": _sign(
            _encrypt(logs, seconds=2),
            2,
            leaf_key=other_leaf_key,
            key_description=_key_description(),  # Without patch levels.
        ),
    }
    _write_batches(self.batch_dir, batches)

    status, report = _run_main("--key", self.key_file, *args, self.batch_dir)

    self.assertEqual(status, 1)
    lines = report.splitlines()
    self.assertEqual(
        [
            line.removeprefix("  PROBLEM: ")
            for line in lines
            if "PROBLEM" in line
        ],
        problems,
    )
    self.assertIn(
        "  attested OS version 150000, OS patch level 201801, vendor patch "
        "level 20180205, boot patch level 20180105",
        lines,
    )

  @parameterized.named_parameters(
      dict(testcase_name="year", level="2025"),
      dict(testcase_name="year_month_day", level="20250105"),
      dict(testcase_name="month_13", level="202513"),
  )
  def test_main_rejects_min_patch_level_not_yyyymm(self, level: str) -> None:
    args = ("--key", self.key_file, "--min-patch-level", level, self.batch_dir)
    with self.assertRaises(SystemExit):
      with contextlib.redirect_stderr(io.StringIO()):
        _run_main(*args)

  @parameterized.named_parameters(
      dict(testcase_name="version_1", log_type=_LOG_ENCRYPTION_TYPE_AES_GCM),
      dict(testcase_name="padded", log_type=_PADDED),
      dict(testcase_name="sealed_metadata", log_type=_SEALED_METADATA),
  )
  def test_main_reports_and_writes_the_logs(self, log_type: int) -> None:
    logs = b"event\n" + _trailer("none", _TAG_A)
    # Only the format version 2 batch seals the chain; _sign adds it to the
    # signature of the others.
    batch = _encrypt(
        logs,
        seconds=1760000000,
        log_type=log_type,
        attestation_chain=_attestation_chain(),
    )
    _write_batches(self.batch_dir, {"b1.bin": _sign(batch, 1)})
    app_certificate = _APP_CERTIFICATE.hex(":").upper()
    status, report = _run_main(
        "--key", self.key_file, "--out", self.out_dir,
        "--app-cert", _OTHER_APP_CERTIFICATE.hex(),
        "--app-cert", app_certificate, self.batch_dir)
    self.assertEqual(status, 0)
    signing_key = hashlib.sha256(_public_key_der(_LEAF_KEY)).hexdigest()
    expected = [
        str(self.batch_dir / "b1.bin"),
        "  written 2025-10-09 08:53:20+00:00 by device 'device-1', key wrap "
        + "RSA-OAEP-SHA256",
        f"  decrypted {len(logs)} bytes of logs",
        "  activity log: since record none, 1 new records, chain head "
        + _TAG_A,
        f"  batch 1, signed by TEE key {signing_key}",
        f"  app signing certificate (SHA-256): {app_certificate}",
        "  bootloader locked, verified boot state Verified, verified boot key "
        + _BOOT_KEY.hex(),
        "  attested OS version unknown, OS patch level unknown, vendor patch "
        + "level unknown, boot patch level unknown",
        f"  written to {self.out_dir / 'b1.bin.txt'}",
        "Device 'device-1': sequences 1 to 1, times "
        + "2025-10-09T08:53:20+00:00 to "
        + "2025-10-09T08:53:20+00:00",
        "1 batches, 0 with problems.",
    ]
    self.assertEqual(report.splitlines(), expected)
    self.assertEqual((self.out_dir / "b1.bin.txt").read_bytes(), logs)
    self.assertEqual(
        (self.out_dir / "b1.bin.txt").stat().st_mode & 0o777, 0o600)
    self.assertEqual(self.out_dir.stat().st_mode & 0o777, 0o700)

  def test_main_reports_problems(self) -> None:
    unverified_dir = self.out_dir / "unverified"
    unverified_dir.mkdir(parents=True)
    (unverified_dir / "b1.bin.txt").write_bytes(b"other logs")
    logs = b"event\n" + _trailer("none", _TAG_A)
    _write_batches(self.batch_dir, {
        "b1.bin": _sign(_encrypt(logs), 1),
        "b2.bin": _encrypt(
            logs, key_type=crumbles_analyst.KEY_ENCRYPTION_TYPE_ASYMMETRIC,
            seconds=2**62),
        "b3.bin": _encrypt(logs, key_type=2),
        "b5.bin": _encrypt(logs, _OTHER_KEY.public_key(),
                           log_type=_SEALED_METADATA),
    })
    (self.batch_dir / "b4.bin").write_bytes(b"junk")
    status, report = _run_main(
        "--key", self.key_file, "--out", self.out_dir,
        "--app-cert", _OTHER_APP_CERTIFICATE.hex(), self.batch_dir)
    self.assertEqual(status, 1)
    self.assertIn(f"{unverified_dir / 'b1.bin.txt'} already exists, so it was "
                  "not overwritten", report)
    self.assertIn("PROBLEM: signed by an app with none of the certificates of "
                  "--app-cert", report)
    self.assertEqual((unverified_dir / "b1.bin.txt").read_bytes(),
                     b"other logs")
    self.assertFalse((self.out_dir / "b1.bin.txt").exists())
    self.assertIn(f"written {2**62} seconds after 1970", report)
    self.assertIn(
        "PROBLEM: key wrap RSA-PKCS1v1.5 (legacy) is refused unless "
        "--allow-pkcs1 is given",
        report,
    )
    self.assertIn("key wrap type 2\n  PROBLEM: unsupported", report)
    self.assertIn("PROBLEM: unsigned batch", report)
    self.assertIn("b4.bin\n  PROBLEM: not a Crumbles log batch", report)
    self.assertIn("b5.bin\n  time and device encrypted with the logs, key wrap "
                  "RSA-OAEP-SHA256\n  PROBLEM: cannot unwrap", report)
    self.assertEndsWith(report, "\n5 batches, 5 with problems.\n")

  def test_main_exits_if_it_cannot_load_the_key(self) -> None:
    self.key_file.write_bytes(b"junk")
    with self.assertRaises(SystemExit):
      with contextlib.redirect_stderr(io.StringIO()):
        _run_main("--key", self.key_file, self.batch_dir)

  @parameterized.named_parameters(
      dict(testcase_name="short", app_cert=_APP_CERTIFICATE.hex()[2:]),
      dict(testcase_name="long", app_cert=_APP_CERTIFICATE.hex() + "00"),
      dict(testcase_name="not_hex", app_cert="g" * 64),
  )
  def test_main_exits_if_an_app_cert_is_not_a_sha256_digest(
      self, app_cert: str) -> None:
    with self.assertRaises(SystemExit):
      with contextlib.redirect_stderr(io.StringIO()):
        _run_main("--key", self.key_file, "--app-cert", app_cert,
                  self.batch_dir)

  @parameterized.named_parameters(
      dict(testcase_name="custom_rom",
           boot_state=_SELF_SIGNED, boot_key_args=[],
           problems=["  PROBLEM: signed on a custom ROM but no --boot-key "
                     "was given"]),
      dict(testcase_name="custom_rom_with_a_given_key",
           boot_state=_SELF_SIGNED,
           boot_key_args=["--boot-key", _OTHER_BOOT_KEY.hex(),
                          "--boot-key", _BOOT_KEY.hex()],
           problems=[]),
      dict(testcase_name="custom_rom_with_another_key",
           boot_state=_SELF_SIGNED,
           boot_key_args=["--boot-key", _OTHER_BOOT_KEY.hex()],
           problems=["  PROBLEM: signed with none of the verified boot keys "
                     "of --boot-key"]),
      dict(testcase_name="device_maker_os_without_boot_key",
           boot_state=_VERIFIED,
           boot_key_args=[],
           problems=[]),
      dict(testcase_name="device_maker_os_with_a_given_key",
           boot_state=_VERIFIED,
           boot_key_args=["--boot-key", _BOOT_KEY.hex()],
           problems=[]),
      dict(testcase_name="device_maker_os_with_another_key",
           boot_state=_VERIFIED,
           boot_key_args=["--boot-key", _OTHER_BOOT_KEY.hex()],
           problems=["  PROBLEM: signed with none of the verified boot keys "
                     "of --boot-key"]),
  )
  def test_main_checks_the_boot_keys(
      self,
      boot_state: bytes,
      boot_key_args: Sequence[str],
      problems: Sequence[str],
  ) -> None:
    batch = _sign(_encrypt(_trailer("none", _TAG_A)), 1,
                  key_description=_key_description(boot_state=boot_state))
    _write_batches(self.batch_dir, {"b1.bin": batch})
    _, report = _run_main(
        "--key", self.key_file, *boot_key_args, self.batch_dir)
    self.assertEqual(
        [line for line in report.splitlines() if "PROBLEM" in line], problems)

  @parameterized.named_parameters(
      dict(testcase_name="revoked",
           serial_number=f"{_INTERMEDIATE_SERIAL_NUMBER:x}",
           problems=["  PROBLEM: attestation certificate 1 is REVOKED "
                     "(KEY_COMPROMISE)"]),
      dict(testcase_name="other_certificate",
           serial_number="c8966fcb2fbb0d7a", problems=[]),
  )
  def test_main_checks_the_attestation_status(
      self, serial_number: str, problems: Sequence[str]) -> None:
    status_file = self.temp_dir / "status.json"
    status_file.write_text(json.dumps({"entries": {serial_number: {
        "status": "REVOKED", "reason": "KEY_COMPROMISE"}}}))
    # A newer copy, from which the certificate was dropped once it expired.
    newer_file = self.temp_dir / "newer_status.json"
    newer_file.write_text('{"entries": {"5ca1ab1e": {"status": "SUSPENDED"}}}')
    os.utime(status_file, (1750000000, 1750000000))
    os.utime(newer_file, (1760000000, 1760000000))
    _write_batches(self.batch_dir, {
        "b1.bin": _sign(_encrypt(
            _trailer("none", _TAG_A, records=('{"sequenceNumber": 1}',))), 1)})
    status_args = ("--attestation-status", status_file)
    newer_args = ("--attestation-status", newer_file)
    _, report = _run_main(
        "--key", self.key_file, *status_args, *newer_args, self.batch_dir
    )
    self.assertEqual(
        [line for line in report.splitlines() if "PROBLEM" in line], problems)
    self.assertIn(
        "2 revoked or suspended attestation certificates in 2 status lists, "
        "the newest from 2025-10-09T08:53+00:00\n",
        report,
    )

  @parameterized.named_parameters(
      dict(testcase_name="missing", file_name="missing.json"),
      dict(testcase_name="not_a_status_list", file_name="junk.json"),
  )
  def test_main_exits_if_it_cannot_load_the_attestation_status(
      self, file_name: str) -> None:
    (self.temp_dir / "junk.json").write_bytes(b"junk")
    with self.assertRaises(SystemExit):
      with contextlib.redirect_stderr(io.StringIO()):
        _run_main("--key", self.key_file, "--attestation-status",
                  self.temp_dir / file_name, self.batch_dir)

  def test_main_escapes_what_a_terminal_would_not_print(self) -> None:
    # Moves the cursor up a line, and erases it.
    (self.batch_dir / "b1\x1b[1A\x1b[2K.bin").write_bytes(b"junk")
    _, report = _run_main("--key", self.key_file, self.batch_dir)
    self.assertEqual(report.splitlines()[0],
                     str(self.batch_dir / "b1\\x1b[1A\\x1b[2K.bin"))

  def test_sealed_record_advances_sequence_number(self) -> None:
    plaintext = _trailer("none", _TAG_A, [
        '{"sequenceNumber": 1, "tag": "x"}',
        '{"sealed": "yes", "tag": "y"}',
        '{"sequenceNumber": 3, "tag": "' + _TAG_A + '"}',
    ])
    trailer = crumbles_analyst.parse_trailer(plaintext)
    self.assertEqual(trailer.records, 3)
    self.assertEqual(trailer.first_seq, 1)
    self.assertEqual(trailer.last_seq, 3)
    self.assertEqual(trailer.leading_sealed, 0)
    self.assertIn("could not be unsealed on the device", trailer.problems)
    self.assertNotIn("activity log sequence gap: 1 to 3", trailer.problems)

  @parameterized.named_parameters(
      dict(testcase_name="log_viewed", event="AUDIT_LOG_VIEWED"),
      dict(testcase_name="kept", event="DESTINATION_HANDOVER_KEPT_ON_DEVICE"),
      dict(testcase_name="not_needed", event="DESTINATION_HANDOVER_NOT_NEEDED"),
      dict(testcase_name="uploaded", event="DESTINATION_HANDOVER_UPLOADED"),
      dict(testcase_name="queued", event="LOGS_KEPT_QUEUED_BEFORE_KEY_CHANGE"),
      dict(testcase_name="alerts_restored", event="NOTIFICATIONS_RESTORED"),
      dict(testcase_name="users_blocked", event="USER_ADDITION_BLOCKED"),
      dict(
          testcase_name="not_sealed",
          event="DESTINATION_HANDOVER_NOT_SEALED",
          problems=("tamper-evidence event: DESTINATION_HANDOVER_NOT_SEALED",),
      ),
      dict(
          testcase_name="changed_without_handover",
          event="DESTINATION_CHANGED_WITHOUT_HANDOVER",
          problems=(
              "tamper-evidence event: DESTINATION_CHANGED_WITHOUT_HANDOVER",
          ),
      ),
      dict(
          testcase_name="handover_upload_failed",
          event="DESTINATION_HANDOVER_UPLOAD_FAILED",
          problems=(
              "tamper-evidence event: DESTINATION_HANDOVER_UPLOAD_FAILED",
          ),
      ),
      dict(
          testcase_name="handover_uploaded_unconfirmed",
          event="DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED",
          problems=(
              (
                  "tamper-evidence event:"
                  " DESTINATION_HANDOVER_UPLOADED_UNCONFIRMED"
              ),
          ),
      ),
      dict(
          testcase_name="handover_uploaded_offline",
          event="DESTINATION_HANDOVER_UPLOADED_OFFLINE",
          problems=(
              "tamper-evidence event: DESTINATION_HANDOVER_UPLOADED_OFFLINE",
          ),
      ),
  )
  def test_classifies_the_activity_log_events_of_newer_versions(
      self, event: str, problems: tuple[str, ...] = ()
  ) -> None:
    record = json.dumps({"sequenceNumber": 1, "eventType": event})

    trailer = crumbles_analyst.parse_trailer(_trailer("none", _TAG_A, [record]))

    self.assertEqual((trailer.problems, trailer.notices), (problems, ()))

  def test_main_notices_an_upload_destination_change(self) -> None:
    logs = b"Crumbles upload destination change\n" + _trailer("none", _TAG_A)
    _write_batches(self.batch_dir, {"b1.bin": _sign(_encrypt(logs), 1)})

    _, report = _run_main("--key", self.key_file, self.batch_dir)

    self.assertIn("  NOTICE: upload destination change", report.splitlines())

  @parameterized.named_parameters(
      *(
          dict(
              testcase_name=f"problem_{ev.lower()}",
              plaintext=_trailer(
                  "none",
                  "none",
                  [
                      f'{{"sequenceNumber": 1, "eventType": "{ev}", '
                      '"tag": "none"}'
                  ],
              ),
              expected_problems=(f"tamper-evidence event: {ev}",),
              expected_notices=(),
          )
          for ev in (
              "AUDIT_LOG_CLEARED",
              "AUDIT_LOG_CLEAR_REQUESTED",
              "AUDIT_LOG_CLEAR_SEAL_FAILED",
              "AUDIT_LOG_KEY_REPLACED",
              "AUDIT_RECORDS_DROPPED",
              "COLLECTION_PAUSED_SECONDARY_USER",
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
          )
      ),
      dict(
          testcase_name="problem_audit_records_dropped_with_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"AUDIT_RECORDS_DROPPED", "message": '
                  '"3 audit records dropped", "tag": "none"}'
              )],
          ),
          expected_problems=("tamper-evidence event: AUDIT_RECORDS_DROPPED",),
          expected_notices=(),
      ),
      dict(
          testcase_name="problem_audit_log_cleared_normal_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": "AUDIT_LOG_CLEARED", '
                  '"message": "Audit log cleared; 5 records removed.", '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=("tamper-evidence event: AUDIT_LOG_CLEARED",),
          expected_notices=(),
      ),
      dict(
          testcase_name="problem_audit_log_cleared_unsealed",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": "AUDIT_LOG_CLEARED", '
                  '"message": "Audit log cleared (2 records not Sealed)", '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=(
              "tamper-evidence event: AUDIT_LOG_CLEARED "
              "(Audit log cleared (2 records not Sealed))",
          ),
          expected_notices=(),
      ),
      dict(
          testcase_name="problem_audit_log_cleared_unpersisted",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": "AUDIT_LOG_CLEARED", '
                  '"message": "Audit log cleared (3 Unpersisted records)", '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=(
              "tamper-evidence event: AUDIT_LOG_CLEARED "
              "(Audit log cleared (3 Unpersisted records))",
          ),
          expected_notices=(),
      ),
      dict(
          testcase_name="problem_audit_log_cleared_dropped",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": "AUDIT_LOG_CLEARED", '
                  '"message": "Audit log cleared (4 records Dropped)", '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=(
              "tamper-evidence event: AUDIT_LOG_CLEARED "
              "(Audit log cleared (4 records Dropped))",
          ),
          expected_notices=(),
      ),
      dict(
          testcase_name="problem_collection_resumed_single_user_discarded",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"COLLECTION_RESUMED_SINGLE_USER", "message": '
                  '"Platform Discarded buffered logs", "tag": "none"}'
              )],
          ),
          expected_problems=(
              "tamper-evidence event: COLLECTION_RESUMED_SINGLE_USER "
              "(Platform Discarded buffered logs)",
          ),
          expected_notices=(),
      ),
      dict(
          testcase_name="notice_collection_resumed_single_user_clean_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"COLLECTION_RESUMED_SINGLE_USER", "message": '
                  '"Single-user mode resumed", "tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=(
              "activity log event: COLLECTION_RESUMED_SINGLE_USER",
          ),
      ),
      dict(
          testcase_name="notice_logs_storage_cap_reached_reclaimed_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"LOGS_STORAGE_CAP_REACHED", "message": '
                  '"Reclaimed 2 uploaded copy(ies) (550 bytes): '
                  'batch_2_sent.bin, batch_3_sent.bin.", "tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=(
              "activity log event: LOGS_STORAGE_CAP_REACHED "
              "(Reclaimed 2 uploaded copy(ies) (550 bytes): "
              "batch_2_sent.bin, batch_3_sent.bin.)",
          ),
      ),
      dict(
          testcase_name="notice_logs_storage_cap_reached_non_reclaim_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"LOGS_STORAGE_CAP_REACHED", "message": '
                  '"Storage cap reached", "tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=("activity log event: LOGS_STORAGE_CAP_REACHED",),
      ),
      dict(
          testcase_name="notice_other_event_with_reclaimed_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"AUDIT_LOG_ROTATED", "message": '
                  '"Reclaimed old file", "tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=("activity log event: AUDIT_LOG_ROTATED",),
      ),
      dict(
          testcase_name="notice_network_collection_scope_changed_with_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"NETWORK_COLLECTION_SCOPE_CHANGED", "message": '
                  '"Full DNS and connect logging enabled", "tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=(
              "activity log event: NETWORK_COLLECTION_SCOPE_CHANGED "
              "(Full DNS and connect logging enabled)",
          ),
      ),
      dict(
          testcase_name="notice_network_collection_scope_changed_empty_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"NETWORK_COLLECTION_SCOPE_CHANGED", "message": "", '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=(
              "activity log event: NETWORK_COLLECTION_SCOPE_CHANGED",
          ),
      ),
      dict(
          testcase_name="notice_network_collection_scope_changed_non_str_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"NETWORK_COLLECTION_SCOPE_CHANGED", "message": 1, '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=(
              "activity log event: NETWORK_COLLECTION_SCOPE_CHANGED",
          ),
      ),
      dict(
          testcase_name="problem_rate_limited_tamper_event",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"AUDIT_EVENTS_RATE_LIMITED", "message": '
                  '"7 LOGS_LOST events were counted but not recorded.", '
                  '"tag": "none"}'
              )],
          ),
          expected_problems=(
              "tamper-evidence event: AUDIT_EVENTS_RATE_LIMITED "
              "(7 LOGS_LOST events were counted but not recorded.)",
          ),
          expected_notices=(),
      ),
      *(
          dict(
              testcase_name=f"notice_rate_limited_{name}",
              plaintext=_trailer(
                  "none",
                  "none",
                  [(
                      '{"sequenceNumber": 1, "eventType": '
                      '"AUDIT_EVENTS_RATE_LIMITED", "message": '
                      f'"7 {ev} events were counted but not recorded.", '
                      '"tag": "none"}'
                  )],
              ),
              expected_problems=(),
              expected_notices=(
                  "activity log event: AUDIT_EVENTS_RATE_LIMITED "
                  f"(7 {ev} events were counted but not recorded.)",
              ),
          )
          for name, ev in (
              ("routine", "DECRYPTION_SUCCESS"),
              ("tamper_name_prefix", "STAGED_LOGS_LOST"),
              ("tamper_name_suffix", "LOGS_LOST_X"),
          )
      ),
      dict(
          testcase_name="notice_rate_limited_non_str_msg",
          plaintext=_trailer(
              "none",
              "none",
              [(
                  '{"sequenceNumber": 1, "eventType": '
                  '"AUDIT_EVENTS_RATE_LIMITED", "message": 7, "tag": "none"}'
              )],
          ),
          expected_problems=(),
          expected_notices=("activity log event: AUDIT_EVENTS_RATE_LIMITED",),
      ),
      *(
          dict(
              testcase_name=f"notice_{ev.lower()}",
              plaintext=_trailer(
                  "none",
                  "none",
                  [
                      f'{{"sequenceNumber": 1, "eventType": "{ev}", '
                      '"tag": "none"}'
                  ],
              ),
              expected_problems=(),
              expected_notices=(f"activity log event: {ev}",),
          )
          for ev in (
              "AUDIT_LOG_ROTATED",
              "COLLECTION_PAUSED",
              "COLLECTION_RESUMED_SINGLE_USER",
              "EXTERNAL_KEY_UNAVAILABLE",
              "FUTURE_UNLISTED_WRITER_EVENT",
              "LOGS_STORAGE_CAP_REACHED",
              "LOG_RETRIEVAL_DEFERRED",
              "NETWORK_COLLECTION_SCOPE_CHANGED",
              "NETWORK_LOGGING_DISABLED",
              "SECURITY_LOGGING_DISABLED",
          )
      ),
      *(
          dict(
              testcase_name=f"batch_signing_failed_{name}",
              plaintext=_trailer(
                  "none",
                  "none",
                  [(
                      '{"sequenceNumber": 1, "eventType": '
                      f'"BATCH_SIGNING_FAILED"{message}, "tag": "none"}}'
                  )],
              ),
              expected_problems=problems,
              expected_notices=notices,
          )
          for name, message, problems, notices in (
              (
                  "new_batch",
                  (', "message": "Log batch written without a signature or '
                   'sequence number: signing failed."'),
                  (
                      "tamper-evidence event: BATCH_SIGNING_FAILED (Log batch "
                      "written without a signature or sequence number: signing "
                      "failed.)",
                  ),
                  (),
              ),
              (
                  "non_str_msg",
                  ', "message": 7',
                  ("tamper-evidence event: BATCH_SIGNING_FAILED",),
                  (),
              ),
              (
                  "re_encrypted_copy",
                  (', "message": "Re-encrypted log batch 3 written without a '
                   'signature: signing it again failed."'),
                  (),
                  (
                      "activity log event: BATCH_SIGNING_FAILED (Re-encrypted "
                      "log batch 3 written without a signature: signing it "
                      "again failed.)",
                  ),
              ),
          )
      ),
      *(
          dict(
              testcase_name=f"routine_{ev.lower()}",
              plaintext=_trailer(
                  "none",
                  "none",
                  [
                      f'{{"sequenceNumber": 1, "eventType": "{ev}", '
                      '"tag": "none"}'
                  ],
              ),
              expected_problems=(),
              expected_notices=(),
          )
          for ev in (
              "DECRYPTION_SUCCESS",
              "EXTERNAL_KEY_IMPORTED",
              "KEYSTORE_KEY_STORAGE",
              "KEY_EXPORTABLE_GENERATED",
              "KEY_HANDOVER_KEPT_ON_DEVICE",
              "KEY_HANDOVER_NOT_NEEDED",
              "KEY_HANDOVER_UPLOADED",
              "KEY_INTERNAL_GENERATED",
              "KEPT_COPIES_DELETED",
              "LOGS_COPIED_BEFORE_KEY_CHANGE",
              "LOGS_RE_ENCRYPTED",
              "LOGS_STAGED",
              "LOGS_UPLOAD_RECOVERED_PROCESSING",
              "LOGS_UPLOAD_SUCCESS",
              "RE_ENCRYPT_KEY_IMPORTED",
              "SECURITY_LOGGING_ENABLED",
              "UPLOAD_AND_WIPE_FINISHED",
              "UPLOAD_AND_WIPE_REQUESTED",
              "UPLOAD_AND_WIPE_SENT_KEPT",
              "UPLOAD_DESTINATION_CONFIGURED",
          )
      ),
  )
  def test_parses_trailer_events(
      self,
      plaintext: bytes,
      expected_problems: tuple[str, ...],
      expected_notices: tuple[str, ...],
  ) -> None:
    trailer = crumbles_analyst.parse_trailer(plaintext)
    self.assertEqual(trailer.problems, expected_problems)
    self.assertEqual(trailer.notices, expected_notices)

  @parameterized.named_parameters(
      dict(testcase_name="default_disallows_unsigned",
           allow_unsigned=False,
           expected_problems=[
               "",
               "unsigned batch",
               "missing sequence number 2"
           ]),
      dict(testcase_name="allow_unsigned",
           allow_unsigned=True,
           expected_problems=[
               "",
               "unsigned batch",
               "missing sequence number 2"
           ]),
  )
  def test_ignores_unsigned_batches_for_sequence_numbers_by_default(
      self, allow_unsigned: bool, expected_problems: list[str]) -> None:
    logs = _trailer(_TAG_A, _TAG_A, [])
    b1 = _encrypt(logs, seconds=2)
    b1.sequence_number = 2
    _write_batches(self.batch_dir, {
        "b0.bin": _sign(_encrypt(logs, seconds=1), 1),
        "b1.bin": b1,
        "b2.bin": _sign(_encrypt(logs, seconds=3), 3),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS,
        allow_unsigned=allow_unsigned)
    problems = [
        " ".join(r.problems) for r in sorted(results, key=lambda r: r.path.name)
    ]
    for problem, expected in zip(problems, expected_problems):
      if expected:
        self.assertIn(expected, problem)
      else:
        self.assertNotIn("missing sequence", problem)

  def test_checks_boot_consistency_and_continuity_across_key_change(
      self) -> None:
    other_leaf_key = ec.generate_private_key(ec.SECP256R1())
    _write_batches(self.batch_dir, {
        "b0.bin": _sign(
            _encrypt(
                _trailer("none", _TAG_A,
                         [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']),
                seconds=1),
            1),
        "b1.bin": _sign(
            _encrypt(
                _trailer(_TAG_A, _TAG_B,
                         [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}']),
                seconds=2),
            3, leaf_key=other_leaf_key),
        "b2.bin": _sign(
            _encrypt(_trailer(_TAG_B, _TAG_B, []), seconds=3),
            4,
            key_description=_key_description(boot_state=_SELF_SIGNED)),
        "b3.bin": _sign(
            _encrypt(_trailer(_TAG_C, _TAG_C, []), seconds=4),
            5,
            key_description=_key_description(boot_key=_OTHER_BOOT_KEY)),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS,
        boot_keys=frozenset([_BOOT_KEY, _OTHER_BOOT_KEY]))
    multi_msg = (
        "batches from 4 signers (b0.bin, b1.bin, b2.bin, b3.bin); "
        "pass --app-cert/--boot-key"
    )
    self.assertEqual(results[0].problems, (multi_msg,))
    self.assertEqual(
        results[1].problems,
        ("signed with another key than b0.bin", multi_msg))
    self.assertEqual(results[1].notices, ())
    self.assertEqual(
        results[2].problems,
        ("signed with another verified boot state than b0.bin", multi_msg))
    self.assertEqual(
        results[3].problems,
        ("signed with another verified boot key than b0.bin", multi_msg))
    for r in results:
      self.assertFalse(r.signer_trusted)
      self.assertIsNotNone(r.trailer)

  def test_allow_unsigned_splices_unsigned_and_signed_batches(self) -> None:
    b0_logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    b1_logs = _trailer(_TAG_A, _TAG_A, [])
    u2_logs = _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}'])
    b3_logs = _trailer(
        _TAG_B, _TAG_C, [f'{{"sequenceNumber": 3, "tag": "{_TAG_C}"}}'])
    _write_batches(self.batch_dir, {
        "b0.bin": _sign(_encrypt(b0_logs, seconds=100), 1),
        "b1.bin": _sign(_encrypt(b1_logs, seconds=101), 2),
        "u2.bin": _encrypt(u2_logs, seconds=20),
        "b3.bin": _sign(_encrypt(b3_logs, seconds=200), 3),
    })
    paths = sorted(self.batch_dir.iterdir())

    disallowed = crumbles_analyst.check_batches(
        paths, _KEY, _ROOT_KEYS, allow_unsigned=False)
    by_name = {r.path.name: " ".join(r.problems) for r in disallowed}
    self.assertIn("activity log break", by_name["b3.bin"])
    self.assertIn(
        "activity log sequence gap between batches: 1 to 3", by_name["b3.bin"])

    allowed = crumbles_analyst.check_batches(
        paths, _KEY, _ROOT_KEYS, allow_unsigned=True)
    self.assertEqual(
        [(r.path.name, r.problems) for r in allowed],
        [("b0.bin", ()), ("b1.bin", ()),
         ("u2.bin", ("unsigned batch",)), ("b3.bin", ())])

  def test_allow_unsigned_places_leading_unsigned_batch_before_successor(
      self) -> None:
    u0_logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    b1_logs = _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}'])
    _write_batches(self.batch_dir, {
        "u0.bin": _encrypt(u0_logs, seconds=200),
        "b1.bin": _sign(_encrypt(b1_logs, seconds=50), 2),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS, allow_unsigned=True)
    self.assertEqual(
        [(r.path.name, r.problems) for r in results],
        [("u0.bin", ("unsigned batch",)), ("b1.bin", ())])

  def test_allow_unsigned_places_trailing_unsigned_batch_after_predecessor(
      self) -> None:
    b0_logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    u1_logs = _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}'])
    _write_batches(self.batch_dir, {
        "b0.bin": _sign(_encrypt(b0_logs, seconds=200), 1),
        "u1.bin": _encrypt(u1_logs, seconds=50),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS, allow_unsigned=True)
    self.assertEqual(
        [(r.path.name, r.problems) for r in results],
        [("b0.bin", ()), ("u1.bin", ("unsigned batch",))])

  def test_main_writes_unsigned_logs_to_unverified_by_default(self) -> None:
    b1_logs = b"signed\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    u2_logs = b"unsigned\n" + _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}'])
    _write_batches(self.batch_dir, {
        "b1.bin": _sign(_encrypt(b1_logs, seconds=1), 1),
        "u2.bin": _encrypt(u2_logs, seconds=2),
        "u3.bin": _encrypt(b"other", _OTHER_KEY.public_key(), seconds=3),
    })

    default_out = self.temp_dir / "out_default"
    status, report = _run_main(
        "--key", self.key_file, "--out", default_out, self.batch_dir)
    self.assertEqual(status, 1)
    self.assertEqual((default_out / "b1.bin.txt").read_bytes(), b1_logs)
    self.assertFalse((default_out / "u2.bin.txt").exists())
    unverified_file = default_out / "unverified" / "u2.bin.txt"
    self.assertEqual(unverified_file.read_bytes(), u2_logs)
    self.assertEqual(unverified_file.stat().st_mode & 0o777, 0o600)
    self.assertEqual(
        (default_out / "unverified").stat().st_mode & 0o777, 0o700)
    self.assertFalse((default_out / "unverified" / "u3.bin.txt").exists())
    self.assertIn(f"written to {unverified_file}", report)

    allow_out = self.temp_dir / "out_allow"
    status, report = _run_main(
        "--key", self.key_file, "--out", allow_out, "--allow-unsigned",
        self.batch_dir)
    self.assertEqual(status, 1)
    self.assertEqual((allow_out / "b1.bin.txt").read_bytes(), b1_logs)
    self.assertFalse((allow_out / "u2.bin.txt").exists())
    allow_unverified = allow_out / "unverified" / "u2.bin.txt"
    self.assertEqual(allow_unverified.read_bytes(), u2_logs)
    self.assertIn(f"written to {allow_unverified}", report)

  def test_leading_and_all_sealed_records_advance_trailer_sequence(
      self) -> None:
    parsed = crumbles_analyst.parse_trailer(_trailer(_TAG_A, _TAG_B, [
        '{"sealed": "s1", "tag": "t1"}',
        '{"sealed": "s2", "tag": "t2"}',
        '{"sequenceNumber": 5, "tag": "t3"}',
        f'{{"sealed": "s3", "tag": "{_TAG_B}"}}',
    ]))
    self.assertEqual(parsed.leading_sealed, 2)
    self.assertEqual(parsed.first_seq, 5)
    self.assertEqual(parsed.last_seq, 6)
    self.assertNotIn("sequence gap", " ".join(parsed.problems))

    _write_batches(self.batch_dir, {
        "b0.bin": _sign(_encrypt(_trailer("none", _TAG_A, [
            '{"sealed": "s1", "tag": "t1"}',
            f'{{"sealed": "s2", "tag": "{_TAG_A}"}}',
        ]), seconds=1), 1),
        "b1.bin": _sign(_encrypt(_trailer(_TAG_A, _TAG_B, [
            '{"sequenceNumber": 3, "tag": "t3"}',
            f'{{"sequenceNumber": 4, "tag": "{_TAG_B}"}}',
        ]), seconds=2), 2),
        "b2.bin": _sign(_encrypt(_trailer(_TAG_B, _TAG_C, [
            '{"sealed": "s5", "tag": "t5"}',
            f'{{"sealed": "s6", "tag": "{_TAG_C}"}}',
        ]), seconds=3), 3),
        "b3.bin": _sign(_encrypt(_trailer(_TAG_C, _TAG_A, [
            '{"sealed": "s7", "tag": "t7"}',
            '{"sealed": "s8", "tag": "t8"}',
            f'{{"sequenceNumber": 9, "tag": "{_TAG_A}"}}',
        ]), seconds=4), 4),
        "b4.bin": _sign(_encrypt(_trailer(_TAG_A, _TAG_B, [
            '{"sealed": "s10", "tag": "t10"}',
            f'{{"sequenceNumber": 12, "tag": "{_TAG_B}"}}',
        ]), seconds=5), 5),
    })
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS)
    for idx in (0, 1, 2, 3):
      self.assertNotIn(
          "sequence gap", " ".join(results[idx].problems), msg=f"b{idx}.bin")
    self.assertIn(
        "activity log sequence gap between batches: 10 to 12",
        results[4].problems)

  @parameterized.named_parameters(
      dict(testcase_name="rkp_software_creation_time",
           hardware_creation_time=False,
           creation_dt=datetime.datetime(2026, 1, 5,
                                         tzinfo=datetime.timezone.utc)),
      dict(testcase_name="rkp_hardware_creation_time_at_start_boundary",
           hardware_creation_time=True,
           creation_dt=datetime.datetime(2026, 1, 1,
                                         tzinfo=datetime.timezone.utc)),
      dict(testcase_name="rkp_at_end_boundary",
           hardware_creation_time=False,
           creation_dt=datetime.datetime(2026, 1, 10,
                                         tzinfo=datetime.timezone.utc)),
  )
  def test_accepts_rkp_chain_expired_at_batch_time_without_expiry_notice(
      self,
      hardware_creation_time: bool,
      creation_dt: datetime.datetime,
  ) -> None:
    rkp_intermediate = _certificate(
        _INTERMEDIATE_KEY,
        _KEY,
        not_valid_before=datetime.datetime(2026, 1, 1),
        not_valid_after=datetime.datetime(2026, 1, 10),
        path_length=0,
        rkp=True,
    )
    batch_seconds = int(
        datetime.datetime(
            2026, 1, 31, tzinfo=datetime.timezone.utc
        ).timestamp()
    )
    logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    batch = _sign(
        _encrypt(logs, seconds=batch_seconds),
        1,
        chain_tail=[rkp_intermediate, _ROOT],
        key_description=_key_description(
            creation_millis=int(creation_dt.timestamp() * 1000),
            hardware_creation_time=hardware_creation_time,
        ),
    )
    _write_batches(self.batch_dir, {"rkp.bin": batch})
    results = crumbles_analyst.check_batches(
        [self.batch_dir / "rkp.bin"], _KEY, _ROOT_KEYS
    )
    self.assertEqual(results[0].problems, ())
    self.assertEqual(results[0].notices, ())

  def test_factory_chain_ignores_expiry_and_emits_analysis_time_notice(
      self,
  ) -> None:
    expired_factory_intermediate = _certificate(
        _INTERMEDIATE_KEY,
        _KEY,
        not_valid_before=datetime.datetime(1970, 1, 1),
        not_valid_after=datetime.datetime(2020, 1, 1),
    )
    batch_seconds = int(
        datetime.datetime(
            2026, 1, 31, tzinfo=datetime.timezone.utc
        ).timestamp()
    )
    logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    with_creation = _sign(
        _encrypt(logs, seconds=batch_seconds),
        1,
        chain_tail=[expired_factory_intermediate, _ROOT],
        key_description=_key_description(
            creation_millis=int(
                datetime.datetime(
                    2026, 1, 5, tzinfo=datetime.timezone.utc
                ).timestamp() * 1000
            )
        ),
    )
    without_creation = _with_chain(
        _sign(
            _encrypt(
                _trailer(_TAG_A, _TAG_A, []), seconds=batch_seconds + 1
            ),
            2,
        ),
        [
            _certificate(
                _LEAF_KEY,
                _INTERMEDIATE_KEY,
                _key_description(creation_millis=None),
                rkp=True,
            ),
            expired_factory_intermediate,
            _ROOT,
        ],
    )
    two_cert_rkp = _with_chain(
        _sign(
            _encrypt(
                logs,
                seconds=batch_seconds + 2,
                device_id=b"dev-rkp-2",
            ),
            1,
        ),
        [
            _certificate(
                _LEAF_KEY,
                _KEY,
                _key_description(
                    challenge=b"dev-rkp-2",
                    creation_millis=int(
                        datetime.datetime(
                            2026, 1, 5, tzinfo=datetime.timezone.utc
                        ).timestamp() * 1000
                    ),
                ),
            ),
            _certificate(
                _KEY,
                _KEY,
                not_valid_before=datetime.datetime(2026, 1, 1),
                not_valid_after=datetime.datetime(2026, 1, 10),
                path_length=0,
                rkp=True,
            ),
        ],
    )
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": with_creation,
            "b2.bin": without_creation,
            "b3.bin": two_cert_rkp,
        },
    )
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS
    )
    self.assertEqual([r.problems for r in results], [(), (), ()])
    self.assertEqual(
        results[0].notices,
        ("attestation certificate 1 is expired at analysis time",),
    )
    self.assertEqual(
        results[1].notices,
        ("attestation certificate 1 is expired at analysis time",),
    )
    self.assertEqual(results[2].notices, ())
    status, report = _run_main("--key", self.key_file, self.batch_dir)
    self.assertEqual(status, 0)
    self.assertIn(
        "  NOTICE: attestation certificate 1 is expired at analysis time",
        report.splitlines(),
    )

  def test_parse_trailer_catches_deeply_nested_json(self) -> None:
    nested = '{"a":' * 50000 + "1" + "}" * 50000
    trailer = crumbles_analyst.parse_trailer(
        _trailer("none", _TAG_A, [nested])
    )
    self.assertEqual(
        trailer.problems, ("malformed JSON in activity log record",)
    )
    bool_seq = crumbles_analyst.parse_trailer(
        _trailer(
            "none", _TAG_A, [f'{{"sequenceNumber": true, "tag": "{_TAG_A}"}}']
        )
    )
    self.assertEqual(
        bool_seq.problems, ("activity log record missing sequenceNumber",)
    )
    tamper_logs = _trailer(
        "none",
        _TAG_A,
        [
            f'{{"sequenceNumber": 1, "eventType": "LOGS_LOST", '
            f'"tag": "{_TAG_A}"}}'
        ],
    )
    tamper_path = self.temp_dir / "tamper.bin"
    tamper_path.write_bytes(
        _sign(_encrypt(tamper_logs, seconds=1), 1).SerializeToString()
    )
    tamper_results = crumbles_analyst.check_batches(
        [tamper_path], _KEY, _ROOT_KEYS
    )
    self.assertEqual(
        tamper_results[0].problems, ("tamper-evidence event: LOGS_LOST",)
    )

  def test_check_batches_isolates_invalid_cert_and_unexpected_errors(
      self,
  ) -> None:
    invalid_cert = _minimal_cert_der(version=1)
    dup_ext = _der(
        _SEQUENCE,
        _der(b"\x06", b"\x55\x1d\x13"),
        _der(_OCTET_STRING, _der(_SEQUENCE)),
    )
    dup_ext_cert = _minimal_cert_der(version=2, extensions=dup_ext * 2)
    # Needs no encryption or signing key: crafted LogBatch with invalid DER.
    crafted_batch = crumbles_analyst.LogBatch()
    crafted_batch.data.log_blob = b"ciphertext"
    crafted_batch.key.key_encryption_type = (
        crumbles_analyst.KEY_ENCRYPTION_TYPE_RSA_OAEP_SHA256
    )
    crafted_batch.key.encrypted_symmetric_key = b"wrapped"
    crafted_batch.key.iv = bytes(_GCM_IV_BYTES)
    crafted_batch.metadata.blob_size = 10
    crafted_batch.metadata.timestamp.seconds = 1
    crafted_batch.metadata.device.device_id = b"device-bad"
    crafted_batch.signature.signature = b"sig"
    crafted_batch.signature.attestation_chain.append(invalid_cert)
    dup_batch = crumbles_analyst.LogBatch()
    dup_batch.CopyFrom(crafted_batch)
    del dup_batch.signature.attestation_chain[:]
    dup_batch.signature.attestation_chain.append(dup_ext_cert)
    logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    good_batch = _sign(
        _encrypt(logs, seconds=2, device_id=b"device-2"),
        1,
        key_description=_key_description(challenge=b"device-2"),
    )
    _write_batches(
        self.batch_dir,
        {
            "a_crash.bin": good_batch,
            "b_bad_cert.bin": crafted_batch,
            "c_good.bin": good_batch,
            "d_empty_dev.bin": _encrypt(logs, seconds=3, device_id=b""),
            "e_dup_ext.bin": dup_batch,
        },
    )
    real_check_batch = crumbles_analyst._check_batch

    def flaky_check_batch(path: pathlib.Path, *args: object) -> object:
      if path.name == "a_crash.bin":
        raise RuntimeError("boom")
      return real_check_batch(path, *args)

    with mock.patch.object(
        crumbles_analyst, "_check_batch", side_effect=flaky_check_batch
    ):
      results = crumbles_analyst.check_batches(
          sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS
      )
    by_result = {r.path.name: r for r in results}
    by_name = {name: r.problems for name, r in by_result.items()}
    self.assertFalse(by_result["a_crash.bin"].signer_trusted)
    self.assertFalse(by_result["b_bad_cert.bin"].signer_trusted)
    self.assertTrue(by_result["c_good.bin"].signer_trusted)
    self.assertFalse(by_result["d_empty_dev.bin"].signer_trusted)
    self.assertEqual(
        by_name["a_crash.bin"], ("unexpected error (RuntimeError): boom",)
    )
    self.assertIn(
        "malformed attestation certificate (InvalidVersion)",
        by_name["b_bad_cert.bin"],
    )
    self.assertEqual(by_name["c_good.bin"], ())
    self.assertIn("empty device ID", by_name["d_empty_dev.bin"])
    self.assertIn(
        "malformed attestation certificate (DuplicateExtension)",
        by_name["e_dup_ext.bin"],
    )

  def test_main_writes_untrusted_signer_logs_to_unverified(self) -> None:
    app_logs = b"wrong-app\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    boot_logs = b"wrong-boot\n" + _trailer(_TAG_A, _TAG_A, [])
    rom_logs = b"custom-rom\n" + _trailer(_TAG_A, _TAG_A, [])
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": _sign(
                _encrypt(app_logs, seconds=1, device_id=b"dev-app"),
                1,
                key_description=_key_description(
                    challenge=b"dev-app",
                    app_certificates=(_OTHER_APP_CERTIFICATE,),
                ),
            ),
            "b2.bin": _sign(
                _encrypt(boot_logs, seconds=2, device_id=b"dev-boot"),
                1,
                key_description=_key_description(
                    challenge=b"dev-boot", boot_key=_OTHER_BOOT_KEY
                ),
            ),
        },
    )
    status, report = _run_main(
        "--key", self.key_file,
        "--out", self.out_dir,
        "--allow-unsigned",
        "--app-cert", _APP_CERTIFICATE.hex(),
        "--boot-key", _BOOT_KEY.hex(),
        self.batch_dir,
    )
    self.assertEqual(status, 1)
    self.assertFalse((self.out_dir / "b1.bin.txt").exists())
    self.assertFalse((self.out_dir / "b2.bin.txt").exists())
    self.assertEqual(
        (self.out_dir / "unverified" / "b1.bin.txt").read_bytes(), app_logs
    )
    self.assertEqual(
        (self.out_dir / "unverified" / "b2.bin.txt").read_bytes(), boot_logs
    )
    self.assertIn(
        f"written to {self.out_dir / 'unverified' / 'b1.bin.txt'}", report
    )
    self.assertIn(
        f"written to {self.out_dir / 'unverified' / 'b2.bin.txt'}", report
    )

    rom_batch = self.temp_dir / "rom.bin"
    rom_batch.write_bytes(
        _sign(
            _encrypt(rom_logs, seconds=3, device_id=b"dev-rom"),
            1,
            key_description=_key_description(
                challenge=b"dev-rom", boot_state=_SELF_SIGNED
            ),
        ).SerializeToString()
    )
    rom_out = self.temp_dir / "rom_out"
    status, _ = _run_main("--key", self.key_file, "--out", rom_out, rom_batch)
    self.assertEqual(status, 1)
    self.assertFalse((rom_out / "rom.bin.txt").exists())
    self.assertEqual(
        (rom_out / "unverified" / "rom.bin.txt").read_bytes(), rom_logs
    )

  def test_paused_period_surfaces_problem_and_notice_batches(self) -> None:
    b1_logs = b"normal security log\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    b2_logs = (
        b"Crumbles: Collection paused: secondary or guest user present at "
        b"2026-10-22T05:00:00Z. No more batches until other users are "
        b"removed.\n"
        + _trailer(
            _TAG_A,
            _TAG_B,
            [(
                '{"sequenceNumber": 2, "eventType": '
                f'"COLLECTION_PAUSED_SECONDARY_USER", "tag": "{_TAG_B}"}}'
            )],
        )
    )
    b3_logs = b"post-pause security log\n" + _trailer(
        _TAG_B,
        _TAG_C,
        [(
            '{"sequenceNumber": 3, "eventType": '
            f'"COLLECTION_RESUMED_SINGLE_USER", "tag": "{_TAG_C}"}}'
        )],
    )
    b4_logs = (
        b"Collection paused: secondary or guest user present\n"
        + _trailer(
            _TAG_C,
            _TAG_A,
            [(
                '{"sequenceNumber": 4, "eventType": '
                '"COLLECTION_RESUMED_SINGLE_USER", "message": '
                f'"Platform discarded unretrieved logs", "tag": "{_TAG_A}"}}'
            )],
        )
    )
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": _sign(_encrypt(b1_logs, seconds=100), 1),
            "b2.bin": _sign(_encrypt(b2_logs, seconds=160), 2),
            # Heartbeats are suppressed throughout seconds 160..7400.
            "b3.bin": _sign(_encrypt(b3_logs, seconds=7400), 3),
            "b4.bin": _sign(_encrypt(b4_logs, seconds=7500), 4),
        },
    )
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()), _KEY, _ROOT_KEYS
    )
    self.assertNotIn(
        "  NOTICE: collection paused: secondary or guest user present",
        crumbles_analyst._describe(results[0]),
    )
    self.assertIn(
        "  NOTICE: collection paused: secondary or guest user present",
        crumbles_analyst._describe(results[1]),
    )
    self.assertEqual(
        results[1].problems,
        ("tamper-evidence event: COLLECTION_PAUSED_SECONDARY_USER",),
    )
    self.assertEqual(results[2].problems, ())
    self.assertEqual(
        results[2].notices,
        ("activity log event: COLLECTION_RESUMED_SINGLE_USER",),
    )
    self.assertIn(
        "  NOTICE: collection paused: secondary or guest user present",
        crumbles_analyst._describe(results[3]),
    )
    self.assertEqual(
        results[3].problems,
        (
            "tamper-evidence event: COLLECTION_RESUMED_SINGLE_USER "
            "(Platform discarded unretrieved logs)",
        ),
    )
    status, report = _run_main("--key", self.key_file, self.batch_dir)
    self.assertEqual(status, 1)
    self.assertIn(
        "  NOTICE: collection paused: secondary or guest user present",
        report.splitlines(),
    )
    self.assertIn(
        "  PROBLEM: tamper-evidence event: COLLECTION_PAUSED_SECONDARY_USER",
        report.splitlines(),
    )

  def test_allow_unsigned_rejects_failed_signatures_and_routes_unverified(
      self,
  ) -> None:
    b0_logs = b"b0\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    bridge_logs = b"forged-bridge\n" + _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}']
    )
    b2_logs = b"b2\n" + _trailer(
        _TAG_B, _TAG_C, [f'{{"sequenceNumber": 3, "tag": "{_TAG_C}"}}']
    )
    other_logs = b"untrusted\n" + _trailer(_TAG_C, _TAG_C, [])

    bad_sig = _sign(_encrypt(bridge_logs, seconds=50), 2)
    bad_sig.signature.signature = b"\x00" * 8
    unlocked = _sign(
        _encrypt(other_logs, seconds=40),
        4,
        key_description=_key_description(locked=_FALSE),
    )
    wrong_dev = _sign(
        _encrypt(other_logs, seconds=30),
        5,
        key_description=_key_description(challenge=b"other-phone"),
    )
    foreign_root = _sign(
        _encrypt(other_logs, seconds=20),
        6,
        chain_tail=[
            _certificate(_INTERMEDIATE_KEY, _OTHER_KEY),
            _certificate(_OTHER_KEY, _OTHER_KEY),
        ],
    )
    revoked_serial = 0x999999
    revoked = _sign(
        _encrypt(other_logs, seconds=10),
        7,
        chain_tail=[
            _certificate(
                _INTERMEDIATE_KEY, _KEY, serial_number=revoked_serial
            ),
            _ROOT,
        ],
    )
    status_file = self.temp_dir / "status.json"
    status_file.write_text(
        json.dumps({
            "entries": {
                f"{revoked_serial:x}": {
                    "status": "REVOKED",
                    "reason": "KEY_COMPROMISE",
                }
            }
        })
    )
    _write_batches(
        self.batch_dir,
        {
            "b0.bin": _sign(_encrypt(b0_logs, seconds=1), 1),
            "b2.bin": _sign(_encrypt(b2_logs, seconds=60), 3),
            "z_bad_sig.bin": bad_sig,
            "y_unlocked.bin": unlocked,
            "x_wrong_dev.bin": wrong_dev,
            "w_foreign_root.bin": foreign_root,
            "v_revoked.bin": revoked,
        },
    )
    paths = sorted(self.batch_dir.iterdir(), reverse=True)
    statuses = crumbles_analyst.load_attestation_status(
        status_file.read_bytes()
    )
    results = crumbles_analyst.check_batches(
        paths,
        _KEY,
        _ROOT_KEYS,
        certificate_statuses=statuses,
        allow_unsigned=True,
    )
    self.assertEqual(
        [r.path.name for r in results],
        [
            "b0.bin",
            "b2.bin",
            "v_revoked.bin",
            "w_foreign_root.bin",
            "x_wrong_dev.bin",
            "y_unlocked.bin",
            "z_bad_sig.bin",
        ],
    )
    by_result = {r.path.name: r for r in results}
    b2_problems = " ".join(by_result["b2.bin"].problems)
    self.assertIn("activity log break", b2_problems)
    self.assertIn(
        "activity log sequence gap between batches: 1 to 3", b2_problems
    )
    failed_names = (
        "v_revoked.bin",
        "w_foreign_root.bin",
        "x_wrong_dev.bin",
        "y_unlocked.bin",
        "z_bad_sig.bin",
    )
    for name in failed_names:
      self.assertFalse(by_result[name].signer_trusted, msg=name)
      self.assertIsNotNone(by_result[name].trailer, msg=name)
      self.assertTrue(by_result[name].problems, msg=name)

    status, _ = _run_main(
        "--key",
        self.key_file,
        "--out",
        self.out_dir,
        "--allow-unsigned",
        "--attestation-status",
        status_file,
        self.batch_dir,
    )
    self.assertEqual(status, 1)
    self.assertEqual((self.out_dir / "b0.bin.txt").read_bytes(), b0_logs)
    self.assertEqual((self.out_dir / "b2.bin.txt").read_bytes(), b2_logs)
    for name in failed_names:
      self.assertFalse((self.out_dir / f"{name}.txt").exists(), msg=name)
      self.assertTrue(
          (self.out_dir / "unverified" / f"{name}.txt").exists(), msg=name
      )

  def test_write_logs_oserror_records_batch_problem_without_aborting(
      self,
  ) -> None:
    long_logs = b"long\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    good_logs = b"good\n" + _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}']
    )
    long_name = "a" * 251 + ".bin"
    _write_batches(
        self.batch_dir,
        {
            long_name: _sign(_encrypt(long_logs, seconds=1), 1),
            "z_good.bin": _sign(_encrypt(good_logs, seconds=2), 2),
        },
    )
    status, report = _run_main(
        "--key", self.key_file, "--out", self.out_dir, self.batch_dir
    )
    self.assertEqual(status, 1)
    self.assertEqual((self.out_dir / "z_good.bin.txt").read_bytes(), good_logs)
    expected_bad_out = self.out_dir / f"{long_name}.txt"
    self.assertIn(f"PROBLEM: cannot write {expected_bad_out}:", report)
    self.assertIn(f"written to {self.out_dir / 'z_good.bin.txt'}", report)
    self.assertEndsWith(report, "\n2 batches, 1 with problems.\n")

  @parameterized.named_parameters(
      dict(testcase_name="seq_0", forged_seq=0),
      dict(testcase_name="seq_1", forged_seq=1),
  )
  def test_forged_batch_sorting_first_with_and_without_policy_flags(
      self, forged_seq: int
  ) -> None:
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    forged_logs = b"forged\n" + _trailer(
        "none", _TAG_C, [f'{{"sequenceNumber": 1, "tag": "{_TAG_C}"}}']
    )
    b1_logs = b"genuine-1\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    b2_logs = b"genuine-2\n" + _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}']
    )
    _write_batches(
        self.batch_dir,
        {
            "a_forged.bin": _sign(
                _encrypt(forged_logs, seconds=1),
                forged_seq,
                leaf_key=attacker_key,
                key_description=_key_description(
                    app_certificates=[_OTHER_APP_CERTIFICATE]
                ),
            ),
            "b1.bin": _sign(_encrypt(b1_logs, seconds=10), 1),
            "b2.bin": _sign(_encrypt(b2_logs, seconds=20), 2),
        },
    )

    no_flags_out = self.temp_dir / f"no_flags_{forged_seq}"
    status, report = _run_main(
        "--key", self.key_file, "--out", no_flags_out, self.batch_dir
    )
    self.assertEqual(status, 1)
    if forged_seq == 0:
      self.assertNotIn("batches from 2 signers", report)
      self.assertIn("PROBLEM: signed with another key than b1.bin", report)
      self.assertIn("PROBLEM: invalid non-positive sequence number 0", report)
      self.assertIn("Device 'device-1': sequences 1 to 2", report)
      self.assertEqual((no_flags_out / "b1.bin.txt").read_bytes(), b1_logs)
      self.assertEqual((no_flags_out / "b2.bin.txt").read_bytes(), b2_logs)
      self.assertFalse((no_flags_out / "a_forged.bin.txt").exists())
      self.assertEqual(
          (no_flags_out / "unverified" / "a_forged.bin.txt").read_bytes(),
          forged_logs,
      )
    else:
      self.assertIn(
          "PROBLEM: batches from 2 signers (a_forged.bin, b1.bin); "
          "pass --app-cert/--boot-key",
          report,
      )
      self.assertNotIn("Device 'device-1':", report)
      for name in ("a_forged.bin", "b1.bin", "b2.bin"):
        self.assertFalse((no_flags_out / f"{name}.txt").exists(), msg=name)
        self.assertTrue(
            (no_flags_out / "unverified" / f"{name}.txt").exists(), msg=name
        )

    with_cert_out = self.temp_dir / f"with_cert_{forged_seq}"
    status, report = _run_main(
        "--key",
        self.key_file,
        "--out",
        with_cert_out,
        "--app-cert",
        _APP_CERTIFICATE.hex(),
        self.batch_dir,
    )
    self.assertEqual(status, 1)
    self.assertEqual((with_cert_out / "b1.bin.txt").read_bytes(), b1_logs)
    self.assertEqual((with_cert_out / "b2.bin.txt").read_bytes(), b2_logs)
    self.assertFalse((with_cert_out / "a_forged.bin.txt").exists())
    self.assertEqual(
        (with_cert_out / "unverified" / "a_forged.bin.txt").read_bytes(),
        forged_logs,
    )
    self.assertIn(
        "Device 'device-1': sequences 1 to 2, times "
        "1970-01-01T00:00:10+00:00 to 1970-01-01T00:00:20+00:00",
        report,
    )
    self.assertEndsWith(report, "\n3 batches, 1 with problems.\n")

  def test_untrusted_batch_does_not_mask_gap_or_freshness(self) -> None:
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    b1_logs = b"g1\n" + _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    forged_logs = b"forged-2\n" + _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}']
    )
    b3_logs = b"g3\n" + _trailer(
        _TAG_B, _TAG_C, [f'{{"sequenceNumber": 3, "tag": "{_TAG_C}"}}']
    )
    fresh_now = int(
        datetime.datetime.now(datetime.timezone.utc).timestamp()
    )
    _write_batches(
        self.batch_dir,
        {
            "b1.bin": _sign(_encrypt(b1_logs, seconds=100), 1),
            "b2_forged.bin": _sign(
                _encrypt(forged_logs, seconds=fresh_now),
                2,
                leaf_key=attacker_key,
                key_description=_key_description(
                    app_certificates=[_OTHER_APP_CERTIFICATE]
                ),
            ),
            "b3.bin": _sign(_encrypt(b3_logs, seconds=200), 3),
        },
    )
    status, report = _run_main(
        "--key",
        self.key_file,
        "--app-cert",
        _APP_CERTIFICATE.hex(),
        "--max-age",
        "1",
        self.batch_dir,
    )
    self.assertEqual(status, 1)
    self.assertIn("PROBLEM: missing sequence number 2", report)
    self.assertIn("PROBLEM: activity log break:", report)
    self.assertIn(
        "PROBLEM: activity log sequence gap between batches: 1 to 3", report
    )
    self.assertIn("exceeding --max-age 1!", report)

  def test_main_summarizes_times_after_a_batch_without_timestamp(self) -> None:
    b1_logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    b2_logs = _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}'])
    _write_batches(self.batch_dir, {
        "b1.bin": _sign(_encrypt(b1_logs, seconds=None), 1),
        "b2.bin": _sign(_encrypt(b2_logs, seconds=20), 2),
    })
    status, report = _run_main("--key", self.key_file, self.batch_dir)
    self.assertEqual(status, 1)
    self.assertIn("PROBLEM: missing batch timestamp", report)
    self.assertIn(
        "Device 'device-1': sequences 1 to 2, times "
        "1970-01-01T00:00:20+00:00 to 1970-01-01T00:00:20+00:00",
        report,
    )

  def test_main_device_flags_an_expected_device_without_batches(self) -> None:
    logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    _write_batches(self.batch_dir, {"b1.bin": _sign(_encrypt(logs), 1)})
    status, report = _run_main(
        "--key", self.key_file, "--app-cert", _APP_CERTIFICATE.hex(),
        "--device", "device-1", "--device", "device-2", self.batch_dir)
    self.assertEqual(status, 1)
    self.assertIn(
        "WARNING: device 'device-2' given with --device has no trusted batch!",
        report)
    self.assertNotIn("not given with --device", report)

  def test_main_device_flags_batches_of_other_devices(self) -> None:
    logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'])
    _write_batches(self.batch_dir, {"b1.bin": _sign(_encrypt(logs), 1)})
    status, report = _run_main(
        "--key", self.key_file, "--out", self.out_dir,
        "--app-cert", _APP_CERTIFICATE.hex(), "--device", "device-2",
        self.batch_dir)
    self.assertEqual(status, 1)
    self.assertIn(
        "PROBLEM: device 'device-1' was not given with --device", report)
    self.assertFalse((self.out_dir / "b1.bin.txt").exists())
    self.assertTrue((self.out_dir / "unverified" / "b1.bin.txt").exists())
    self.assertIn(
        "WARNING: device 'device-2' given with --device has no trusted batch!",
        report)

  def test_allow_unsigned_splices_multi_batch_runs_in_chain_order(
      self,
  ) -> None:
    tag_d = "d" * 64
    tag_e = "e" * 64
    tag_f = "f" * 64
    tag_0 = "0" * 64
    u0_logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    u1_logs = _trailer(
        _TAG_A, _TAG_B, [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}']
    )
    b2_logs = _trailer(
        _TAG_B, _TAG_C, [f'{{"sequenceNumber": 3, "tag": "{_TAG_C}"}}']
    )
    u3_logs = _trailer(
        _TAG_C, tag_d, [f'{{"sequenceNumber": 4, "tag": "{tag_d}"}}']
    )
    u4_logs = _trailer(
        tag_d, tag_e, [f'{{"sequenceNumber": 5, "tag": "{tag_e}"}}']
    )
    u5_logs = _trailer(
        tag_e, tag_f, [f'{{"sequenceNumber": 6, "tag": "{tag_f}"}}']
    )
    b6_logs = _trailer(
        tag_f, tag_0, [f'{{"sequenceNumber": 7, "tag": "{tag_0}"}}']
    )
    _write_batches(
        self.batch_dir,
        {
            "u0.bin": _encrypt(u0_logs, seconds=500),
            "u1.bin": _encrypt(u1_logs, seconds=10),
            "b2.bin": _sign(_encrypt(b2_logs, seconds=100), 1),
            "u3.bin": _encrypt(u3_logs, seconds=20),
            "u4.bin": _encrypt(u4_logs, seconds=600),
            "u5.bin": _encrypt(u5_logs, seconds=30),
            "b6.bin": _sign(_encrypt(b6_logs, seconds=200), 2),
        },
    )
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()),
        _KEY,
        _ROOT_KEYS,
        allow_unsigned=True,
    )
    self.assertEqual(
        [(r.path.name, r.problems) for r in results],
        [
            ("u0.bin", ("unsigned batch",)),
            ("u1.bin", ("unsigned batch",)),
            ("b2.bin", ()),
            ("u3.bin", ("unsigned batch",)),
            ("u4.bin", ("unsigned batch",)),
            ("u5.bin", ("unsigned batch",)),
            ("b6.bin", ()),
        ],
    )

  def test_unverified_batches_preserve_intra_batch_trailer_findings(
      self,
  ) -> None:
    missing_prev_unverified = (
        "the device no longer had the previous batch's last activity "
        "record, so records written in between may have been deleted "
        "(unverified)"
    )
    b1_logs = _trailer(
        "none", _TAG_A, [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}']
    )
    b3_logs = _trailer(
        _TAG_B, _TAG_C, [f'{{"sequenceNumber": 4, "tag": "{_TAG_C}"}}']
    )
    bridge_logs = _trailer(
        _TAG_A,
        _TAG_B,
        [
            (
                '{"sequenceNumber": 2, "eventType": "AUDIT_LOG_CLEARED", '
                '"tag": "t2"}'
            ),
            (
                '{"sequenceNumber": 3, "eventType": "AUDIT_LOG_ROTATED", '
                f'"tag": "{_TAG_B}"}}'
            ),
        ],
        previous_record_missing=True,
    )

    unsigned_dir = self.temp_dir / "unsigned_bridge"
    unsigned_dir.mkdir()
    _write_batches(
        unsigned_dir,
        {
            "b1.bin": _sign(_encrypt(b1_logs, seconds=10), 1),
            "u2.bin": _encrypt(bridge_logs, seconds=20),
            "b3.bin": _sign(_encrypt(b3_logs, seconds=30), 3),
        },
    )
    unsigned_res = {
        r.path.name: r
        for r in crumbles_analyst.check_batches(
            sorted(unsigned_dir.iterdir()),
            _KEY,
            _ROOT_KEYS,
            allow_unsigned=False,
        )
    }
    self.assertIsNotNone(unsigned_res["u2.bin"].trailer)
    self.assertEqual(
        unsigned_res["u2.bin"].problems,
        (
            "unsigned batch",
            missing_prev_unverified,
            "tamper-evidence event: AUDIT_LOG_CLEARED (unverified)",
        ),
    )
    self.assertEqual(
        unsigned_res["u2.bin"].notices,
        ("activity log event: AUDIT_LOG_ROTATED (unverified)",),
    )
    self.assertIn(
        "activity log break", " ".join(unsigned_res["b3.bin"].problems)
    )

    failed_sig_dir = self.temp_dir / "failed_sig_bridge"
    failed_sig_dir.mkdir()
    bad_sig = _sign(_encrypt(bridge_logs, seconds=20), 2)
    bad_sig.signature.signature = b"\x00" * 8
    _write_batches(
        failed_sig_dir,
        {
            "b1.bin": _sign(_encrypt(b1_logs, seconds=10), 1),
            "f2.bin": bad_sig,
            "b3.bin": _sign(_encrypt(b3_logs, seconds=30), 3),
        },
    )
    failed_res = {
        r.path.name: r
        for r in crumbles_analyst.check_batches(
            sorted(failed_sig_dir.iterdir()),
            _KEY,
            _ROOT_KEYS,
            allow_unsigned=True,
        )
    }
    self.assertEqual(
        failed_res["f2.bin"].problems,
        (
            "bad signature",
            missing_prev_unverified,
            "tamper-evidence event: AUDIT_LOG_CLEARED (unverified)",
        ),
    )
    self.assertEqual(
        failed_res["f2.bin"].notices,
        ("activity log event: AUDIT_LOG_ROTATED (unverified)",),
    )
    self.assertIn(
        "activity log break", " ".join(failed_res["b3.bin"].problems)
    )

    expired_intermediate = _certificate(
        _INTERMEDIATE_KEY,
        _KEY,
        not_valid_before=datetime.datetime(1970, 1, 1),
        not_valid_after=datetime.datetime(2020, 1, 1),
    )
    policy_logs = _trailer(
        "none",
        _TAG_A,
        [
            '{"sequenceNumber": 1, "eventType": "LOGS_LOST", "tag": "t1"}',
            (
                '{"sequenceNumber": 2, "eventType": "AUDIT_LOG_ROTATED", '
                f'"tag": "{_TAG_A}"}}'
            ),
        ],
    )
    sealed_no_ts = crumbles_analyst.SealedLogs(logs=policy_logs)
    sealed_no_ts.metadata.device.device_id = b"dev-pol"
    sealed_no_ts.attestation_chain.extend(
        _attestation_chain(
            chain_tail=[expired_intermediate, _ROOT],
            key_description=_key_description(
                challenge=b"dev-pol",
                app_certificates=(_OTHER_APP_CERTIFICATE,),
                creation_millis=int(
                    datetime.datetime(
                        2019, 1, 1, tzinfo=datetime.timezone.utc
                    ).timestamp()
                    * 1000
                ),
            ),
        )
    )
    policy_batch = _sign(
        _encrypt(
            b"",
            device_id=b"dev-pol",
            log_type=_SEALED_METADATA,
            plaintext=_pad(sealed_no_ts.SerializeToString()),
        ),
        1,
    )
    policy_path = self.temp_dir / "policy_bad.bin"
    policy_path.write_bytes(policy_batch.SerializeToString())
    policy_res = crumbles_analyst.check_batches(
        [policy_path],
        _KEY,
        _ROOT_KEYS,
        app_certificates=frozenset([_APP_CERTIFICATE]),
    )[0]
    self.assertFalse(policy_res.signer_trusted)
    self.assertEqual(
        policy_res.problems,
        (
            "missing batch timestamp",
            "tamper-evidence event: LOGS_LOST (unverified)",
            "signed by an app with none of the certificates of --app-cert",
        ),
    )
    self.assertEqual(
        policy_res.notices,
        (
            "attestation certificate 1 is expired at analysis time",
            "activity log event: AUDIT_LOG_ROTATED (unverified)",
        ),
    )

    seq0_dir = self.temp_dir / "seq0_same_signer"
    seq0_dir.mkdir()
    seq0_out = self.temp_dir / "seq0_out"
    _write_batches(
        seq0_dir,
        {
            "s0.bin": _sign(_encrypt(policy_logs, seconds=1), 0),
            "s1.bin": _sign(_encrypt(b1_logs, seconds=10), 1),
        },
    )
    status, report = _run_main(
        "--key", self.key_file, "--out", seq0_out, seq0_dir
    )
    self.assertEqual(status, 1)
    self.assertFalse((seq0_out / "s0.bin.txt").exists())
    self.assertEqual(
        (seq0_out / "unverified" / "s0.bin.txt").read_bytes(), policy_logs
    )
    self.assertEqual((seq0_out / "s1.bin.txt").read_bytes(), b1_logs)
    self.assertIn(
        "  PROBLEM: tamper-evidence event: LOGS_LOST (unverified)",
        report.splitlines(),
    )
    self.assertIn(
        "  PROBLEM: invalid non-positive sequence number 0",
        report.splitlines(),
    )
    self.assertIn(
        "  NOTICE: activity log event: AUDIT_LOG_ROTATED (unverified)",
        report.splitlines(),
    )
    self.assertIn("Device 'device-1': sequences 1 to 1", report)

  def test_clear_requested_problem_and_network_scope_notice_in_main(
      self,
  ) -> None:
    logs = b"pre-clear notice\n" + _trailer(
        "none",
        _TAG_B,
        [
            (
                '{"sequenceNumber": 1, "eventType": '
                '"NETWORK_COLLECTION_SCOPE_CHANGED", "message": '
                f'"DNS and connect logging disabled", "tag": "{_TAG_A}"}}'
            ),
            (
                '{"sequenceNumber": 2, "eventType": '
                '"AUDIT_LOG_CLEAR_REQUESTED", "message": '
                f'"Admin requested clear", "tag": "{_TAG_B}"}}'
            ),
        ],
    )
    _write_batches(
        self.batch_dir, {"b1.bin": _sign(_encrypt(logs, seconds=10), 1)}
    )
    status, report = _run_main("--key", self.key_file, self.batch_dir)
    self.assertEqual(status, 1)
    self.assertIn(
        "  NOTICE: activity log event: NETWORK_COLLECTION_SCOPE_CHANGED "
        "(DNS and connect logging disabled)",
        report.splitlines(),
    )
    self.assertIn(
        "  PROBLEM: tamper-evidence event: AUDIT_LOG_CLEAR_REQUESTED",
        report.splitlines(),
    )

  def test_allow_unsigned_links_zero_record_interior_and_edge_batches(
      self,
  ) -> None:
    tag_d = "d" * 64
    tag_w = "1" * 64
    tag_x = "2" * 64
    tag_y = "3" * 64
    tag_z = "4" * 64
    _write_batches(
        self.batch_dir,
        {
            "b0.bin": _sign(
                _encrypt(
                    _trailer(
                        "none",
                        _TAG_A,
                        [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'],
                    ),
                    seconds=100,
                ),
                1,
            ),
            "u_loop_a.bin": _encrypt(_trailer(_TAG_A, _TAG_A, []), seconds=900),
            "u1.bin": _encrypt(
                _trailer(
                    _TAG_A,
                    _TAG_B,
                    [f'{{"sequenceNumber": 2, "tag": "{_TAG_B}"}}'],
                ),
                seconds=50,
            ),
            "u_loop_b1.bin": _encrypt(_trailer(_TAG_B, _TAG_B, []), seconds=5),
            "u_loop_b2.bin": _encrypt(
                _trailer(_TAG_B, _TAG_B, []), seconds=800
            ),
            "u2.bin": _encrypt(
                _trailer(
                    _TAG_B,
                    _TAG_C,
                    [f'{{"sequenceNumber": 3, "tag": "{_TAG_C}"}}'],
                ),
                seconds=60,
            ),
            "u_loop_c.bin": _encrypt(_trailer(_TAG_C, _TAG_C, []), seconds=7),
            "b3.bin": _sign(
                _encrypt(
                    _trailer(
                        _TAG_C,
                        tag_d,
                        [f'{{"sequenceNumber": 4, "tag": "{tag_d}"}}'],
                    ),
                    seconds=500,
                ),
                2,
            ),
            "u_loop_z.bin": _encrypt(_trailer(tag_z, tag_z, []), seconds=1000),
        },
    )
    results = crumbles_analyst.check_batches(
        sorted(self.batch_dir.iterdir()),
        _KEY,
        _ROOT_KEYS,
        allow_unsigned=True,
    )
    self.assertEqual(
        [(r.path.name, r.problems) for r in results[:-1]],
        [
            ("b0.bin", ()),
            ("u_loop_a.bin", ("unsigned batch",)),
            ("u1.bin", ("unsigned batch",)),
            ("u_loop_b1.bin", ("unsigned batch",)),
            ("u_loop_b2.bin", ("unsigned batch",)),
            ("u2.bin", ("unsigned batch",)),
            ("u_loop_c.bin", ("unsigned batch",)),
            ("b3.bin", ()),
        ],
    )
    self.assertEqual(results[-1].path.name, "u_loop_z.bin")
    self.assertIn("activity log break", " ".join(results[-1].problems))

    splice_dir = self.temp_dir / "splice_guard"
    splice_dir.mkdir()
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    _write_batches(
        splice_dir,
        {
            "b0_notrailer.bin": _sign(_encrypt(b"plain\n", seconds=5), 1),
            "b1_forged.bin": _sign(
                _encrypt(
                    _trailer(
                        tag_x,
                        tag_y,
                        [f'{{"sequenceNumber": 9, "tag": "{tag_y}"}}'],
                    ),
                    seconds=50,
                ),
                2,
                leaf_key=attacker_key,
                key_description=_key_description(
                    app_certificates=(_OTHER_APP_CERTIFICATE,)
                ),
            ),
            "b2_good.bin": _sign(
                _encrypt(
                    _trailer(
                        "none",
                        _TAG_A,
                        [f'{{"sequenceNumber": 1, "tag": "{_TAG_A}"}}'],
                    ),
                    seconds=100,
                ),
                2,
            ),
            "b3_notrailer.bin": _sign(_encrypt(b"plain2\n", seconds=150), 3),
            "u_after_forged.bin": _encrypt(
                _trailer(
                    tag_y,
                    tag_z,
                    [f'{{"sequenceNumber": 2, "tag": "{tag_z}"}}'],
                ),
                seconds=10,
            ),
            "u_before_forged.bin": _encrypt(
                _trailer(
                    tag_w,
                    tag_x,
                    [f'{{"sequenceNumber": 3, "tag": "{tag_x}"}}'],
                ),
                seconds=200,
            ),
        },
    )
    splice_res = crumbles_analyst.check_batches(
        sorted(splice_dir.iterdir()),
        _KEY,
        _ROOT_KEYS,
        app_certificates=frozenset([_APP_CERTIFICATE]),
        allow_unsigned=True,
    )
    self.assertEqual(
        [r.path.name for r in splice_res],
        [
            "b0_notrailer.bin",
            "u_after_forged.bin",
            "b1_forged.bin",
            "b2_good.bin",
            "b3_notrailer.bin",
            "u_before_forged.bin",
        ],
    )

    def make_res(name: str, trailer: crumbles_analyst.Trailer | None):
      empty = crumbles_analyst.LogBatch()
      return crumbles_analyst.Result(
          path=pathlib.Path(name),
          batch=empty,
          metadata=empty.metadata,
          trailer=trailer,
      )

    def make_t(since: str, head: str) -> crumbles_analyst.Trailer:
      return crumbles_analyst.Trailer(
          since=since,
          head=head,
          records=0,
          previous_record_missing=False,
          first_seq=None,
          last_seq=None,
          problems=(),
      )

    n1 = make_res("n1", make_t("none", "none"))
    n2 = make_res("n2", make_t("none", "none"))
    t_none = make_res("t_none", None)
    self.assertEqual(
        crumbles_analyst._link_unsigned_runs([n1, n2, t_none]),
        [[n1], [n2], [t_none]],
    )

    e_to_none = make_res("e_to_none", make_t(_TAG_A, "none"))
    e_from_none = make_res("e_from_none", make_t("none", _TAG_B))
    self.assertEqual(
        crumbles_analyst._link_unsigned_runs([e_to_none, e_from_none]),
        [[e_to_none], [e_from_none]],
    )
    self.assertEqual(
        crumbles_analyst._link_unsigned_runs([e_from_none, e_to_none]),
        [[e_from_none], [e_to_none]],
    )

    in1 = make_res("in1", make_t(_TAG_A, _TAG_B))
    in2 = make_res("in2", make_t(_TAG_C, _TAG_B))
    out1 = make_res("out1", make_t(_TAG_B, tag_d))
    self.assertEqual(
        crumbles_analyst._link_unsigned_runs([in1, in2, out1]),
        [[in1, out1], [in2]],
    )

    s1 = make_res("s1", make_t(_TAG_B, _TAG_C))
    s2 = make_res("s2", make_t(_TAG_B, tag_d))
    s3 = make_res("s3", make_t(_TAG_B, tag_w))
    pre = make_res("pre", make_t(_TAG_A, _TAG_B))
    self.assertEqual(
        crumbles_analyst._link_unsigned_runs([s1, s2, s3, pre]),
        [[s2], [s3], [pre, s1]],
    )

    cyc1 = make_res("cyc1", make_t(_TAG_A, _TAG_B))
    cyc2 = make_res("cyc2", make_t(_TAG_B, _TAG_A))
    self.assertEqual(
        crumbles_analyst._link_unsigned_runs([cyc1, cyc2]),
        [[cyc1, cyc2]],
    )


if __name__ == "__main__":
  absltest.main()
