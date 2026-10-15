#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — QR device engagement parsing and SessionTranscript construction.

Reader side. Clause references: 8.2.1.1 (DeviceEngagement), 9.1.5.1 (SessionTranscript),
9.1.1.4 (EDeviceKeyBytes / EReaderKeyBytes), 9.1.1.5 (key derivation).

THE CARDINAL RULE: DeviceEngagementBytes must carry the bytes received from the QR
*verbatim*. Decoding the engagement to a dict and re-encoding it can produce a
different byte string (map key order, integer widths), and every signature and
session key is bound to the exact bytes. A re-encoded transcript fails with an
AES-GCM tag mismatch and no other diagnostic. So we keep the raw payload and only
ever parse a *copy* of it for inspection.

Requires: cbor2, cryptography
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# DeviceEngagement map keys (8.2.1.1)
DE_VERSION = 0
DE_SECURITY = 1
DE_DEVICE_RETRIEVAL_METHODS = 2

# BleOptions map keys (8.2.1.1)
BLE_PERIPHERAL_SERVER_MODE = 0
BLE_CENTRAL_CLIENT_MODE = 1
BLE_PERIPHERAL_SERVER_UUID = 10
BLE_CENTRAL_CLIENT_UUID = 11
BLE_PERIPHERAL_SERVER_ADDRESS = 20

RETRIEVAL_TYPE_BLE = 2

CURVE = ec.SECP256R1()


@dataclass(frozen=True)
class BleEngagement:
    """The BLE retrieval method from device engagement."""

    peripheral_server_mode: bool
    central_client_mode: bool
    peripheral_server_uuid: bytes | None
    central_client_uuid: bytes | None
    peripheral_server_address: bytes | None

    @property
    def reader_is_gatt_client(self) -> bool:
        """True when only mdoc peripheral server mode is on offer.

        When the mdoc offers both, 8.3.3.1.1.1 says the reader *should* choose
        mdoc central client mode — and then the reader is the GATT server. That
        is a policy decision rather than a fact about the engagement, so it
        lives in `mdoc_reader.choose_ble_mode`; this property and `service_uuid`
        below only report the unambiguous case.
        """
        return self.peripheral_server_mode and not self.central_client_mode

    @property
    def service_uuid(self) -> bytes | None:
        """The UUID for the mode this engagement unambiguously asks for."""
        return (self.peripheral_server_uuid if self.reader_is_gatt_client
                else self.central_client_uuid)


@dataclass(frozen=True)
class DeviceEngagement:
    raw: bytes
    """Verbatim CBOR from the QR. This is what goes into the transcript."""

    version: str
    cipher_suite: int
    edevice_key_bytes: bytes
    """Verbatim encoding of #6.24(bstr .cbor EDeviceKey) — needed for ECDH and BLEIdent."""

    edevice_key_public: ec.EllipticCurvePublicKey
    ble: BleEngagement | None


def parse_mdoc_uri(uri: str) -> bytes:
    """`mdoc:<base64url>` -> raw DeviceEngagement CBOR bytes."""
    if not uri.startswith("mdoc:"):
        raise ValueError(f"not an mdoc URI: {uri[:16]!r}")
    payload = uri.split(":", 1)[1].strip()
    return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))


def _cose_key_to_public(cose: dict) -> ec.EllipticCurvePublicKey:
    """COSE_Key (RFC 8152) EC2 -> public key. Cipher suite 1 means P-256."""
    crv = cose.get(-1)
    if crv != 1:  # 1 = P-256
        raise ValueError(f"unsupported COSE curve {crv!r}; only P-256 (1) handled")
    x = int.from_bytes(cose[-2], "big")
    y = int.from_bytes(cose[-3], "big")
    return ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()


def _parse_ble(options: dict) -> BleEngagement:
    return BleEngagement(
        peripheral_server_mode=bool(options.get(BLE_PERIPHERAL_SERVER_MODE, False)),
        central_client_mode=bool(options.get(BLE_CENTRAL_CLIENT_MODE, False)),
        peripheral_server_uuid=options.get(BLE_PERIPHERAL_SERVER_UUID),
        central_client_uuid=options.get(BLE_CENTRAL_CLIENT_UUID),
        peripheral_server_address=options.get(BLE_PERIPHERAL_SERVER_ADDRESS),
    )


def parse_device_engagement(raw: bytes) -> DeviceEngagement:
    """Parse engagement for inspection while retaining `raw` for the transcript."""
    de = cbor2.loads(raw)

    cipher_suite, edevice_key_tag = de[DE_SECURITY]
    if not (isinstance(edevice_key_tag, cbor2.CBORTag) and edevice_key_tag.tag == 24):
        raise ValueError("EDeviceKeyBytes is not a #6.24 tagged byte string")

    ble = None
    for method in de.get(DE_DEVICE_RETRIEVAL_METHODS, []):
        method_type, _version, options = method
        if method_type == RETRIEVAL_TYPE_BLE:
            ble = _parse_ble(options)
            break

    return DeviceEngagement(
        raw=raw,
        version=de[DE_VERSION],
        cipher_suite=cipher_suite,
        edevice_key_bytes=cbor2.dumps(edevice_key_tag),
        edevice_key_public=_cose_key_to_public(cbor2.loads(edevice_key_tag.value)),
        ble=ble,
    )


def tag24(payload: bytes) -> cbor2.CBORTag:
    """#6.24(bstr .cbor X) — the 'embedded CBOR' wrapper used throughout 18013-5."""
    return cbor2.CBORTag(24, payload)


def encode_ereader_cose_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Our ephemeral public key as a bare COSE_Key (RFC 8152), *untagged*.

    Wrap with `tag24(...)` to get EReaderKeyBytes where the spec calls for it
    (SessionEstablishment, and element 1 of the transcript).
    """
    numbers = public_key.public_numbers()
    cose = {
        1: 2,                                    # kty: EC2
        -1: 1,                                   # crv: P-256
        -2: numbers.x.to_bytes(32, "big"),       # x
        -3: numbers.y.to_bytes(32, "big"),       # y
    }
    return cbor2.dumps(cose)


def build_session_transcript(
    device_engagement_raw: bytes,
    ereader_cose_key_raw: bytes,
    handover=None,
) -> bytes:
    """9.1.5.1 — SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover].

    Both arguments are the *untagged inner* CBOR: the verbatim QR payload, and the
    bare COSE_Key from `encode_ereader_cose_key`. This function applies the #6.24
    wrapping. Neither payload is decoded or re-encoded.

    `handover` is None for QR engagement (QRHandover = null). For NFC, pass
    [handover_select_bytes, handover_request_bytes_or_None].
    """
    return cbor2.dumps([
        tag24(device_engagement_raw),
        tag24(ereader_cose_key_raw),
        handover,
    ])


def session_transcript_bytes(session_transcript: bytes) -> bytes:
    """9.1.5.1 — SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)."""
    return cbor2.dumps(tag24(session_transcript))


def derive_session_keys(
    ereader_private: ec.EllipticCurvePrivateKey,
    edevice_public: ec.EllipticCurvePublicKey,
    transcript_bytes: bytes,
) -> dict[str, bytes]:
    """9.1.1.5 — ECKA-DH then HKDF-SHA256 salted with SHA-256(SessionTranscriptBytes)."""
    zab = ereader_private.exchange(ec.ECDH(), edevice_public)
    salt = hashlib.sha256(transcript_bytes).digest()
    return {
        info: HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt, info=info.encode("utf-8")
        ).derive(zab)
        for info in ("SKReader", "SKDevice")
    }


def ble_ident(edevice_key_bytes: bytes) -> bytes:
    """8.3.3.1.1.3 — Ident value. Only used in mdoc central client mode, where the
    *reader* is the GATT server and the mdoc reads this to check it found us."""
    return HKDF(
        algorithm=hashes.SHA256(), length=16, salt=None, info=b"BLEIdent"
    ).derive(edevice_key_bytes)


def session_nonce(counter: int, *, reader: bool) -> bytes:
    """9.1.1.5 — 8-byte identifier || 4-byte BE counter; counter starts at 1."""
    if counter < 1:
        raise ValueError("message counter starts at 1 and never repeats")
    identifier = bytes(8) if reader else bytes(7) + b"\x01"
    return identifier + counter.to_bytes(4, "big")
