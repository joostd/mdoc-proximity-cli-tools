#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — NFC device engagement over a PC/SC contactless reader.

The mdoc emulates an NFC Forum Type 4 Tag (AID `D2760000850101`) and serves a
**Handover Select** message. We read it with APDUs over PC/SC — tested with an
ACS ACR122U — and get everything a session needs from one tap.

Two things differ from QR engagement, and both will bite if you assume
otherwise:

  * The DeviceEngagement served over NFC has **no retrieval methods** (no map
    key 2). In static handover the transport lives in the NDEF carrier records
    instead, so the service UUID comes from the Bluetooth LE OOB record.
  * The transcript's third element is `NFCHandover = [HandoverSelectMessage,
    null]` rather than `null`, where the first element is the NDEF message
    **verbatim as read** (9.1.5.1). Same cardinal rule as everywhere else.

This is *engagement* only. ISO 18013-5 also defines NFC data retrieval
(8.3.3.2), running the whole session over APDUs, but the EUDI wallet does not
implement it — the handover to BLE is mandatory.

Negotiated handover is out of scope: it needs NFC peer-to-peer (LLCP), which a
PC/SC reader does not do and which Android dropped in version 10.

Requires: pyscard, cbor2
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import cbor2

# Type 4 Tag command APDUs (NFC Forum T4T Operation Specification)
SELECT_NDEF_APPLICATION = [0x00, 0xA4, 0x04, 0x00, 0x07,
                           0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00]
SELECT_CAPABILITY_CONTAINER = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03]
STATUS_OK = (0x90, 0x00)

# Short APDUs cap Le at 255; stay under it regardless of what the CC advertises.
MAX_READ = 0xF0

# NDEF record type names used by 18013-5 NFC engagement (8.2.2.1)
TYPE_HANDOVER_SELECT = b"Hs"
TYPE_ALTERNATIVE_CARRIER = b"ac"
TYPE_DEVICE_ENGAGEMENT = b"iso.org:18013:deviceengagement"
TYPE_LE_OOB = b"application/vnd.bluetooth.le.oob"

# Bluetooth assigned numbers, used inside the LE OOB payload
AD_INCOMPLETE_UUID128 = 0x06
AD_COMPLETE_UUID128 = 0x07
AD_LE_DEVICE_ADDRESS = 0x1B
AD_LE_ROLE = 0x1C

# LE Role values. "Peripheral" here means the *mdoc* is the peripheral, which
# is mdoc peripheral server mode — the reader becomes the GATT client.
LE_ROLE_PERIPHERAL_ONLY = 0x00
LE_ROLE_CENTRAL_ONLY = 0x01
LE_ROLE_PERIPHERAL_PREFERRED = 0x02
LE_ROLE_CENTRAL_PREFERRED = 0x03


class NfcError(Exception):
    pass


# --- NDEF ------------------------------------------------------------------

@dataclass(frozen=True)
class NdefRecord:
    tnf: int
    type: bytes
    id: bytes
    payload: bytes


def parse_ndef(message: bytes) -> list[NdefRecord]:
    """Minimal NDEF parser — short and long records, no chunking.

    Chunked records (CF set) do not appear in handover messages, so rather than
    half-support them we refuse them outright.
    """
    records: list[NdefRecord] = []
    offset = 0
    while offset < len(message):
        header = message[offset]
        offset += 1
        chunked = bool(header & 0x20)
        short = bool(header & 0x10)
        has_id = bool(header & 0x08)
        tnf = header & 0x07
        if chunked:
            raise NfcError("chunked NDEF records are not supported")

        type_length = message[offset]
        offset += 1
        if short:
            payload_length = message[offset]
            offset += 1
        else:
            payload_length = int.from_bytes(message[offset:offset + 4], "big")
            offset += 4
        id_length = message[offset] if has_id else 0
        offset += 1 if has_id else 0

        record_type = message[offset:offset + type_length]
        offset += type_length
        record_id = message[offset:offset + id_length]
        offset += id_length
        payload = message[offset:offset + payload_length]
        offset += payload_length

        records.append(NdefRecord(tnf, record_type, record_id, payload))
        if header & 0x40:  # ME — message end
            break
    return records


def _parse_le_oob(payload: bytes) -> dict:
    """Bluetooth LE OOB data: a sequence of length-prefixed AD structures."""
    fields = {}
    offset = 0
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            break
        ad_type = payload[offset + 1]
        value = payload[offset + 2:offset + 1 + length]
        fields[ad_type] = value
        offset += 1 + length
    return fields


# --- engagement -------------------------------------------------------------

@dataclass(frozen=True)
class NfcEngagement:
    handover_select: bytes
    """The NDEF message verbatim. Element 0 of NFCHandover."""

    device_engagement_raw: bytes
    """Verbatim DeviceEngagement CBOR from the aux-data record."""

    service_uuid: bytes | None
    """16 bytes, big-endian — already byte-swapped out of the AD structure."""

    le_role: int | None
    device_address: bytes | None

    @property
    def reader_is_gatt_client(self) -> bool:
        """True when the mdoc is the BLE peripheral and GATT server.

        The LE Role field describes the *mdoc's* role, so peripheral means
        mdoc peripheral server mode — the one this reader can do.
        """
        return self.le_role in (LE_ROLE_PERIPHERAL_ONLY, LE_ROLE_PERIPHERAL_PREFERRED)

    @property
    def handover(self) -> list:
        """9.1.5.1 — NFCHandover. The second element is null for static
        handover, which is the only kind a PC/SC reader can perform."""
        return [self.handover_select, None]


def parse_handover_select(message: bytes) -> NfcEngagement:
    """Pull the DeviceEngagement and the BLE carrier out of a Handover Select."""
    records = parse_ndef(message)
    if not records or records[0].type != TYPE_HANDOVER_SELECT:
        found = records[0].type if records else b""
        raise NfcError(f"first record is {found!r}, expected a Handover Select")

    device_engagement = next(
        (r.payload for r in records if r.type == TYPE_DEVICE_ENGAGEMENT), None)
    if device_engagement is None:
        raise NfcError("no iso.org:18013:deviceengagement record in the handover")

    carrier = next((r.payload for r in records if r.type == TYPE_LE_OOB), None)
    if carrier is None:
        raise NfcError("no Bluetooth LE OOB carrier record in the handover")
    fields = _parse_le_oob(carrier)

    uuid_le = fields.get(AD_COMPLETE_UUID128) or fields.get(AD_INCOMPLETE_UUID128)
    # AD structures carry 128-bit UUIDs least-significant byte first; the
    # engagement and BLE APIs both want the conventional big-endian order.
    service_uuid = bytes(reversed(uuid_le)) if uuid_le else None

    role = fields.get(AD_LE_ROLE)
    return NfcEngagement(
        handover_select=message,
        device_engagement_raw=device_engagement,
        service_uuid=service_uuid,
        le_role=role[0] if role else None,
        device_address=fields.get(AD_LE_DEVICE_ADDRESS),
    )


# --- PC/SC transport --------------------------------------------------------

def _contactless_reader(name_hint: str | None = None):
    try:
        from smartcard.System import readers
    except ImportError as exc:  # pragma: no cover - environment problem
        raise NfcError("pyscard is not installed (pip install pyscard)") from exc

    available = readers()
    if not available:
        raise NfcError("no PC/SC readers found")
    if name_hint:
        matches = [r for r in available if name_hint.lower() in str(r).lower()]
        if not matches:
            raise NfcError(f"no reader matching {name_hint!r} in "
                           f"{[str(r) for r in available]}")
        return matches[0]
    # A YubiKey or similar CCID token is also a "reader"; prefer a contactless one.
    contactless = [r for r in available
                   if "picc" in str(r).lower() or "contactless" in str(r).lower()]
    if not contactless:
        raise NfcError(f"no contactless reader among {[str(r) for r in available]}")
    return contactless[0]


def _transmit(connection, apdu: list[int], label: str) -> bytes:
    data, sw1, sw2 = connection.transmit(apdu)
    if (sw1, sw2) != STATUS_OK:
        raise NfcError(f"{label} failed with SW {sw1:02X}{sw2:02X}")
    return bytes(data)


def read_handover_select(*, reader_name: str | None = None, timeout: float = 60.0,
                         verbose: bool = False) -> bytes:
    """Wait for a tap, then read the Type 4 Tag's NDEF message."""
    reader = _contactless_reader(reader_name)
    log = (lambda m: print(f"[nfc] {m}")) if verbose else (lambda m: None)
    log(f"reader: {reader}")

    connection = reader.createConnection()
    deadline = time.monotonic() + timeout
    while True:
        try:
            connection.connect()
            break
        except Exception:
            if time.monotonic() >= deadline:
                raise NfcError(f"nothing presented to the reader within {timeout:.0f}s")
            time.sleep(0.4)
    log("tag connected")

    _transmit(connection, SELECT_NDEF_APPLICATION, "SELECT NDEF application")
    _transmit(connection, SELECT_CAPABILITY_CONTAINER, "SELECT capability container")
    cc = _transmit(connection, [0x00, 0xB0, 0x00, 0x00, 0x0F], "READ capability container")

    # CC layout: len(2) version(1) MLe(2) MLc(2) then the NDEF File Control TLV
    # 04 06 <file id(2)> <max size(2)> <read access> <write access>.
    if len(cc) < 15 or cc[7] != 0x04:
        raise NfcError(f"unexpected capability container: {cc.hex()}")
    file_id = list(cc[9:11])
    log(f"NDEF file {bytes(file_id).hex()}, max {int.from_bytes(cc[11:13], 'big')} bytes")

    _transmit(connection, [0x00, 0xA4, 0x00, 0x0C, 0x02] + file_id, "SELECT NDEF file")
    length = int.from_bytes(
        _transmit(connection, [0x00, 0xB0, 0x00, 0x00, 0x02], "READ NLEN"), "big")
    if length == 0:
        raise NfcError("the tag holds an empty NDEF message")

    message = b""
    offset = 2  # the first two bytes are NLEN itself
    while len(message) < length:
        want = min(MAX_READ, length - len(message))
        chunk = _transmit(connection,
                          [0x00, 0xB0, offset >> 8, offset & 0xFF, want],
                          f"READ at {offset}")
        if not chunk:
            raise NfcError(f"read stalled at {len(message)} of {length} bytes")
        message += chunk
        offset += len(chunk)

    log(f"read {len(message)} bytes of NDEF")
    try:
        connection.disconnect()
    except Exception:
        pass
    return message


def engage(*, reader_name: str | None = None, timeout: float = 60.0,
           verbose: bool = False) -> NfcEngagement:
    """One tap: read the Handover Select and parse it."""
    return parse_handover_select(
        read_handover_select(reader_name=reader_name, timeout=timeout, verbose=verbose))


if __name__ == "__main__":
    import sys

    try:
        engagement = engage(verbose=True)
    except NfcError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    print(f"\nHandover Select   {len(engagement.handover_select)} bytes")
    print(f"DeviceEngagement  {len(engagement.device_engagement_raw)} bytes "
          f"{cbor2.loads(engagement.device_engagement_raw)!r}"[:120])
    print(f"service UUID      {engagement.service_uuid.hex() if engagement.service_uuid else None}")
    print(f"LE role           {engagement.le_role} "
          f"(reader is GATT client: {engagement.reader_is_gatt_client})")
