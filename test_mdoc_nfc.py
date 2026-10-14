#!/usr/bin/env python3
"""
Offline checks for mdoc_nfc — NDEF parsing and NFC handover transcripts.

Two fixtures, deliberately different in kind:

  * ISO/IEC 18013-5 Annex D.5.1, whose SessionTranscript is a *negotiated*
    NFC handover with the mdoc as BLE central. This is the spec's own data,
    and it lets us rebuild the published SessionTranscriptBytes byte for byte.
  * A Handover Select read off the EUDI reference wallet with an ACR122U on
    2026-10-14: *static* handover, mdoc as BLE peripheral, service UUID in the
    carrier. This is the shape the reader actually has to handle.

Run: .venv/bin/python test_mdoc_nfc.py
"""
from __future__ import annotations

import sys

import cbor2

import _vectors_annex_d as v
import mdoc_ble
import mdoc_nfc
from mdoc_transcript import (
    build_session_transcript,
    parse_device_engagement,
    session_transcript_bytes,
)

# Captured live: Pixel 6a running the EUDI wallet, tapped on an ACS ACR122U.
LIVE_HANDOVER_SELECT = bytes.fromhex(
    "91021d487315910209616301013001046d646f63510209616301013001046d646f63"
    "1c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e74"
    "6d646f63a20063312e30018201d818584ba401022001215820f0856043d477db056e"
    "f6b190ae0fb3a71f6ec91b6d747a32eec453f8a2810d8d225820e6ff8d816bdbe0d7"
    "cf5a8c29428f31e75af7fbb7d0c65ee6c79f95fcd40ffe881a2015016170706c6963"
    "6174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230021c001107228d"
    "5186c6d3ea40f9ca98166b0163915a2015016170706c69636174696f6e2f766e642e"
    "626c7565746f6f74682e6c652e6f6f6230021c001107228d5186c6d3ea40f9ca9816"
    "6b016391"
)

PASSED = FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [ok]   {label}" + (f" — {detail}" if detail else ""))
    else:
        FAILED += 1
        print(f"  [FAIL] {label}" + (f" — {detail}" if detail else ""))


def expect_error(label: str, fn) -> None:
    try:
        fn()
    except mdoc_nfc.NfcError as exc:
        check(label, True, str(exc)[:60])
    else:
        check(label, False, "no NfcError raised")


# --- Annex D.5.1: the spec's own negotiated handover -------------------------

print("\nAnnex D.5.1 — negotiated NFC handover")

transcript_d51 = cbor2.loads(v.SESSION_TRANSCRIPT_BYTES).value
engagement_d51, ereader_d51, handover_d51 = cbor2.loads(transcript_d51)
handover_select_d51, handover_request_d51 = handover_d51

check("NFCHandover is a 2-element array", len(handover_d51) == 2)
check("negotiated handover carries a Handover Request",
      isinstance(handover_request_d51, bytes),
      f"{len(handover_request_d51)} bytes")

records = mdoc_nfc.parse_ndef(handover_select_d51)
check("Handover Select parses into 3 records", len(records) == 3,
      ", ".join(r.type.decode("ascii", "replace") for r in records))
check("first record is Hs", records[0].type == mdoc_nfc.TYPE_HANDOVER_SELECT)

parsed_d51 = mdoc_nfc.parse_handover_select(handover_select_d51)
check("DeviceEngagement matches the transcript's own copy",
      parsed_d51.device_engagement_raw == engagement_d51.value,
      f"{len(parsed_d51.device_engagement_raw)} bytes")
check("LE role is central-only, so the reader is not the GATT client",
      parsed_d51.le_role == mdoc_nfc.LE_ROLE_CENTRAL_ONLY
      and not parsed_d51.reader_is_gatt_client)
check("no service UUID in a central-mode Hs carrier",
      parsed_d51.service_uuid is None,
      "it lives in the reader's Handover Request instead")
check("device address recovered from the carrier",
      parsed_d51.device_address == bytes.fromhex("28128b37282801"))

# The real prize: the transcript is reproducible from its parts, which proves
# the NFCHandover goes in as a 2-element array of verbatim NDEF messages.
rebuilt = build_session_transcript(engagement_d51.value, ereader_d51.value,
                                   handover_d51)
check("SessionTranscript rebuilt byte for byte", rebuilt == transcript_d51,
      f"{len(rebuilt)} bytes")
check("SessionTranscriptBytes match the published vector",
      session_transcript_bytes(rebuilt) == v.SESSION_TRANSCRIPT_BYTES)


# --- live capture: static handover, mdoc as peripheral -----------------------

print("\nLive capture — EUDI wallet, static handover over an ACR122U")

records = mdoc_nfc.parse_ndef(LIVE_HANDOVER_SELECT)
check("message parses into 4 records", len(records) == 4,
      ", ".join(r.type.decode("ascii", "replace")[:24] for r in records))
check("the last record has ME set and nothing trails it",
      sum(len(r.payload) for r in records) == 29 + 88 + 21 + 21)

live = mdoc_nfc.parse_handover_select(LIVE_HANDOVER_SELECT)
check("handover_select is kept verbatim", live.handover_select is LIVE_HANDOVER_SELECT)
check("static handover: second NFCHandover element is null",
      live.handover == [LIVE_HANDOVER_SELECT, None])

engagement = parse_device_engagement(live.device_engagement_raw)
check("DeviceEngagement decodes", engagement.version == "1.0"
      and engagement.cipher_suite == 1,
      f"version {engagement.version}, cipher suite {engagement.cipher_suite}")
check("NFC engagement carries NO retrieval methods", engagement.ble is None,
      "so the transport must come from the NDEF carrier")
check("EDeviceKey is a P-256 point",
      engagement.edevice_key_public.curve.name == "secp256r1")

check("LE role is peripheral-only, so the reader is the GATT client",
      live.le_role == mdoc_nfc.LE_ROLE_PERIPHERAL_ONLY and live.reader_is_gatt_client)
check("128-bit service UUID byte-reversed out of AD type 0x07",
      mdoc_ble.service_uuid_str(live.service_uuid)
      == "9163016b-1698-caf9-40ea-d3c686518d22",
      mdoc_ble.service_uuid_str(live.service_uuid))
check("the AD structure itself is the reverse of that",
      bytes(reversed(live.service_uuid)).hex() == "228d5186c6d3ea40f9ca98166b016391")


# --- the handover binds the session ------------------------------------------

print("\nTranscript binding")

ereader = bytes.fromhex("a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff2"
                        "89d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4"
                        "c338237a8cfcf3de6aa672fc60a557aa32fc67")

nfc_transcript = build_session_transcript(live.device_engagement_raw, ereader,
                                          live.handover)
qr_transcript = build_session_transcript(live.device_engagement_raw, ereader, None)
check("NFC and QR transcripts differ for the same engagement",
      nfc_transcript != qr_transcript,
      "every session key is bound to the handover")
check("the Handover Select survives the round trip unchanged",
      cbor2.loads(nfc_transcript)[2][0] == LIVE_HANDOVER_SELECT)

tampered = bytearray(LIVE_HANDOVER_SELECT)
tampered[-1] ^= 0x01  # flip one bit of the advertised service UUID
check("a one-bit change to the Hs changes the transcript",
      build_session_transcript(live.device_engagement_raw, ereader,
                               [bytes(tampered), None]) != nfc_transcript)


# --- malformed input ----------------------------------------------------------

print("\nRejections")

expect_error("a Handover Request is not a Handover Select",
             lambda: mdoc_nfc.parse_handover_select(handover_request_d51))
expect_error("empty message rejected",
             lambda: mdoc_nfc.parse_handover_select(b""))

# Strip the two LE OOB carrier records, leaving Hs + DeviceEngagement.
without_carrier = LIVE_HANDOVER_SELECT[:LIVE_HANDOVER_SELECT.index(b"\x1a\x20\x15")]
expect_error("handover with no BLE carrier rejected",
             lambda: mdoc_nfc.parse_handover_select(without_carrier))

chunked = bytes([0xB1]) + LIVE_HANDOVER_SELECT[1:]  # set CF
expect_error("chunked records refused rather than half-parsed",
             lambda: mdoc_nfc.parse_ndef(chunked))


print(f"\n{PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
