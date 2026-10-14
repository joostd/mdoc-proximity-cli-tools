#!/usr/bin/env python3
"""
Validate SessionTranscript construction against a REAL captured session.

Fixtures are from the live run on 2026-10-13 17:28 — EUDI wallet (Pixel 6a)
presenting eu.europa.ec.eudi.employee.1 to the EUDI verifier (Mi A2 Lite) over
QR engagement + BLE. Both values were read out of the verifier's logcat:

  * the `mdoc:` URI the verifier scanned
  * the 201-byte SessionTranscript the verifier then built

If our builder reproduces those 201 bytes exactly, it agrees with a shipping
ISO 18013-5 implementation — a stronger check than any self-consistency test.

Run:  .venv/bin/python test_mdoc_transcript.py
"""
import sys

import cbor2

from mdoc_transcript import (
    build_session_transcript,
    parse_device_engagement,
    parse_mdoc_uri,
    session_transcript_bytes,
    tag24,
)

# --- fixtures from capture-2026-10-13.md ------------------------------------

MDOC_URI = (
    "mdoc:owBjMS4wAYIB2BhYS6QBAiABIVgg6cOt2fEaFi-pkxIFZMYXOAjApP4A6mPaAvJcbxhr"
    "hYAiWCBoTYnZB71xCnPxheg9GgYzvY-2fodH_o5_LL_ZfvNI0wKBgwIBowD1AfQKUGpja85WJV"
    "9E1D6wH6ocNTg"
)

CAPTURED_SESSION_TRANSCRIPT = bytes.fromhex(
    "83d8185874a30063312e30018201d818584ba401022001215820e9c3add9f11a162fa9931205"
    "64c6173808c0a4fe00ea63da02f25c6f186b8580225820684d89d907bd710a73f185e83d1a06"
    "33bd8fb67e8747fe8e7f2cbfd97ef348d30281830201a300f501f40a506a636bce56255f44d4"
    "3eb01faa1c3538d818584ba4010220012158200f36a9a79a5da99f283943e20e2b0d4f2cdaf6"
    "c11a3439c48d36972783ba082b22582033c0797bed30d92e6acf84da5073a139478be29e44dc"
    "48be153dc726fd7de182f6"
)

# The verifier's ephemeral public key, recovered from element 1 of the capture.
CAPTURED_EREADER_COSE_KEY = bytes.fromhex(
    "a4010220012158200f36a9a79a5da99f283943e20e2b0d4f2cdaf6c11a3439c48d36972783ba"
    "082b22582033c0797bed30d92e6acf84da5073a139478be29e44dc48be153dc726fd7de182"
)

PASS, FAIL = "PASS", "FAIL"
_UNSET = object()  # distinct from None, which is a legitimate expected value
_failures = 0


def check(label, got, want=_UNSET):
    global _failures
    ok = bool(got) if want is _UNSET else got == want
    if not ok:
        _failures += 1
    print(f"{PASS if ok else FAIL}  {label}")
    if not ok and want is not None:
        g = got.hex() if isinstance(got, bytes) else got
        w = want.hex() if isinstance(want, bytes) else want
        print(f"        got  {g}\n        want {w}")


def main() -> int:
    raw = parse_mdoc_uri(MDOC_URI)
    de = parse_device_engagement(raw)

    # --- engagement parsing -------------------------------------------------
    check("engagement version is 1.0", de.version, "1.0")
    check("cipher suite 1", de.cipher_suite, 1)
    check("BLE retrieval method present", de.ble is not None)
    check("mdoc peripheral server mode", de.ble.peripheral_server_mode, True)
    check("mdoc central client mode off", de.ble.central_client_mode, False)
    check("reader takes GATT client role", de.ble.reader_is_gatt_client, True)
    check("service UUID",
          de.ble.service_uuid, bytes.fromhex("6a636bce56255f44d43eb01faa1c3538"))
    check("no peripheral address offered", de.ble.peripheral_server_address, None)

    # --- the verbatim rule --------------------------------------------------
    # Re-encoding the decoded engagement must NOT be assumed equal to the original.
    reencoded = cbor2.dumps(cbor2.loads(raw))
    print(f"      note: re-encoded engagement is "
          f"{'byte-identical here' if reencoded == raw else 'DIFFERENT from the original'}"
          f" ({len(reencoded)} vs {len(raw)} bytes) — never rely on this")

    # --- transcript construction -------------------------------------------
    transcript = build_session_transcript(raw, CAPTURED_EREADER_COSE_KEY)
    check("SessionTranscript length", len(transcript), len(CAPTURED_SESSION_TRANSCRIPT))
    check("SessionTranscript matches real verifier byte-for-byte",
          transcript, CAPTURED_SESSION_TRANSCRIPT)

    # --- structural assertions ---------------------------------------------
    elements = cbor2.loads(transcript)
    check("transcript is a 3-element array", len(elements), 3)
    check("element 0 is #6.24", elements[0].tag, 24)
    check("element 0 holds the QR payload verbatim", elements[0].value, raw)
    check("element 1 is #6.24", elements[1].tag, 24)
    check("QRHandover is null", elements[2], None)

    # --- SessionTranscriptBytes --------------------------------------------
    stb = session_transcript_bytes(transcript)
    check("STB is tag 24 wrapping the transcript",
          stb, cbor2.dumps(tag24(transcript)))
    check("STB is strictly longer than the transcript", len(stb) > len(transcript))
    print(f"      STB = {len(stb)} bytes; HKDF salt is SHA-256 of THIS, "
          "not of the transcript")

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
