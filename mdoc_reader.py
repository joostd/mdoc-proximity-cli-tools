#!/usr/bin/env python3
"""
An ISO/IEC 18013-5 mdoc reader in Python: engagement + BLE + validation.

Composes the verified modules:

    mdoc_transcript  engagement parsing, SessionTranscript, session keys
    mdoc_nfc         NFC static handover over PC/SC (optional)
    mdoc_ble         GATT client transport (mdoc peripheral server mode)
    mdoc_auth        issuer data authentication, value digests, mdoc auth

Usage:
    .venv/bin/python mdoc_reader.py 'mdoc:owBjMS4w...'
    .venv/bin/python mdoc_reader.py --dry-run 'mdoc:...'        # no radio
    .venv/bin/python mdoc_reader.py --trust-anchor iaca.pem 'mdoc:...'
    .venv/bin/python mdoc_reader.py --nfc --trust-anchor iaca.pem

Both engagement routes end in the same BLE session; they differ only in where
the DeviceEngagement comes from and in the Handover element of the transcript
(null for QR, [HandoverSelect, null] for NFC static handover).

The engagement QR is single-use and short-lived: scan it, run this within
seconds. A stale URI gives a device that is no longer advertising.

Requires: cbor2, cryptography, bleak; pyscard for --nfc
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import mdoc_ble
from mdoc_auth import (
    ValidationError,
    build_device_authentication_bytes,
    check_mso_validity,
    device_public_key_from_mso,
    verify_device_signature,
    verify_issuer_auth,
    verify_value_digests,
)
from mdoc_transcript import (
    build_session_transcript,
    derive_session_keys,
    encode_ereader_cose_key,
    parse_device_engagement,
    parse_mdoc_uri,
    session_nonce,
    session_transcript_bytes,
    tag24,
)

DEFAULT_DOC_TYPE = "eu.europa.ec.eudi.employee.1"
DEFAULT_ELEMENTS = {"eu.europa.ec.eudi.employee.1": {"employee_id": False}}

STATUS_TERMINATION = 20


def build_device_request(doc_type: str, namespaces: dict) -> bytes:
    """8.3.2.1.2.1 — unsigned DeviceRequest (no readerAuth).

    Without readerAuth the wallet cannot tell who is asking, so it will warn
    the holder that the verifier is unidentified — and may refuse outright for
    data elements that require an authenticated reader.
    """
    items_request = cbor2.dumps({"docType": doc_type, "nameSpaces": namespaces})
    return cbor2.dumps({
        "version": "1.0",
        "docRequests": [{"itemsRequest": tag24(items_request)}],
    })


def build_session_establishment(ereader_cose_key: bytes, ciphertext: bytes) -> bytes:
    """9.1.1.4 — the reader's first message."""
    return cbor2.dumps({"eReaderKey": tag24(ereader_cose_key), "data": ciphertext})


def report(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'ok' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    return ok


def validate_response(device_response: dict, session_transcript: bytes,
                      anchors: list, *, require_chain: bool) -> bool:
    """Run every check 18013-5 requires of a reader, and report each one."""
    now = datetime.now(timezone.utc)
    all_ok = True

    for document in device_response.get("documents", []):
        doc_type = document["docType"]
        print(f"\nDocument: {doc_type}")

        issuer_signed = document["issuerSigned"]
        try:
            mso = verify_issuer_auth(issuer_signed["issuerAuth"], anchors,
                                     now=now, require_chain=require_chain)
            all_ok &= report("issuer data authentication", True,
                             "signature valid" + ("" if require_chain else
                                                  ", CHAIN NOT CHECKED"))
        except ValidationError as exc:
            report("issuer data authentication", False, str(exc))
            all_ok = False
            continue

        if mso["docType"] != doc_type:
            all_ok &= report("MSO docType matches the document", False,
                             f"MSO says {mso['docType']!r}")
        else:
            report("MSO docType matches the document", True)

        try:
            check_mso_validity(mso, now=now)
            report("MSO validity window", True,
                   f"until {mso['validityInfo']['validUntil'].isoformat()}")
        except ValidationError as exc:
            all_ok &= report("MSO validity window", False, str(exc))

        try:
            elements = verify_value_digests(issuer_signed.get("nameSpaces", {}), mso)
            report("value digests", True, f"{len(elements)} element(s) match the MSO")
        except ValidationError as exc:
            elements = []
            all_ok &= report("value digests", False, str(exc))

        device_signed = document["deviceSigned"]
        device_namespaces = device_signed["nameSpaces"]
        raw_namespaces = (device_namespaces.value
                          if isinstance(device_namespaces, cbor2.CBORTag)
                          else device_namespaces)
        device_auth_bytes = build_device_authentication_bytes(
            session_transcript, doc_type, raw_namespaces)

        device_auth = device_signed["deviceAuth"]
        if "deviceSignature" in device_auth:
            try:
                verify_device_signature(device_auth["deviceSignature"],
                                        device_public_key_from_mso(mso),
                                        device_auth_bytes)
                report("mdoc authentication (deviceSignature)", True,
                       "bound to this session transcript")
            except ValidationError as exc:
                all_ok &= report("mdoc authentication (deviceSignature)", False, str(exc))
        else:
            # deviceMac needs EMacKey from the *static* device key, which the
            # reader can only derive if the MSO device key is an agreement key.
            all_ok &= report("mdoc authentication (deviceMac)", False,
                             "deviceMac path not wired up in this reader")

        for element in elements:
            print(f"      {element.namespace}/{element.identifier} = {element.value!r}")

    return all_ok


async def run(device_engagement_raw: bytes, doc_type: str, namespaces: dict,
              anchors: list, *, handover=None, service_uuid_override: bytes | None = None,
              require_chain: bool, dry_run: bool, verbose: bool,
              save: str | None = None) -> int:
    engagement = parse_device_engagement(device_engagement_raw)
    print(f"Engagement: version {engagement.version}, cipher suite "
          f"{engagement.cipher_suite}")

    if service_uuid_override is not None:
        # NFC static handover: the engagement carries no retrieval methods, so
        # the transport comes from the NDEF Bluetooth LE OOB carrier instead.
        service_uuid = mdoc_ble.service_uuid_str(service_uuid_override)
        print(f"Transport: BLE, mdoc peripheral server mode, service {service_uuid} "
              f"(from the NFC carrier)")
    else:
        if engagement.ble is None:
            print("No BLE retrieval method in this engagement.", file=sys.stderr)
            return 2
        if not engagement.ble.reader_is_gatt_client:
            print("Wallet wants mdoc central client mode; this reader only supports "
                  "mdoc peripheral server mode (see mdoc_ble docstring).", file=sys.stderr)
            return 2
        service_uuid = mdoc_ble.service_uuid_str(engagement.ble.service_uuid)
        print(f"Transport: BLE, mdoc peripheral server mode, service {service_uuid}")

    # Fresh ephemeral key per transaction — these are never reused (9.1.1.4).
    ereader_private = ec.generate_private_key(ec.SECP256R1())
    ereader_cose_key = encode_ereader_cose_key(ereader_private.public_key())

    transcript = build_session_transcript(engagement.raw, ereader_cose_key, handover)
    stb = session_transcript_bytes(transcript)
    keys = derive_session_keys(ereader_private, engagement.edevice_key_public, stb)
    print(f"SessionTranscript: {len(transcript)} bytes, SKReader "
          f"{keys['SKReader'][:8].hex()}…")

    device_request = build_device_request(doc_type, namespaces)
    ciphertext = AESGCM(keys["SKReader"]).encrypt(
        session_nonce(1, reader=True), device_request, None)
    establishment = build_session_establishment(ereader_cose_key, ciphertext)
    print(f"DeviceRequest: {len(device_request)} bytes -> SessionEstablishment "
          f"{len(establishment)} bytes")

    if dry_run:
        print("\n--dry-run: not touching the radio. Request would be:")
        print(f"  {cbor2.loads(device_request)}")
        return 0

    print(f"\nScanning for {service_uuid} …")
    device = await mdoc_ble.find_mdoc(service_uuid)
    if device is None:
        print("Not found. The QR is single-use and the wallet stops advertising "
              "when its engagement screen closes — rescan and retry.", file=sys.stderr)
        return 1
    print(f"Found {device.address} ({device.name or 'unnamed'})")

    async with mdoc_ble.MdocBleReader(device, service_uuid, verbose=verbose) as link:
        await link.send(establishment)
        print("Request sent. Waiting for the holder to consent on the handset…")
        raw = await link.receive()

        session_data = cbor2.loads(raw)
        if "data" not in session_data:
            print(f"Session ended with status {session_data.get('status')}",
                  file=sys.stderr)
            return 1

        plaintext = AESGCM(keys["SKDevice"]).decrypt(
            session_nonce(1, reader=False), session_data["data"], None)
        print(f"DeviceResponse: {len(plaintext)} bytes decrypted")
        if save:
            # The transcript goes alongside it: without those exact bytes the
            # deviceSignature in the response can never be checked again.
            with open(save, "wb") as handle:
                handle.write(cbor2.dumps({"deviceResponse": plaintext,
                                          "sessionTranscript": transcript}))
            print(f"               saved to {save}")

        # Terminate politely before we start validating (9.1.1.4, status 20).
        await link.send(cbor2.dumps({"status": STATUS_TERMINATION}))

    device_response = cbor2.loads(plaintext)
    print(f"\nResponse version {device_response['version']}, "
          f"status {device_response['status']}")

    ok = validate_response(device_response, transcript, anchors,
                           require_chain=require_chain)
    print("\nVERIFIED" if ok else "\nNOT VERIFIED — see failures above")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("uri", nargs="?",
                        help="the mdoc: URI from the wallet's QR code")
    parser.add_argument("--from-image", metavar="PATH",
                        help="decode the QR from a screenshot or photo instead")
    parser.add_argument("--from-adb", nargs="?", const="", metavar="SERIAL",
                        help="screencap the attached handset and decode its QR")
    parser.add_argument("--nfc", action="store_true",
                        help="engage by NFC tap on a PC/SC contactless reader "
                             "instead of scanning a QR")
    parser.add_argument("--nfc-reader", metavar="NAME",
                        help="substring of the PC/SC reader name to use")
    parser.add_argument("--doc-type", default=DEFAULT_DOC_TYPE)
    parser.add_argument("--trust-anchor", action="append", default=[], metavar="PEM",
                        help="IACA certificate; repeatable")
    parser.add_argument("--dry-run", action="store_true",
                        help="build the request and stop before using the radio")
    parser.add_argument("--wait", type=float, default=0.0, metavar="SECONDS",
                        help="how long to wait for the engagement: with --from-adb "
                             "poll the handset screen, with --nfc wait for a tap")
    parser.add_argument("--save", metavar="PATH",
                        help="write the decrypted response and its transcript as CBOR")
    parser.add_argument("-v", "--verbose", action="store_true", help="BLE tracing")
    args = parser.parse_args()

    anchors = [x509.load_pem_x509_certificate(open(p, "rb").read())
               for p in args.trust_anchor]
    if not anchors:
        print("WARNING: no --trust-anchor given. The issuer signature will be "
              "checked but NOT traced to a trusted IACA, so a valid result says "
              "nothing about who issued the credential.\n")

    namespaces = (DEFAULT_ELEMENTS if args.doc_type == DEFAULT_DOC_TYPE
                  else {args.doc_type: {}})

    handover = None
    service_uuid_override = None

    if args.nfc:
        import mdoc_nfc
        timeout = args.wait or 60.0
        print(f"Tap the handset on the contactless reader (up to {timeout:.0f}s)…")
        try:
            nfc = mdoc_nfc.engage(reader_name=args.nfc_reader, timeout=timeout,
                                  verbose=args.verbose)
        except mdoc_nfc.NfcError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not nfc.reader_is_gatt_client:
            print(f"The handover offers LE role {nfc.le_role} (mdoc as central); "
                  "this reader only supports mdoc peripheral server mode.",
                  file=sys.stderr)
            return 2
        if nfc.service_uuid is None:
            print("The LE OOB carrier names no service UUID — nothing to scan for.",
                  file=sys.stderr)
            return 2
        print(f"NFC engagement: {len(nfc.handover_select)} byte Handover Select, "
              f"{len(nfc.device_engagement_raw)} byte DeviceEngagement\n")
        device_engagement_raw = nfc.device_engagement_raw
        # 9.1.5.1 — the Handover Select goes into the transcript exactly as read;
        # the second element is null because this is a static handover.
        handover = nfc.handover
        service_uuid_override = nfc.service_uuid
    else:
        uri = args.uri
        if args.from_image or args.from_adb is not None:
            import qr_engagement
            try:
                if args.from_image:
                    uri = qr_engagement.uri_from_image(args.from_image)
                else:
                    if args.wait:
                        print(f"Waiting up to {args.wait:.0f}s for a QR on the handset…")
                    uri = qr_engagement.uri_from_adb(args.from_adb or None,
                                                     wait=args.wait)
            except qr_engagement.QrError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(f"Scanned QR: {uri[:40]}…\n")
        if not uri:
            parser.error("give an mdoc: URI, or --from-image / --from-adb / --nfc")
        device_engagement_raw = parse_mdoc_uri(uri)

    return asyncio.run(run(device_engagement_raw, args.doc_type, namespaces, anchors,
                           handover=handover,
                           service_uuid_override=service_uuid_override,
                           require_chain=bool(anchors), dry_run=args.dry_run,
                           verbose=args.verbose, save=args.save))


if __name__ == "__main__":
    sys.exit(main())
