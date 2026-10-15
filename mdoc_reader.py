#!/usr/bin/env python3
"""
An ISO/IEC 18013-5 mdoc reader in Python: engagement + BLE + validation.

Composes the verified modules:

    mdoc_transcript       engagement parsing, SessionTranscript, session keys
    mdoc_nfc              NFC static handover over PC/SC (optional)
    mdoc_ble              GATT client — mdoc peripheral server mode
    mdoc_ble_peripheral   GATT server — mdoc central client mode
    mdoc_auth             issuer data authentication, value digests, mdoc auth

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
    derive_emac_key,
    device_public_key_from_mso,
    verify_device_mac,
    verify_device_signature,
    verify_issuer_auth,
    verify_value_digests,
)
from mdoc_transcript import (
    ble_ident,
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

# docType -> (namespace, [data element identifiers])
#
# The namespace is NOT the docType in general. An mDL is docType
# `org.iso.18013.5.1.mDL` but its elements live in namespace
# `org.iso.18013.5.1` — assume they are the same and the wallet matches no
# namespace, returning an empty document rather than an error.
KNOWN_DOC_TYPES = {
    "eu.europa.ec.eudi.employee.1": (
        "eu.europa.ec.eudi.employee.1", ["employee_id"]),
    "org.iso.18013.5.1.mDL": (
        "org.iso.18013.5.1", ["family_name", "given_name", "birth_date",
                              "document_number", "expiry_date"]),
    "eu.europa.ec.eudi.pid.1": (
        "eu.europa.ec.eudi.pid.1", ["family_name", "given_name", "birth_date"]),
    "eu.europa.ec.eudi.pseudonym.age_over_18.1": (
        "eu.europa.ec.eudi.pseudonym.age_over_18.1", ["age_over_18"]),
}

STATUS_TERMINATION = 20


def build_device_request(requests: list[tuple[str, dict]]) -> bytes:
    """8.3.2.1.2.1 — unsigned DeviceRequest (no readerAuth).

    `requests` is a list of (docType, nameSpaces). More than one is legal and
    is the cheapest way to find out what a wallet holds: the mdoc returns a
    Document for each docType it can satisfy and a documentError for the rest.

    Without readerAuth the wallet cannot tell who is asking, so it will warn
    the holder that the verifier is unidentified — and may refuse outright for
    data elements that require an authenticated reader.
    """
    return cbor2.dumps({
        "version": "1.0",
        "docRequests": [
            {"itemsRequest": tag24(cbor2.dumps({"docType": doc_type,
                                                "nameSpaces": namespaces}))}
            for doc_type, namespaces in requests
        ],
    })


def build_session_establishment(ereader_cose_key: bytes, ciphertext: bytes) -> bytes:
    """9.1.1.4 — the reader's first message."""
    return cbor2.dumps({"eReaderKey": tag24(ereader_cose_key), "data": ciphertext})


def report(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'ok' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    return ok


def validate_response(device_response: dict, session_transcript: bytes,
                      anchors: list, *, require_chain: bool,
                      ereader_private=None) -> bool:
    """Run every check 18013-5 requires of a reader, and report each one.

    `ereader_private` is the reader's ephemeral private key, and is only
    needed for the `deviceMac` variant — which agrees EMacKey with it rather
    than with anything derivable from the session keys. Keeping it this far
    down the call is the whole cost of supporting that variant.
    """
    now = datetime.now(timezone.utc)
    all_ok = True

    # 8.3.2.1.2.2 — the mdoc says so explicitly when it cannot answer a
    # docRequest. Error 0 is "no such document"; the others are in Table 9.
    for document_error in device_response.get("documentErrors", []):
        for doc_type, code in document_error.items():
            print(f"\nNot returned: {doc_type} — error {code}"
                  + (" (the wallet holds no such document)" if code == 0 else ""))

    if not device_response.get("documents"):
        print("\nNo documents in the response.")
        return False

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
        elif "deviceMac" in device_auth:
            # EMacKey agrees the MSO's *static* device key with EReaderKey, so
            # unlike deviceSignature this can only ever be checked by the
            # reader that was there — a captured response proves nothing to a
            # third party, which is the point of the variant.
            if ereader_private is None:
                all_ok &= report("mdoc authentication (deviceMac)", False,
                                 "needs the reader's ephemeral private key")
            else:
                try:
                    zab = ereader_private.exchange(
                        ec.ECDH(), device_public_key_from_mso(mso))
                    verify_device_mac(
                        device_auth["deviceMac"],
                        derive_emac_key(zab, session_transcript_bytes(session_transcript)),
                        device_auth_bytes)
                    report("mdoc authentication (deviceMac)", True,
                           "bound to this session transcript and to this reader")
                except ValidationError as exc:
                    all_ok &= report("mdoc authentication (deviceMac)", False, str(exc))
        else:
            all_ok &= report("mdoc authentication", False,
                             f"deviceAuth has neither variant: {sorted(device_auth)}")

        for element in elements:
            print(f"      {element.namespace}/{element.identifier} = {element.value!r}")

        # 8.3.2.1.2.2 — per-element errors, the mdoc's account of what it
        # could not give us. Printed, never checked: `errors` lives outside
        # issuerSigned and outside DeviceAuthentication, so it is signed by
        # nobody. An mdoc can claim not to hold an element it is simply
        # withholding, and a reader has no way to tell.
        for namespace, codes in document.get("errors", {}).items():
            for identifier, code in codes.items():
                reason = ("the mdoc holds no such element" if code == 0
                          else f"error {code}")
                print(f"      {namespace}/{identifier} — not returned, "
                      f"{reason} (unsigned)")

    return all_ok


def choose_ble_mode(ble, preference: str) -> tuple[str, bytes]:
    """8.3.3.1.1.1 — pick a transport mode and the UUID that goes with it.

    When the mdoc offers both, the spec says the reader *should* select mdoc
    central client mode, so that is what `auto` does. Each mode has its own
    UUID in BleOptions (key 10 vs key 11); taking the wrong one means scanning
    for, or advertising, a UUID nobody is using.
    """
    if preference == "auto":
        if not (ble.central_client_mode or ble.peripheral_server_mode):
            raise ValueError("the mdoc offers neither BLE mode")
        preference = ("central-client" if ble.central_client_mode
                      else "peripheral-server")

    offered, uuid, key = (
        (ble.central_client_mode, ble.central_client_uuid, 11)
        if preference == "central-client" else
        (ble.peripheral_server_mode, ble.peripheral_server_uuid, 10))

    if not offered:
        raise ValueError(f"the mdoc does not offer mdoc {preference.replace('-', ' ')} "
                         "mode")
    if not uuid:
        raise ValueError(f"{preference} mode offered with no UUID (BleOptions {key})")
    return preference, uuid


MODE_DESCRIPTION = {
    "peripheral-server": "mdoc peripheral server mode (we are the GATT client)",
    "central-client": "mdoc central client mode (we are the GATT server)",
}


async def run(device_engagement_raw: bytes, requests: list[tuple[str, dict]],
              anchors: list, *, handover=None, service_uuid_override: bytes | None = None,
              mode_override: str | None = None, ble_mode: str = "auto",
              require_chain: bool, dry_run: bool, verbose: bool,
              save: str | None = None) -> int:
    engagement = parse_device_engagement(device_engagement_raw)
    print(f"Engagement: version {engagement.version}, cipher suite "
          f"{engagement.cipher_suite}")

    if service_uuid_override is not None:
        # NFC static handover: the engagement carries no retrieval methods, so
        # the transport comes from the NDEF Bluetooth LE OOB carrier instead —
        # its LE Role byte is the only statement of who is central.
        mode = (ble_mode if ble_mode != "auto"
                else mode_override or "peripheral-server")
        uuid_bytes = service_uuid_override
        source = " (from the NFC carrier)"
    else:
        if engagement.ble is None:
            print("No BLE retrieval method in this engagement.", file=sys.stderr)
            return 2
        try:
            mode, uuid_bytes = choose_ble_mode(engagement.ble, ble_mode)
        except ValueError as exc:
            print(f"Cannot pick a BLE mode: {exc}", file=sys.stderr)
            return 2
        offered = [name for name, on in
                   (("peripheral server", engagement.ble.peripheral_server_mode),
                    ("central client", engagement.ble.central_client_mode)) if on]
        source = f" (mdoc offers: {', '.join(offered)})"

    service_uuid = mdoc_ble.service_uuid_str(uuid_bytes)
    print(f"Transport: BLE, {MODE_DESCRIPTION[mode]}, service {service_uuid}{source}")

    # Fresh ephemeral key per transaction — these are never reused (9.1.1.4).
    ereader_private = ec.generate_private_key(ec.SECP256R1())
    ereader_cose_key = encode_ereader_cose_key(ereader_private.public_key())

    transcript = build_session_transcript(engagement.raw, ereader_cose_key, handover)
    stb = session_transcript_bytes(transcript)
    keys = derive_session_keys(ereader_private, engagement.edevice_key_public, stb)
    print(f"SessionTranscript: {len(transcript)} bytes, SKReader "
          f"{keys['SKReader'][:8].hex()}…")

    device_request = build_device_request(requests)
    ciphertext = AESGCM(keys["SKReader"]).encrypt(
        session_nonce(1, reader=True), device_request, None)
    establishment = build_session_establishment(ereader_cose_key, ciphertext)
    print(f"DeviceRequest: {len(device_request)} bytes, "
          f"{len(requests)} docRequest(s) -> SessionEstablishment "
          f"{len(establishment)} bytes")
    for doc_type, namespaces in requests:
        for namespace, elements in namespaces.items():
            print(f"  asking {doc_type} / {namespace}: {', '.join(elements)}")

    if dry_run:
        print("\n--dry-run: not touching the radio. Request would be:")
        print(f"  {cbor2.loads(device_request)}")
        return 0

    if mode == "central-client":
        # We are the GATT server, so there is nothing to scan for: we
        # advertise and the wallet comes to us. Ident is how it checks it
        # reached the right reader (8.3.3.1.1.3).
        import mdoc_ble_peripheral
        ident = ble_ident(engagement.edevice_key_bytes)
        print(f"\nAdvertising {service_uuid}, Ident {ident.hex()[:16]}… — "
              "start the scan on the handset")
        link_context = mdoc_ble_peripheral.MdocBlePeripheral(
            service_uuid, ident, verbose=verbose)
    else:
        print(f"\nScanning for {service_uuid} …")
        device = await mdoc_ble.find_mdoc(service_uuid)
        if device is None:
            print("Not found. The QR is single-use and the wallet stops advertising "
                  "when its engagement screen closes — rescan and retry.",
                  file=sys.stderr)
            return 1
        print(f"Found {device.address} ({device.name or 'unnamed'})")
        link_context = mdoc_ble.MdocBleReader(device, service_uuid, verbose=verbose)

    async with link_context as link:
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
                           require_chain=require_chain,
                           ereader_private=ereader_private)
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
    parser.add_argument("--doc-type", action="append", default=[], metavar="DOCTYPE",
                        help="repeatable; one docRequest each. Known types: "
                             + ", ".join(sorted(KNOWN_DOC_TYPES)))
    parser.add_argument("--namespace", metavar="NS",
                        help="namespace for an unknown --doc-type "
                             "(only with a single --doc-type)")
    parser.add_argument("--element", action="append", default=[], metavar="ID",
                        help="data element to ask for; repeatable "
                             "(only with a single --doc-type)")
    parser.add_argument("--probe", action="store_true",
                        help="ask for every known docType at once and report "
                             "which ones the wallet holds")
    parser.add_argument("--ble-mode", default="auto",
                        choices=["auto", "central-client", "peripheral-server"],
                        help="which side is the GATT server. auto follows the "
                             "engagement, preferring mdoc central client mode "
                             "when the mdoc offers both (8.3.3.1.1.1)")
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

    doc_types = args.doc_type or (sorted(KNOWN_DOC_TYPES) if args.probe
                                  else [DEFAULT_DOC_TYPE])
    if (args.namespace or args.element) and len(doc_types) != 1:
        parser.error("--namespace / --element need exactly one --doc-type")

    requests = []
    for doc_type in doc_types:
        known = KNOWN_DOC_TYPES.get(doc_type)
        namespace = args.namespace or (known[0] if known else None)
        elements = args.element or (known[1] if known else None)
        if namespace is None or not elements:
            parser.error(
                f"{doc_type} is not in KNOWN_DOC_TYPES — give --namespace and at "
                "least one --element. Note the namespace is often not the docType "
                "(an mDL lives in org.iso.18013.5.1).")
        # IntentToRetain false: we are reading, not storing (8.3.2.1.2.1).
        requests.append((doc_type, {namespace: {e: False for e in elements}}))

    handover = None
    service_uuid_override = None
    mode_override = None

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
        if nfc.service_uuid is None:
            print("The LE OOB carrier names no service UUID — no BLE carrier.",
                  file=sys.stderr)
            return 2
        # The LE Role byte describes the *mdoc's* role, so it decides ours.
        mode_override = ("peripheral-server" if nfc.reader_is_gatt_client
                         else "central-client")
        print(f"NFC engagement: {len(nfc.handover_select)} byte Handover Select, "
              f"{len(nfc.device_engagement_raw)} byte DeviceEngagement, "
              f"LE role {nfc.le_role}\n")
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

    return asyncio.run(run(device_engagement_raw, requests, anchors,
                           handover=handover,
                           service_uuid_override=service_uuid_override,
                           mode_override=mode_override, ble_mode=args.ble_mode,
                           require_chain=bool(anchors), dry_run=args.dry_run,
                           verbose=args.verbose, save=args.save))


if __name__ == "__main__":
    sys.exit(main())
