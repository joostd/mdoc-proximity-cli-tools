#!/usr/bin/env python3
"""
End-to-end check of the reader's validation path, without a radio or a wallet.

test_mdoc_auth proves each check against the Annex D vectors. This proves the
*plumbing* around them: mint a throwaway IACA -> DS -> MSO -> DeviceResponse,
feed it to mdoc_reader.validate_response, and confirm it accepts a good one and
rejects each way of breaking it.

Annex D cannot do this job: its DeviceResponse is a raster scan in the PDF, and
even if it were not, the holder's private device key is not published, so no
deviceSignature over a transcript of our choosing can be reproduced.

Run:  .venv/bin/python test_mdoc_reader.py
"""
import hashlib
import io
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from mdoc_auth import build_device_authentication_bytes
from mdoc_reader import validate_response
from mdoc_transcript import build_session_transcript, encode_ereader_cose_key, tag24

DOC_TYPE = "eu.europa.ec.eudi.employee.1"
NAMESPACE = DOC_TYPE
NOW = datetime.now(timezone.utc)

_failures = 0


def check(label, ok, detail=""):
    global _failures
    if not ok:
        _failures += 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"\n      {detail}" if detail else ""))


# --- synthetic issuer -------------------------------------------------------

def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(subject_name, subject_key, issuer_name, issuer_key, *, ca):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_name))
        .issuer_name(_name(issuer_name))
        .public_key(subject_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None),
                       critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256())


def _cose_sign1(private_key, protected: dict, unprotected: dict, payload):
    protected_raw = cbor2.dumps(protected)
    message = cbor2.dumps(["Signature1", protected_raw, b"", payload])
    r, s = utils.decode_dss_signature(
        private_key.sign(message, ec.ECDSA(hashes.SHA256())))
    return [protected_raw, unprotected, payload,
            r.to_bytes(32, "big") + s.to_bytes(32, "big")]


def _cose_key(public_key):
    numbers = public_key.public_numbers()
    return {1: 2, -1: 1,
            -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}


def mint_credential(elements: dict, device_public_key):
    """Build (issuerSigned, iaca_certificate) for a toy credential."""
    iaca_key = ec.generate_private_key(ec.SECP256R1())
    ds_key = ec.generate_private_key(ec.SECP256R1())
    iaca = _certificate("test iaca", iaca_key.public_key(), "test iaca", iaca_key, ca=True)
    ds = _certificate("test ds", ds_key.public_key(), "test iaca", iaca_key, ca=False)

    items, digests = [], {}
    for digest_id, (identifier, value) in enumerate(elements.items()):
        item = tag24(cbor2.dumps({
            "digestID": digest_id,
            "random": bytes(32),  # a real issuer uses 16+ random bytes per item
            "elementIdentifier": identifier,
            "elementValue": value,
        }))
        items.append(item)
        digests[digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()

    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": {NAMESPACE: digests},
        "deviceKeyInfo": {"deviceKey": _cose_key(device_public_key)},
        "docType": DOC_TYPE,
        "validityInfo": {
            "signed": NOW,
            "validFrom": NOW - timedelta(days=1),
            "validUntil": NOW + timedelta(days=30),
        },
    }
    issuer_auth = _cose_sign1(
        ds_key,
        {1: -7},
        {33: ds.public_bytes(serialization.Encoding.DER)},
        cbor2.dumps(tag24(cbor2.dumps(mso))))

    return {"nameSpaces": {NAMESPACE: items}, "issuerAuth": issuer_auth}, iaca


def mint_response(issuer_signed, device_key, session_transcript):
    """Wrap issuerSigned in a DeviceResponse with a deviceSignature."""
    device_namespaces_raw = cbor2.dumps({})
    # The payload is detached (null): what gets signed is the externally
    # supplied DeviceAuthenticationBytes (9.1.3.4).
    device_auth_bytes = build_device_authentication_bytes(
        session_transcript, DOC_TYPE, device_namespaces_raw)
    protected = cbor2.dumps({1: -7})
    r, s = utils.decode_dss_signature(device_key.sign(
        cbor2.dumps(["Signature1", protected, b"", device_auth_bytes]),
        ec.ECDSA(hashes.SHA256())))
    signature = [protected, {}, None, r.to_bytes(32, "big") + s.to_bytes(32, "big")]

    return {
        "version": "1.0",
        "status": 0,
        "documents": [{
            "docType": DOC_TYPE,
            "issuerSigned": issuer_signed,
            "deviceSigned": {
                "nameSpaces": tag24(device_namespaces_raw),
                "deviceAuth": {"deviceSignature": signature},
            },
        }],
    }


def run_validation(response, transcript, anchors):
    """Call validate_response, capturing its report so output stays readable."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        ok = validate_response(response, transcript, anchors, require_chain=True)
    return ok, buffer.getvalue()


def main() -> int:
    device_key = ec.generate_private_key(ec.SECP256R1())
    reader_key = ec.generate_private_key(ec.SECP256R1())

    # A plausible engagement; only its bytes matter for the transcript.
    engagement_raw = cbor2.dumps({
        0: "1.0",
        1: [1, tag24(cbor2.dumps(_cose_key(device_key.public_key())))],
        2: [[2, 1, {0: True, 1: False, 10: bytes(16)}]],
    })
    transcript = build_session_transcript(
        engagement_raw, encode_ereader_cose_key(reader_key.public_key()))

    elements = {"employee_id": "E-12345", "family_name": "Doe"}
    issuer_signed, iaca = mint_credential(elements, device_key.public_key())
    response = mint_response(issuer_signed, device_key, transcript)

    ok, report = run_validation(response, transcript, [iaca])
    check("a well-formed response validates", ok, report.strip())

    disclosed = [line for line in report.splitlines() if "employee_id = " in line]
    check("disclosed element values are reported", len(disclosed) == 1,
          disclosed[0].strip() if disclosed else "no element line in the report")

    # --- each way of breaking it must be caught ----------------------------

    unrelated_iaca = mint_credential({}, device_key.public_key())[1]
    ok, _ = run_validation(response, transcript, [unrelated_iaca])
    check("unknown IACA is rejected", not ok)

    # Bind the response to a different session: this is the replay case, where
    # an attacker resends a genuine response captured from another transaction.
    other_transcript = build_session_transcript(
        engagement_raw,
        encode_ereader_cose_key(ec.generate_private_key(ec.SECP256R1()).public_key()))
    ok, _ = run_validation(response, other_transcript, [iaca])
    check("response replayed into another session is rejected", not ok)

    # Swap an element value while keeping the issuer signature intact.
    tampered = cbor2.loads(cbor2.dumps(response))
    item = tampered["documents"][0]["issuerSigned"]["nameSpaces"][NAMESPACE][0]
    inner = cbor2.loads(item.value)
    inner["elementValue"] = "E-99999"
    tampered["documents"][0]["issuerSigned"]["nameSpaces"][NAMESPACE][0] = \
        tag24(cbor2.dumps(inner))
    ok, _ = run_validation(tampered, transcript, [iaca])
    check("altered element value is rejected", not ok)

    # A response whose deviceSignature comes from a key the MSO does not name.
    impostor = mint_response(issuer_signed, ec.generate_private_key(ec.SECP256R1()),
                             transcript)
    ok, _ = run_validation(impostor, transcript, [iaca])
    check("deviceSignature from an unbound key is rejected", not ok)

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
