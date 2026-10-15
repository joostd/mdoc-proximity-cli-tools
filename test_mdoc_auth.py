#!/usr/bin/env python3
"""
Validate mdoc_auth against ISO/IEC 18013-5:2021 Annex D test vectors.

Covers the three reader-side checks:

  D.5.2  issuer data authentication — IssuerAuth COSE_Sign1, DS->IACA chain, MSO
  D.4.1.2 value digests            — one recovered IssuerSignedItem vs the MSO
  D.5.3  mdoc authentication       — EMacKey derivation and the deviceMac tag

Plus a self-consistency round trip for the deviceSignature variant, which no
Annex D vector covers but which is what the live 2026-10-13 capture used.

Run:  .venv/bin/python test_mdoc_auth.py
"""
import sys
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509.oid import NameOID

import _vectors_annex_d as v
from mdoc_auth import (
    ValidationError,
    _verify_chain_to_anchor,
    build_device_authentication_bytes,
    check_mso_validity,
    derive_emac_key,
    verify_device_mac,
    verify_device_signature,
    verify_issuer_auth,
    verify_value_digests,
)

# Annex D's credential expired in 2021; validate as of a date inside its window.
AS_OF = datetime(2021, 1, 1, tzinfo=timezone.utc)

DOC_TYPE = "org.iso.18013.5.1.mDL"
NAMESPACE = "org.iso.18013.5.1"

_failures = 0


def check(label, ok, detail=""):
    global _failures
    if not ok:
        _failures += 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}")
    if detail:
        print(f"      {detail}")


def raises(label, exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        check(label, True, f"rejected: {exc}")
    except Exception as exc:  # wrong exception type is still a failure
        check(label, False, f"raised {type(exc).__name__}: {exc}")
    else:
        check(label, False, "accepted when it should have been rejected")


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(subject, subject_key, issuer, issuer_key, *, ca: bool):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(issuer)
               .public_key(subject_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                              critical=True))
    return builder.sign(issuer_key, hashes.SHA256())


def _self_signed(key, common_name: str):
    return _certificate(_name(common_name), key, _name(common_name), key, ca=True)


def _issued_by(issuer_key, issuer_name, subject_key, common_name: str):
    return _certificate(_name(common_name), subject_key, issuer_name, issuer_key,
                        ca=False)


def main() -> int:
    iaca = x509.load_der_x509_certificate(v.IACA_DER)

    # --- D.5.2 issuer data authentication -----------------------------------
    mso = verify_issuer_auth(v.ISSUER_AUTH, [iaca], now=AS_OF)
    check("IssuerAuth verifies and chains to the IACA", True,
          f"docType {mso['docType']}, version {mso['version']}")
    check("MSO digest algorithm is SHA-256", mso["digestAlgorithm"] == "SHA-256")
    check("valueDigests present for the mDL namespace", NAMESPACE in mso["valueDigests"],
          ", ".join(f"{ns}: {len(d)} digests" for ns, d in mso["valueDigests"].items()))

    check_mso_validity(mso, now=AS_OF)
    check("MSO is valid at the reference instant", True,
          f"{mso['validityInfo']['validFrom'].isoformat()} .. "
          f"{mso['validityInfo']['validUntil'].isoformat()}")
    raises("MSO expiry is enforced", ValidationError,
           check_mso_validity, mso, now=datetime(2026, 1, 1, tzinfo=timezone.utc))

    # An untrusted anchor must not be accepted. Use the DS cert as a bogus root.
    unrelated = x509.load_der_x509_certificate(
        cbor2.loads(v.ISSUER_AUTH)[1][33])
    raises("unknown trust anchor rejected", ValidationError,
           verify_issuer_auth, v.ISSUER_AUTH, [unrelated], now=AS_OF)

    # --- an RSA trust anchor -------------------------------------------------
    #
    # Annex B says an mDL PKI is ECDSA on P-256/384/521, and the verifier used
    # to assume it: it built an `ec.ECDSA` verifier for every anchor, so an RSA
    # root raised, got swallowed by a bare `except Exception`, and was reported
    # as "does not chain to any trust anchor". Test PKIs are routinely RSA
    # (wwWallet's is), and openssl verifying a chain this code rejects is the
    # worst kind of disagreement — it points the blame at the credential.

    rsa_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_root = _self_signed(rsa_root_key, "RSA Test Root CA")
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds_cert = _issued_by(rsa_root_key, rsa_root.subject, ds_key, "DS under an RSA root")

    _verify_chain_to_anchor(ds_cert, [rsa_root])
    check("an EC document signer chains to an RSA root", True,
          f"{ds_cert.signature_algorithm_oid._name} verified")

    other_rsa_root = _self_signed(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "RSA Test Root CA")  # same DN, different key
    raises("a same-DN RSA root with the wrong key is rejected", ValidationError,
           _verify_chain_to_anchor, ds_cert, [other_rsa_root])

    try:
        _verify_chain_to_anchor(ds_cert, [iaca])
    except ValidationError as exc:
        check("the rejection names the anchor and the reason",
              "subject does not match" in str(exc)
              and iaca.subject.rfc4514_string() in str(exc),
              str(exc))

    # A single flipped byte in the signature must break verification.
    tampered = list(cbor2.loads(v.ISSUER_AUTH))
    tampered[3] = bytes([tampered[3][0] ^ 0x01]) + tampered[3][1:]
    raises("tampered IssuerAuth signature rejected", ValidationError,
           verify_issuer_auth, cbor2.dumps(tampered), [iaca], now=AS_OF)

    # --- D.4.1.2 value digests ----------------------------------------------
    namespaces = {NAMESPACE: [v.ISSUER_SIGNED_ITEM_DRIVING_PRIVILEGES]}
    elements = verify_value_digests(namespaces, mso)
    check("recovered IssuerSignedItem matches its MSO digest", len(elements) == 1,
          f"digestID {elements[0].digest_id}: {elements[0].identifier}")

    # Flip one byte of the element value: the digest must stop matching.
    item = cbor2.loads(v.ISSUER_SIGNED_ITEM_DRIVING_PRIVILEGES)
    inner = cbor2.loads(item.value)
    inner["random"] = bytes([inner["random"][0] ^ 0x01]) + inner["random"][1:]
    forged = cbor2.CBORTag(24, cbor2.dumps(inner))
    raises("forged IssuerSignedItem rejected", ValidationError,
           verify_value_digests, {NAMESPACE: [forged]}, mso)

    # --- D.5.3 mdoc authentication, deviceMac variant -----------------------
    session_transcript = cbor2.loads(v.SESSION_TRANSCRIPT_BYTES).value
    device_auth_bytes = build_device_authentication_bytes(
        session_transcript, DOC_TYPE, cbor2.dumps({}))
    check("DeviceAuthenticationBytes reconstructed byte-for-byte",
          device_auth_bytes == v.DEVICE_AUTH_BYTES,
          f"{len(device_auth_bytes)} bytes vs {len(v.DEVICE_AUTH_BYTES)} expected")

    emac_key = derive_emac_key(v.EMAC_ZAB, v.SESSION_TRANSCRIPT_BYTES)
    check("EMacKey matches D.5.3", emac_key == v.EMAC_KEY, emac_key.hex())

    # Annex D prints DeviceAuth with the MAC tag cut short (45 bytes, needs 52);
    # splice the full tag from the separately printed MAC_TAG vector.
    device_auth_raw = v.DEVICE_AUTH[:v.DEVICE_AUTH.index(b"\x58\x20") + 2] + v.MAC_TAG
    device_mac = cbor2.loads(device_auth_raw)["deviceMac"]
    check("spliced DeviceAuth decodes as a COSE_Mac0", len(device_mac) == 4)

    verify_device_mac(device_mac, emac_key, device_auth_bytes)
    check("deviceMac tag verifies against the transcript", True)

    # The MAC_structure we build must be the one the spec printed.
    built = cbor2.dumps(["MAC0", device_mac[0], b"", device_auth_bytes])
    check("MAC_structure matches D.5.3", built == v.MAC_STRUCTURE,
          f"{len(built)} bytes vs {len(v.MAC_STRUCTURE)} expected")

    raises("deviceMac under the wrong key rejected", ValidationError,
           verify_device_mac, device_mac, bytes(32), device_auth_bytes)
    raises("deviceMac over a different transcript rejected", ValidationError,
           verify_device_mac, device_mac, emac_key, device_auth_bytes[:-1] + b"\x00")

    # --- deviceSignature variant (no Annex D vector; mirrors our capture) ----
    device_key = ec.generate_private_key(ec.SECP256R1())
    protected = b"\xa1\x01\x26"  # {1: -7} = ES256
    der = device_key.sign(
        cbor2.dumps(["Signature1", protected, b"", device_auth_bytes]),
        ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    cose_sign1 = [protected, {}, None, r.to_bytes(32, "big") + s.to_bytes(32, "big")]

    verify_device_signature(cose_sign1, device_key.public_key(), device_auth_bytes)
    check("deviceSignature verifies (ES256, detached payload)", True)

    raises("deviceSignature from the wrong key rejected", ValidationError,
           verify_device_signature, cose_sign1,
           ec.generate_private_key(ec.SECP256R1()).public_key(), device_auth_bytes)

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
