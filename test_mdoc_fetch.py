#!/usr/bin/env python3
"""
`mdoc_fetch` without the network: the parsing and the proof, not the issuer.

Six of the eight steps in that script are HTTP against a server we do not
control, and testing those would test the dev instance rather than this code.
What is worth pinning down is the part that runs on either side of them — the
proof of possession we sign, and the credential we parse back out — because
both are places where being wrong fails silently. A proof with the wrong curve
encoding still gets accepted by an issuer that never verifies it, and a
credential parsed into the wrong shape still verifies as issuer-signed and
only fails mdoc authentication, hours later, on a handset.

So the end-to-end check here runs a *minted* credential through the whole
fetch path — wrapped the way the real issuer wraps it, through `to_credential`,
through a bundle on disk, through `MdocHolder`, into `mdoc_reader`. If the
device key survives that round trip, it will survive a real one.

Run:  .venv/bin/python test_mdoc_fetch.py
"""
import base64
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from mdoc_fetch import (
    FetchError,
    b64u_decode,
    describe,
    jwk_of,
    load_credential,
    proof_jwt,
    save_bundle,
    to_credential,
)
from mdoc_holder import MdocHolder
from mdoc_issuer import MDL_DOC_TYPE, MDL_NAMESPACE, mint, sample_mdl_elements
from mdoc_reader import build_device_request, validate_response
from mdoc_transcript import build_session_transcript, encode_ereader_cose_key, tag24

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
    except Exception as exc:
        check(label, False, f"raised {type(exc).__name__}: {exc}")
    else:
        check(label, False, "accepted when it should have been rejected")


def a_transcript() -> bytes:
    engagement = cbor2.dumps({0: "1.0", 1: [1, tag24(b"\x00" * 32)]})
    reader_key = encode_ereader_cose_key(
        ec.generate_private_key(ec.SECP256R1()).public_key())
    return build_session_transcript(engagement, reader_key, None)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main() -> int:
    credential, pki = mint(sample_mdl_elements())
    device_key = credential.device_private_key

    # --- the proof of possession ---------------------------------------------
    #
    # The reference issuer reads the jwk out of the unverified header and never
    # checks the signature, so none of this has to be right for issuance to
    # succeed. It has to be right for the proof to mean what it says.

    token = proof_jwt(device_key, audience="https://issuer.example",
                      nonce="n-0S6_WzA2Mj", client_id="c-123")
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(b64u_decode(header_b64))
    payload = json.loads(b64u_decode(payload_b64))

    check("the proof carries the OpenID4VCI typ",
          header["typ"] == "openid4vci-proof+jwt" and header["alg"] == "ES256",
          f"{header['typ']}, {header['alg']}")
    check("the audience is the credential issuer and the nonce is echoed",
          payload["aud"] == "https://issuer.example"
          and payload["nonce"] == "n-0S6_WzA2Mj" and payload["iss"] == "c-123")
    check("a nonce-less issuer gets a proof without one",
          "nonce" not in json.loads(b64u_decode(
              proof_jwt(device_key, audience="x", nonce=None).split(".")[1])),
          "the endpoint is optional and older deployments have none")

    signature = b64u_decode(signature_b64)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    check("the ES256 signature is raw r||s, not DER", len(signature) == 64,
          f"{len(signature)} bytes")
    device_key.public_key().verify(
        utils.encode_dss_signature(r, s),
        f"{header_b64}.{payload_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    check("and it verifies under the key in the header", True,
          "re-encoded to DER to check it, which is the conversion in reverse")

    numbers = device_key.public_key().public_numbers()
    jwk = header["jwk"]
    check("the jwk is the device public key, 32 bytes per coordinate",
          jwk["crv"] == "P-256"
          and b64u_decode(jwk["x"]) == numbers.x.to_bytes(32, "big")
          and b64u_decode(jwk["y"]) == numbers.y.to_bytes(32, "big")
          and len(b64u_decode(jwk["x"])) == 32,
          "left-padding matters: a short x is a different key")

    # --- the shapes an issuer might return -----------------------------------
    #
    # OpenID4VCI does not pin down what an `mso_mdoc` credential looks like on
    # the wire beyond "base64url of the mdoc", and the implementations disagree.
    # pymdoccbor, which the EUDI issuer uses, hands back a whole DeviceResponse.

    issuer_signed = {"nameSpaces": credential.namespaces,
                     "issuerAuth": credential.issuer_auth}

    wrappings = {
        "a DeviceResponse, which is what pymdoccbor's dump() returns":
            {"version": "1.0", "status": 0,
             "documents": [{"docType": MDL_DOC_TYPE,
                            "issuerSigned": issuer_signed}]},
        "a Document on its own":
            {"docType": MDL_DOC_TYPE, "issuerSigned": issuer_signed},
        "a bare IssuerSigned, with no docType anywhere but the MSO":
            issuer_signed,
    }
    for label, wrapping in wrappings.items():
        parsed = to_credential(b64u(cbor2.dumps(wrapping)), device_key)
        check(f"parses {label}",
              parsed.doc_type == MDL_DOC_TYPE
              and len(parsed.namespaces[MDL_NAMESPACE]) == 11)

    tagged = dict(issuer_signed)
    tagged["issuerAuth"] = cbor2.CBORTag(18, credential.issuer_auth)
    check("an issuerAuth tagged as COSE_Sign1 is untagged on the way in",
          to_credential(b64u(cbor2.dumps(tagged)), device_key).issuer_auth
          == credential.issuer_auth,
          "tag 18 is correct CBOR and `mdoc_auth` wants the bare array")

    raises("something that is not an mdoc at all is refused", FetchError,
           to_credential, b64u(cbor2.dumps({"vc": "sd-jwt"})), device_key)

    raises("a credential configuration the issuer does not offer is refused",
           FetchError, describe,
           {"credential_configurations_supported": {"eu.europa.ec.eudi.pid_mdoc": {}}},
           "eu.europa.ec.eudi.mdl_mdoc")

    # --- the bundle, and the device key it exists to carry -------------------

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "mdl.bundle"
        fetched = to_credential(
            b64u(cbor2.dumps(wrappings[next(iter(wrappings))])), device_key)
        save_bundle(path, fetched, issuer="https://issuer.example")

        check("the bundle is 0600 — half of it is a private key in the clear",
              path.stat().st_mode & 0o777 == 0o600)

        reloaded = load_credential(path)
        check("the credential survives the round trip to disk",
              reloaded.doc_type == MDL_DOC_TYPE
              and reloaded.element_names() == credential.element_names())
        check("and so does the device private key",
              reloaded.device_private_key.private_numbers()
              == device_key.private_numbers(),
              "without it the credential is issuer-signed and unpresentable")

        # The whole point, end to end: a credential this process did not mint,
        # read off disk, presented by the holder, validated by the reader.
        transcript = a_transcript()
        request = build_device_request(
            [(MDL_DOC_TYPE, {MDL_NAMESPACE: {"family_name": False}})])
        response = MdocHolder([reloaded]).respond(request, transcript)
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink):
            ok = validate_response(cbor2.loads(response), transcript,
                                   [pki.iaca_certificate], require_chain=True)
        report = sink.getvalue()
        check("a credential loaded from a bundle presents and verifies", ok,
              f"{report.count('[ok]')} reader checks passed")
        check("including mdoc authentication, which is the device key's job",
              "[ok] mdoc authentication" in report,
              "the only check that fails if the bundle loses the private half")

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
