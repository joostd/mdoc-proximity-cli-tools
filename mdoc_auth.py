#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — mdoc response validation (reader side).

Covers the three checks a verifier must perform on a DeviceResponse:

  1. Issuer data authentication (9.1.2) — IssuerAuth is a COSE_Sign1 over the
     MobileSecurityObject; verify it with the DS certificate, and chain that
     certificate to a trusted IACA.
  2. Value digests (9.1.2.4) — every disclosed IssuerSignedItem must hash to the
     digest the MSO committed to. This is what makes selective disclosure sound:
     undisclosed attributes stay committed but unopened.
  3. mdoc authentication (9.1.3) — DeviceAuth proves the holder controls the key
     the MSO names, over the SessionTranscript. Two variants, deviceMac (HMAC
     from an ECDH-derived EMacKey) and deviceSignature (ECDSA). Both here.

Requires: cbor2, cryptography
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

COSE_HEADER_X5CHAIN = 33
COSE_ALG_ES256 = -7
COSE_ALG_HMAC_256 = 5

DIGEST_ALGORITHMS = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}
_HASHLIB = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}


class ValidationError(Exception):
    """A check required by the standard failed."""


@dataclass
class VerifiedElement:
    namespace: str
    identifier: str
    value: object
    digest_id: int


def _tag24(payload: bytes) -> cbor2.CBORTag:
    return cbor2.CBORTag(24, payload)


def _require(condition, message):
    if not condition:
        raise ValidationError(message)


# --- 1. issuer data authentication -----------------------------------------

def _cose_sign1_parts(cose_sign1):
    structure = cbor2.loads(cose_sign1) if isinstance(cose_sign1, bytes) else cose_sign1
    if isinstance(structure, cbor2.CBORTag):  # COSE_Sign1 may be tagged (18)
        structure = structure.value
    _require(isinstance(structure, list) and len(structure) == 4,
             "IssuerAuth is not a 4-element COSE_Sign1")
    return structure


def _x5chain(unprotected) -> list[x509.Certificate]:
    raw = unprotected.get(COSE_HEADER_X5CHAIN)
    _require(raw is not None, "COSE_Sign1 has no x5chain (header 33)")
    # RFC 9360: a single certificate may appear as a bare bstr.
    ders = [raw] if isinstance(raw, bytes) else list(raw)
    return [x509.load_der_x509_certificate(d) for d in ders]


def _verify_ecdsa(public_key, signature: bytes, message: bytes, hash_alg) -> None:
    """COSE packs ECDSA as raw r||s; cryptography wants DER."""
    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    public_key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hash_alg))


def verify_issuer_auth(
    issuer_auth,
    trust_anchors: list[x509.Certificate],
    *,
    now: datetime | None = None,
    require_chain: bool = True,
) -> dict:
    """Verify IssuerAuth and return the decoded MobileSecurityObject.

    `trust_anchors` are IACA certificates. Raises ValidationError on any failure.

    `require_chain=False` skips only the chain-to-anchor step, for inspecting a
    credential whose IACA you do not have. The signature itself is still
    checked, but the result proves nothing about *who* issued the credential —
    anyone can mint a self-signed DS certificate. Never use it to accept one.
    """
    protected, unprotected, payload, signature = _cose_sign1_parts(issuer_auth)

    alg = cbor2.loads(protected).get(1) if protected else None
    _require(alg == COSE_ALG_ES256, f"unsupported IssuerAuth algorithm {alg!r}; expected ES256")

    chain = _x5chain(unprotected)
    ds_cert = chain[0]

    # Sig_structure per RFC 8152 §4.4. external_aad is empty for mdoc.
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    try:
        _verify_ecdsa(ds_cert.public_key(), signature, sig_structure, hashes.SHA256())
    except Exception as exc:
        raise ValidationError(f"IssuerAuth signature invalid: {exc}") from exc

    if require_chain:
        _verify_chain_to_anchor(ds_cert, trust_anchors)

    instant = now or datetime.now(timezone.utc)
    if not (ds_cert.not_valid_before_utc <= instant <= ds_cert.not_valid_after_utc):
        raise ValidationError(
            f"DS certificate not valid at {instant.isoformat()} "
            f"({ds_cert.not_valid_before_utc.isoformat()} .. "
            f"{ds_cert.not_valid_after_utc.isoformat()})")

    tagged = cbor2.loads(payload)
    _require(isinstance(tagged, cbor2.CBORTag) and tagged.tag == 24,
             "IssuerAuth payload is not #6.24(bstr .cbor MobileSecurityObject)")
    return cbor2.loads(tagged.value)


def _verify_certificate_signature(cert, issuer_public_key) -> None:
    """Check one certificate's signature, whatever key its issuer uses.

    18013-5 Annex B allows only ECDSA on P-256/384/521 in an mDL PKI, so it is
    tempting to hardcode that — but test PKIs are routinely RSA, and an anchor
    this code cannot *parse* must not be reported as an anchor that does not
    *match*. `signature_algorithm_parameters` carries the padding for RSA and
    the hash for ECDSA, so it handles PSS as well as PKCS#1 v1.5.
    """
    parameters = cert.signature_algorithm_parameters
    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes,
                                 parameters)
    elif isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes,
                                 parameters, cert.signature_hash_algorithm)
    elif isinstance(issuer_public_key, (ed25519.Ed25519PublicKey,
                                        ed448.Ed448PublicKey)):
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes)
    else:
        raise ValidationError(
            f"unsupported trust anchor key type {type(issuer_public_key).__name__}")


def _verify_chain_to_anchor(cert, trust_anchors) -> None:
    """Chain the DS certificate to one of the configured IACAs.

    Every rejection carries its reason. "Does not chain to any trust anchor"
    on its own is the least useful message in this file: a DN mismatch, a bad
    signature and a key type the verifier cannot handle are three very
    different problems, and the last one is a bug in *this* code rather than a
    fact about the credential.
    """
    if not trust_anchors:
        raise ValidationError("no trust anchors configured")

    reasons = []
    for anchor in trust_anchors:
        name = anchor.subject.rfc4514_string()
        if cert.issuer != anchor.subject:
            reasons.append(f"{name}: subject does not match the DS issuer DN")
            continue
        try:
            _verify_certificate_signature(cert, anchor.public_key())
            return
        except ValidationError as exc:
            reasons.append(f"{name}: {exc}")
        except InvalidSignature:
            reasons.append(f"{name}: DN matches but the signature does not verify")

    detail = "; ".join(reasons)
    raise ValidationError(
        f"DS certificate {cert.subject.rfc4514_string()!r} does not chain to any "
        f"trust anchor ({detail})")


def check_mso_validity(mso: dict, *, now: datetime | None = None) -> None:
    """9.1.2.4 — validityInfo. Note this is the MSO's own window, separate from
    the DS certificate's, and both must hold."""
    instant = now or datetime.now(timezone.utc)
    info = mso["validityInfo"]
    valid_from, valid_until = info["validFrom"], info["validUntil"]
    if not (valid_from <= instant <= valid_until):
        raise ValidationError(
            f"MSO not valid at {instant.isoformat()} "
            f"({valid_from.isoformat()} .. {valid_until.isoformat()})")


# --- 2. value digests -------------------------------------------------------

def verify_value_digests(issuer_namespaces: dict, mso: dict) -> list[VerifiedElement]:
    """Recompute the digest of every disclosed item and match it against the MSO.

    `issuer_namespaces` is IssuerSigned["nameSpaces"]: namespace -> [#6.24 items].
    Every item must match, or the whole response is rejected.
    """
    algorithm = mso["digestAlgorithm"]
    hasher = _HASHLIB.get(algorithm)
    _require(hasher is not None, f"unsupported digestAlgorithm {algorithm!r}")

    verified = []
    for namespace, items in issuer_namespaces.items():
        committed = mso["valueDigests"].get(namespace)
        _require(committed is not None, f"MSO commits no digests for namespace {namespace!r}")

        for item in items:
            tag = item if isinstance(item, cbor2.CBORTag) else cbor2.loads(item)
            _require(tag.tag == 24, "IssuerSignedItem is not #6.24 tagged")

            # Digest is over the *tagged, encoded* IssuerSignedItemBytes.
            digest = hasher(cbor2.dumps(tag)).digest()
            inner = cbor2.loads(tag.value)
            digest_id = inner["digestID"]

            expected = committed.get(digest_id)
            _require(expected is not None,
                     f"no digest committed for digestID {digest_id} in {namespace!r}")
            _require(hmac.compare_digest(digest, expected),
                     f"digest mismatch for {inner['elementIdentifier']!r} "
                     f"(digestID {digest_id}) in {namespace!r}")

            verified.append(VerifiedElement(
                namespace=namespace,
                identifier=inner["elementIdentifier"],
                value=inner["elementValue"],
                digest_id=digest_id,
            ))
    return verified


# --- 3. mdoc authentication -------------------------------------------------

def build_device_authentication_bytes(
    session_transcript: bytes, doc_type: str, device_namespaces_raw: bytes
) -> bytes:
    """9.1.3.4 — DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication),
    where DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
    DocType, DeviceNameSpacesBytes].

    `session_transcript` is spliced in as raw bytes, never decoded and re-encoded:
    the mdoc signed the transcript exactly as it built it, and any difference in
    encoding shows up only as a signature failure. Same cardinal rule as in
    mdoc_transcript.
    """
    device_authentication = b"".join([
        b"\x84",                                # array(4)
        cbor2.dumps("DeviceAuthentication"),
        session_transcript,                     # verbatim
        cbor2.dumps(doc_type),
        cbor2.dumps(_tag24(device_namespaces_raw)),
    ])
    return cbor2.dumps(_tag24(device_authentication))


def derive_emac_key(zab: bytes, session_transcript_bytes: bytes) -> bytes:
    """9.1.3.5 — EMacKey, same salt as the session keys but info 'EMacKey'."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=hashlib.sha256(session_transcript_bytes).digest(),
        info=b"EMacKey",
    ).derive(zab)


def verify_device_mac(device_mac, emac_key: bytes, device_auth_bytes: bytes) -> None:
    """deviceMac variant: COSE_Mac0, HMAC-SHA-256 over the MAC_structure."""
    structure = device_mac.value if isinstance(device_mac, cbor2.CBORTag) else device_mac
    protected, _unprotected, payload, tag = structure

    alg = cbor2.loads(protected).get(1) if protected else None
    _require(alg == COSE_ALG_HMAC_256, f"unsupported deviceMac algorithm {alg!r}")
    _require(payload is None, "deviceMac payload must be detached (null)")

    mac_structure = cbor2.dumps(["MAC0", protected, b"", device_auth_bytes])
    expected = hmac.new(emac_key, mac_structure, hashlib.sha256).digest()
    _require(hmac.compare_digest(expected, tag), "deviceMac tag mismatch")


def verify_device_signature(device_signature, device_public_key, device_auth_bytes: bytes) -> None:
    """deviceSignature variant: COSE_Sign1 with a detached payload."""
    structure = (device_signature.value if isinstance(device_signature, cbor2.CBORTag)
                 else device_signature)
    protected, _unprotected, payload, signature = structure

    alg = cbor2.loads(protected).get(1) if protected else None
    _require(alg == COSE_ALG_ES256, f"unsupported deviceSignature algorithm {alg!r}")
    _require(payload is None, "deviceSignature payload must be detached (null)")

    sig_structure = cbor2.dumps(["Signature1", protected, b"", device_auth_bytes])
    try:
        _verify_ecdsa(device_public_key, signature, sig_structure, hashes.SHA256())
    except Exception as exc:
        raise ValidationError(f"deviceSignature invalid: {exc}") from exc


def device_public_key_from_mso(mso: dict) -> ec.EllipticCurvePublicKey:
    """The key the issuer bound to this credential, from MSO deviceKeyInfo."""
    cose = mso["deviceKeyInfo"]["deviceKey"]
    _require(cose.get(-1) == 1, "only P-256 device keys handled")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose[-2], "big"),
        int.from_bytes(cose[-3], "big"),
        ec.SECP256R1(),
    ).public_key()
