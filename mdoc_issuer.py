#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — the issuing authority's half: minting a credential.

`test_mdoc_reader.py` has had a `mint_credential()` since the beginning, good
enough to exercise the reader. This is that function grown up: real salts, a
two-level PKI, an Annex B certificate profile, and the mandatory mDL data
elements from Table 5. It exists so there is something for `mdoc_holder` to
present that was not built by the code validating it.

Nothing here is a real issuer. There is no key management, no revocation, no
device-key attestation, and the device private key is handed back in the clear
rather than living in a secure element — which on a handset is the entire
point of `deviceKeyInfo`. Treat it as a test fixture with its edges filed off.

The one thing it does take seriously is `random`. 9.1.2.5 requires at least 16
bytes per IssuerSignedItem, and it is the only reason selective disclosure
works: the digests of undisclosed elements are published in the MSO, so
without a salt a verifier could brute-force `sex` or `age_over_18` from the
digest alone. `test_mdoc_reader.mint_credential` uses `bytes(32)` — a constant
— which is correct for a test of the reader and would be a critical flaw here.

Requires: cbor2, cryptography
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mdoc_auth import COSE_ALG_ES256, COSE_HEADER_X5CHAIN
from mdoc_transcript import tag24

MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
MDL_NAMESPACE = "org.iso.18013.5.1"

# Annex B.1.1.3 — the extended key usage that marks a document signer.
EKU_MDL_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")

SALT_BYTES = 32  # 9.1.2.5 requires >= 16

# 7.2.1 Table 5, all 33 rows, mandatory first. Worth having as data because a
# verifier asking for a "full mDL" asks for exactly this, and the last two are
# the reason that request can never be fully satisfied: they are templates,
# not identifiers. An issuer writes `age_over_18` and `biometric_template_face`.
TABLE_5 = (
    "family_name", "given_name", "birth_date", "issue_date", "expiry_date",
    "issuing_country", "issuing_authority", "document_number", "portrait",
    "driving_privileges", "un_distinguishing_sign",
    "administrative_number", "sex", "height", "weight", "eye_colour",
    "hair_colour", "birth_place", "resident_address", "portrait_capture_date",
    "age_in_years", "age_birth_year", "issuing_jurisdiction", "nationality",
    "resident_city", "resident_state", "resident_postal_code",
    "resident_country", "family_name_national_character",
    "given_name_national_character", "signature_usual_mark",
    "age_over_NN", "biometric_template_xx",
)


@dataclass
class Pki:
    """A throwaway two-level PKI: one IACA, one document signer under it."""
    iaca_certificate: x509.Certificate
    iaca_key: ec.EllipticCurvePrivateKey
    ds_certificate: x509.Certificate
    ds_key: ec.EllipticCurvePrivateKey


@dataclass
class Credential:
    """What an issuer hands a wallet: signed attributes plus the key bound to them.

    `namespaces` holds *every* IssuerSignedItemBytes, disclosed or not — the
    wallet keeps them all and chooses per request. That choice is the holder's
    alone, which is what `mdoc_holder` is for.
    """
    doc_type: str
    issuer_auth: list           # COSE_Sign1 as a 4-element array, per the CDDL
    namespaces: dict[str, list[cbor2.CBORTag]] = field(default_factory=dict)
    device_private_key: ec.EllipticCurvePrivateKey | None = None

    def element_names(self) -> dict[str, list[str]]:
        """namespace -> identifiers, for logging and for over-disclosure tests."""
        return {
            namespace: [cbor2.loads(item.value)["elementIdentifier"] for item in items]
            for namespace, items in self.namespaces.items()
        }


def _name(common_name: str, country: str = "UT") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ])


def generate_pki(*, country: str = "UT", now: datetime | None = None) -> Pki:
    """An IACA and a document signer beneath it.

    Annex B wants ECDSA on P-256/384/521 for both, CA:TRUE plus keyCertSign on
    the IACA, and CA:FALSE plus the mdlDS extended key usage on the signer.
    `mdoc_auth` checks none of that — only the signature and the DN chain — but
    minting certificates that would fail a profile check makes the fixture
    useless for ever testing one.
    """
    instant = now or datetime.now(timezone.utc)
    iaca_key = ec.generate_private_key(ec.SECP256R1())
    ds_key = ec.generate_private_key(ec.SECP256R1())
    iaca_name = _name("Utopia Test IACA", country)

    iaca = (x509.CertificateBuilder()
            .subject_name(iaca_name).issuer_name(iaca_name)
            .public_key(iaca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(instant - timedelta(days=1))
            .not_valid_after(instant + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(iaca_key, hashes.SHA256()))

    ds = (x509.CertificateBuilder()
          .subject_name(_name("Utopia Test Document Signer", country))
          .issuer_name(iaca_name)
          .public_key(ds_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(instant - timedelta(days=1))
          .not_valid_after(instant + timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                         critical=True)
          .add_extension(x509.KeyUsage(
              digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False,
              key_agreement=False, key_cert_sign=False, crl_sign=False,
              encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.ExtendedKeyUsage([EKU_MDL_DS]), critical=False)
          .sign(iaca_key, hashes.SHA256()))

    return Pki(iaca_certificate=iaca, iaca_key=iaca_key,
               ds_certificate=ds, ds_key=ds_key)


def _cose_key(public_key: ec.EllipticCurvePublicKey) -> dict:
    """COSE_Key for a P-256 public key, as `device_public_key_from_mso` reads it."""
    numbers = public_key.public_numbers()
    return {
        1: 2,                                    # kty: EC2
        -1: 1,                                   # crv: P-256
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def _whole_seconds(moment: datetime) -> datetime:
    """A tdate has no fractional part. See `mint`."""
    return moment.replace(microsecond=0)


def _cose_sign1(private_key, payload: bytes, certificates: list[x509.Certificate]):
    """COSE_Sign1 with the x5chain in the *unprotected* header, label 33.

    RFC 9360 §2: one certificate goes in as a bare bstr, and only a chain of
    two or more becomes an array. An array of one is a different encoding of
    the same chain, and a reader is entitled to reject it — ours accepts both,
    which is exactly why this was invisible here for so long. The two EUDI
    captures in this repo send a bstr; the Siros one sends an array of two.
    """
    protected = cbor2.dumps({1: COSE_ALG_ES256})
    signature = private_key.sign(
        cbor2.dumps(["Signature1", protected, b"", payload]),
        ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    ders = [c.public_bytes(serialization.Encoding.DER) for c in certificates]
    return [
        protected,
        {COSE_HEADER_X5CHAIN: ders[0] if len(ders) == 1 else ders},
        payload,
        r.to_bytes(32, "big") + s.to_bytes(32, "big"),
    ]


def mint(
    elements: dict[str, dict],
    *,
    doc_type: str = MDL_DOC_TYPE,
    pki: Pki | None = None,
    device_private_key: ec.EllipticCurvePrivateKey | None = None,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    signed_at: datetime | None = None,
    include_anchor: bool = False,
) -> tuple[Credential, Pki]:
    """Issue a credential over `elements`, a mapping of namespace -> {id: value}.

    Returns the credential and the PKI that signed it; the caller needs the
    IACA certificate as a trust anchor, which is the one piece of this a real
    deployment distributes out of band.

    `valid_from` / `valid_until` are exposed so a test can mint an expired
    credential without waiting a year for one.

    `include_anchor` puts the IACA into the x5chain as well. 9.1.2.4 does not
    ask for it — the anchor is supposed to arrive out of band, and a chain that
    carries its own root proves nothing a verifier should believe. It is here
    because a verifier that has never heard of `Utopia Test IACA` has to look
    the anchor up by issuer name, and at least one of them dereferences the
    result without checking it for null. Shipping the root turns a crash into
    an honest "untrusted", which is a far more useful thing to be told. The
    Siros capture in this repo does the same.
    """
    pki = pki or generate_pki()
    device_private_key = device_private_key or ec.generate_private_key(ec.SECP256R1())
    # ValidityInfo is three tdate, and a tdate carries no fractional seconds:
    # `2026-10-13T15:24:13Z`, not `…:13.976663Z`. `datetime.now` hands you
    # microseconds, cbor2 faithfully writes them out, and a strict verifier
    # then fails to parse the MSO it is standing in front of. All three real
    # wallets captured in this repo send whole seconds.
    signed = _whole_seconds(signed_at or datetime.now(timezone.utc))
    valid_from = _whole_seconds(valid_from) if valid_from else signed
    valid_until = (_whole_seconds(valid_until) if valid_until
                   else signed + timedelta(days=365))

    namespaces: dict[str, list[cbor2.CBORTag]] = {}
    digests: dict[str, dict[int, bytes]] = {}
    digest_id = 0

    for namespace, values in elements.items():
        namespaces[namespace] = []
        digests[namespace] = {}
        for identifier, value in values.items():
            # digestID is unique across the whole MSO, not merely per namespace:
            # the stricter reading costs nothing and satisfies either one.
            digest_id += 1
            item = tag24(cbor2.dumps({
                "digestID": digest_id,
                "random": secrets.token_bytes(SALT_BYTES),
                "elementIdentifier": identifier,
                "elementValue": value,
            }))
            namespaces[namespace].append(item)
            # The digest is over the tagged, encoded IssuerSignedItemBytes —
            # not over the inner map. Same cardinal rule as the transcript.
            digests[namespace][digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()

    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": digests,
        "deviceKeyInfo": {"deviceKey": _cose_key(device_private_key.public_key())},
        "docType": doc_type,
        "validityInfo": {"signed": signed, "validFrom": valid_from,
                         "validUntil": valid_until},
    }

    issuer_auth = _cose_sign1(
        pki.ds_key,
        cbor2.dumps(tag24(cbor2.dumps(mso))),
        [pki.ds_certificate] + ([pki.iaca_certificate] if include_anchor else []),
    )
    return Credential(doc_type=doc_type, issuer_auth=issuer_auth,
                      namespaces=namespaces,
                      device_private_key=device_private_key), pki


# 60x80 greyscale silhouette, 532 bytes. `portrait` is mandatory in Table 5,
# and `b"\xff\xd8\xff\xd9"` satisfies the schema while decoding to nothing —
# fine between our own two halves, useless in front of a verifier UI that
# tries to draw it. Pass this to `sample_mdl_elements` when something else is
# going to read the credential; `mdoc_wallet` does.
PLACEHOLDER_PORTRAIT = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABQODxIPDRQSEBIXFRQYHjIhHhwcHj0sLiQy"
    "SUBMS0dARkVQWnNiUFVtVkVGZIhlbXd7gYKBTmCNl4x9lnN+gXz/2wBDARUXFx4aHjsh"
    "ITt8U0ZTfHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8"
    "fHx8fHz/wAARCABQADwDASIAAhEBAxEB/8QAGgABAAMBAQEAAAAAAAAAAAAAAAIEBQMB"
    "Bv/EACQQAAMAAgIBBAIDAAAAAAAAAAABAgMRBCFhEjFBUSIyM3LR/8QAFgEBAQEAAAAA"
    "AAAAAAAAAAAAAAEC/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A+iAB"
    "pAA51yMUPVWt+OwOgIxkjItxSZIAAAAAAr8vK8cJT06+SgXubjdQqXfp9yiBLHkrHSqX"
    "2ak0qlUvZrZlTLulMrbZqxPpiZ3vS0B6AAAAbSW30gBwriYqe+58I45+W6/HFtL5f2Vm"
    "3T3Tbf2wNLFhjF+q7+2dDKjJeP8ASmvBewcmcv4vq/r7A7gAAVeblcpY52m+2/BaMvNX"
    "qzW9779wIAAIHs04pVL00eADUxWsmNWlrfwTKnArq535SLYUMg1zKyz6MtTrST6AiAAg"
    "AALPB/mf9f8AC8U+BPd1rwmXAr//2Q==")


def sample_mdl_elements(*, portrait: bytes = b"\xff\xd8\xff\xd9",
                        complete: bool = False) -> dict:
    """The mandatory mDL data elements from 7.2.1 Table 5.

    Dates are CBOR tag 1004 (full-date, RFC 8943) rather than tag 0 — an mDL
    birth date is a calendar day, not an instant, and encoding it as a
    date-time would imply a timezone the credential does not have. The default
    `portrait` is an empty JPEG, since a real one is 10-20 kB and would make
    every fixture in this repo tedious to read; `PLACEHOLDER_PORTRAIT` above
    is a real one for when a real verifier is looking.

    `complete` adds the 22 optional elements as well, for the 33 of Table 5 in
    full. The point is not realism — it is that a verifier asking for a full
    mDL and getting Table 8 errors for two thirds of it is a case real wallets
    never put their UIs through. The EUDI reference verifier answers that with
    `getClass() on a null object reference` and shows nothing, the same way it
    does for an unknown trust anchor; holding all of Table 5 makes it render.

    Which of the 22 it actually trips over is not known. It is not simply "any
    absent element": the working run is still missing one, because the request
    asks for `biometric_template_xx` *literally*. That and `age_over_NN` are
    templates in the table rather than identifiers — xx is a biometric
    modality, NN a real age — so they are instantiated here as
    `biometric_template_face` and `age_over_18`, which is what an issuer would
    do, and nothing can ever satisfy a request for the template itself.
    """
    if complete:
        return {MDL_NAMESPACE: {
            **sample_mdl_elements(portrait=portrait)[MDL_NAMESPACE],
            "administrative_number": "UT-ADM-0099",
            "sex": 2,                       # ISO/IEC 5218: 0 unknown, 1 M, 2 F
            "height": 170,                  # cm
            "weight": 64,                   # kg
            "eye_colour": "blue",           # Table 5 enumerates the values
            "hair_colour": "blond",
            "birth_place": "Utopia City",
            "resident_address": "Hauptstrasse 1",
            "portrait_capture_date": datetime(2024, 1, 15, 10, 30,
                                              tzinfo=timezone.utc),
            "age_in_years": 55,
            "age_birth_year": 1971,
            "age_over_18": True,
            "age_over_21": True,
            "issuing_jurisdiction": "UT-CT",   # ISO 3166-2
            "nationality": "UT",               # ISO 3166-1 alpha-2
            "resident_city": "Utopia City",
            "resident_state": "Central",
            "resident_postal_code": "10115",
            "resident_country": "UT",
            "biometric_template_face": b"\x00" * 32,
            "family_name_national_character": "Mustermann",
            "given_name_national_character": "Erika",
            "signature_usual_mark": PLACEHOLDER_PORTRAIT,
        }}

    return {MDL_NAMESPACE: {
        "family_name": "Mustermann",
        "given_name": "Erika",
        "birth_date": cbor2.CBORTag(1004, "1971-09-01"),
        "issue_date": cbor2.CBORTag(1004, "2024-02-01"),
        "expiry_date": cbor2.CBORTag(1004, "2029-02-01"),
        "issuing_country": "UT",
        "issuing_authority": "Utopia Department of Transport",
        "document_number": "UT-1234567",
        "portrait": portrait,
        "driving_privileges": [{
            "vehicle_category_code": "B",
            "issue_date": cbor2.CBORTag(1004, "2024-02-01"),
            "expiry_date": cbor2.CBORTag(1004, "2029-02-01"),
        }],
        "un_distinguishing_sign": "UTO",
    }}
