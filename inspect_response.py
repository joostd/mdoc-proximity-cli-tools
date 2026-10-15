#!/usr/bin/env python3
"""
Who issued this credential? Reads a `--save` artifact and prints the chain.

mdoc_reader answers "is this credential valid"; this answers "where did it come
from". The two are separate questions and only the second one needs a human:
`issuerAuth`'s x5chain carries the document signer's certificate, and its
issuer DN, country and validity window are the only statement in the whole
response about who stands behind it.

Run:  .venv/bin/python inspect_response.py siros-mdl.cbor
"""
from __future__ import annotations

import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def _name(name: x509.Name) -> str:
    return ", ".join(f"{a.rfc4514_attribute_name}={a.value}" for a in name)


def describe(certificate: x509.Certificate, label: str) -> None:
    print(f"\n{label}")
    print(f"  subject   {_name(certificate.subject)}")
    print(f"  issuer    {_name(certificate.issuer)}")
    print(f"  serial    {certificate.serial_number:x}")
    print(f"  valid     {certificate.not_valid_before_utc.date()} .. "
          f"{certificate.not_valid_after_utc.date()}")
    print(f"  SHA-256   {certificate.fingerprint(hashes.SHA256()).hex()}")
    print(f"  self-signed: {certificate.subject == certificate.issuer}")

    for oid, getter in (("subjectAltName", x509.SubjectAlternativeName),
                        ("crlDistributionPoints", x509.CRLDistributionPoints)):
        try:
            value = certificate.extensions.get_extension_for_class(getter).value
        except x509.ExtensionNotFound:
            continue
        print(f"  {oid}: {value}")


def main(path: str) -> int:
    with open(path, "rb") as handle:
        saved = cbor2.load(handle)

    response = cbor2.loads(saved["deviceResponse"])
    for document in response.get("documents", []):
        print(f"docType: {document['docType']}")
        issuer_auth = document["issuerSigned"]["issuerAuth"]
        if isinstance(issuer_auth, cbor2.CBORTag):  # COSE_Sign1 may be tagged (18)
            issuer_auth = issuer_auth.value

        # COSE_Sign1 = [protected, unprotected, payload, signature]; the chain
        # lives in the unprotected header under label 33 (x5chain).
        chain = issuer_auth[1].get(33, [])
        if isinstance(chain, bytes):
            chain = [chain]
        print(f"x5chain: {len(chain)} certificate(s)")
        for index, der in enumerate(chain):
            describe(x509.load_der_x509_certificate(der),
                     f"[{index}] {'document signer' if index == 0 else 'CA'}")

        # The payload is a bstr holding #6.24(bstr .cbor MobileSecurityObject),
        # so it takes two decodes to reach the MSO itself.
        mso = cbor2.loads(cbor2.loads(issuer_auth[2]).value)
        validity = mso["validityInfo"]
        print(f"\nMSO signed {validity['signed'].isoformat()}, valid "
              f"{validity['validFrom'].isoformat()} .. "
              f"{validity['validUntil'].isoformat()}")
        namespaces = mso["valueDigests"]
        for namespace, digests in namespaces.items():
            print(f"  committed: {len(digests)} element(s) in {namespace}")

        for namespace, items in document["issuerSigned"].get("nameSpaces", {}).items():
            print(f"\ndisclosed from {namespace}:")
            for item in items:
                inner = cbor2.loads(item.value)
                print(f"  {inner['elementIdentifier']} = {inner['elementValue']!r}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
