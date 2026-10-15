#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — the mdoc's half of a presentation.

The reader in this repo was written against two real wallets. This is the
other side: parse a DeviceRequest, decide what to disclose, and build a
DeviceResponse whose `deviceSignature` binds it to the session transcript.

Two things make it worth having beyond symmetry.

It closes `deviceMac`. The variant is implemented in `mdoc_auth` and verified
against the Annex D.5.3 vector, but no wallet we can reach uses it, so the
reader's MAC path has never run against a live counterparty. A holder we
control can be told to use it.

And it makes over-disclosure demonstrable. The README's sharpest point is that
a verifier cannot distinguish an over-sharing wallet from a well-behaved one,
because the extra elements carry perfectly valid digests — observed when
wwWallet answered a 5-element request with 27. `Disclosure.EVERYTHING` turns
that from an anecdote into a test: the reader prints VERIFIED either way, and
that is the finding, not a bug to fix.

What this is not is a wallet. There is no holder consent, no UI, no key
attestation, and the device private key sits in memory instead of a secure
element. `mdoc_issuer` hands it over in the clear.

Requires: cbor2, cryptography
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from mdoc_auth import COSE_ALG_ES256, build_device_authentication_bytes
from mdoc_issuer import Credential
from mdoc_transcript import tag24

# 8.3.2.1.2.2 Table 8 — DeviceResponse status codes.
STATUS_OK = 0
STATUS_GENERAL_ERROR = 10

# Table 9 — documentErrors. 0 means the mdoc holds no such document.
ERROR_DOCUMENT_NOT_FOUND = 0


class HolderError(Exception):
    pass


class Disclosure(Enum):
    """What the holder is willing to hand over.

    REQUESTED is the only honest setting. The others exist to produce
    responses a conformant reader should notice, and currently cannot.
    """

    REQUESTED = "requested"
    """Exactly the elements the reader asked for, and nothing else."""

    EVERYTHING = "everything"
    """Every element in the credential, regardless of the request. Valid CBOR,
    valid digests, valid signatures — and far more data than was asked for."""

    NOTHING = "nothing"
    """Disclose no elements at all. The response is still well-formed and
    still authenticates; it simply opens nothing."""


@dataclass(frozen=True)
class DocRequest:
    """One docRequest out of a DeviceRequest."""
    doc_type: str
    namespaces: dict[str, dict[str, bool]]
    """namespace -> {elementIdentifier: intentToRetain}"""

    def requested(self, namespace: str) -> set[str]:
        return set(self.namespaces.get(namespace, {}))

    @property
    def element_count(self) -> int:
        return sum(len(v) for v in self.namespaces.values())


def parse_device_request(raw: bytes) -> tuple[str, list[DocRequest]]:
    """8.3.2.1.2.1 — unpack a DeviceRequest into its docRequests.

    `itemsRequest` is `#6.24(bstr .cbor ItemsRequest)`, so it needs the same
    two-step unwrap as everything else tagged 24 in this protocol.

    A `readerAuth` alongside it would carry the verifier's certificate chain
    and a signature over the ItemsRequest. We note its presence and otherwise
    ignore it: verifying it needs a reader trust list, and the reader in this
    repo does not send one.
    """
    message = cbor2.loads(raw)
    if not isinstance(message, dict):
        raise HolderError(f"DeviceRequest is {type(message).__name__}, not a map")

    version = message.get("version", "unknown")
    requests = []
    for doc_request in message.get("docRequests", []):
        items = doc_request.get("itemsRequest")
        if items is None:
            raise HolderError("docRequest has no itemsRequest")
        if isinstance(items, cbor2.CBORTag):
            items = items.value
        decoded = cbor2.loads(items)
        requests.append(DocRequest(
            doc_type=decoded["docType"],
            namespaces={ns: dict(elements)
                        for ns, elements in decoded.get("nameSpaces", {}).items()},
        ))
    return version, requests


def reader_is_authenticated(raw: bytes) -> bool:
    """Whether any docRequest carried a readerAuth.

    A real wallet uses this to decide what to warn the holder about, and may
    refuse elements that require an identified verifier. Ours only reports it.
    """
    message = cbor2.loads(raw)
    return any("readerAuth" in d for d in message.get("docRequests", []))


class MdocHolder:
    """A wallet holding one or more credentials.

    Usage:
        holder = MdocHolder([credential])
        response = holder.respond(device_request, session_transcript)
    """

    def __init__(self, credentials: list[Credential], *,
                 disclosure: Disclosure = Disclosure.REQUESTED,
                 verbose: bool = False):
        self._credentials = {c.doc_type: c for c in credentials}
        self._disclosure = disclosure
        self._verbose = verbose

    # --- disclosure ---------------------------------------------------------

    def _disclose(self, credential: Credential, request: DocRequest) -> dict:
        """Choose which IssuerSignedItems to open, per the disclosure policy.

        Items are returned verbatim. They were encoded by the issuer and the
        MSO committed to those exact bytes, so re-encoding one would break its
        digest — the same trap as the transcript, in a different costume.
        """
        if self._disclosure is Disclosure.NOTHING:
            return {}
        if self._disclosure is Disclosure.EVERYTHING:
            return {ns: list(items) for ns, items in credential.namespaces.items()}

        disclosed = {}
        for namespace, items in credential.namespaces.items():
            wanted = request.requested(namespace)
            kept = [item for item in items
                    if cbor2.loads(item.value)["elementIdentifier"] in wanted]
            if kept:
                disclosed[namespace] = kept
        return disclosed

    # --- device authentication ---------------------------------------------

    def _device_signature(self, credential: Credential, session_transcript: bytes,
                          device_namespaces_raw: bytes) -> list:
        """9.1.3 — COSE_Sign1 over DeviceAuthenticationBytes, payload detached.

        The payload is null on the wire: the reader rebuilds it from the
        transcript it already has, which is precisely what makes a captured
        response useless in another session.
        """
        protected = cbor2.dumps({1: COSE_ALG_ES256})
        device_auth_bytes = build_device_authentication_bytes(
            session_transcript, credential.doc_type, device_namespaces_raw)
        der = credential.device_private_key.sign(
            cbor2.dumps(["Signature1", protected, b"", device_auth_bytes]),
            ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return [protected, {}, None, r.to_bytes(32, "big") + s.to_bytes(32, "big")]

    # --- response -----------------------------------------------------------

    def respond(self, device_request: bytes, session_transcript: bytes) -> bytes:
        """Build a DeviceResponse for one DeviceRequest.

        Every docType the reader asked for and we do not hold becomes a
        documentError rather than silence — 8.3.2.1.2.2 is explicit that the
        mdoc says so, and a reader that cannot tell "no such document" from "no
        answer" has to guess.
        """
        version, requests = parse_device_request(device_request)
        self._log(f"DeviceRequest {version}, {len(requests)} docRequest(s), "
                  f"readerAuth: {reader_is_authenticated(device_request)}")

        documents, errors = [], []
        for request in requests:
            credential = self._credentials.get(request.doc_type)
            if credential is None:
                self._log(f"{request.doc_type}: not held")
                errors.append({request.doc_type: ERROR_DOCUMENT_NOT_FOUND})
                continue

            disclosed = self._disclose(credential, request)
            opened = sum(len(items) for items in disclosed.values())
            self._log(f"{request.doc_type}: asked {request.element_count}, "
                      f"disclosing {opened} ({self._disclosure.value})")

            # DeviceNameSpaces is empty: these are elements the *device*
            # asserts rather than the issuer, and this holder has none. It is
            # still signed over, so it cannot be stripped.
            device_namespaces_raw = cbor2.dumps({})
            documents.append({
                "docType": credential.doc_type,
                "issuerSigned": {
                    "nameSpaces": disclosed,
                    "issuerAuth": credential.issuer_auth,
                },
                "deviceSigned": {
                    "nameSpaces": tag24(device_namespaces_raw),
                    "deviceAuth": {"deviceSignature": self._device_signature(
                        credential, session_transcript, device_namespaces_raw)},
                },
            })

        response = {"version": "1.0", "status": STATUS_OK}
        if documents:
            response["documents"] = documents
        if errors:
            response["documentErrors"] = errors
        encoded = cbor2.dumps(response)
        self._log(f"DeviceResponse {len(encoded)} bytes")
        return encoded

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[holder] {message}")
