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

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mdoc_auth import (
    COSE_ALG_ES256,
    COSE_ALG_HMAC_256,
    build_device_authentication_bytes,
    derive_emac_key,
)
from mdoc_issuer import Credential
from mdoc_transcript import (
    build_device_engagement,
    build_session_transcript,
    derive_session_keys,
    encode_ereader_cose_key,
    mdoc_uri,
    session_nonce,
    session_transcript_bytes,
    tag24,
)

# 8.3.2.1.2.2 Table 8 — DeviceResponse status codes.
STATUS_OK = 0
STATUS_GENERAL_ERROR = 10

# Table 9 — documentErrors. 0 means the mdoc holds no such document.
ERROR_DOCUMENT_NOT_FOUND = 0

# 8.3.2.1.2.2 — the per-element `errors` map inside a Document. 0 means the
# mdoc does not have this element. Distinct from declining to disclose one,
# which the spec gives the holder no way to say at all.
ERROR_ELEMENT_NOT_FOUND = 0


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


class DeviceAuth(Enum):
    """Which of the two mdoc authentication variants in 9.1.3 to produce.

    SIGNATURE is what both wallets this repo has read actually send, and the
    only one a reader can verify without having been the counterparty. MAC is
    the reason this module exists: `mdoc_auth.verify_device_mac` has been
    correct against the Annex D.5.3 vector since the beginning and had never
    once run against something that was not the test vector.
    """

    SIGNATURE = "deviceSignature"
    """ECDSA over DeviceAuthenticationBytes. Anyone holding the transcript and
    the MSO can check it — including, later, someone who was not there."""

    MAC = "deviceMac"
    """HMAC under EMacKey, from ECDH between the credential's device key and
    EReaderKey. Only the reader in that session can verify it, which is a
    feature: the response is not evidence to anyone else."""


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
                 device_auth: DeviceAuth = DeviceAuth.SIGNATURE,
                 verbose: bool = False):
        self._credentials = {c.doc_type: c for c in credentials}
        self._disclosure = disclosure
        self._device_auth = device_auth
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

    def _missing(self, credential: Credential, request: DocRequest) -> dict:
        """Requested elements this credential does not have, as Table 8 errors.

        Only honest under `Disclosure.REQUESTED`. Under the other two policies
        what came back has nothing to do with what was asked for, and claiming
        "not found" for an element we are simply withholding would be a lie —
        a distinction the spec gives the holder no vocabulary for, so the
        right move is to say nothing.
        """
        if self._disclosure is not Disclosure.REQUESTED:
            return {}

        errors = {}
        for namespace, wanted in request.namespaces.items():
            held = {cbor2.loads(item.value)["elementIdentifier"]
                    for item in credential.namespaces.get(namespace, [])}
            absent = {element: ERROR_ELEMENT_NOT_FOUND
                      for element in wanted if element not in held}
            if absent:
                errors[namespace] = absent
        return errors

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

    def _device_mac(self, credential: Credential, session_transcript: bytes,
                    device_namespaces_raw: bytes,
                    ereader_public: ec.EllipticCurvePublicKey) -> list:
        """9.1.3.5 — COSE_Mac0 under EMacKey, payload detached.

        The agreement is between the credential's *static* device key and the
        reader's ephemeral key, not between the two ephemeral keys — so EMacKey
        is not derivable from the session keys, and a reader that threw away
        its ephemeral private key after decryption cannot check this at all.
        """
        zab = credential.device_private_key.exchange(ec.ECDH(), ereader_public)
        emac_key = derive_emac_key(zab, session_transcript_bytes(session_transcript))

        protected = cbor2.dumps({1: COSE_ALG_HMAC_256})
        device_auth_bytes = build_device_authentication_bytes(
            session_transcript, credential.doc_type, device_namespaces_raw)
        tag = hmac.new(emac_key,
                       cbor2.dumps(["MAC0", protected, b"", device_auth_bytes]),
                       hashlib.sha256).digest()
        return [protected, {}, None, tag]

    def _device_auth_entry(self, credential: Credential, session_transcript: bytes,
                           device_namespaces_raw: bytes, ereader_public) -> dict:
        """The one-key `deviceAuth` map, in whichever variant is configured."""
        if self._device_auth is DeviceAuth.SIGNATURE:
            return {"deviceSignature": self._device_signature(
                credential, session_transcript, device_namespaces_raw)}
        if ereader_public is None:
            raise HolderError(
                "deviceMac needs the reader's ephemeral public key; pass "
                "ereader_public to respond(), or let HolderSession do it")
        return {"deviceMac": self._device_mac(
            credential, session_transcript, device_namespaces_raw, ereader_public)}

    # --- response -----------------------------------------------------------

    def respond(self, device_request: bytes, session_transcript: bytes, *,
                ereader_public: ec.EllipticCurvePublicKey | None = None) -> bytes:
        """Build a DeviceResponse for one DeviceRequest.

        Every docType the reader asked for and we do not hold becomes a
        documentError rather than silence — 8.3.2.1.2.2 is explicit that the
        mdoc says so, and a reader that cannot tell "no such document" from "no
        answer" has to guess.

        `ereader_public` is only needed for `DeviceAuth.MAC`, which agrees a
        key with it. `HolderSession` already has it and passes it through.
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
            missing = self._missing(credential, request)
            opened = sum(len(items) for items in disclosed.values())
            absent = sum(len(items) for items in missing.values())
            self._log(f"{request.doc_type}: asked {request.element_count}, "
                      f"disclosing {opened} ({self._disclosure.value})"
                      + (f", {absent} not held" if absent else "")
                      + f", {self._device_auth.value}")
            for namespace, absent_elements in missing.items():
                # Named, not just counted. A Table 8 error is a well-formed
                # answer and our reader takes it in its stride, but it is also
                # the shape that makes verifier UIs fall over — they ask for an
                # element, look it up in the response, and dereference the
                # miss. When that happens you want to know which names to mint,
                # and counting them does not tell you.
                self._log(f"  not held in {namespace}: "
                          + ", ".join(sorted(absent_elements)))

            # DeviceNameSpaces is empty: these are elements the *device*
            # asserts rather than the issuer, and this holder has none. It is
            # still signed over, so it cannot be stripped.
            device_namespaces_raw = cbor2.dumps({})
            document = {
                "docType": credential.doc_type,
                "issuerSigned": {
                    "nameSpaces": disclosed,
                    "issuerAuth": credential.issuer_auth,
                },
                "deviceSigned": {
                    "nameSpaces": tag24(device_namespaces_raw),
                    "deviceAuth": self._device_auth_entry(
                        credential, session_transcript, device_namespaces_raw,
                        ereader_public),
                },
            }
            # `errors` sits outside issuerSigned, and so outside everything the
            # issuer signed and everything mdoc authentication covers. It is
            # the mdoc talking about itself, and a reader must treat it as a
            # hint, not as evidence.
            if missing:
                document["errors"] = missing
            documents.append(document)

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


# --- the session layer ------------------------------------------------------

class HolderSession:
    """One presentation, from generating the QR to answering the request.

    The mdoc's mirror of `mdoc_reader.run()`:

        session = HolderSession(holder)
        print(session.uri)                       # on the QR
        reply = session.handle(establishment)    # SessionData, encrypted
        session.handle(termination)              # -> None

    `engagement_raw` is retained verbatim and spliced into the transcript. An
    mdoc that rebuilt its engagement from a decoded copy would derive
    different session keys from the reader and see only a GCM tag mismatch,
    which is the same trap the reader has on the other side.
    """

    def __init__(self, holder: MdocHolder, *, service_uuid: bytes | None = None,
                 central_client_mode: bool = False, handover=None,
                 verbose: bool = False):
        # Fresh ephemeral key *and* a fresh service UUID per transaction
        # (9.1.1.4, 8.3.3.1.1.3). Reusing either across sessions would let an
        # observer link them.
        self._holder = holder
        self._verbose = verbose
        self._handover = handover
        self._edevice_private = ec.generate_private_key(ec.SECP256R1())
        self.service_uuid = service_uuid or secrets.token_bytes(16)
        self.engagement_raw = build_device_engagement(
            encode_ereader_cose_key(self._edevice_private.public_key()),
            service_uuid=self.service_uuid,
            peripheral_server_mode=not central_client_mode,
            central_client_mode=central_client_mode,
        )
        self.transcript: bytes | None = None
        self._keys: dict[str, bytes] | None = None
        self._ereader_public: ec.EllipticCurvePublicKey | None = None
        self.terminated = False

    @property
    def uri(self) -> str:
        """The `mdoc:` URI a wallet would render as a QR code."""
        return mdoc_uri(self.engagement_raw)

    def handle(self, message: bytes) -> bytes | None:
        """Process one message from the reader and return the reply, if any.

        A SessionEstablishment carries the reader's ephemeral key and the
        encrypted request. A later message carries only `data`, or a `status`
        — 20 is termination, after which there is nothing to answer.
        """
        envelope = cbor2.loads(message)
        if not isinstance(envelope, dict):
            raise HolderError(f"session message is {type(envelope).__name__}, not a map")

        if "eReaderKey" in envelope:
            self._establish(envelope["eReaderKey"])
        if self._keys is None:
            raise HolderError("session data arrived before SessionEstablishment")

        if "data" not in envelope:
            status = envelope.get("status")
            self.terminated = True
            self._log(f"session ended by the reader, status {status}")
            return None

        request = AESGCM(self._keys["SKReader"]).decrypt(
            session_nonce(1, reader=True), envelope["data"], None)
        self._log(f"decrypted a {len(request)} byte DeviceRequest")

        response = self._holder.respond(request, self.transcript,
                                        ereader_public=self._ereader_public)
        ciphertext = AESGCM(self._keys["SKDevice"]).encrypt(
            session_nonce(1, reader=False), response, None)
        return cbor2.dumps({"data": ciphertext})

    def _establish(self, ereader_key_bytes) -> None:
        """9.1.1.4 — bind the reader's ephemeral key into the transcript.

        EReaderKeyBytes goes into the transcript as the exact `#6.24` the
        reader sent, not a re-wrap of the key we decoded out of it.
        """
        if not (isinstance(ereader_key_bytes, cbor2.CBORTag)
                and ereader_key_bytes.tag == 24):
            raise HolderError("eReaderKey is not a #6.24 tagged byte string")
        raw = ereader_key_bytes.value

        cose = cbor2.loads(raw)
        if cose.get(-1) != 1:
            raise HolderError(f"unsupported COSE curve {cose.get(-1)!r}; P-256 only")
        # Kept on the session: EMacKey agrees the credential's device key with
        # this, long after the session keys have been derived from it.
        self._ereader_public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"),
            int.from_bytes(cose[-3], "big"),
            ec.SECP256R1()).public_key()

        self.transcript = build_session_transcript(
            self.engagement_raw, raw, self._handover)
        self._keys = derive_session_keys(
            self._edevice_private, self._ereader_public,
            session_transcript_bytes(self.transcript))
        self._log(f"SessionTranscript {len(self.transcript)} bytes, SKDevice "
                  f"{self._keys['SKDevice'][:8].hex()}…")

    async def serve(self, transport, *, timeout: float = 60.0) -> None:
        """Run the session over an `MdocTransport` until the reader ends it.

        The counterpart to `mdoc_reader.run()`'s `async with link` block. Over
        `mdoc_transport.loopback_pair()` this is a whole presentation with no
        radio; over `mdoc_ble*` it would be a wallet, if one were advertising.
        """
        from mdoc_transport import TransportClosed

        while not self.terminated:
            try:
                message = await transport.receive(timeout=timeout)
            except TransportClosed:
                self._log("transport closed by the reader")
                return
            reply = self.handle(message)
            if reply is not None:
                await transport.send(reply)

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[session] {message}")
