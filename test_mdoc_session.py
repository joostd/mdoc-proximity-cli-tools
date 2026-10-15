#!/usr/bin/env python3
"""
A whole presentation in one process: QR, session keys, AES-GCM, both roles.

`test_mdoc_holder.py` runs the issuer, holder and reader against each other at
the CBOR layer, with the session transcript handed to both sides. This closes
the loop: the mdoc generates its own engagement, the reader reads it off the
"QR", and each derives the session keys independently. If either side gets the
transcript wrong by a byte they agree on nothing, and the only symptom is a
GCM tag mismatch — the failure the README warns about twice.

Everything runs over `mdoc_transport.loopback_pair()`, concurrently, so the
message ordering is real: the reader blocks on `receive()` while the mdoc is
still deciding what to disclose.

Run:  .venv/bin/python test_mdoc_session.py
"""
import asyncio
import contextlib
import io
import sys

import cbor2
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mdoc_holder import Disclosure, HolderError, HolderSession, MdocHolder
from mdoc_issuer import MDL_DOC_TYPE, MDL_NAMESPACE, mint, sample_mdl_elements
from mdoc_reader import (
    STATUS_TERMINATION,
    build_device_request,
    build_session_establishment,
    validate_response,
)
from mdoc_transcript import (
    build_device_engagement,
    build_session_transcript,
    derive_session_keys,
    encode_ereader_cose_key,
    parse_device_engagement,
    parse_mdoc_uri,
    session_nonce,
    session_transcript_bytes,
)
from mdoc_transport import loopback_pair

_failures = 0


def check(label, ok, detail=""):
    global _failures
    if not ok:
        _failures += 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}")
    if detail:
        print(f"      {detail}")


async def raises(label, exc_type, coro):
    try:
        await coro
    except exc_type as exc:
        # InvalidTag carries no message; there the type name is the diagnostic.
        check(label, True, f"rejected: {str(exc) or type(exc).__name__}")
    except Exception as exc:
        check(label, False, f"raised {type(exc).__name__}: {exc}")
    else:
        check(label, False, "accepted when it should have been rejected")


def verify(response, transcript, anchors):
    """`validate_response`, with its five-line report swallowed."""
    with contextlib.redirect_stdout(io.StringIO()):
        return validate_response(response, transcript, anchors, require_chain=True)


async def drive_reader(transport, uri, requests, *, timeout=5.0):
    """The reader half of `mdoc_reader.run()`, minus the radio and the printing.

    Deliberately re-implemented from the engagement rather than sharing state
    with the mdoc: that is the only way this proves the two sides agree.
    """
    engagement = parse_device_engagement(parse_mdoc_uri(uri))
    ereader_private = ec.generate_private_key(ec.SECP256R1())
    ereader_cose_key = encode_ereader_cose_key(ereader_private.public_key())

    transcript = build_session_transcript(engagement.raw, ereader_cose_key, None)
    keys = derive_session_keys(ereader_private, engagement.edevice_key_public,
                               session_transcript_bytes(transcript))

    ciphertext = AESGCM(keys["SKReader"]).encrypt(
        session_nonce(1, reader=True), build_device_request(requests), None)
    await transport.send(build_session_establishment(ereader_cose_key, ciphertext))

    reply = cbor2.loads(await transport.receive(timeout=timeout))
    plaintext = AESGCM(keys["SKDevice"]).decrypt(
        session_nonce(1, reader=False), reply["data"], None)
    await transport.send(cbor2.dumps({"status": STATUS_TERMINATION}))
    return transcript, keys, cbor2.loads(plaintext)


async def present(holder, requests, *, central_client_mode=False, verbose=False):
    """Run both roles concurrently over a loopback and return what each saw."""
    reader_link, mdoc_link = loopback_pair(verbose=verbose)
    session = HolderSession(holder, central_client_mode=central_client_mode,
                            verbose=verbose)

    async with reader_link, mdoc_link:
        mdoc_task = asyncio.create_task(session.serve(mdoc_link, timeout=5.0))
        transcript, keys, response = await drive_reader(
            reader_link, session.uri, requests)
        await asyncio.wait_for(mdoc_task, timeout=5.0)
    return session, transcript, keys, response


async def main() -> int:
    credential, pki = mint(sample_mdl_elements())
    anchors = [pki.iaca_certificate]
    requests = [(MDL_DOC_TYPE, {MDL_NAMESPACE: {"family_name": True,
                                                "portrait": False}})]

    # --- engagement generation ----------------------------------------------

    probe = HolderSession(MdocHolder([credential]))
    check("the generated URI parses as an mdoc engagement",
          probe.uri.startswith("mdoc:")
          and parse_mdoc_uri(probe.uri) == probe.engagement_raw,
          probe.uri[:48] + "…")

    parsed = parse_device_engagement(probe.engagement_raw)
    check("it round trips through this repo's own parser",
          parsed.version == "1.0" and parsed.cipher_suite == 1
          and parsed.ble is not None,
          f"version {parsed.version}, cipher suite {parsed.cipher_suite}")
    check("peripheral server mode is offered with its UUID in BleOptions 10",
          parsed.ble.peripheral_server_mode
          and not parsed.ble.central_client_mode
          and parsed.ble.peripheral_server_uuid == probe.service_uuid)

    central = HolderSession(MdocHolder([credential]), central_client_mode=True)
    centrally_parsed = parse_device_engagement(central.engagement_raw)
    check("central client mode puts the UUID in BleOptions 11 instead",
          centrally_parsed.ble.central_client_mode
          and centrally_parsed.ble.central_client_uuid == central.service_uuid
          and centrally_parsed.ble.peripheral_server_uuid is None)

    check("each session gets a fresh service UUID and ephemeral key",
          probe.service_uuid != central.service_uuid
          and probe.engagement_raw != central.engagement_raw,
          "reuse would let an observer link two presentations")

    key = encode_ereader_cose_key(ec.generate_private_key(ec.SECP256R1()).public_key())
    for label, kwargs in [
        ("a UUID that is not 16 bytes is refused", {"service_uuid": b"\x00" * 15}),
        ("an engagement offering no BLE mode is refused",
         {"service_uuid": bytes(16), "peripheral_server_mode": False}),
    ]:
        try:
            build_device_engagement(key, **kwargs)
        except ValueError as exc:
            check(label, True, f"rejected: {exc}")
        else:
            check(label, False, "encoded an engagement no reader could use")

    # --- a whole session ----------------------------------------------------

    session, transcript, keys, response = await present(
        MdocHolder([credential]), requests)

    check("both sides derived the same SessionTranscript",
          session.transcript == transcript,
          f"{len(transcript)} bytes, independently built")
    check("both sides derived the same session keys",
          session._keys == keys, f"SKDevice {keys['SKDevice'][:8].hex()}…")

    check("the reader verifies a credential presented over the loopback",
          verify(response, transcript, anchors))

    disclosed = response["documents"][0]["issuerSigned"]["nameSpaces"][MDL_NAMESPACE]
    names = sorted(cbor2.loads(i.value)["elementIdentifier"] for i in disclosed)
    check("and got exactly the two elements it asked for",
          names == ["family_name", "portrait"], ", ".join(names))
    check("the mdoc saw the reader's termination", session.terminated,
          f"status {STATUS_TERMINATION}")

    # --- the same, in the other BLE role ------------------------------------

    _, central_transcript, _, central_response = await present(
        MdocHolder([credential]), requests, central_client_mode=True)
    check("a central-client engagement presents identically",
          verify(central_response, central_transcript, anchors),
          "the mode changes the radio, not the session")

    # --- over-disclosure survives the full stack ----------------------------

    _, greedy_transcript, _, greedy_response = await present(
        MdocHolder([credential], disclosure=Disclosure.EVERYTHING), requests)
    greedy = greedy_response["documents"][0]["issuerSigned"]["nameSpaces"]
    check("an over-sharing mdoc returns 11 elements over a real session",
          len(greedy[MDL_NAMESPACE]) == 11)
    check("and the reader still verifies it",
          verify(greedy_response, greedy_transcript, anchors),
          "end to end, the protocol offers no way to tell")

    # --- the transcript is load-bearing -------------------------------------

    tampered = HolderSession(MdocHolder([credential]))
    reader_link, mdoc_link = loopback_pair()
    async with reader_link, mdoc_link:
        # `drive_reader`'s arguments are evaluated now, so the reader gets the
        # URI as it stands and builds its transcript from that. One byte later
        # the mdoc will build its own from something else.
        task = asyncio.create_task(
            drive_reader(reader_link, tampered.uri, requests, timeout=2.0))
        tampered.engagement_raw += b"\x00"
        await raises("an mdoc whose engagement drifted cannot decrypt the request",
                     InvalidTag, tampered.serve(mdoc_link, timeout=2.0))
        task.cancel()

    # --- protocol errors ------------------------------------------------------

    stray = HolderSession(MdocHolder([credential]))
    await raises("session data before SessionEstablishment is refused",
                 HolderError,
                 asyncio.to_thread(stray.handle, cbor2.dumps({"data": b"x"})))

    bad_key = HolderSession(MdocHolder([credential]))
    await raises("an untagged eReaderKey is refused", HolderError,
                 asyncio.to_thread(bad_key.handle,
                                   cbor2.dumps({"eReaderKey": b"not tagged",
                                                "data": b""})))

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
