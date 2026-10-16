#!/usr/bin/env python3
"""
Issue a credential, present it, and verify it — all three roles in one process.

Until now the reader was only ever tested against CBOR this repo had written
for the purpose, or against a handset. This runs `mdoc_issuer` ->
`mdoc_holder` -> `mdoc_reader.validate_response` with no radio and no wallet,
which is the first time the reader has faced a counterparty it did not build.

The over-disclosure section is the point of the exercise, not a curiosity.
A wallet returning eleven elements to a one-element request produces a
response that passes every check 18013-5 asks a reader to make. The test
asserts VERIFIED, because that is what conformant software does — and the gap
between "verified" and "did not overshare" is the finding.

Run:  .venv/bin/python test_mdoc_holder.py
"""
import contextlib
import io
import sys
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec

from mdoc_holder import Disclosure, HolderError, MdocHolder, parse_device_request
from mdoc_issuer import MDL_DOC_TYPE, MDL_NAMESPACE, mint, sample_mdl_elements
from mdoc_reader import build_device_request, validate_response
from mdoc_transcript import (
    build_session_transcript,
    encode_ereader_cose_key,
    tag24,
)

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
    """A structurally real QR SessionTranscript. Its contents do not matter to
    these tests, only that both sides splice the identical bytes."""
    engagement = cbor2.dumps({0: "1.0", 1: [1, tag24(b"\x00" * 32)]})
    reader_key = encode_ereader_cose_key(
        ec.generate_private_key(ec.SECP256R1()).public_key())
    return build_session_transcript(engagement, reader_key, None)


def verify(response_bytes, transcript, anchors, *, require_chain=True):
    """Run the real reader over a response, swallowing its report."""
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        ok = validate_response(cbor2.loads(response_bytes), transcript, anchors,
                               require_chain=require_chain)
    return ok, sink.getvalue()


def main() -> int:
    transcript = a_transcript()
    credential, pki = mint(sample_mdl_elements())
    anchors = [pki.iaca_certificate]

    # --- request parsing -----------------------------------------------------

    request = build_device_request([
        (MDL_DOC_TYPE, {MDL_NAMESPACE: {"family_name": True, "birth_date": False}})])
    version, parsed = parse_device_request(request)
    check("a DeviceRequest the reader built parses back", version == "1.0"
          and len(parsed) == 1 and parsed[0].doc_type == MDL_DOC_TYPE,
          f"version {version}, {len(parsed)} docRequest(s)")
    check("intentToRetain survives the round trip",
          parsed[0].namespaces[MDL_NAMESPACE] == {"family_name": True,
                                                  "birth_date": False})
    check("element_count counts across namespaces", parsed[0].element_count == 2)

    raises("a DeviceRequest that is not a map is refused", HolderError,
           parse_device_request, cbor2.dumps([1, 2, 3]))
    raises("a docRequest with no itemsRequest is refused", HolderError,
           parse_device_request, cbor2.dumps({"docRequests": [{}]}))

    # --- an honest holder ----------------------------------------------------

    holder = MdocHolder([credential])
    response = holder.respond(request, transcript)
    decoded = cbor2.loads(response)
    disclosed = decoded["documents"][0]["issuerSigned"]["nameSpaces"][MDL_NAMESPACE]
    names = sorted(cbor2.loads(i.value)["elementIdentifier"] for i in disclosed)
    check("the holder discloses exactly what was asked",
          names == ["birth_date", "family_name"], ", ".join(names))
    check("and reports no errors when it held everything asked for",
          "errors" not in decoded["documents"][0])

    # --- elements the credential does not have -------------------------------

    mixed = build_device_request([(MDL_DOC_TYPE, {MDL_NAMESPACE: {
        "family_name": False, "age_over_18": False, "height": False}})])
    mixed_document = cbor2.loads(holder.respond(mixed, transcript))["documents"][0]
    opened = [cbor2.loads(i.value)["elementIdentifier"]
              for i in mixed_document["issuerSigned"]["nameSpaces"][MDL_NAMESPACE]]
    check("an element the mdoc does not hold becomes a Table 8 error",
          mixed_document.get("errors") == {MDL_NAMESPACE:
                                           {"age_over_18": 0, "height": 0}},
          f"disclosed {opened}, errors {sorted(mixed_document.get('errors', {}).get(MDL_NAMESPACE, {}))}")
    check("the elements it does hold come back alongside",
          opened == ["family_name"])

    ok, report = verify(cbor2.dumps({"version": "1.0", "status": 0,
                                     "documents": [mixed_document]}),
                        transcript, anchors)
    check("and a response carrying errors still verifies", ok,
          "`errors` sits outside issuerSigned, so it changes no digest")

    ok, report = verify(response, transcript, anchors)
    check("the reader verifies a credential this repo issued", ok,
          report.strip().splitlines()[-1] if report.strip() else "")
    check("all five reader checks pass", report.count("[ok]") == 5
          and "[FAIL]" not in report, f"{report.count('[ok]')} ok, "
          f"{report.count('[FAIL]')} failed")

    # --- what the wire looks like to someone else ----------------------------
    #
    # Both of these were invisible to the reader in this repo, which accepts
    # either encoding, and cost an evening in front of a verifier that does
    # not. Checked against `live-response.cbor` and `siros-mdl.cbor`, captured
    # off wallets that real verifiers accept.

    protected, unprotected, payload, _ = credential.issuer_auth
    validity = cbor2.loads(cbor2.loads(payload).value)["validityInfo"]
    check("ValidityInfo tdate has no fractional seconds",
          all(moment.microsecond == 0 for moment in validity.values()),
          f"signed {validity['signed'].isoformat().replace('+00:00', 'Z')}")

    check("a one-certificate x5chain is a bstr, not an array of one",
          isinstance(unprotected[33], bytes),
          "RFC 9360 §2 — an array is for a chain of two or more")

    # --- carrying the anchor, and why it buys nothing ------------------------
    #
    # A verifier that has never heard of our IACA has to find the anchor by
    # issuer DN, and the EUDI reference verifier dereferences that lookup
    # without a null check: it threw `getClass() on a null object reference`
    # and showed an empty result for every response this repo sent it, until
    # the IACA travelled in the chain. The response grew 1542 -> 1927 bytes
    # and the mDL finally rendered.

    anchored, anchored_pki = mint(sample_mdl_elements(), include_anchor=True)
    chain = anchored.issuer_auth[1][33]
    check("include_anchor makes the x5chain an array of two",
          isinstance(chain, list) and len(chain) == 2,
          "DS then IACA, leaf first, as RFC 9360 orders it")

    ok, report = verify(MdocHolder([anchored]).respond(request, transcript),
                        transcript, [anchored_pki.iaca_certificate])
    check("and the reader reads a two-certificate chain", ok)

    _, stranger_pki = mint(sample_mdl_elements())
    ok, report = verify(MdocHolder([anchored]).respond(request, transcript),
                        transcript, [stranger_pki.iaca_certificate])
    check("but an anchor is not trusted for having shipped itself",
          not ok and "does not chain" in report,
          "the chain is checked against the configured anchors, not itself")

    # --- the salt is per-item and random -------------------------------------

    salts = {cbor2.loads(i.value)["random"] for i in credential.namespaces[MDL_NAMESPACE]}
    check("every IssuerSignedItem carries a distinct 32-byte salt",
          len(salts) == 11 and all(len(s) == 32 for s in salts),
          f"{len(salts)} distinct salts over 11 elements")

    other, _ = mint(sample_mdl_elements(), pki=pki)
    reused = salts & {cbor2.loads(i.value)["random"]
                      for i in other.namespaces[MDL_NAMESPACE]}
    check("a second credential reuses none of them", not reused)

    # --- over-disclosure, which the reader cannot catch ----------------------

    greedy = MdocHolder([credential], disclosure=Disclosure.EVERYTHING)
    greedy_response = greedy.respond(request, transcript)
    greedy_count = len(cbor2.loads(greedy_response)
                       ["documents"][0]["issuerSigned"]["nameSpaces"][MDL_NAMESPACE])
    check("an over-sharing holder returns 11 elements for a 2-element request",
          greedy_count == 11, f"{greedy_count} returned")
    check("a holder not answering the question claims no missing elements",
          "errors" not in cbor2.loads(greedy.respond(mixed, transcript))
                               ["documents"][0],
          "'not found' would be a lie about an element it is withholding")

    ok, report = verify(greedy_response, transcript, anchors)
    check("and the reader still reports VERIFIED — selective disclosure is "
          "enforced by the holder alone", ok,
          f"{report.count('[ok]')} checks passed on an over-sharing response")

    # --- disclosing nothing is also well-formed ------------------------------

    silent = MdocHolder([credential], disclosure=Disclosure.NOTHING)
    ok, report = verify(silent.respond(request, transcript), transcript, anchors)
    check("a holder disclosing nothing still authenticates", ok,
          "value digests over 0 elements is vacuously true")

    # --- a docType the holder does not have ----------------------------------

    empty = MdocHolder([])
    decoded = cbor2.loads(empty.respond(request, transcript))
    check("an unheld docType becomes documentError 0, not silence",
          decoded.get("documentErrors") == [{MDL_DOC_TYPE: 0}]
          and "documents" not in decoded,
          "8.3.2.1.2.2 Table 9")

    # --- the signature is bound to this session ------------------------------

    ok, report = verify(response, a_transcript(), anchors)
    check("a response replayed into another session fails mdoc authentication",
          not ok and "mdoc authentication" in report,
          [l.strip() for l in report.splitlines() if "FAIL" in l][0])

    # --- issuer-side failures the reader must catch --------------------------

    past = datetime.now(timezone.utc) - timedelta(days=400)
    stale, stale_pki = mint(sample_mdl_elements(), signed_at=past,
                            valid_until=past + timedelta(days=30))
    ok, report = verify(MdocHolder([stale]).respond(request, transcript),
                        transcript, [stale_pki.iaca_certificate])
    check("an expired MSO is rejected", not ok and "MSO validity" in report,
          [l.strip() for l in report.splitlines() if "FAIL" in l][0])

    _, unrelated_pki = mint(sample_mdl_elements())
    ok, report = verify(response, transcript, [unrelated_pki.iaca_certificate])
    check("a credential under an unknown IACA is rejected",
          not ok and "does not chain" in report,
          "the DS signature is fine; the chain is not")

    ok, _ = verify(response, transcript, [], require_chain=False)
    check("...but --no-trust-anchor still verifies the signature itself", ok,
          "which proves someone signed it, and nothing about who")

    # --- tampering with a disclosed value ------------------------------------

    forged = cbor2.loads(response)
    items = forged["documents"][0]["issuerSigned"]["nameSpaces"][MDL_NAMESPACE]
    inner = cbor2.loads(items[0].value)
    inner["elementValue"] = "Falsified"
    items[0] = tag24(cbor2.dumps(inner))
    ok, report = verify(cbor2.dumps(forged), transcript, anchors)
    check("editing a disclosed element breaks its value digest",
          not ok and "value digests" in report,
          [l.strip() for l in report.splitlines() if "FAIL" in l][0])

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
