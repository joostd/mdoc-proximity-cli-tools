# Implementation status — ISO/IEC 18013-5:2021

Coverage of the standard by the Python tools in this repository.

| | |
| --- | --- |
| Measured | 2026-10-16 |
| Standard | ISO/IEC 18013-5:2021(E), first edition 2021-09, 152 pp |
| Repository | `main` @ `d24a119` |
| Code | 7052 lines across 24 Python files (14 modules, 9 test files, 1 vector file) |
| Tests | 179 checks, all passing |

## Summary

| denominator | coverage |
| --- | --- |
| whole document, 152 pp incl. informative annexes | **~26%** |
| implementable surface — clauses 7–9 + normative Annex B, 73 pp | **~53%** |
| clauses 7–9 only, 45 pp | **~74%** |
| device retrieval only, server retrieval excluded, 39 pp | **~86%** |

The figure to quote is **~53%**: the share of the standard that is code-bearing
and that we have written code for. The others are given because "how much of
the standard" has no single honest answer — clauses 1–6 are 15 pages of scope,
terms and overview with nothing to implement, and 64 pages of annex are
informative.

The last row is the one that reflects intent. Server retrieval was declined
early (`iec.18013-5.2021.txt:161`, the reading notes: *"skipping server
retrieval 9.2.{1,2}"*), and that one decision accounts for most of the
distance between 74% and 86%.

## Method

Weighted by page span, derived from the standard's own table of contents:

```sh
pdftotext -layout iec.18013-5.2021.pdf /tmp/iso18013-5.txt
sed -n '29,90p' /tmp/iso18013-5.txt          # contents, for page spans
grep -nE "^\s*[89]\.[0-9](\.[0-9]+)*\s+[A-Z]" /tmp/iso18013-5.txt   # subclauses
grep -oEh "\b[89]\.[0-9]+(\.[0-9]+){0,4}\b" *.py | sort | uniq -c   # our citations
```

Per-clause percentages are judgement against the subclause list, not a
line-count ratio. Page weighting is a proxy and it flatters us: Annex B's
pages are tabular certificate profiles that are cheap per page, while 9.1.1's
two pages of key derivation were among the most demanding work in the repo.
**Read the table, not the total.**

## By clause

| clause | pp | state | gap |
| --- | --- | --- | --- |
| 1–6 scope, terms, overview | 15 | n/a | nothing to implement |
| 7 mDL data model | 8 | ~85% | 7.2.5 nearest-true-above-request |
| 8.1 encoding | 1 | complete | — |
| 8.2 device engagement | 5 | ~75% | 8.2.1.2 server-retrieval info; negotiated handover |
| 8.3.1 data model | ½ | complete | — |
| 8.3.2 retrieval methods | 7 | ~65% | 8.3.2.2 server retrieval / WebAPI |
| 8.3.3 transmission | 11 | ~50% | NFC data retrieval, Wi-Fi Aware, server transports, L2CAP |
| 9.1 security, device retrieval | 11 | ~90% | 9.1.4 reader authentication |
| 9.2 server retrieval TLS/JWS | 1 | none | all of it |
| 9.3 validation and inspection | 2 | ~60% | 9.3.3 path validation partial; 9.3.2 n/a |
| Annex A L2CAP *(informative)* | 1 | none | — |
| **Annex B certificate profiles** | **28** | **~20%** | seven of nine profiles, CRLs, path examples |
| Annex C VICAL *(informative)* | 22 | none | — |
| Annex D examples *(informative)* | 23 | consumed as test vectors | — |
| Annex E privacy/security *(informative)* | 14 | partially observed | not audited against |
| Annex F IANA *(informative)* | 4 | n/a | — |

## Modules to clauses

| module | lines | implements |
| --- | --- | --- |
| `mdoc_issuer.py` | 366 | 7.2 Table 5, 9.1.2 MSO, Annex B.1.2/B.1.4 (partial) |
| `mdoc_holder.py` | 500 | 8.3.2.1.2.2, Table 8/9 errors, 9.1.3 both variants |
| `mdoc_reader.py` | 513 | 8.3.2.1.2.1, 9.3.1 inspection, BLE mode selection |
| `mdoc_auth.py` | 322 | 9.1.2 issuer data auth, 9.1.2.4 digests, 9.1.3 mdoc auth |
| `mdoc_transcript.py` | 277 | 8.2.1.1, 9.1.5.1, 9.1.1.4, 9.1.1.5 |
| `mdoc_transport.py` | 249 | 8.3.3.1.1.6 framing, chunking, State |
| `mdoc_ble.py` | 259 | 8.3.3.1.1 peripheral server mode, reader side |
| `mdoc_ble_holder.py` | 573 | 8.3.3.1.1 peripheral server mode, holder side |
| `mdoc_ble_peripheral.py` | 369 | 8.3.3.1.1 central client mode |
| `mdoc_nfc.py` | 353 | 8.2.2.1 / 8.2.2.2 static handover engagement |
| `qr_engagement.py` | 278 | 8.2.2.3 QR engagement |
| `mdoc_wallet.py` | 243 | holder application |
| `inspect_response.py` | 89 | tooling |
| `mdoc_fetch.py` | 553 | **not 18013-5** — OpenID4VCI issuance |

`mdoc_fetch.py` is the second-largest module and implements interface 1
(issuing authority to mdoc), which this standard explicitly places out of
scope. A material fraction of the codebase implements something 18013-5
declines to specify.

## Gaps, ranked by normative weight

1. **Annex B certificate profiles — 28 pp, ~20% done.** The largest normative
   gap in the repo by a wide margin. Nine profiles are specified; we generate
   two, both incomplete. `mdoc_issuer.py:125-147` emits `BasicConstraints`,
   `KeyUsage` and `ExtendedKeyUsage` and stops. Missing from those two:
   `subjectKeyIdentifier`, `authorityKeyIdentifier` (both mandatory, both
   present in every real capture we hold), `crlDistributionPoints`,
   `issuerAlternativeName`. Not attempted: B.1.3 IACA link, B.1.5 JWS signer,
   B.1.6–B.1.8 TLS, B.1.9 OCSP signer, B.2 CRL profile, B.3 validation
   examples. The certificate work is sized to make the demo verify, not to
   conform.

2. **8.3.3 transmission technologies — 11 pp, ~50%.** BLE is done in both
   modes, which is the bulk of the clause. Absent: NFC *data retrieval*
   (8.3.3.1.2 — we do NFC engagement only, by design, since the EUDI wallet
   mandates handover to BLE), Wi-Fi Aware (8.3.3.1.3), and L2CAP (Annex A,
   informative).

3. **9.1.4 mdoc reader authentication — 1 pp, detected only.** The holder sees
   whether a `readerAuth` is present and warns (`mdoc_holder.py:171`,
   `:305`); nothing signs one or verifies one. Small in pages, large in
   consequence — it is the mechanism by which a wallet knows who is asking,
   and its absence is why the over-disclosure demonstrations work.

4. **7.2.5 age attestation — selection logic absent.** We issue `age_over_18`
   and `age_over_21` as static elements and match requests by name. The
   normative behaviour is to return the nearest "true" attestation above the
   requested threshold; a request for `age_over_20` against our holder gets a
   Table 8 error rather than `age_over_21`.

5. **9.3.3 certificate path validation — partial.** `validate_response`
   (`mdoc_reader.py:118`) runs issuer data authentication, MSO docType match,
   MSO validity window, value digests and mdoc authentication, and can be
   told to skip the chain with `require_chain=False`. It does not implement
   the full path validation procedure, and there is no CRL or OCSP checking
   anywhere — consistent with the Annex B gap above.

## Out of scope by decision

Not gaps, and not planned. Recorded so the coverage numbers can be read
correctly:

- **Server retrieval in its entirety** — 8.2.1.2, 8.3.2.2, 8.3.3.2, 9.2,
  9.3.2. Roughly 6–7 pp of the implementable surface. The étude is about
  proximity presentation.
- **Negotiated NFC handover** — requires NFC peer-to-peer (LLCP), which a
  PC/SC reader cannot perform (`mdoc_nfc.py:23`).
- **Annex C VICAL** — 22 informative pages of trust-list distribution.

## Tests

179 checks, all passing.

| file | checks | covers |
| --- | --- | --- |
| `test_mdoc_holder.py` | 32 | issuer → holder → reader in process, over-disclosure, Table 8 |
| `test_mdoc_session.py` | 27 | full presentation over loopback: QR, ECDH, AES-GCM, both auth variants |
| `test_mdoc_nfc.py` | 27 | Annex D.5.1 handover, plus a Handover Select read off a real wallet |
| `test_mdoc_auth.py` | 21 | Annex D.5.2 and D.5.3 vectors, plus negatives |
| `test_mdoc_transcript.py` | 17 | a real captured session, byte-for-byte |
| `test_mdoc_reader.py` | 17 | synthetic credential, BLE mode choice, chunk sizing |
| `test_mdoc_fetch.py` | 17 | OpenID4VCI proof and credential parsing |
| `test_mdoc_transport.py` | 16 | loopback framing, chunk prefixes, State ordering |
| `d51_session_encryption_test.py` | 5 | Annex D.5.1 session encryption |

Annex D is informative, but it is the only place the standard gives
byte-exact expected values, so three test files are built on it. Interop
beyond the vectors is covered by live captures against the EUDI wallet and
verifier rather than by conformance tooling — there is no 18013-5 test suite
in this repository, and the percentages above are self-assessed.

## Related

- `README.md` — what the tools are and how to run them
- `key-attestation.md` — what the EUDI reference issuer enforces (OpenID4VCI,
  outside this standard)
- `capture-2026-10-13.md` — a live session captured byte-for-byte
- `notes/nfc.md`, `notes/ble.md`, `notes/ble_mode.md` — transport working notes
