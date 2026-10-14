# mdoc — an ISO/IEC 18013-5 reader in Python

An étude on mobile documents: the ISO/IEC 18013-5:2021 proximity presentation
flow, as used by mobile driving licences (mDL) and EUDI wallet credentials.

It ends with a working **mdoc reader** — a Python script on a MacBook that
scans a wallet's engagement QR, negotiates a BLE session, and
cryptographically validates the credential it receives. No Android verifier in
the loop.

Verified end to end on 2026-10-13 against the EUDI reference wallet:

```
Document: eu.europa.ec.eudi.employee.1
  [ok] issuer data authentication — signature valid
  [ok] MSO docType matches the document
  [ok] MSO validity window — until 2027-01-11T15:21:58+00:00
  [ok] value digests — 1 element(s) match the MSO
  [ok] mdoc authentication (deviceSignature) — bound to this session transcript
      eu.europa.ec.eudi.employee.1/employee_id = '1234678'

VERIFIED
```

## Quick start

```sh
python3 -m venv .venv && .venv/bin/pip install cbor2 cryptography bleak zxing-cpp pillow

# offline: everything except the radio
.venv/bin/python test_mdoc_auth.py

# live: scan a wallet's QR off its screen over adb and verify what comes back
.venv/bin/python mdoc_reader.py --from-adb <serial> --wait 120 \
    --trust-anchor eudi-preprod-iaca.pem -v
```

Built against Python 3.14, cbor2 6.1.5, cryptography 50.0.2, bleak 3.0.2.

If you have the URI already, pass it directly; `--dry-run` builds the whole
request and stops before touching the radio:

```sh
.venv/bin/python mdoc_reader.py --dry-run 'mdoc:owBjMS4w…'
```

The engagement QR is single-use and the wallet stops advertising the moment its
screen closes, so `--wait` is usually the practical option: start the reader
first, bring up the wallet screen second.

## What's here

### The reader

| File | Role |
|---|---|
| `mdoc_transcript.py` | Engagement parsing, SessionTranscript, session key derivation |
| `mdoc_ble.py` | GATT-client transport — scan, subscribe, `State=Start`, MTU−3 chunking |
| `mdoc_auth.py` | Issuer data authentication, value digests, mdoc authentication |
| `qr_engagement.py` | Lifts the `mdoc:` URI from a screenshot or a live `adb screencap` |
| `mdoc_reader.py` | The driver that composes all four |

### Tests — 46 checks, all passing

| File | Checks | Against what |
|---|---|---|
| `d51_session_encryption_test.py` | 5 | Annex D.5.1 — ECDH, HKDF, AES-256-GCM |
| `test_mdoc_transcript.py` | 17 | A real captured session, byte-for-byte |
| `test_mdoc_auth.py` | 18 | Annex D.5.2 and D.5.3 vectors, plus negative cases |
| `test_mdoc_reader.py` | 6 | A synthetic credential minted in-process |

```sh
for t in d51_session_encryption_test test_mdoc_transcript test_mdoc_auth test_mdoc_reader
do .venv/bin/python $t.py; done
```

### Notes and artifacts

| File | Contents |
|---|---|
| `example.md` | The original étude notes — a decoded DeviceEngagement from a YouTube demo. **Contains two misreadings**; see *Corrections* below. |
| `ble-reader-reference.md` | Characteristic tables, framing and key derivation, read out of the spec PDF rather than recalled |
| `capture-2026-10-13.md` | A live session pulled from the Android verifier's logcat: URI, transcript, request, response |
| `_vectors_annex_d.py` | Annex D fixtures, machine-extracted from the PDF text layer |
| `wallet.md`, `verifier.md` | How the two EUDI Android apps were built, including the JDK toolchain hurdle |
| `eudi-preprod-iaca.pem` | EUDI preprod IACA root, for `--trust-anchor` |
| `live-response.cbor` | A captured DeviceResponse with its SessionTranscript |

The three symlinks point at the two EUDI repositories and the spec PDF.

## How it works

```
mdoc: URI  ──parse──▶  DeviceEngagement (version, EDeviceKey, BLE options)
                              │
      ephemeral P-256 ────────┤
                              ▼
                      SessionTranscript = [DeviceEngagementBytes,
                                           EReaderKeyBytes, null]
                              │
            ECDH ──▶ HKDF ──▶ SKReader / SKDevice
                              │
    DeviceRequest ──AES-GCM──▶ SessionEstablishment ──BLE──▶ wallet
                                                               │
    DeviceResponse ◀──AES-GCM── SessionData ◀──BLE─────────────┘
                              │
                              ▼
            issuerAuth ✓   valueDigests ✓   deviceSignature ✓
```

Three checks make a verified credential:

1. **Issuer data authentication** — `issuerAuth` is a COSE_Sign1 over the Mobile
   Security Object. Verify it with the DS certificate from the x5chain, then
   chain that certificate to a trusted IACA. Without the second half, a valid
   signature proves only that *someone* signed it.
2. **Value digests** — every disclosed `IssuerSignedItem` must hash to the
   digest the MSO committed to. Undisclosed attributes stay committed but
   unopened: in the live run the MSO committed to 8 attributes and the wallet
   opened 1, and the per-element `random` salt is what stops the verifier
   brute-forcing the other 7.
3. **mdoc authentication** — `deviceSignature` (or `deviceMac`) proves the
   holder controls the key the MSO names, signed over *this* session's
   transcript. This is what makes a captured response useless in a replay.

### Three things that will cost you an afternoon

**The transcript must carry the QR bytes verbatim.** `DeviceEngagementBytes` is
the exact byte string that came off the QR. Decoding it to a dict and
re-encoding can change the bytes — map key order, integer widths — and every
session key is bound to the exact encoding. The failure mode is an AES-GCM tag
mismatch with no other diagnostic. The same applies to the SessionTranscript
inside `DeviceAuthenticationBytes`, which is why `build_device_authentication_bytes`
splices raw bytes rather than re-encoding. Our round trips happened to be
byte-identical, which is exactly the trap: the tests pass and you learn nothing.

**The HKDF salt is hashed twice.** It is `SHA-256(SessionTranscriptBytes)`, and
`SessionTranscriptBytes` is itself `#6.24(bstr .cbor SessionTranscript)`. Two
wrapping steps that are easy to collapse into one. Same silent GCM failure.

**`Ident` is not where you'd guess.** Table 11 (mdoc as GATT server — the
common case) has no `Ident` characteristic at all. It exists only in Table 12,
where the *reader* is the GATT server, and it is served by the reader and read
by the mdoc, not the other way round.

## Limitations

- **mdoc peripheral server mode only.** The reader is a BLE central / GATT
  client. The other mode would make it a BLE peripheral, which CoreBluetooth
  does not offer a Python process. A conformant mDL reader must support both;
  this one talks only to wallets whose engagement sets BleOptions key `0`.
- **No reader authentication.** The `DeviceRequest` carries no `readerAuth`, so
  the wallet cannot tell who is asking and will say so. Fixing this needs a
  reader certificate the wallet's trust list recognises.
- **`deviceMac` is implemented but not wired into the driver.** It is verified
  against the Annex D.5.3 vectors in `test_mdoc_auth.py`; `mdoc_reader.py` only
  takes the `deviceSignature` path, which is what the EUDI wallet uses.
- **No revocation checking**, and no validation of the mDL-specific certificate
  profile in Annex B.
- `--trust-anchor` is optional. Omitting it prints a warning and skips only the
  chain check; the result then says nothing about *who* issued the credential.

Two gaps in the spec's own test data are worth knowing about. The D.4.1.2
DeviceResponse is a JPEG-2000 raster scan in the PDF with no text layer, so it
cannot be extracted — only one `IssuerSignedItem` survived in the surrounding
text. And the D.5.1 SessionTranscript is an *NFC handover* example, so it
validates the key derivation but not QR transcript construction; that is what
`test_mdoc_transcript.py` uses a real capture for.

## Corrections to `example.md`

Two readings in the original notes are wrong, and both matter:

- `[2, 1, {…}]` is `[type, version, options]`. The `1` is the **version of the
  retrieval method**, not the BLE mode. The mode lives in the options map.
- BleOptions `0` and `1` are **mode support flags** — `0: true` means the mdoc
  supports peripheral server mode, `1: false` means it does not support central
  client mode. They are not "random peripheral address flags" or "legacy setup
  steps".

So `{0: true, 1: false, 10: h'…'}` reads: *the mdoc will be the GATT server, the
reader must be the GATT client, and here is the service UUID to scan for*. That
UUID is freshly generated per transaction — it changed on every run.

## References

- ISO/IEC 18013-5:2021, clauses 8.2 (engagement), 8.3.3.1.1 (BLE), 9.1
  (security), Annex D (test vectors)
- [eudi-app-android-wallet-ui](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui)
- [eudi-app-multiplatform-verifier-ui](https://github.com/eu-digital-identity-wallet/eudi-app-multiplatform-verifier-ui)
- ISO/IEC 18013-7 / OID4VP — the online counterpart, which avoids BLE entirely
