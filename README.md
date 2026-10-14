# mdoc — an ISO/IEC 18013-5 reader in Python

An étude on mobile documents: the ISO/IEC 18013-5:2021 proximity presentation
flow, as used by mobile driving licences (mDL) and EUDI wallet credentials.

It ends with a working **mdoc reader** — a Python script on a MacBook that
takes a wallet's engagement, by QR or by NFC tap, negotiates a BLE session, and
cryptographically validates the credential it receives. No Android verifier in
the loop.

Verified end to end against the EUDI reference wallet — over QR on 2026-10-13,
over NFC on 2026-10-14:

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

# live, by tap: engage over NFC on a PC/SC contactless reader (needs pyscard)
.venv/bin/python mdoc_reader.py --nfc --wait 120 \
    --trust-anchor eudi-preprod-iaca.pem -v
```

Built against Python 3.14, cbor2 6.1.5, cryptography 50.0.2, bleak 3.0.2,
pyscard 2.3.1.

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
| `mdoc_nfc.py` | NFC static handover — Type 4 Tag APDUs over PC/SC, NDEF parsing |
| `mdoc_reader.py` | The driver that composes all five |

### Tests — 73 checks, all passing

| File | Checks | Against what |
|---|---|---|
| `d51_session_encryption_test.py` | 5 | Annex D.5.1 — ECDH, HKDF, AES-256-GCM |
| `test_mdoc_transcript.py` | 17 | A real captured session, byte-for-byte |
| `test_mdoc_auth.py` | 18 | Annex D.5.2 and D.5.3 vectors, plus negative cases |
| `test_mdoc_reader.py` | 6 | A synthetic credential minted in-process |
| `test_mdoc_nfc.py` | 27 | The Annex D.5.1 handover, plus a Handover Select read off the wallet |

```sh
for t in d51_session_encryption_test test_mdoc_transcript test_mdoc_auth \
         test_mdoc_reader test_mdoc_nfc
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
| `live-response.cbor` | A captured DeviceResponse with its SessionTranscript (QR) |
| `nfc-response.cbor` | The same, from the NFC run — note the 2-element Handover |

The three symlinks point at the two EUDI repositories and the spec PDF.

## How it works

```
mdoc: URI  ──parse──▶  DeviceEngagement (version, EDeviceKey, BLE options)
   or NFC tap                 │
      ephemeral P-256 ────────┤
                              ▼
                      SessionTranscript = [DeviceEngagementBytes,
                                           EReaderKeyBytes, Handover]
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

### Two ways in: QR and NFC

The QR and the tap are interchangeable front doors onto the same BLE session.
What differs is where the DeviceEngagement comes from, and — the part that is
easy to miss — the third element of the SessionTranscript.

```
QR    SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, null]
NFC   SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes,
                           [HandoverSelectMessage, null]]
```

Get that wrong and you get an AES-GCM tag mismatch and nothing else to go on.

Over NFC the wallet is an NFC Forum Type 4 Tag (AID `D2760000850101`, host-card
emulated) serving a **Handover Select** NDEF message. `mdoc_nfc.py` reads it
with plain APDUs over PC/SC — `SELECT` the NDEF application, read the
capability container, read the file — so any contactless reader works. Proven
against the EUDI wallet with an ACS ACR122U: tap, consent, `VERIFIED`, with a
380-byte SessionTranscript instead of the QR path's 201.

The Handover Select the EUDI wallet serves:

| TNF | Type | Carries |
|---|---|---|
| 1 | `Hs` | Version 0x15 and nested `ac` Alternative Carrier records |
| 4 | `iso.org:18013:deviceengagement` | The DeviceEngagement, 88 bytes |
| 2 | `application/vnd.bluetooth.le.oob` | LE Role and the service UUID |

Its length varies between taps — 276 bytes in the captured fixture, which
repeats the carrier record, and 204 bytes in the verified run. Another reason
the transcript must carry the message verbatim rather than a reconstruction.

The surprise is that the **DeviceEngagement served over NFC has no retrieval
methods** — map key 2 is absent, so `parse_device_engagement` returns
`ble=None`. In static handover the transport is not described in the
engagement at all; it is described by the NDEF carrier records. The reader has
to take the service UUID and the LE role from the Bluetooth LE OOB payload
instead, which is why `run()` grew a `service_uuid_override`.

Only *static* handover is reachable this way. Negotiated handover — where the
reader sends a Handover Request and the mdoc answers — needs NFC peer-to-peer
(LLCP), which a PC/SC reader cannot do and which Android dropped in version 10.
The Annex D.5.1 vector happens to be a negotiated handover, which makes it a
useful second fixture: `test_mdoc_nfc.py` parses its Handover Select and
rebuilds the published `SessionTranscriptBytes` byte for byte.

### Five things that will cost you an afternoon

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

**The service UUID in an NFC carrier is little-endian.** Bluetooth AD type
`0x07` lists 128-bit UUIDs least-significant byte first, so the carrier bytes
`228d5186c6d3ea40f9ca98166b016391` mean the UUID
`9163016b-1698-caf9-40ea-d3c686518d22`. Scan for the unreversed one and you
will find nothing, with no hint as to why. The same payload's LE Role byte
describes the **mdoc's** role, not the reader's: `0x00`, peripheral only, means
mdoc peripheral server mode and so the reader is the GATT client.

**Don't look characteristics up by UUID alone.** Every transaction gets a fresh
*service* UUID but reuses the same three *characteristic* UUIDs, and macOS
caches a peripheral's GATT database. The second time you talk to a wallet there
are several characteristics called `00000001-a123-…`, and bleak raises
`Multiple Characteristics with this UUID` rather than guess. Resolve them
inside the service you actually engaged with — `mdoc_ble._resolve_characteristics`
does, and logs their handles. Had bleak guessed, the symptom would have been a
Start write into a dead service and a silent hang.

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
- **NFC engagement only, static handover only.** ISO 18013-5 also defines NFC
  *data retrieval* (8.3.3.2), running the whole session over APDUs with no
  radio handover at all; the EUDI wallet does not implement it. Negotiated
  handover is out of reach for a PC/SC reader, as above.
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

- ISO/IEC 18013-5:2021, clauses 8.2 (engagement), 8.2.2 (NFC engagement),
  8.3.3.1.1 (BLE), 9.1 (security), Annex D (test vectors)
- NFC Forum, *Type 4 Tag Operation Specification* and *Connection Handover*
- Bluetooth SIG, *Assigned Numbers* §2.3 — AD types `0x07` and `0x1C`
- [eudi-app-android-wallet-ui](https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui)
- [eudi-app-multiplatform-verifier-ui](https://github.com/eu-digital-identity-wallet/eudi-app-multiplatform-verifier-ui)
- ISO/IEC 18013-7 / OID4VP — the online counterpart, which avoids BLE entirely
