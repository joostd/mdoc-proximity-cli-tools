# mdoc — an ISO/IEC 18013-5 reader in Python

An étude on mobile documents: the ISO/IEC 18013-5:2021 proximity presentation
flow, as used by mobile driving licences (mDL) and EUDI wallet credentials.

It ends with a working **mdoc reader** — a Python script on a MacBook that
takes a wallet's engagement, by QR or by NFC tap, negotiates a BLE session, and
cryptographically validates the credential it receives. No Android verifier in
the loop.

Verified end to end against two unrelated wallets: the EUDI reference wallet
over QR on 2026-10-13 and over NFC on 2026-10-14, and wwWallet (`org.siros.id`)
on 2026-10-14 in the opposite BLE role, where the reader is the GATT server.

It also ends with a **wallet**. `mdoc_wallet.py` mints a credential, advertises
as an mdoc over BlueZ and presents it — so on 2026-10-15 both halves of
18013-5, both written here, met over a real radio between two machines.

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
python3 -m venv .venv && .venv/bin/pip install cbor2 cryptography bleak zxing-cpp \
    pillow pyqrcode pyscard pyobjc-framework-CoreBluetooth

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
pyscard 2.3.1. The wallet side was run on a Raspberry Pi 5 — Python 3.13.5,
BlueZ 5.82, the distribution's dbus-python and pygobject.

If you have the URI already, pass it directly; `--dry-run` builds the whole
request and stops before touching the radio:

```sh
.venv/bin/python mdoc_reader.py --dry-run 'mdoc:owBjMS4w…'
```

The engagement QR is single-use and the wallet stops advertising the moment its
screen closes, so `--wait` is usually the practical option: start the reader
first, bring up the wallet screen second.

No wallet to hand? Run ours. It needs a second machine with BlueZ — a Raspberry
Pi does, a Mac does not — because a Mac cannot see its own advertisement:

```sh
# on the Pi: cbor2 and cryptography, plus the system dbus-python and pygobject
pi$  python3 -m venv --system-site-packages .venv
pi$  .venv/bin/pip install cbor2 cryptography pyqrcode
pi$  .venv/bin/python mdoc_wallet.py --save-anchor iaca.pem --reuse-pki pki.pem -v
     mdoc:owBjMS4wAYIB2BhYS6QBAiABIVgg…
     (and the same engagement as a QR, for a verifier app's camera — give
      the window 106 columns, or it falls back to a half-height one)

# on the Mac: the IACA has to travel out of band, exactly as a trust list would
mac$ scp pi:iaca.pem .
mac$ .venv/bin/python mdoc_reader.py 'mdoc:owBjMS4w…' --trust-anchor iaca.pem \
         --doc-type org.iso.18013.5.1.mDL --element family_name -v
```

`--device-mac` makes it answer with `deviceMac` instead of `deviceSignature`,
and `--disclosure everything` makes it the over-sharing wallet below.

Pointing someone else's verifier at it — the EUDI reference verifier on an
Android handset is the one this was tried against — wants `--full-chain`:

```sh
pi$  .venv/bin/python mdoc_wallet.py --reuse-pki pki.pem --full-chain
```

Without it the verifier connected, ran the whole session correctly, took the
response, and displayed nothing but
`Error [Attempt to invoke virtual method 'java.lang.Class
java.lang.Object.getClass()' on a null object reference]`. Nothing was wrong
with the response. `Utopia Test IACA` is in no trust list on earth, the
verifier looked the anchor up by issuer DN, got null, and dereferenced it.
Shipping the IACA in the x5chain gives the lookup something to find. It does
not make the credential *trusted* — ours still checks the chain against the
anchors it was given, which `test_mdoc_holder.py` asserts — but a verifier
that can build a path can at least tell you it does not trust you, which is a
diagnosis rather than a stack trace.

That is the only thing that verifier needs. `--full-mdl` holds all 33
elements of Table 5 rather than the 11 mandatory ones, which makes a fuller
demo, but it fixes nothing: asking for a full mDL while holding only the
mandatory core returns 22 Table 8 errors and renders the other 11 perfectly
well.

It is worth saying because this repo briefly claimed otherwise. The same
crash appeared on a full-mDL request, `--full-mdl` was added, the crash went
away, and the obvious inference was wrong — that run had simply been started
without `--full-chain`. Reading the verifier's source settled it, and a
control run with `--full-chain` alone confirmed it on the handset. Two
observations, one cause; the second variable was never tested on its own.

Reading the source turned up the better finding anyway. The verifier app is a
thin layer over multipaz's `DeviceResponseParser`, and that parser has no
`errors` or `documentErrors` in it at all — the string constants are
`issuerSigned`, `deviceSigned`, `digestID`, `elementValue` and so on, and
nothing else. Table 8 and Table 9 are parsed by nobody. A verifier built on
it cannot distinguish "the mdoc does not hold this" from "the holder declined
to give it to you", because the error codes that carry that distinction are
dropped before the app ever sees them. All it observes is a shorter list of
claims. That is a far more interesting gap than a null check, and it is
invisible from the wire: our response is correct, and the information in it
is simply discarded.

The holder names the elements it does not hold under `-v`, which turned up
one more thing — a full-mDL request asks for `biometric_template_xx`
*literally*:

```
[holder] org.iso.18013.5.1.mDL: asked 33, disclosing 32 (requested), 1 not held
[holder]   not held in org.iso.18013.5.1: biometric_template_xx
```

That row of Table 5, and `age_over_NN`, are templates rather than
identifiers: xx is a biometric modality, NN a real age. No credential can
satisfy a request for them as written, so that request is unsatisfiable by
construction — and because Table 8 goes unread, nothing on the verifier will
ever tell you so.

### A credential someone else signed

`--full-chain` buys a render, not trust. The verifier's trust list is seven
PEMs compiled into the binary (`ConfigProvider.kt:67`), and `Utopia Test IACA`
will never be one of them. The other way round is to stop minting and ask the
EUDI reference issuer for an mDL, which `mdoc_fetch.py` does over OpenID4VCI:

```sh
mac$ .venv/bin/python mdoc_fetch.py --save mdl.bundle
     # open the URL it prints, pick a country, fill in the form, consent
mac$ scp mdl.bundle joostd@raspberrypi.local:mdoc/
pi$  python3 mdoc_wallet.py --credential mdl.bundle
```

The reason it is worth the trouble is the chain. Both live instances publish
an `issuer_info` JWT whose `x5c` roots in `CN=PID Issuer CA - UT 02,
O=EUDI Wallet Reference Implementation, C=UT` — and that root is byte-identical
to `pidissuerca02_ut.pem` in the verifier's own bundle, down to the serial
(`130C9B15…`) and the SHA-256 (`F5:D8:B0:3D:…:45:00`). A credential signed
under it comes up *trusted*, with no `--full-chain` and no rebuild.

Two things the script makes plain that the metadata does not.

The proof of possession proves nothing. `eu.europa.ec.eudi.mdl_mdoc` advertises
`key_attestations_required` with `key_storage: ["iso_18045_high"]` on both the
`jwt` and `attestation` proof types — keys in certified hardware. The server
never checks: `route_oidc.py:417` lifts the public key out of
`jwt.get_unverified_header(...)["jwk"]` and verifies no signature over it, and
`grep -rn key_attestation --include='*.py' app/` finds no enforcement anywhere.
A P-256 key generated in Python on a Pi is accepted and bound into the MSO's
`deviceKeyInfo`, which is the only reason the holder here can present the
result at all. `mdoc_fetch` signs the proof correctly regardless; the étude is
about what the protocol asks for, not what this deployment settles for.

And the issuer agrees about Table 5. Its mDL claim list is 32 entries: the 31
rows of Table 5 that can actually be issued, plus `age_over_18`. No
`age_over_NN`. No `biometric_template_xx`, and no biometric template of any
kind. It instantiated the two template rows exactly the way
`sample_mdl_elements(complete=True)` does — which means the reference
*verifier's* full-mDL request cannot be satisfied by the reference *issuer*
either. Two halves of the same project, and Table 8 would have said so if
anything read it.

What this costs is the thing the rest of the repo is for. Both conformance
bugs found here — fractional `tdate` seconds and a one-element x5chain array —
were found by controlling the bytes and diffing them against captures.
A fetched credential is a black box: no control over `validityInfo`, salts,
digest algorithm or the element set. So it is an artifact to compare against,
not a replacement for `mdoc_issuer`.

A last note on what "real" means here. The reference issuer's mock path puts
*you* at a web form typing the attribute values in, and nothing verifies them.
The credential is real in the sense that a real CA signed it, and in no other
sense.

## What's here

### The reader

| File | Role |
|---|---|
| `mdoc_transcript.py` | Engagement parsing *and* generation, SessionTranscript, session key derivation |
| `mdoc_transport.py` | The `MdocTransport` contract, plus a radio-free loopback link |
| `mdoc_ble.py` | GATT-client transport — scan, subscribe, `State=Start`, MTU−3 chunking |
| `mdoc_ble_peripheral.py` | GATT-*server* transport, for mdoc central client mode |
| `mdoc_auth.py` | Issuer data authentication, value digests, mdoc authentication |
| `qr_engagement.py` | Lifts the `mdoc:` URI off a screenshot or a live `adb screencap` — and draws one, for when we are the wallet |
| `mdoc_nfc.py` | NFC static handover — Type 4 Tag APDUs over PC/SC, NDEF parsing |
| `mdoc_reader.py` | The driver that composes the rest |

### The other two roles

| File | Role |
|---|---|
| `mdoc_issuer.py` | Mints a credential: MSO, value digests, a two-level PKI, the mandatory mDL elements |
| `mdoc_holder.py` | Parses a DeviceRequest, decides what to disclose, signs or MACs a DeviceResponse — and `HolderSession` runs the whole session, QR included |
| `mdoc_ble_holder.py` | The `MdocTransport` contract from the mdoc's side — a GATT server and LE advertisement over BlueZ |
| `mdoc_wallet.py` | The driver: mint, advertise, print the URI, present |
| `mdoc_fetch.py` | The other way to get a credential: OpenID4VCI against the EUDI reference issuer, for one signed by a CA the verifier already trusts |

### Tests — 179 checks, all passing

| File | Checks | Against what |
|---|---|---|
| `d51_session_encryption_test.py` | 5 | Annex D.5.1 — ECDH, HKDF, AES-256-GCM |
| `test_mdoc_transcript.py` | 17 | A real captured session, byte-for-byte |
| `test_mdoc_auth.py` | 21 | Annex D.5.2 and D.5.3 vectors, plus negative cases |
| `test_mdoc_reader.py` | 17 | A synthetic credential minted in-process, plus BLE mode choice and chunk sizing |
| `test_mdoc_nfc.py` | 27 | The Annex D.5.1 handover, plus a Handover Select read off the wallet |
| `test_mdoc_transport.py` | 16 | Loopback framing — chunk prefixes, State ordering, reassembly |
| `test_mdoc_holder.py` | 32 | Issuer → holder → reader in one process, including over-disclosure, Table 8 errors, and the encodings a foreign verifier cares about |
| `test_mdoc_session.py` | 27 | A whole presentation over the loopback: QR, ECDH, AES-GCM, both variants of mdoc auth |
| `test_mdoc_fetch.py` | 17 | The OpenID4VCI proof we sign and the credential we parse back, with the six HTTP calls between them left out |

```sh
for t in d51_session_encryption_test test_mdoc_transcript test_mdoc_auth \
         test_mdoc_reader test_mdoc_nfc test_mdoc_transport test_mdoc_holder \
         test_mdoc_session test_mdoc_fetch
do .venv/bin/python $t.py; done
```

(The header said 157 until now, which was 162 minus the five Annex D.5.1
checks the table had always listed. Counted, not recalled.)

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
| `siros-mdl.cbor` | An mDL from wwWallet, read in mdoc central client mode |
| `inspect_response.py` | Prints the x5chain, MSO validity and disclosed elements of a `--save` artifact |

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

What those three checks do *not* cover is worth saying plainly. All three
passed on the wwWallet mDL, which had asked for 5 data elements and returned
27 — including the portrait and a `pseudonym_seed`. Selective disclosure is
enforced by the holder and by nothing else in the protocol: a verifier cannot
tell an over-sharing wallet from a well-behaved one, because the extra
elements carry perfectly valid digests. Nor do the checks say anything about
provenance. That mDL claims `issuing_authority = 'SUNET'` and
`issuing_country = 'SE'` in its payload, while its actual document signer is
`CN=E2E Test Credential Signer` under a self-signed `E2E Test Root CA`, SAN
`https://sirosid-yitbarek-vc-apigw.fly.dev`. The payload is a claim; the
certificate chain is the evidence, and only an out-of-band IACA makes the
difference visible — which is the whole argument for `--trust-anchor`.

### All three roles, in one process

`mdoc_issuer` mints credentials and `mdoc_holder` presents them, so the reader
can be run against a counterparty this repo did not also validate. Over the
loopback transport the whole thing takes milliseconds and no handset.

It turns the over-disclosure observation into an assertion. Ask a
`Disclosure.EVERYTHING` holder for two elements, get eleven, and watch all five
checks pass:

```
PASS  an over-sharing holder returns 11 elements for a 2-element request
PASS  and the reader still reports VERIFIED — selective disclosure is
      enforced by the holder alone
```

That test asserts success deliberately. A conformant reader *must* accept that
response: every extra element carries a valid digest the issuer committed to,
and nothing in the protocol records what was asked for. The gap between
"verified" and "did not overshare" is not a bug to fix in the reader.

`mdoc_issuer` is a fixture, not an issuer — no key management, no revocation,
no device-key attestation, and the device private key is handed over in the
clear instead of living in a secure element. The one thing it does take
seriously is the per-item `random` salt (32 bytes from `secrets`, against the
16-byte minimum in 9.1.2.5), because that salt is the only thing stopping a
verifier brute-forcing `age_over_18` from the digests of the elements the
holder *declined* to disclose.

#### The session, not just the CBOR

`mdoc_holder.HolderSession` wraps the holder in the half of the protocol the
reader already had: generate an ephemeral key and a service UUID, encode them
into a DeviceEngagement, hand out the `mdoc:` URI, and from the reader's
SessionEstablishment derive `SKReader` / `SKDevice` and answer encrypted.
`mdoc_transcript.build_device_engagement` is the inverse of the parser that has
been reading wallets' QR codes since the start; `mdoc_uri` is the inverse of
`parse_mdoc_uri`.

So `test_mdoc_session.py` runs both roles as concurrent tasks over
`loopback_pair()`, and the reader half is written *from the engagement* rather
than handed the mdoc's state. That is what makes it worth running: the two
sides build the SessionTranscript independently, and if they disagree by one
byte the only symptom is an AES-GCM tag mismatch. One check asserts exactly
that, by appending a single `0x00` to the mdoc's engagement after the reader
has read it:

```
PASS  both sides derived the same SessionTranscript
      201 bytes, independently built
PASS  an mdoc whose engagement drifted cannot decrypt the request
      rejected: InvalidTag
```

ECDH is symmetric, so `derive_session_keys` serves both roles unchanged — the
mdoc calls it as `derive_session_keys(edevice_private, ereader_public, stb)`.
Its parameter names stay reader-centric because that is where it is used in
anger.

What this is still not is a wallet: no holder consent, no UI, no key
attestation, and the device private key sits in memory rather than in a secure
element. But it does now speak over a radio — see *A wallet of our own* below.

#### What a holder was for: `deviceMac`

`mdoc_auth.verify_device_mac` has been correct against the Annex D.5.3 vector
since the start and had never run against anything else, because neither wallet
sends it and a reader cannot produce one. `MdocHolder(device_auth=DeviceAuth.MAC)`
can, and `mdoc_reader.validate_response` now takes that branch.

The asymmetry between the two variants is the interesting part, and it is not
about strength. `deviceSignature` is ECDSA over `DeviceAuthenticationBytes`:
anyone holding the transcript and the MSO can check it, *including someone who
was not there*. `deviceMac` is an HMAC under `EMacKey`, derived by ECDH between
the credential's static device key and `EReaderKey` — so only the reader in
that session can verify it, and a transcript of the exchange proves nothing to
a third party. Handing someone a signed response is handing them evidence;
handing them a MACed one is not.

That cuts both ways, and the tests assert both directions:

```
PASS  and the reader verifies it against EMacKey
      first time this path has run outside the Annex D.5.3 vector
PASS  a reader that discarded its ephemeral key cannot verify the MAC
      unlike deviceSignature, the response is not evidence to anyone else
PASS  nor can a reader holding the wrong ephemeral key
      EMacKey agrees the device key with EReaderKey, not with the session keys
```

The practical cost is that `ereader_private` has to survive all the way down
into `validate_response`, which for `deviceSignature` is needed nowhere past
decryption. That is the signature change the variant forces, and the reason it
sat unwired for as long as it did.

### A wallet of our own

Everything above happened in one process. `mdoc_ble_holder.py` gives the holder
a radio: it is the third implementation of the `MdocTransport` contract, and
the first one where *we* are the GATT server — the mdoc side of Table 11,
exported over BlueZ's D-Bus API. `mdoc_wallet.py` drives it.

That needs a second machine. A Mac cannot read a wallet running on the same
Mac, for the reason `loopback_pair()` exists, and CoreBluetooth cannot be a
GATT server for a *fresh* service UUID per transaction anyway. A Raspberry Pi
running BlueZ 5.82 can, as a non-root user. On 2026-10-15, Pi to MacBook:

```
[bluez] advertising 7231fb68-0197-c8ef-825a-fc7c031d684d on hci0
[bluez] reader ready, MTU 517, chunk size 512
[holder] org.iso.18013.5.1.mDL: asked 2, disclosing 2 (requested), deviceSignature
[bluez] sending 1704 bytes in 4 chunk(s) of <= 511
```
```
  [ok] mdoc authentication (deviceSignature) — bound to this session transcript
      org.iso.18013.5.1/family_name = 'Mustermann'
VERIFIED
```

And with `--device-mac`, the variant no shipping wallet will send:

```
  [ok] mdoc authentication (deviceMac) — bound to this session transcript and to this reader
```

Standing up a GATT server over BlueZ is mostly D-Bus, not Bluetooth, and three
things cost real time:

**The service has to be a real exported object.** Returning it from
`GetManagedObjects` is not enough — `org.bluez.GattService1` must exist at its
own path, the way the characteristics do. Without it `RegisterApplication`
*succeeds*, the advertisement goes up, the Mac connects, and the service simply
is not in the GATT database. The only diagnostic is one line in the
bluetoothd journal: `gatt-database.c:client_ready_cb() No object received`.

**`RegisterApplication` will deadlock a blocking call.** BlueZ answers it by
calling `GetManagedObjects` back on us over the same connection, so a
synchronous call holding the GLib thread can never be served and you get
`org.freedesktop.DBus.Error.NoReply` after 25 seconds. Both registrations go
out with `reply_handler=`/`error_handler=` resolving asyncio futures instead.

**A GATT server learns the MTU only from `options`.** There is nothing to
query: BlueZ passes `{'mtu': 517, …}` to `ReadValue` and `WriteValue`, and
that dict is the only place it appears. Until the reader's first write the
holder has to assume the 23-byte minimum — which is correct, and costs
nothing, because the reader's first write is `State=Start`.

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

### Both BLE modes, and why the second one needs no bleak

18013-5 defines two BLE arrangements, and a conformant reader must support both
(clause 549). They differ only in who is the GATT server:

| | mdoc peripheral server mode | mdoc central client mode |
|---|---|---|
| mdoc is | GATT server, BLE peripheral | GATT client, BLE central |
| reader is | GATT client, BLE central | GATT server, BLE peripheral |
| characteristics | Table 11, `0x0001`–`0x0003` | Table 12, `0x0005`–`0x0008` |
| `Ident` | absent | present — served by the **reader** |
| engagement | BleOptions `0: true`, UUID in `10` | BleOptions `1: true`, UUID in `11` |
| reader module | `mdoc_ble.py` | `mdoc_ble_peripheral.py` |
| mdoc module | `mdoc_ble_holder.py` | — |

When a wallet offers both, 8.3.3.1.1.1 says the reader *should* choose central
client mode, which is what `--ble-mode auto` does. `choose_ble_mode` makes that
one decision, because the mode also decides which UUID to use: take the wrong
key out of BleOptions and you advertise a UUID nobody is looking for, which
looks exactly like a wallet that never appeared.

bleak cannot be a peripheral — it is a central-only library — so the second
mode goes under it to `CBPeripheralManager` through PyObjC. The role *is*
available to a Python process on macOS; it just is not available through bleak.
CoreBluetooth delivers its callbacks on a dispatch queue, so every one of them
hops back to the event loop with `call_soon_threadsafe`.

Both classes grew the same four methods independently, because the driver uses
them identically once the mode is chosen. `mdoc_transport.MdocTransport` writes
that contract down, and `TransportError` is now the base of both modules'
exceptions, so one `except` covers either mode.

A fourth implementation uses no radio at all. A Mac cannot talk to itself over BLE —
CoreBluetooth will not surface a machine's own advertisement to its own
scanner — so a reader and an mdoc in one process can never find each other.
`loopback_pair()` replaces the link with two queues and keeps the framing from
8.3.3.1.1.6, chunk prefixes and State bytes included, because that is where
transport bugs live. A loopback that passed whole messages would be a test of
nothing much.

The EUDI reference wallet offers peripheral server mode; `org.siros.id`
(wwWallet in a native Android shell) offers central client mode only. Having
both is the difference between reading one wallet and reading wallets — siros
was verified on 2026-10-14, an `org.iso.18013.5.1.mDL` with 27 elements.

Two things make a live central-client session harder to land than the mode
itself. siros scans for a reader for **20 seconds** and then gives up, and it
regenerates its engagement — a new QR and a new service UUID — on every retry,
so the QR must be read from the *current* attempt. Worse, `adb screencap`
returns the last rendered frame when the display is asleep, so a QR from a
long-dead engagement decodes perfectly and the session then fails against a
UUID nobody is advertising. `qr_engagement.screen_is_on` now refuses a capture
unless the handset is awake; the reliable choreography is to wait for
`ProximityBridge: Proximity session started in CENTRAL mode` in logcat and
screencap a second later.

### Nine things that will cost you an afternoon

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
by the mdoc, not the other way round. It is `HKDF(EDeviceKeyBytes, info =
"BLEIdent")` — derived from the *mdoc's* ephemeral key, which is the point:
only something that saw the engagement can compute it.

**The service UUID in an NFC carrier is little-endian.** Bluetooth AD type
`0x07` lists 128-bit UUIDs least-significant byte first, so the carrier bytes
`228d5186c6d3ea40f9ca98166b016391` mean the UUID
`9163016b-1698-caf9-40ea-d3c686518d22`. Scan for the unreversed one and you
will find nothing, with no hint as to why. The same payload's LE Role byte
describes the **mdoc's** role, not the reader's: `0x00`, peripheral only, means
mdoc peripheral server mode and so the reader is the GATT client.

**Two wallets on one handset break NFC, silently.** AID `D2760000850101` is
*the* NDEF application — every mdoc wallet registers it, in HCE category
`other`, where Android has no notion of a default. Install a second wallet and
every tap raises a "Choose app to scan" dialog instead of answering; while it
is up nothing responds to the SELECT, the RF session dies, and PC/SC reports
`SCARD_E_NOT_TRANSACTED (0x80100016)` — a transport error for what is really a
routing conflict. Identical symptom to lifting the handset too early, which is
why it is worth checking before blaming your hand:

```sh
adb shell dumpsys nfc | grep -B12 'AID: D2760000850101'
```

There is no reader-side fix. `CardEmulation.setPreferredService()` pre-empts
routing only for an app in the foreground, which a verifier on a Mac is not, so
the only cure is to leave exactly one claimant installed. From `adb shell` that
has to be done at *package* granularity — the obvious component-level form is
refused on a production build:

```
$ pm disable-user --user 0 org.siros.wwwallet/…MdocHostApduService
SecurityException: Shell cannot change component state for ComponentInfo{…} to 3
$ pm disable-user --user 0 org.siros.wwwallet        # this one works
Package org.siros.wwwallet new state: disabled-user  # pm enable to undo
```

With the other two wallets disabled the tap verified first try, on 2026-10-15:
204-byte Handover Select, 380-byte SessionTranscript, `VERIFIED`.

The QR path is unaffected: it does not go through AID routing at all.

**Don't assume the PKI is ECDSA.** Annex B says an mDL PKI uses ECDSA on
P-256/384/521, so building an `ec.ECDSA` verifier for every trust anchor looks
safe. Test PKIs are routinely RSA — wwWallet's root is — and the RSA anchor
then raised inside a `try` whose `except Exception: continue` turned it into
"does not chain to any trust anchor". `openssl verify` accepted the same
chain. A verifier that cannot parse an anchor must not report it as an anchor
that does not match: the first is a bug here, the second is a fact about the
credential, and conflating them sends you looking in the wrong place.

**MTU − 3 is wrong above MTU 515.** 8.3.3.1.1.6 sizes every message part at
MTU − 3 and says no more. GATT says an attribute value is at most 512 octets
(Core 5.3 Vol 3 Part F 3.2.9), and a notification carries an attribute value.
A Pi and a MacBook negotiate 517, so MTU − 3 is 514 — and BlueZ sends 512 of
those bytes and drops the other two, per chunk, without a word in any log.
`btmon` shows `Handle Value Notification len 514`, which is the handle plus
512. A 1592-byte DeviceResponse arrived as 1586 and CBOR decoding failed six
bytes from the end, nowhere near the lie. The chunk size is
`min(MTU − 3, 512)` in both directions now; macOS hides the bug on the reader
side, because bleak derives `mtu_size` from `maximumWriteValueLength`, which
Apple already caps at 512.

**Don't let teardown hold the result hostage.** The reader's `close()` writes
`State=End`, unsubscribes, disconnects — and an mdoc that unregisters its GATT
application the instant it sees the session termination leaves `stop_notify`
waiting on handles that no longer exist. bleak waits forever. The
DeviceResponse was decrypted and in hand; the verdict is printed after the
`async with` block, so nothing was ever shown. Every step of the teardown is
on a 3-second clock now. Past the last `receive()`, nothing the peer does
should be able to cost you the answer.

**Don't look characteristics up by UUID alone.** Every transaction gets a fresh
*service* UUID but reuses the same three *characteristic* UUIDs, and macOS
caches a peripheral's GATT database. The second time you talk to a wallet there
are several characteristics called `00000001-a123-…`, and bleak raises
`Multiple Characteristics with this UUID` rather than guess. Resolve them
inside the service you actually engaged with — `mdoc_ble._resolve_characteristics`
does, and logs their handles. Had bleak guessed, the symptom would have been a
Start write into a dead service and a silent hang.

## Limitations

- **Only the BLE transport.** Clause 549 requires a conformant mDL reader to
  support both BLE modes, which this one now does, but 18013-5 also defines
  NFC and Wi-Fi Aware data retrieval. Neither is implemented.
- **No reader authentication.** The `DeviceRequest` carries no `readerAuth`, so
  the wallet cannot tell who is asking and will say so. Fixing this needs a
  reader certificate the wallet's trust list recognises.
- **`deviceMac` has never been seen from a real wallet.** Both ends are wired,
  and it has now travelled over a radio between two machines — but the only
  mdoc that has ever sent one is `mdoc_holder.py`. Neither the EUDI wallet nor
  `org.siros.id` offers it, so the variant is still tested against a
  counterparty this repo also wrote.
- **`mdoc_wallet.py` only does peripheral server mode.** It is the mdoc half of
  Table 11. Table 12 — where the mdoc is the GATT client and reads `Ident` off
  the reader — exists only on the reader side here, in
  `mdoc_ble_peripheral.py`, so the two halves of this repo cannot meet in the
  mode `org.siros.id` uses.
- **No real wallet has ever read this repo's holder**, and no real verifier has
  ever read it either. Both ends of every radio session so far were written
  here, which proves they agree with each other and not that either agrees
  with the spec. The Annex D vectors are the only outside judge.
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
