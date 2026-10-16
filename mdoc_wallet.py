#!/usr/bin/env python3
"""
A Python mDL wallet: mint a credential, advertise, present it over BLE.

The counterpart to `mdoc_reader.py`, and the first thing in this repo that
makes the holder a *counterparty* rather than a fixture. Everything
`mdoc_holder` had done until now happened in the same process as the reader
validating it, over `mdoc_transport.loopback_pair()`.

Run it on a machine with BlueZ (a Raspberry Pi works; a Mac does not — see
`mdoc_ble_holder`), point `mdoc_reader.py` at the URI it prints, and the two
halves of 18013-5 meet over a real radio:

    pi$  python3 mdoc_wallet.py --save-anchor iaca.pem
         mdoc:owBjMS4wAYIB2BhYS6QBAiABIVgg...
         ███████  █ ██ █  ███████      (and the same thing as a QR, for a
         █     █  ██  ██  █     █       verifier app that wants to scan it;
         █ ███ █  ██ ███  █ ███ █       needs a 106-column window)

    mac$ scp joostd@raspberrypi.local:iaca.pem .
    mac$ .venv/bin/python mdoc_reader.py 'mdoc:owBjMS4w...' --trust-anchor iaca.pem

The credential is minted fresh on every run by `mdoc_issuer`, so the IACA is
new each time and has to travel to the reader out of band. That is annoying in
exactly the way a real trust list is annoying, which is the point —
`--save-anchor` writes it out, and `--reuse-pki` keeps one across runs so you
only have to copy it once.

This is not a wallet in any sense a user would recognise: no consent prompt,
no UI, no key attestation, and the device private key sits in memory rather
than a secure element. It is the holder half of the protocol with a radio
attached.
"""
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mdoc_holder import DeviceAuth, Disclosure, HolderSession, MdocHolder
from mdoc_issuer import (
    PLACEHOLDER_PORTRAIT,
    Pki,
    generate_pki,
    mint,
    sample_mdl_elements,
)
from mdoc_transport import service_uuid_str


PEM_BLOCK = re.compile(rb"-----BEGIN [^-]+-----.*?-----END [^-]+-----\n?", re.S)


def load_or_make_pki(path: Path | None):
    """A PKI that survives restarts, so the reader's anchor stays valid.

    Four PEM blocks in a fixed order — IACA key, IACA certificate, DS key, DS
    certificate. Unencrypted private keys on disk, which is only acceptable
    because this is a throwaway test authority; the alternative is copying a
    fresh IACA to the reader before every single run.
    """
    if path is None:
        return generate_pki()

    if path.exists():
        blocks = PEM_BLOCK.findall(path.read_bytes())
        if len(blocks) != 4:
            raise SystemExit(f"{path}: expected 4 PEM blocks, found {len(blocks)}")
        iaca_key, iaca_certificate, ds_key, ds_certificate = blocks
        return Pki(
            iaca_key=serialization.load_pem_private_key(iaca_key, password=None),
            iaca_certificate=x509.load_pem_x509_certificate(iaca_certificate),
            ds_key=serialization.load_pem_private_key(ds_key, password=None),
            ds_certificate=x509.load_pem_x509_certificate(ds_certificate),
        )

    pki = generate_pki()
    private = dict(encoding=serialization.Encoding.PEM,
                   format=serialization.PrivateFormat.PKCS8,
                   encryption_algorithm=serialization.NoEncryption())
    path.write_bytes(b"".join([
        pki.iaca_key.private_bytes(**private),
        pki.iaca_certificate.public_bytes(serialization.Encoding.PEM),
        pki.ds_key.private_bytes(**private),
        pki.ds_certificate.public_bytes(serialization.Encoding.PEM),
    ]))
    path.chmod(0o600)
    return pki


async def serve_once(args) -> int:
    pki = load_or_make_pki(Path(args.reuse_pki) if args.reuse_pki else None)
    # A decodable portrait, unlike the repo's fixture default: this credential
    # is meant to be read by something that will try to draw it.
    credential, _ = mint(
        sample_mdl_elements(portrait=PLACEHOLDER_PORTRAIT,
                            complete=args.full_mdl),
        pki=pki, include_anchor=args.full_chain)

    if args.save_anchor:
        Path(args.save_anchor).write_bytes(
            pki.iaca_certificate.public_bytes(serialization.Encoding.PEM))
        print(f"IACA written to {args.save_anchor} — copy it to the reader and "
              f"pass it as --trust-anchor")

    holder = MdocHolder(
        [credential],
        disclosure=Disclosure[args.disclosure.upper()],
        device_auth=DeviceAuth.MAC if args.device_mac else DeviceAuth.SIGNATURE,
        verbose=True)
    session = HolderSession(holder, verbose=args.verbose)

    elements = credential.element_names()
    print(f"\nHolding {credential.doc_type} with "
          f"{sum(len(v) for v in elements.values())} elements")
    print(f"Disclosure policy: {args.disclosure}, "
          f"{'deviceMac' if args.device_mac else 'deviceSignature'}")
    print(f"\nEngagement — give this to the reader:\n\n{session.uri}\n")

    if args.qr:
        # A verifier app has a camera, not a clipboard. Drawn here rather than
        # on the machine you are sitting at, so there is nothing to copy and
        # no window to find: ssh in, and the QR is already on your screen.
        import shutil

        from qr_engagement import qr_terminal, qr_terminal_width

        needed = qr_terminal_width(session.uri)
        if shutil.get_terminal_size().columns < needed:
            # Say so rather than quietly drawing the squashed one: oblong
            # modules look fine to a human and scan badly, which is the worst
            # way for this to fail.
            print(f"(widen this window to {needed} columns for square "
                  f"modules — drawing the compact QR instead)\n")
        print(qr_terminal(session.uri))
        print()

    if args.dry_run:
        print("--dry-run: stopping before the radio.")
        return 0

    # Imported this late so --help and --dry-run work on a machine without
    # BlueZ — which includes the Mac the reader runs on.
    from mdoc_ble_holder import MdocBleHolder

    uuid = service_uuid_str(session.service_uuid)
    link = MdocBleHolder(uuid, adapter=args.adapter, verbose=args.verbose)
    print(f"Advertising service {uuid}; waiting for a reader "
          f"(up to {args.wait:.0f}s)…")

    try:
        await link.open(timeout=args.wait)
    except Exception as exc:
        print(f"\nNothing connected: {exc}")
        await link.close()
        return 1

    try:
        await session.serve(link, timeout=args.timeout)
    finally:
        await link.close()

    print("\nSession finished." if session.terminated
          else "\nSession ended without a termination from the reader.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--adapter", default="hci0",
                        help="BlueZ adapter to advertise on (default hci0)")
    parser.add_argument("--disclosure", default="requested",
                        choices=["requested", "everything", "nothing"],
                        help="what the holder is willing to hand over. "
                             "'everything' reproduces the over-sharing wallet "
                             "the README describes")
    parser.add_argument("--device-mac", action="store_true",
                        help="authenticate with deviceMac instead of "
                             "deviceSignature (9.1.3.5)")
    parser.add_argument("--save-anchor", metavar="PATH",
                        help="write the IACA certificate as PEM for the reader")
    parser.add_argument("--reuse-pki", metavar="PATH",
                        help="keep the PKI in this file across runs, so the "
                             "reader's --trust-anchor stays valid")
    parser.add_argument("--wait", type=float, default=120.0, metavar="SECONDS",
                        help="how long to advertise before giving up")
    parser.add_argument("--timeout", type=float, default=60.0, metavar="SECONDS",
                        help="how long to wait for each message once connected")
    parser.add_argument("--full-chain", action="store_true",
                        help="send the IACA in the x5chain too, so a verifier "
                             "that has never been given our anchor can still "
                             "build a path to it (see `mdoc_issuer.mint`)")
    parser.add_argument("--full-mdl", action="store_true",
                        help="hold all 33 elements of Table 5, not just the 11 "
                             "mandatory ones, so a 'full mDL' request comes "
                             "back without Table 8 errors")
    parser.add_argument("--no-qr", dest="qr", action="store_false",
                        help="skip the QR — it is 53 lines of ANSI escapes, "
                             "which is not what you want in a log file")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the engagement and stop before the radio")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="BLE and session tracing")
    args = parser.parse_args()

    try:
        return asyncio.run(serve_once(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
