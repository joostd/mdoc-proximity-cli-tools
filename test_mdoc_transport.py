#!/usr/bin/env python3
"""
Validate the loopback transport against the framing rules in 8.3.3.1.1.5/6.

The loopback is about to carry a Python mdoc talking to the Python reader, so
it has to be wrong in the same places the radio would be — chunk prefixes,
State ordering, reassembly across many parts — or every test built on it
proves nothing. These checks pin the framing down before anything depends on it.

Run:  .venv/bin/python test_mdoc_transport.py
"""
import asyncio
import sys

from mdoc_ble import BleTransportError
from mdoc_ble_peripheral import BlePeripheralError
from mdoc_transport import (
    STATE_END,
    STATE_START,
    LoopbackTransport,
    MdocTransport,
    TransportClosed,
    TransportError,
    loopback_pair,
)

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
        check(label, True, f"rejected: {exc}")
    except Exception as exc:
        check(label, False, f"raised {type(exc).__name__}: {exc}")
    else:
        check(label, False, "accepted when it should have been rejected")


async def main() -> int:
    # --- the contract --------------------------------------------------------

    reader, mdoc = loopback_pair()
    check("LoopbackTransport satisfies MdocTransport",
          isinstance(reader, MdocTransport))
    check("both BLE errors are catchable as TransportError",
          issubclass(BleTransportError, TransportError)
          and issubclass(BlePeripheralError, TransportError),
          "one except clause covers every mode")

    # --- Start precedes data -------------------------------------------------

    await reader.open()
    await mdoc.open(timeout=1.0)
    check("the reader signals Start and the mdoc waits for it", True,
          f"STATE_START={STATE_START.hex()}, STATE_END={STATE_END.hex()}")

    lonely_reader, lonely_mdoc = loopback_pair()
    await raises("an mdoc with no reader times out waiting for Start",
                 TransportError, lonely_mdoc.open(timeout=0.05))

    # Data before Start is a protocol error, not a message.
    early_reader, early_mdoc = loopback_pair()
    await early_reader.send(b"premature")
    await raises("data arriving before State=Start is refused",
                 TransportError, early_mdoc.open(timeout=1.0))

    # --- round trip both ways ------------------------------------------------

    await reader.send(b"SessionEstablishment")
    check("mdoc receives what the reader sent",
          await mdoc.receive(timeout=1.0) == b"SessionEstablishment")

    await mdoc.send(b"DeviceResponse")
    check("reader receives what the mdoc sent",
          await reader.receive(timeout=1.0) == b"DeviceResponse")

    # --- reassembly across many chunks ---------------------------------------

    small_reader, small_mdoc = loopback_pair(chunk_size=20)
    await small_reader.open()
    await small_mdoc.open(timeout=1.0)

    payload = bytes(range(256)) * 9  # 2304 bytes, the size of a real response
    await small_reader.send(payload)
    received = await small_mdoc.receive(timeout=1.0)
    check("2304 bytes reassemble across 122 chunks at the 20-byte floor",
          received == payload,
          f"{len(received)} bytes back, chunk_size {small_reader.chunk_size}")

    # An empty message still costs one chunk — `or [b""]` in send().
    await small_reader.send(b"")
    check("an empty message round trips as a single last-chunk",
          await small_mdoc.receive(timeout=1.0) == b"")

    # --- End is not data -----------------------------------------------------

    closing_reader, closing_mdoc = loopback_pair()
    await closing_reader.open()
    await closing_mdoc.open(timeout=1.0)
    await closing_reader.close()
    await raises("State=End surfaces as TransportClosed, not a message",
                 TransportClosed, closing_mdoc.receive(timeout=1.0))
    await raises("sending on a closed transport is refused",
                 TransportError, closing_reader.send(b"too late"))

    # close() must be safe twice — mdoc_reader calls it explicitly and again
    # on the way out of `async with`.
    await closing_reader.close()
    check("close() is idempotent", True)

    # --- neither end hears itself --------------------------------------------

    solo_reader, solo_mdoc = loopback_pair()
    await solo_reader.open()
    await solo_mdoc.open(timeout=1.0)
    await solo_reader.send(b"mine")
    await raises("a sender does not receive its own message",
                 TransportError, solo_reader.receive(timeout=0.05))
    check("the peer got it instead", await solo_mdoc.receive(timeout=1.0) == b"mine")

    # --- construction guards -------------------------------------------------

    for bad, why in [({"role": "verifier"}, "unknown role"),
                     ({"chunk_size": 1}, "no room for the continuation prefix")]:
        try:
            LoopbackTransport(inbox=asyncio.Queue(), outbox=asyncio.Queue(),
                              **{"role": "reader", **bad})
        except ValueError as exc:
            check(f"rejected at construction: {why}", True, str(exc))
        else:
            check(f"rejected at construction: {why}", False, "accepted")

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
