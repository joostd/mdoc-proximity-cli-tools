#!/usr/bin/env python3
"""
Validate the TCP stand-in against the framing rules in 8.3.3.1.1.5/6.

`mdoc_tcp` is about to carry the reader against a wallet written in another
language, which makes it the one place where a framing mistake would be
blamed on the wallet. These checks pin it down against a hand-written peer
that speaks the frame format literally, so neither side can be wrong in the
same way as the other.

The thing TCP adds over the loopback, and the thing tested hardest here, is
that a stream has no record boundaries: one read can hold several frames or
half of one, and both have to work.

Run:  .venv/bin/python test_mdoc_tcp.py
"""
import asyncio
import sys

from mdoc_tcp import (
    DEFAULT_CHUNK_SIZE,
    KIND_DATA,
    KIND_STATE,
    TcpTransport,
)
from mdoc_transport import (
    STATE_END,
    STATE_START,
    MdocTransport,
    TransportClosed,
    TransportError,
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


def frame(kind: int, payload: bytes) -> bytes:
    return bytes([kind]) + len(payload).to_bytes(2, "big") + payload


class Peer:
    """The other end, speaking frames literally. Stands in for the wallet."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def send(self, raw: bytes) -> None:
        self.writer.write(raw)
        await self.writer.drain()

    async def frames(self, count: int) -> list[tuple[int, bytes]]:
        out = []
        for _ in range(count):
            header = await asyncio.wait_for(self.reader.readexactly(3), 5.0)
            length = int.from_bytes(header[1:], "big")
            body = await asyncio.wait_for(self.reader.readexactly(length), 5.0) \
                if length else b""
            out.append((header[0], body))
        return out


async def linked(**kwargs) -> tuple[TcpTransport, Peer, asyncio.AbstractServer]:
    """A connected (transport, peer) pair on the loopback interface."""
    accepted: asyncio.Future = asyncio.get_running_loop().create_future()

    def on_connect(reader, writer):
        accepted.set_result(Peer(reader, writer))

    server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    transport = TcpTransport("127.0.0.1", port, **kwargs)
    await transport.open()           # connects, and sends State=Start
    peer = await accepted
    check("open sends State=Start first",
          await peer.frames(1) == [(KIND_STATE, STATE_START)])
    return transport, peer, server


async def main() -> int:
    # --- the contract --------------------------------------------------------

    check("TcpTransport satisfies MdocTransport",
          isinstance(TcpTransport("127.0.0.1", 1), MdocTransport))

    await raises("connecting to a closed port fails as a TransportError",
                 TransportError,
                 TcpTransport("127.0.0.1", 1).open(timeout=2.0))

    # --- sending -------------------------------------------------------------

    transport, peer, server = await linked(chunk_size=4)
    await transport.send(b"\x01\x02\x03\x04\x05\x06\x07")
    check("a message is cut into prefixed chunks",
          await peer.frames(3) == [(KIND_DATA, b"\x01\x01\x02\x03"),
                                   (KIND_DATA, b"\x01\x04\x05\x06"),
                                   (KIND_DATA, b"\x00\x07")],
          "3 payload bytes per 4-byte chunk; the prefix costs one")
    await transport.close()
    check("close signals State=End",
          await peer.frames(1) == [(KIND_STATE, STATE_END)])
    await raises("send on a closed transport is refused",
                 TransportError, transport.send(b"late"))
    server.close()

    transport, peer, server = await linked()
    await transport.send(b"")
    check("an empty message is still one chunk",
          await peer.frames(1) == [(KIND_DATA, b"\x00")],
          "dropping it would leave the peer waiting for what was already sent")
    await transport.close()
    server.close()

    # --- receiving -----------------------------------------------------------

    transport, peer, server = await linked()
    await peer.send(frame(KIND_DATA, b"\x01ab") + frame(KIND_DATA, b"\x00cd"))
    check("chunks are reassembled", await transport.receive(timeout=5.0) == b"abcd")

    # Two whole messages in one write: the reader must not merge them.
    await peer.send(frame(KIND_DATA, b"\x00one") + frame(KIND_DATA, b"\x00two"))
    check("several frames in one read stay separate",
          await transport.receive(timeout=5.0) == b"one"
          and await transport.receive(timeout=5.0) == b"two")

    # One message split across writes, a byte at a time.
    whole = frame(KIND_DATA, b"\x00split")
    for byte in whole:
        await peer.send(bytes([byte]))
    check("a frame arriving in pieces is still one frame",
          await transport.receive(timeout=5.0) == b"split")

    await peer.send(frame(KIND_STATE, b"\x7f"))
    await peer.send(frame(KIND_DATA, b"\x00after"))
    check("an unknown State value is logged past, not fatal",
          await transport.receive(timeout=5.0) == b"after")

    await raises("a timeout names the partial state",
                 TransportError, transport.receive(timeout=0.05))
    await transport.close()
    server.close()

    transport, peer, server = await linked()
    await peer.send(frame(KIND_DATA, b"\x07oops"))
    await raises("a bad chunk prefix is rejected rather than absorbed",
                 TransportError, transport.receive(timeout=5.0))
    await transport.close()
    server.close()

    transport, peer, server = await linked()
    await peer.send(frame(KIND_STATE, STATE_END))
    await raises("State=End surfaces as TransportClosed",
                 TransportClosed, transport.receive(timeout=5.0))
    await transport.close()
    server.close()

    transport, peer, server = await linked()
    peer.writer.close()
    await raises("a peer that vanishes mid-session is TransportClosed",
                 TransportClosed, transport.receive(timeout=5.0))
    await transport.close()
    server.close()

    # --- construction guards -------------------------------------------------

    try:
        TcpTransport("127.0.0.1", 1, chunk_size=1)
    except ValueError as exc:
        check("rejected at construction: no room for the continuation prefix",
              True, str(exc))
    else:
        check("rejected at construction: no room for the continuation prefix",
              False, "accepted")

    check("the default chunk size matches the loopback",
          DEFAULT_CHUNK_SIZE == 244,
          "so both stand-ins frame identically")

    print("\nALL PASS" if not _failures else f"\n{_failures} FAILURE(S)")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
