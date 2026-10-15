#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — the session transport contract, and a loopback link.

`mdoc_ble` and `mdoc_ble_peripheral` grew the same four methods independently,
because `mdoc_reader` drives them identically once the mode is chosen. This
module writes that contract down as `MdocTransport`, and adds a third
implementation that uses no radio at all.

The loopback exists because a Mac cannot talk to itself over BLE: CoreBluetooth
will not surface a machine's own advertisement to its own scanner, so a reader
and an mdoc in one process can never find each other. Swapping the link for a
pair of queues is the only way to run both halves of a session on one machine —
and it turns a 30-second choreography with a handset into a millisecond test.

It deliberately keeps the framing from 8.3.3.1.1.6 rather than passing whole
messages: the chunk prefixes (0x01 more, 0x00 last) and the State byte are
where the transport bugs live, so a loopback that skipped them would be a test
of nothing much. What it does *not* model is BLE itself — no MTU negotiation,
no notification backpressure, no dropped links.

Requires: nothing beyond the standard library.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# 8.3.3.1.1.5 — State characteristic values.
STATE_START = b"\x01"
STATE_END = b"\x02"

# 8.3.3.1.1.6 — the one-byte continuation prefix on every chunk.
CHUNK_MORE = 0x01
CHUNK_LAST = 0x00

# Tables 11 and 12. These live here rather than in one of the BLE modules
# because all three transports need them and the modules have incompatible
# dependencies: `mdoc_ble` needs bleak, `mdoc_ble_peripheral` needs
# CoreBluetooth, `mdoc_ble_holder` needs BlueZ and never runs on a Mac. A
# mistyped UUID in one copy would show up only as a peer that is never found.
#
# The characteristic *names* are fixed by the table and do not follow the
# roles: Server2Client always carries GATT-server -> GATT-client traffic, so
# which side notifies on it depends on the mode, not on the name.

# Table 11 — mdoc peripheral server mode: the mdoc is the GATT server.
STATE_UUID = "00000001-a123-48ce-896b-4c76973373e6"
CLIENT_TO_SERVER_UUID = "00000002-a123-48ce-896b-4c76973373e6"
SERVER_TO_CLIENT_UUID = "00000003-a123-48ce-896b-4c76973373e6"

# Table 12 — mdoc central client mode: the reader is the GATT server, and
# there is an extra Ident characteristic the mdoc reads to check it found us.
PERIPHERAL_STATE_UUID = "00000005-a123-48ce-896b-4c76973373e6"
PERIPHERAL_CLIENT_TO_SERVER_UUID = "00000006-a123-48ce-896b-4c76973373e6"
PERIPHERAL_SERVER_TO_CLIENT_UUID = "00000007-a123-48ce-896b-4c76973373e6"
PERIPHERAL_IDENT_UUID = "00000008-a123-48ce-896b-4c76973373e6"


def service_uuid_str(raw: bytes) -> str:
    """16 engagement bytes -> the dashed UUID string every BLE stack wants."""
    import uuid

    if len(raw) != 16:
        raise ValueError(f"service UUID must be 16 bytes, got {len(raw)}")
    return str(uuid.UUID(bytes=raw))


class TransportError(Exception):
    """The session link failed. Base class for every transport's errors, so a
    caller can catch one exception regardless of which mode was negotiated."""


class TransportClosed(TransportError):
    """The peer signalled State=End (0x02) while we were waiting for data."""


@runtime_checkable
class MdocTransport(Protocol):
    """What `mdoc_reader` needs from a link, and all it needs.

    Implementations: `mdoc_ble.MdocBleReader` (GATT client, mdoc peripheral
    server mode), `mdoc_ble_peripheral.MdocBlePeripheral` (GATT server, mdoc
    central client mode), and `LoopbackTransport` below.

    `open` takes an implementation-specific timeout — waiting for a central to
    subscribe is not the same wait as connecting to a peripheral — so it is not
    part of the signature here. Use the async context manager and let each one
    pick its own default.
    """

    async def send(self, message: bytes) -> None:
        """Chunk and transmit one SessionEstablishment or SessionData."""
        ...

    async def receive(self, *, timeout: float = 60.0) -> bytes:
        """Wait for one fully reassembled message from the peer."""
        ...

    async def close(self, *, send_end: bool = True) -> None:
        """Signal End and tear the link down. Must be safe to call twice."""
        ...

    async def __aenter__(self) -> "MdocTransport":
        ...

    async def __aexit__(self, *exc) -> None:
        ...


# --- loopback ---------------------------------------------------------------

@dataclass(frozen=True)
class _Frame:
    """One ATT-sized write or notification: either a State byte or a chunk."""
    kind: str  # "state" | "data"
    payload: bytes


class LoopbackTransport:
    """One end of an in-process link. Build both ends with `loopback_pair`.

    The two ends are symmetric apart from `open`: the reader signals Start, the
    mdoc waits for it, mirroring who writes to the State characteristic in
    either BLE mode.
    """

    def __init__(self, *, inbox: asyncio.Queue, outbox: asyncio.Queue, role: str,
                 chunk_size: int = 244, verbose: bool = False):
        if role not in ("reader", "mdoc"):
            raise ValueError(f"role must be 'reader' or 'mdoc', not {role!r}")
        if chunk_size < 2:
            raise ValueError("chunk_size must leave room for the continuation prefix")
        self._inbox = inbox
        self._outbox = outbox
        self._role = role
        self._chunk_size = chunk_size
        self._verbose = verbose
        self._parts: list[bytes] = []
        self._closed = False
        self._peer_ended = False

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "LoopbackTransport":
        await self.open()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def open(self, *, timeout: float = 10.0) -> None:
        if self._role == "reader":
            await self._outbox.put(_Frame("state", STATE_START))
            self._log("sent State=Start (0x01)")
        else:
            frame = await self._next_frame(timeout, "State=Start")
            if frame.kind != "state" or frame.payload != STATE_START:
                raise TransportError(
                    f"expected State=Start, got {frame.kind} {frame.payload.hex()}")
            self._log("received State=Start (0x01)")

    async def close(self, *, send_end: bool = True) -> None:
        if self._closed:
            return
        self._closed = True
        if send_end and not self._peer_ended:
            await self._outbox.put(_Frame("state", STATE_END))
            self._log("sent State=End (0x02)")

    # --- properties --------------------------------------------------------

    @property
    def chunk_size(self) -> int:
        """Stands in for MTU - 3. Settable per pair so a test can force the
        20-byte floor and prove reassembly across many chunks."""
        return self._chunk_size

    # --- messages ----------------------------------------------------------

    async def send(self, message: bytes) -> None:
        if self._closed:
            raise TransportError("send on a closed transport")
        size = self._chunk_size - 1  # the continuation prefix costs a byte
        chunks = [message[i:i + size] for i in range(0, len(message), size)] or [b""]
        self._log(f"sending {len(message)} bytes in {len(chunks)} chunk(s) of <= {size}")
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            await self._outbox.put(
                _Frame("data", bytes([CHUNK_LAST if last else CHUNK_MORE]) + chunk))

    async def receive(self, *, timeout: float = 60.0) -> bytes:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TransportError(
                    f"no response within {timeout}s "
                    f"({len(self._parts)} partial chunk(s) buffered)")
            frame = await self._next_frame(remaining, "a message")

            if frame.kind == "state":
                if frame.payload == STATE_END:
                    self._peer_ended = True
                    raise TransportClosed("peer signalled State=End (0x02)")
                self._log(f"State notification: 0x{frame.payload.hex()}")
                continue

            prefix, payload = frame.payload[0], frame.payload[1:]
            self._parts.append(payload)
            if prefix == CHUNK_LAST:
                message = b"".join(self._parts)
                self._parts = []
                self._log(f"reassembled {len(message)} bytes")
                return message
            if prefix != CHUNK_MORE:
                self._parts = []
                raise TransportError(f"bad chunk prefix 0x{prefix:02x}")

    # --- internals ---------------------------------------------------------

    async def _next_frame(self, timeout: float, waiting_for: str) -> _Frame:
        try:
            return await asyncio.wait_for(self._inbox.get(), timeout)
        except asyncio.TimeoutError as exc:
            raise TransportError(
                f"timed out after {timeout:.1f}s waiting for {waiting_for}") from exc

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[loop:{self._role}] {message}")


def loopback_pair(*, chunk_size: int = 244, verbose: bool = False
                  ) -> tuple[LoopbackTransport, LoopbackTransport]:
    """Two ends of one link: `(reader_side, mdoc_side)`.

    Each end's outbox is the other's inbox, so neither can hear itself — the
    one property a single-machine BLE loopback could not have given us anyway.
    """
    reader_to_mdoc: asyncio.Queue = asyncio.Queue()
    mdoc_to_reader: asyncio.Queue = asyncio.Queue()
    return (
        LoopbackTransport(inbox=mdoc_to_reader, outbox=reader_to_mdoc,
                          role="reader", chunk_size=chunk_size, verbose=verbose),
        LoopbackTransport(inbox=reader_to_mdoc, outbox=mdoc_to_reader,
                          role="mdoc", chunk_size=chunk_size, verbose=verbose),
    )
