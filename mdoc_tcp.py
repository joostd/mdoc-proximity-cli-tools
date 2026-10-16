#!/usr/bin/env python3
"""
A TCP stand-in for the BLE link, for driving a wallet that is not on a radio.

`LoopbackTransport` in `mdoc_transport` runs both halves of a session in one
Python process. This runs them in two processes, on one machine, over a socket
— which is what you need when the other half is written in another language.
It exists to drive the Flutter wallet in `~/etudes/mdoc-flutter-wallet` before
any of its BLE or HCE code is switched on, so that when the radio does come up,
every remaining failure is a radio failure and not a CBOR one.

Nothing here is in 18013-5. What *is* kept from the standard is the framing of
8.3.3.1.1.5 and 8.3.3.1.1.6 — the State byte and the one-byte continuation
prefix on each chunk — because those are where the transport bugs live and a
link that passed whole messages would prove nothing about them.

TCP is a stream and GATT is not, so one length-delimited frame stands in for
one ATT write or notification:

    kind(1) || length(2, big-endian) || payload
      kind 0x00   a State characteristic value, one byte
      kind 0x01   a data chunk: continuation prefix + payload

What it does not model: MTU negotiation, notification backpressure, dropped
links, or a peer that is 30cm away and moving.

Requires: nothing beyond the standard library.
"""
from __future__ import annotations

import asyncio

from mdoc_transport import (CHUNK_LAST, CHUNK_MORE, STATE_END, STATE_START,
                            TransportClosed, TransportError)

KIND_STATE = 0x00
KIND_DATA = 0x01

# What the loopback uses, so both links chunk identically by default.
DEFAULT_CHUNK_SIZE = 244


class TcpTransport:
    """The reader's end of a socket link. Implements `MdocTransport`.

    The wallet listens and we connect, because the wallet is the side that
    publishes an engagement: it prints its port the way it would show a QR.
    """

    def __init__(self, host: str, port: int, *, chunk_size: int = DEFAULT_CHUNK_SIZE,
                 verbose: bool = False):
        if chunk_size < 2:
            raise ValueError("chunk_size must leave room for the continuation prefix")
        self._host = host
        self._port = port
        self._chunk_size = chunk_size
        self._verbose = verbose
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._parts: list[bytes] = []
        self._closed = False
        self._peer_ended = False

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "TcpTransport":
        await self.open()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def open(self, *, timeout: float = 10.0) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise TransportError(
                f"cannot reach the wallet at {self._host}:{self._port}: {exc}") from exc
        self._log(f"connected to {self._host}:{self._port}")
        # The reader signals Start, exactly as it writes the State
        # characteristic in mdoc peripheral server mode.
        await self._send_frame(KIND_STATE, STATE_START)
        self._log("sent State=Start (0x01)")

    async def close(self, *, send_end: bool = True) -> None:
        if self._closed:
            return
        self._closed = True
        if send_end and not self._peer_ended and self._writer is not None:
            try:
                await self._send_frame(KIND_STATE, STATE_END)
                self._log("sent State=End (0x02)")
            except (OSError, TransportError):
                pass  # the peer is already gone; nothing left to tell it
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except OSError:
                pass

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    # --- messages ----------------------------------------------------------

    async def send(self, message: bytes) -> None:
        if self._closed:
            raise TransportError("send on a closed transport")
        size = self._chunk_size - 1  # the continuation prefix costs a byte
        chunks = [message[i:i + size] for i in range(0, len(message), size)] or [b""]
        self._log(f"sending {len(message)} bytes in {len(chunks)} chunk(s)")
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            await self._send_frame(
                KIND_DATA, bytes([CHUNK_LAST if last else CHUNK_MORE]) + chunk)

    async def receive(self, *, timeout: float = 60.0) -> bytes:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TransportError(
                    f"no response within {timeout}s "
                    f"({len(self._parts)} partial chunk(s) buffered)")
            kind, payload = await self._next_frame(remaining)

            if kind == KIND_STATE:
                if payload == STATE_END:
                    self._peer_ended = True
                    raise TransportClosed("peer signalled State=End (0x02)")
                self._log(f"State notification: 0x{payload.hex()}")
                continue
            if kind != KIND_DATA:
                raise TransportError(f"unknown frame kind 0x{kind:02x}")

            prefix, chunk = payload[0], payload[1:]
            self._parts.append(chunk)
            if prefix == CHUNK_LAST:
                message = b"".join(self._parts)
                self._parts = []
                self._log(f"reassembled {len(message)} bytes")
                return message
            if prefix != CHUNK_MORE:
                self._parts = []
                raise TransportError(f"bad chunk prefix 0x{prefix:02x}")

    # --- framing -----------------------------------------------------------

    async def _send_frame(self, kind: int, payload: bytes) -> None:
        if self._writer is None:
            raise TransportError("the transport is not open")
        self._writer.write(bytes([kind]) + len(payload).to_bytes(2, "big") + payload)
        await self._writer.drain()

    async def _next_frame(self, timeout: float) -> tuple[int, bytes]:
        if self._reader is None:
            raise TransportError("the transport is not open")
        try:
            header = await asyncio.wait_for(self._reader.readexactly(3), timeout)
            length = int.from_bytes(header[1:], "big")
            payload = await asyncio.wait_for(
                self._reader.readexactly(length), timeout) if length else b""
        except asyncio.IncompleteReadError as exc:
            # A half-written frame is a dead peer, not a short read: the wallet
            # exited mid-session.
            raise TransportClosed("the wallet closed the socket") from exc
        except asyncio.TimeoutError as exc:
            raise TransportError(f"timed out after {timeout:.1f}s "
                                 "waiting for a frame") from exc
        return header[0], payload

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[tcp] {message}")
