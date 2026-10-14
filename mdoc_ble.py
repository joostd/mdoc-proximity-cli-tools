#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — BLE transport for an mdoc reader (8.3.3.1.1).

Implements **mdoc peripheral server mode** only: the mdoc is the GATT server and
we are the GATT client (BLE central). That is the role CoreBluetooth gives a
Python process on macOS, and it is the mode the EUDI wallet offers.

The other mode (mdoc central client) would make us the GATT *server* and BLE
peripheral. bleak cannot do that at all, so a reader built on this module will
only talk to wallets whose engagement sets BleOptions key 0 = true.

Framing, from 8.3.3.1.1.5 and 8.3.3.1.1.6:

  * subscribe to State and Server2Client notifications
  * write 0x01 (Start) to State
  * every message is split into (MTU - 3)-byte parts, each prefixed
    0x01 "more coming" or 0x00 "last part"
  * client -> server on Client2Server (write without response)
  * server -> client on Server2Client (notify)
  * 0x02 (End) on State closes the transaction

Requires: bleak
"""
from __future__ import annotations

import asyncio
import uuid as _uuid

from bleak import BleakClient, BleakScanner

# Table 11 — mdoc is the GATT server.
STATE_UUID = "00000001-a123-48ce-896b-4c76973373e6"
CLIENT_TO_SERVER_UUID = "00000002-a123-48ce-896b-4c76973373e6"
SERVER_TO_CLIENT_UUID = "00000003-a123-48ce-896b-4c76973373e6"

# Table 12 — reader is the GATT server. Here for reference; unused in this mode.
PERIPHERAL_STATE_UUID = "00000005-a123-48ce-896b-4c76973373e6"
PERIPHERAL_CLIENT_TO_SERVER_UUID = "00000006-a123-48ce-896b-4c76973373e6"
PERIPHERAL_SERVER_TO_CLIENT_UUID = "00000007-a123-48ce-896b-4c76973373e6"
PERIPHERAL_IDENT_UUID = "00000008-a123-48ce-896b-4c76973373e6"

STATE_START = b"\x01"
STATE_END = b"\x02"

CHUNK_MORE = 0x01
CHUNK_LAST = 0x00

DEFAULT_MTU = 23  # the BLE minimum; only used if the stack won't tell us


class BleTransportError(Exception):
    pass


def service_uuid_str(raw: bytes) -> str:
    """16 engagement bytes -> the dashed UUID string bleak expects."""
    if len(raw) != 16:
        raise ValueError(f"service UUID must be 16 bytes, got {len(raw)}")
    return str(_uuid.UUID(bytes=raw))


async def find_mdoc(service_uuid: str, *, timeout: float = 15.0):
    """Scan for a peripheral advertising the engagement's service UUID.

    The UUID is unique per transaction (8.3.3.1.1.3), so a match is as specific
    as it gets. Connecting to the wrong peer is harmless anyway — the session
    simply never forms.
    """
    wanted = service_uuid.lower()

    def matches(_device, advertisement) -> bool:
        return wanted in [u.lower() for u in advertisement.service_uuids]

    return await BleakScanner.find_device_by_filter(matches, timeout=timeout)


class MdocBleReader:
    """GATT-client side of an mdoc BLE session.

    Usage:
        async with MdocBleReader(device) as link:
            await link.send(session_establishment)
            response = await link.receive()
            await link.send(session_termination)
    """

    def __init__(self, device, *, verbose: bool = False):
        self._device = device
        self._verbose = verbose
        self._client: BleakClient | None = None
        self._incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self._parts: list[bytes] = []
        self._state_events: asyncio.Queue[int] = asyncio.Queue()

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "MdocBleReader":
        await self.open()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def open(self) -> None:
        self._client = BleakClient(self._device)
        await self._client.connect()
        self._log(f"connected to {self._device.address}, MTU {self.mtu}")

        # 8.3.3.1.1.5 step order matters: subscribe first, only then signal Start,
        # or the mdoc's first notification can land before we are listening.
        await self._client.start_notify(STATE_UUID, self._on_state)
        await self._client.start_notify(SERVER_TO_CLIENT_UUID, self._on_data)
        await self._client.write_gatt_char(STATE_UUID, STATE_START, response=False)
        self._log("sent State=Start (0x01)")

    async def close(self, *, send_end: bool = True) -> None:
        if self._client is None or not self._client.is_connected:
            return
        try:
            if send_end:
                await self._client.write_gatt_char(STATE_UUID, STATE_END, response=False)
            await self._client.stop_notify(SERVER_TO_CLIENT_UUID)
            await self._client.stop_notify(STATE_UUID)
        except Exception as exc:  # a dropped link during teardown is not interesting
            self._log(f"teardown warning: {exc}")
        finally:
            await self._client.disconnect()
            self._client = None
            self._log("disconnected")

    # --- properties --------------------------------------------------------

    @property
    def mtu(self) -> int:
        try:
            return self._client.mtu_size or DEFAULT_MTU
        except Exception:
            return DEFAULT_MTU

    @property
    def chunk_size(self) -> int:
        """8.3.3.1.1.6 — MTU minus 3. The 3 covers the ATT write header; the
        1-byte continuation prefix comes out of the payload on top of that."""
        return max(self.mtu - 3, 20)

    # --- notification handlers ---------------------------------------------

    def _on_state(self, _characteristic, data: bytearray) -> None:
        value = data[0] if data else -1
        self._log(f"State notification: 0x{value:02x}")
        self._state_events.put_nowait(value)

    def _on_data(self, _characteristic, data: bytearray) -> None:
        if not data:
            return
        prefix, payload = data[0], bytes(data[1:])
        self._parts.append(payload)
        if prefix == CHUNK_LAST:
            message = b"".join(self._parts)
            self._parts = []
            self._log(f"reassembled {len(message)} bytes")
            self._incoming.put_nowait(message)
        elif prefix != CHUNK_MORE:
            self._parts = []
            self._log(f"discarding message: bad chunk prefix 0x{prefix:02x}")

    # --- messages ----------------------------------------------------------

    async def send(self, message: bytes) -> None:
        """Chunk and write one SessionEstablishment / SessionData."""
        size = self.chunk_size - 1  # one byte goes to the continuation prefix
        chunks = [message[i:i + size] for i in range(0, len(message), size)] or [b""]
        self._log(f"sending {len(message)} bytes in {len(chunks)} chunk(s) of <= {size}")

        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            await self._client.write_gatt_char(
                CLIENT_TO_SERVER_UUID,
                bytes([CHUNK_LAST if last else CHUNK_MORE]) + chunk,
                response=False,
            )

    async def receive(self, *, timeout: float = 60.0) -> bytes:
        """Wait for one fully reassembled message from the mdoc.

        The timeout is generous on purpose: the holder has to consent on the
        handset between our request and their response.
        """
        try:
            return await asyncio.wait_for(self._incoming.get(), timeout)
        except asyncio.TimeoutError as exc:
            raise BleTransportError(
                f"no response within {timeout}s "
                f"({len(self._parts)} partial chunk(s) buffered)") from exc

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[ble] {message}")
