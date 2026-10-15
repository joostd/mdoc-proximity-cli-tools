#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — BLE transport for an mdoc reader (8.3.3.1.1).

Implements **mdoc peripheral server mode**: the mdoc is the GATT server and we
are the GATT client (BLE central). That is the mode the EUDI wallet offers, and
the only one bleak can do — it is a central-only library.

The other mode (mdoc central client) makes us the GATT *server* and BLE
peripheral. That lives in `mdoc_ble_peripheral`, which goes under bleak to
CoreBluetooth directly. The two modules present the same interface, so
`mdoc_reader` picks between them on the engagement alone.

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

from bleak import BleakClient, BleakScanner

from mdoc_transport import (  # noqa: F401 — re-exported for existing callers
    CHUNK_LAST,
    CHUNK_MORE,
    CLIENT_TO_SERVER_UUID,
    PERIPHERAL_CLIENT_TO_SERVER_UUID,
    PERIPHERAL_IDENT_UUID,
    PERIPHERAL_SERVER_TO_CLIENT_UUID,
    PERIPHERAL_STATE_UUID,
    SERVER_TO_CLIENT_UUID,
    STATE_END,
    STATE_START,
    STATE_UUID,
    TransportError,
    service_uuid_str,
)

DEFAULT_MTU = 23  # the BLE minimum; only used if the stack won't tell us
MAX_ATTRIBUTE_VALUE = 512  # Core 5.3 Vol 3 Part F 3.2.9; see `chunk_size`


class BleTransportError(TransportError):
    pass


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
        async with MdocBleReader(device, service_uuid) as link:
            await link.send(session_establishment)
            response = await link.receive()
            await link.send(session_termination)
    """

    def __init__(self, device, service_uuid: str, *, verbose: bool = False):
        self._device = device
        self._service_uuid = service_uuid
        self._verbose = verbose
        self._client: BleakClient | None = None
        self._incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self._parts: list[bytes] = []
        self._state_events: asyncio.Queue[int] = asyncio.Queue()
        self._state = self._client_to_server = self._server_to_client = None

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "MdocBleReader":
        await self.open()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    def _resolve_characteristics(self) -> None:
        """Bind the three characteristics *inside our service*.

        Not by bare UUID across the whole GATT database. Every transaction uses
        a fresh service UUID but the same three characteristic UUIDs, and macOS
        caches a peripheral's services, so the second time you talk to a wallet
        there are several characteristics called `00000001-a123-…`. bleak
        refuses to guess between them, and it is right to: writing Start to a
        dead service's State would hang with no diagnostic.
        """
        wanted = self._service_uuid.lower()
        services = [s for s in self._client.services if s.uuid.lower() == wanted]
        if not services:
            offered = [s.uuid for s in self._client.services]
            raise BleTransportError(
                f"peripheral offers no service {self._service_uuid}; it has {offered}")
        if len(services) > 1:
            # Shouldn't happen — the UUID is per-transaction — but if the cache
            # has gone strange, the newest copy is the live one.
            self._log(f"{len(services)} copies of {wanted} cached; using the last")
        service = services[-1]

        def pick(uuid: str, name: str):
            for characteristic in service.characteristics:
                if characteristic.uuid.lower() == uuid.lower():
                    return characteristic
            raise BleTransportError(
                f"service {service.uuid} has no {name} characteristic ({uuid}). "
                "Is the mdoc in peripheral server mode?")

        self._state = pick(STATE_UUID, "State")
        self._client_to_server = pick(CLIENT_TO_SERVER_UUID, "Client2Server")
        self._server_to_client = pick(SERVER_TO_CLIENT_UUID, "Server2Client")
        self._log(f"service {service.uuid}: State h{self._state.handle}, "
                  f"Client2Server h{self._client_to_server.handle}, "
                  f"Server2Client h{self._server_to_client.handle}")

    async def open(self) -> None:
        self._client = BleakClient(self._device)
        await self._client.connect()
        self._log(f"connected to {self._device.address}, MTU {self.mtu}")
        self._resolve_characteristics()

        # 8.3.3.1.1.5 step order matters: subscribe first, only then signal Start,
        # or the mdoc's first notification can land before we are listening.
        await self._client.start_notify(self._state, self._on_state)
        await self._client.start_notify(self._server_to_client, self._on_data)
        await self._client.write_gatt_char(self._state, STATE_START, response=False)
        self._log("sent State=Start (0x01)")

    async def close(self, *, send_end: bool = True) -> None:
        """Signal End and drop the link, on a clock.

        Every step here is bounded, because by this point we already have the
        DeviceResponse and nothing the peer does should be able to hold it
        hostage. That is not hypothetical: an mdoc that unregisters its GATT
        application the instant it sees the termination leaves our
        `stop_notify` waiting on handles that no longer exist, and bleak waits
        forever. The response was already in hand; the verdict was not.
        """
        if self._client is None or not self._client.is_connected:
            return
        try:
            if send_end:
                await self._bounded(
                    self._client.write_gatt_char(self._state, STATE_END,
                                                 response=False))
            await self._bounded(self._client.stop_notify(self._server_to_client))
            await self._bounded(self._client.stop_notify(self._state))
        except Exception as exc:  # a dropped link during teardown is not interesting
            # `str()` on a TimeoutError is empty, and that is the one we expect
            # most here — print the class when there is nothing else to print.
            self._log(f"teardown warning: {str(exc) or type(exc).__name__}")
        finally:
            try:
                await self._bounded(self._client.disconnect())
            except Exception as exc:
                self._log(f"disconnect warning: {str(exc) or type(exc).__name__}")
            self._client = None
            self._log("disconnected")

    @staticmethod
    async def _bounded(awaitable, timeout: float = 3.0):
        return await asyncio.wait_for(awaitable, timeout)

    # --- properties --------------------------------------------------------

    @property
    def mtu(self) -> int:
        try:
            return self._client.mtu_size or DEFAULT_MTU
        except Exception:
            return DEFAULT_MTU

    @property
    def chunk_size(self) -> int:
        """8.3.3.1.1.6 — MTU minus 3, capped at 512.

        The 3 covers the ATT write header; the 1-byte continuation prefix
        comes out of the payload on top of that. The cap is GATT's maximum
        attribute value length, which 18013-5 does not mention and which bites
        above MTU 515 — `mdoc_ble_holder.chunk_size` tells that story. macOS
        hides it here, because bleak derives `mtu_size` from
        `maximumWriteValueLength`, which Apple already caps at 512.
        """
        return max(min(self.mtu - 3, MAX_ATTRIBUTE_VALUE), 20)

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
                self._client_to_server,
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
