#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — BLE transport for **mdoc central client mode** (8.3.3.1.1).

The mirror image of `mdoc_ble`. Here the *mdoc* is the BLE central and GATT
client, and the **reader** — us — is the BLE peripheral and GATT server. We
advertise the engagement's central-client UUID, publish the Table 12 service,
and wait for the wallet to come to us.

bleak cannot do this; it is a central-only library. CoreBluetooth can, via
`CBPeripheralManager`, which PyObjC exposes to Python. So on macOS the mode is
reachable after all — it just cannot be reached through bleak.

Table 12 differs from Table 11 in two ways that matter:

  * The UUIDs are 0x0005–0x0008, not 0x0001–0x0003.
  * There is an **Ident** characteristic, which the mdoc reads to check it has
    found the right reader. We serve it; `mdoc_transcript.ble_ident` computes
    it. Note the direction — this is the reader proving itself to the mdoc,
    not the other way round.

Roles swap but the characteristic *names* do not: `Server2Client` is still the
one carrying reader→mdoc traffic, and it is now ours to notify on rather than
to subscribe to.

Threading: CoreBluetooth delivers delegate callbacks on a dispatch queue, so
everything below hops back to the asyncio loop with `call_soon_threadsafe`.
Nothing in the delegate touches asyncio objects directly.

Requires: pyobjc-framework-CoreBluetooth
"""
from __future__ import annotations

import asyncio

import libdispatch
import objc
from CoreBluetooth import (
    CBAdvertisementDataLocalNameKey,
    CBAdvertisementDataServiceUUIDsKey,
    CBATTErrorAttributeNotFound,
    CBATTErrorSuccess,
    CBAttributePermissionsReadable,
    CBAttributePermissionsWriteable,
    CBCharacteristicPropertyNotify,
    CBCharacteristicPropertyRead,
    CBCharacteristicPropertyWriteWithoutResponse,
    CBManagerStatePoweredOn,
    CBMutableCharacteristic,
    CBMutableService,
    CBPeripheralManager,
    CBUUID,
)
from Foundation import NSData, NSObject

from mdoc_transport import TransportError

# Table 12 — the mdoc reader is the GATT server.
STATE_UUID = "00000005-A123-48CE-896B-4C76973373E6"
CLIENT_TO_SERVER_UUID = "00000006-A123-48CE-896B-4C76973373E6"
SERVER_TO_CLIENT_UUID = "00000007-A123-48CE-896B-4C76973373E6"
IDENT_UUID = "00000008-A123-48CE-896B-4C76973373E6"

STATE_START = 0x01
STATE_END = 0x02

CHUNK_MORE = 0x01
CHUNK_LAST = 0x00

DEFAULT_CHUNK = 20  # ATT_MTU 23 minus 3; only used until a central subscribes


class BlePeripheralError(TransportError):
    pass


def service_uuid_str(raw: bytes) -> str:
    """16 engagement bytes -> the dashed UUID string CoreBluetooth expects."""
    import uuid as _uuid

    if len(raw) != 16:
        raise ValueError(f"service UUID must be 16 bytes, got {len(raw)}")
    return str(_uuid.UUID(bytes=raw))


class _PeripheralDelegate(NSObject):
    """CBPeripheralManagerDelegate. Lives on the dispatch queue."""

    def initWithOwner_(self, owner):
        self = objc.super(_PeripheralDelegate, self).init()
        if self is None:
            return None
        self._owner = owner
        return self

    # --- lifecycle ---------------------------------------------------------

    def peripheralManagerDidUpdateState_(self, manager):
        self._owner._on_state_change(manager.state())

    def peripheralManager_didAddService_error_(self, manager, service, error):
        self._owner._on_service_added(error)

    def peripheralManagerDidStartAdvertising_error_(self, manager, error):
        self._owner._on_advertising_started(error)

    # --- the mdoc arrives --------------------------------------------------

    def peripheralManager_central_didSubscribeToCharacteristic_(
            self, manager, central, characteristic):
        self._owner._on_subscribe(str(characteristic.UUID()),
                                  central.maximumUpdateValueLength())

    def peripheralManager_central_didUnsubscribeFromCharacteristic_(
            self, manager, central, characteristic):
        self._owner._log(f"central unsubscribed from {characteristic.UUID()}")

    def peripheralManager_didReceiveReadRequest_(self, manager, request):
        uuid = str(request.characteristic().UUID()).upper()
        if uuid != IDENT_UUID.upper():
            manager.respondToRequest_withResult_(request, CBATTErrorAttributeNotFound)
            return
        value = self._owner._ident[request.offset():]
        request.setValue_(NSData.dataWithBytes_length_(value, len(value)))
        manager.respondToRequest_withResult_(request, CBATTErrorSuccess)
        self._owner._log(f"served Ident ({len(value)} bytes from offset "
                         f"{request.offset()})")

    def peripheralManager_didReceiveWriteRequests_(self, manager, requests):
        for request in requests:
            value = request.value()
            self._owner._on_write(str(request.characteristic().UUID()),
                                  bytes(value) if value else b"")
        # Apple requires exactly one response, for the first request, even
        # though these are Write Without Response at the ATT layer.
        if requests:
            manager.respondToRequest_withResult_(requests[0], CBATTErrorSuccess)

    def peripheralManagerIsReadyToUpdateSubscribers_(self, manager):
        self._owner._on_ready_to_update()


class MdocBlePeripheral:
    """GATT-server side of an mdoc BLE session (mdoc central client mode).

    Usage mirrors MdocBleReader:

        async with MdocBlePeripheral(service_uuid, ident) as link:
            await link.send(session_establishment)
            response = await link.receive()
    """

    def __init__(self, service_uuid: str, ident: bytes, *, verbose: bool = False):
        self._service_uuid = service_uuid
        self._ident = ident
        self._verbose = verbose

        self._loop = asyncio.get_event_loop()
        self._queue = libdispatch.dispatch_queue_create(b"mdoc.ble.peripheral", None)
        self._delegate = _PeripheralDelegate.alloc().initWithOwner_(self)
        self._manager = None

        self._powered_on = self._loop.create_future()
        self._service_added = self._loop.create_future()
        self._advertising = self._loop.create_future()
        self._started = self._loop.create_future()

        self._incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self._parts: list[bytes] = []
        self._chunk = DEFAULT_CHUNK
        self._ready = asyncio.Event()
        self._ready.set()
        self._s2c = None
        self._state = None

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "MdocBlePeripheral":
        await self.open()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def open(self, *, timeout: float = 120.0) -> None:
        """Advertise, then block until the mdoc connects and signals Start."""
        self._manager = CBPeripheralManager.alloc().initWithDelegate_queue_(
            self._delegate, self._queue)

        await self._await(self._powered_on, 10.0, "Bluetooth did not power on")
        self._log("peripheral manager powered on")

        self._publish_service()
        await self._await(self._service_added, 10.0, "service was not added")
        self._log(f"published Table 12 service {self._service_uuid}")

        # The empty local name is load-bearing. Omit the key and CoreBluetooth
        # advertises the Mac's system name ("Joost's MacBook Pro", 20-odd
        # bytes), which together with an 18-byte 128-bit UUID overflows the
        # 31-byte advertising payload. CoreBluetooth's answer is to move the
        # UUID into Apple's proprietary *overflow area*, which only Apple
        # devices can decode — so an Android wallet scanning for exactly this
        # UUID sees nothing at all, with no error on either side.
        self._manager.startAdvertising_({
            CBAdvertisementDataLocalNameKey: "",
            CBAdvertisementDataServiceUUIDsKey: [
                CBUUID.UUIDWithString_(self._service_uuid)],
        })
        await self._await(self._advertising, 10.0, "advertising did not start")
        self._log("advertising; waiting for the wallet to connect")

        # 8.3.3.1.1.6 — the GATT client signals Start before any data moves.
        await self._await(self._started, timeout,
                          f"the mdoc did not signal Start within {timeout:.0f}s")
        self._log(f"got State=Start; chunk size {self._chunk}")

    def _publish_service(self) -> None:
        def characteristic(uuid, properties, permissions, value=None):
            return CBMutableCharacteristic.alloc().initWithType_properties_value_permissions_(
                CBUUID.UUIDWithString_(uuid), properties, value, permissions)

        self._state = characteristic(
            STATE_UUID,
            CBCharacteristicPropertyNotify | CBCharacteristicPropertyWriteWithoutResponse,
            CBAttributePermissionsWriteable)
        client_to_server = characteristic(
            CLIENT_TO_SERVER_UUID,
            CBCharacteristicPropertyWriteWithoutResponse,
            CBAttributePermissionsWriteable)
        self._s2c = characteristic(
            SERVER_TO_CLIENT_UUID,
            CBCharacteristicPropertyNotify,
            CBAttributePermissionsReadable)
        # Ident could be given its value here — CoreBluetooth serves a
        # constructed-with-value characteristic from cache, which is legal for
        # read-only ones. We answer the read by hand instead, purely so the
        # read is visible: "did the wallet check Ident, and did it like the
        # answer?" is the first question when a session dies before Start.
        ident = characteristic(
            IDENT_UUID,
            CBCharacteristicPropertyRead,
            CBAttributePermissionsReadable)

        service = CBMutableService.alloc().initWithType_primary_(
            CBUUID.UUIDWithString_(self._service_uuid), True)
        service.setCharacteristics_(
            [self._state, client_to_server, self._s2c, ident])
        self._manager.addService_(service)

    async def close(self, *, send_end: bool = True) -> None:
        if self._manager is None:
            return
        try:
            if send_end and self._state is not None:
                self._notify(self._state, bytes([STATE_END]))
            self._manager.stopAdvertising()
            self._manager.removeAllServices()
        except Exception as exc:
            self._log(f"teardown warning: {exc}")
        finally:
            self._manager = None
            self._log("stopped advertising")

    # --- messages ----------------------------------------------------------

    async def send(self, message: bytes) -> None:
        """Chunk and notify one SessionEstablishment / SessionData."""
        size = self._chunk - 1  # one byte goes to the continuation prefix
        chunks = [message[i:i + size] for i in range(0, len(message), size)] or [b""]
        self._log(f"sending {len(message)} bytes in {len(chunks)} chunk(s) of <= {size}")

        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            payload = bytes([CHUNK_LAST if last else CHUNK_MORE]) + chunk
            while not self._notify(self._s2c, payload):
                # The transmit queue is full; CoreBluetooth will call
                # peripheralManagerIsReadyToUpdateSubscribers: when it drains.
                self._ready.clear()
                await self._ready.wait()

    def _notify(self, characteristic, payload: bytes) -> bool:
        return bool(self._manager.updateValue_forCharacteristic_onSubscribedCentrals_(
            NSData.dataWithBytes_length_(payload, len(payload)),
            characteristic, None))

    async def receive(self, *, timeout: float = 60.0) -> bytes:
        try:
            return await asyncio.wait_for(self._incoming.get(), timeout)
        except asyncio.TimeoutError as exc:
            raise BlePeripheralError(
                f"no response within {timeout}s "
                f"({len(self._parts)} partial chunk(s) buffered)") from exc

    # --- delegate callbacks, all arriving on the dispatch queue -------------

    def _on_state_change(self, state) -> None:
        if state == CBManagerStatePoweredOn:
            self._resolve(self._powered_on, None)
        else:
            self._resolve(self._powered_on, BlePeripheralError(
                f"Bluetooth is not powered on (CBManagerState {state})"))

    def _on_service_added(self, error) -> None:
        self._resolve(self._service_added,
                      BlePeripheralError(str(error)) if error else None)

    def _on_advertising_started(self, error) -> None:
        self._resolve(self._advertising,
                      BlePeripheralError(str(error)) if error else None)

    def _on_subscribe(self, uuid: str, max_update_length: int) -> None:
        # maximumUpdateValueLength is already ATT_MTU - 3, so it *is* the
        # chunk size 8.3.3.1.1.6 asks for. Subtracting 3 again would work but
        # waste three bytes per notification.
        self._loop.call_soon_threadsafe(self._set_chunk, uuid, max_update_length)

    def _set_chunk(self, uuid: str, max_update_length: int) -> None:
        self._chunk = max(max_update_length, DEFAULT_CHUNK)
        self._log(f"central subscribed to {uuid}, max update {max_update_length}")

    def _on_write(self, uuid: str, value: bytes) -> None:
        self._loop.call_soon_threadsafe(self._handle_write, uuid.upper(), value)

    def _handle_write(self, uuid: str, value: bytes) -> None:
        if uuid == STATE_UUID.upper():
            command = value[0] if value else -1
            self._log(f"State written: 0x{command:02x}")
            if command == STATE_START and not self._started.done():
                self._started.set_result(None)
            return

        if uuid != CLIENT_TO_SERVER_UUID.upper() or not value:
            return
        prefix, payload = value[0], value[1:]
        self._parts.append(payload)
        if prefix == CHUNK_LAST:
            message = b"".join(self._parts)
            self._parts = []
            self._log(f"reassembled {len(message)} bytes")
            self._incoming.put_nowait(message)
        elif prefix != CHUNK_MORE:
            self._parts = []
            self._log(f"discarding message: bad chunk prefix 0x{prefix:02x}")

    def _on_ready_to_update(self) -> None:
        self._loop.call_soon_threadsafe(self._ready.set)

    # --- plumbing ----------------------------------------------------------

    def _resolve(self, future: asyncio.Future, error) -> None:
        def complete():
            if future.done():
                return
            if error is None:
                future.set_result(None)
            else:
                future.set_exception(error)

        self._loop.call_soon_threadsafe(complete)

    async def _await(self, future: asyncio.Future, timeout: float, message: str):
        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout)
        except asyncio.TimeoutError as exc:
            raise BlePeripheralError(message) from exc

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[ble-peripheral] {message}")
