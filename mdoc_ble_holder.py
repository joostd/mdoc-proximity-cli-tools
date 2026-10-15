#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 — BLE transport for an **mdoc** (8.3.3.1.1), over BlueZ.

The repo's third BLE transport and the first that is not a reader. All three
speak the same framing; what differs is which end of the GATT link you are.

    mdoc_ble.py             reader as GATT client   Table 11   bleak / macOS
    mdoc_ble_peripheral.py  reader as GATT server   Table 12   CoreBluetooth
    mdoc_ble_holder.py      *mdoc* as GATT server   Table 11   BlueZ / Linux

This one is the counterparty to `mdoc_ble`: mdoc peripheral server mode, the
same three characteristics that module connects to, with every direction
reversed.

    mdoc_ble (reader)               mdoc_ble_holder (mdoc)
    ---------------------------     ------------------------------
    subscribes to State             receives Start/End writes there
    writes Client2Server            receives Client2Server writes
    subscribes to Server2Client     notifies on Server2Client

Neither existing module could be adapted: bleak is central-only, and
CoreBluetooth is not on a Raspberry Pi. BlueZ exposes a GATT server over
D-Bus instead — export objects implementing org.bluez.GattService1 and
GattCharacteristic1, hand the tree to GattManager1.RegisterApplication, and
register an LEAdvertisement1 so the reader can find the per-transaction
service UUID.

Two things a GATT server learns differently from a client:

  * **The MTU.** There is nothing to query. BlueZ passes it in the `options`
    dict of every ReadValue/WriteValue, so we take it from the reader's first
    write — which is State=Start, before any data, exactly when we need it.
  * **When the peer is ready.** A client knows it has subscribed; a server has
    to wait to be subscribed to. `open()` waits for Server2Client notifications
    to be enabled *and* for State=Start, in whichever order they arrive.

Threading: dbus-python drives a GLib main loop, which cannot share a thread
with asyncio. The loop runs in a daemon thread; D-Bus callbacks hop back with
`loop.call_soon_threadsafe` and notifications hop out with `GLib.idle_add`.
Same shape as the CoreBluetooth bridge in `mdoc_ble_peripheral`.

Requires: dbus-python, PyGObject, BlueZ 5.48+. Linux only.
"""
from __future__ import annotations

import asyncio
import threading

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from mdoc_transport import (
    CHUNK_LAST,
    CHUNK_MORE,
    CLIENT_TO_SERVER_UUID,
    SERVER_TO_CLIENT_UUID,
    STATE_UUID,
    TransportClosed,
    TransportError,
)

BLUEZ = "org.bluez"
ADAPTER_IFACE = "org.bluez.Adapter1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
SERVICE_IFACE = "org.bluez.GattService1"
CHARACTERISTIC_IFACE = "org.bluez.GattCharacteristic1"
ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"
OBJECT_MANAGER_IFACE = "org.freedesktop.DBus.ObjectManager"
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"

APP_PATH = "/org/mdoc/holder"

DEFAULT_MTU = 23  # the BLE minimum; only used until the reader's first write

# Core 5.3 Vol 3 Part F 3.2.9: an attribute value is never longer than 512
# octets, whatever the MTU. A notification carries an attribute value, so this
# caps a chunk too — see `MdocBleHolder.chunk_size`.
MAX_ATTRIBUTE_VALUE = 512

# State characteristic values, as ints — a D-Bus byte array arrives as a list
# of ints, so comparing against bytes would need a conversion at every use.
STATE_START_BYTE = 0x01
STATE_END_BYTE = 0x02


class BleHolderError(TransportError):
    pass


# --- D-Bus plumbing ---------------------------------------------------------

class _Advertisement(dbus.service.Object):
    """org.bluez.LEAdvertisement1 — one 128-bit service UUID and nothing else.

    A complete 128-bit UUID list is 18 of the 31 advertising bytes, so there is
    no room to be generous. No local name: the reader matches on the UUID,
    which is unique to this transaction anyway (8.3.3.1.1.3).
    """

    def __init__(self, bus, path: str, service_uuid: str):
        self.path = path
        self._service_uuid = service_uuid
        super().__init__(bus, path)

    @dbus.service.method(PROPERTIES_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs")
        return {
            "Type": dbus.String("peripheral"),
            "ServiceUUIDs": dbus.Array([self._service_uuid], signature="s"),
            # The mdoc is not a general-purpose peripheral; it exists for this
            # one session and should not linger in anyone's device list.
            "Discoverable": dbus.Boolean(True),
        }

    @dbus.service.method(ADVERTISEMENT_IFACE, in_signature="", out_signature="")
    def Release(self):
        pass


class _Service(dbus.service.Object):
    """org.bluez.GattService1 — the per-transaction primary service.

    Exported as a real D-Bus object rather than existing only in the
    `GetManagedObjects` reply. BlueZ builds a proxy per managed object and
    wants to be able to read properties off it; a path with nothing behind it
    makes the whole application register successfully and then expose nothing,
    which shows up as `gatt-database.c:client_ready_cb() No object received`
    in the bluetoothd journal and as a missing service on the reader.
    """

    def __init__(self, bus, path: str, uuid: str):
        self.path = path
        self._uuid = uuid
        super().__init__(bus, path)

    def properties(self) -> dict:
        return {
            "UUID": dbus.String(self._uuid),
            "Primary": dbus.Boolean(True),
        }

    @dbus.service.method(PROPERTIES_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != SERVICE_IFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs")
        return self.properties()


class _Characteristic(dbus.service.Object):
    """One org.bluez.GattCharacteristic1.

    `on_write` is called with (value, options) on the GLib thread; `notify`
    pushes a value out as a PropertiesChanged signal, which is how BlueZ
    delivers a notification to a subscribed client.
    """

    def __init__(self, bus, path: str, uuid: str, flags: list[str],
                 service_path: str, on_write=None, on_notifying=None):
        self.path = path
        self._uuid = uuid
        self._flags = flags
        self._service_path = service_path
        self._on_write = on_write
        self._on_notifying = on_notifying
        self.notifying = False
        self.value: list[int] = []
        super().__init__(bus, path)

    def properties(self) -> dict:
        return {
            "UUID": dbus.String(self._uuid),
            "Service": dbus.ObjectPath(self._service_path),
            "Flags": dbus.Array(self._flags, signature="s"),
            "Value": dbus.Array(self.value, signature="y"),
        }

    @dbus.service.method(PROPERTIES_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != CHARACTERISTIC_IFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs")
        return self.properties()

    @dbus.service.signal(PROPERTIES_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    @dbus.service.method(CHARACTERISTIC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        return dbus.Array(self.value, signature="y")

    @dbus.service.method(CHARACTERISTIC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        if self._on_write is not None:
            self._on_write(bytes(bytearray(value)), options)

    @dbus.service.method(CHARACTERISTIC_IFACE)
    def StartNotify(self):
        self.notifying = True
        if self._on_notifying is not None:
            self._on_notifying(True)

    @dbus.service.method(CHARACTERISTIC_IFACE)
    def StopNotify(self):
        self.notifying = False
        if self._on_notifying is not None:
            self._on_notifying(False)

    def notify(self, payload: bytes) -> None:
        """Emit one notification. Must run on the GLib thread."""
        if not self.notifying:
            return
        self.value = list(payload)
        self.PropertiesChanged(
            CHARACTERISTIC_IFACE,
            {"Value": dbus.Array(self.value, signature="y")},
            [])


class _Application(dbus.service.Object):
    """The ObjectManager BlueZ walks to discover our service and characteristics."""

    def __init__(self, bus, path: str, on_queried=None):
        self.path = path
        self.service: _Service | None = None
        self.characteristics: list[_Characteristic] = []
        self._on_queried = on_queried
        super().__init__(bus, path)

    def add_characteristic(self, characteristic: _Characteristic) -> None:
        self.characteristics.append(characteristic)

    @dbus.service.method(OBJECT_MANAGER_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        objects = {
            dbus.ObjectPath(self.service.path): {
                SERVICE_IFACE: self.service.properties()
            }
        }
        for characteristic in self.characteristics:
            objects[dbus.ObjectPath(characteristic.path)] = {
                CHARACTERISTIC_IFACE: characteristic.properties()
            }
        if self._on_queried is not None:
            self._on_queried(len(objects))
        return objects


# --- the transport ----------------------------------------------------------

class MdocBleHolder:
    """GATT-server side of an mdoc BLE session, satisfying `MdocTransport`.

    Usage:
        async with MdocBleHolder(service_uuid) as link:
            await session.serve(link)
    """

    def __init__(self, service_uuid: str, *, adapter: str = "hci0",
                 verbose: bool = False):
        self._service_uuid = service_uuid.lower()
        self._adapter = adapter
        self._verbose = verbose

        # Rebound in open(), which is guaranteed to be inside the running loop.
        self._loop = asyncio.get_event_loop()
        self._app_registered: asyncio.Future | None = None
        self._advertisement_registered: asyncio.Future | None = None
        self._incoming: asyncio.Queue[bytes] = asyncio.Queue()
        self._parts: list[bytes] = []
        self._mtu = DEFAULT_MTU
        self._closed = False
        self._ended = asyncio.Event()
        self._subscribed = asyncio.Event()
        self._started = asyncio.Event()

        self._bus = None
        self._glib_loop = None
        self._glib_thread: threading.Thread | None = None
        self._app = None
        self._advertisement = None
        self._state = self._client_to_server = self._server_to_client = None
        self._registered = False

    # --- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> "MdocBleHolder":
        await self.open()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def open(self, *, timeout: float = 120.0) -> None:
        """Advertise, then wait for a reader to subscribe and send Start.

        The timeout is long because this end does the waiting: between
        advertising and State=Start sits however long it takes someone to
        point a reader at the QR.
        """
        self._loop = asyncio.get_running_loop()
        self._app_registered = self._loop.create_future()
        self._advertisement_registered = self._loop.create_future()

        self._start_glib()
        await self._run_on_glib(self._build_and_register)
        await asyncio.wait_for(
            asyncio.gather(self._app_registered, self._advertisement_registered),
            30.0)
        self._registered = True
        self._log(f"advertising {self._service_uuid} on {self._adapter}")

        # 8.3.3.1.1.5 — the reader subscribes, then writes Start. Both have to
        # land before we are allowed to notify anything; waiting on only one of
        # them is how you get a response that goes nowhere.
        try:
            await asyncio.wait_for(
                asyncio.gather(self._subscribed.wait(), self._started.wait()),
                timeout)
        except asyncio.TimeoutError as exc:
            raise BleHolderError(
                f"no reader subscribed and sent State=Start within {timeout}s"
            ) from exc
        self._log(f"reader ready, MTU {self._mtu}, chunk size {self.chunk_size}")

    async def close(self, *, send_end: bool = True) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if send_end and self._state is not None and self._state.notifying:
                await self._run_on_glib(
                    lambda: self._state.notify(bytes([STATE_END_BYTE])))
            await self._run_on_glib(self._unregister)
        except Exception as exc:  # teardown of a link that is already gone
            self._log(f"teardown warning: {exc}")
        finally:
            self._stop_glib()
            self._log("stopped advertising")

    # --- properties --------------------------------------------------------

    @property
    def mtu(self) -> int:
        return self._mtu

    @property
    def chunk_size(self) -> int:
        """8.3.3.1.1.6 — MTU minus 3, but never more than 512.

        18013-5 says MTU - 3 and stops there, which is fine while the MTU is
        below 516. Above that it collides with GATT: an attribute value is at
        most 512 octets (Core 5.3 Vol 3 Part F 3.2.9), and a notification
        carries an attribute value. At the 517 this Pi and this Mac negotiate,
        MTU - 3 is 514 — and BlueZ truncates each notification to 512 without
        saying so. Two bytes vanish per full chunk, the reassembled
        DeviceResponse is short, and the only symptom is a CBOR decode error
        at the far end, long after the damage.
        """
        return max(min(self._mtu - 3, MAX_ATTRIBUTE_VALUE), 20)

    # --- messages ----------------------------------------------------------

    async def send(self, message: bytes) -> None:
        """Chunk one DeviceResponse out over Server2Client notifications."""
        if self._closed:
            raise BleHolderError("transport is closed")
        size = self.chunk_size - 1  # one byte goes to the continuation prefix
        chunks = [message[i:i + size] for i in range(0, len(message), size)] or [b""]
        self._log(f"sending {len(message)} bytes in {len(chunks)} chunk(s) of <= {size}")

        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            payload = bytes([CHUNK_LAST if last else CHUNK_MORE]) + chunk
            await self._run_on_glib(
                lambda p=payload: self._server_to_client.notify(p))
            # BlueZ queues notifications but a long burst can outrun a central
            # that is slow to ack. Yielding between chunks costs nothing here
            # and keeps the GLib thread from starving the asyncio one.
            await asyncio.sleep(0)

    async def receive(self, *, timeout: float = 60.0) -> bytes:
        """Wait for one fully reassembled message, or for the reader to end it."""
        getter = asyncio.ensure_future(self._incoming.get())
        ender = asyncio.ensure_future(self._ended.wait())
        try:
            done, _ = await asyncio.wait(
                {getter, ender}, timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED)
            if getter in done:
                return getter.result()
            if ender in done:
                raise TransportClosed("reader signalled State=End (0x02)")
            raise BleHolderError(
                f"no message within {timeout}s "
                f"({len(self._parts)} partial chunk(s) buffered)")
        finally:
            for task in (getter, ender):
                if not task.done():
                    task.cancel()

    # --- D-Bus callbacks, all on the GLib thread ---------------------------

    def _on_state_write(self, value: bytes, options) -> None:
        self._note_mtu(options)
        command = value[0] if value else -1
        self._log(f"State write: 0x{command:02x}")
        if command == STATE_START_BYTE:
            self._loop.call_soon_threadsafe(self._started.set)
        elif command == STATE_END_BYTE:
            self._loop.call_soon_threadsafe(self._ended.set)

    def _on_data_write(self, value: bytes, options) -> None:
        self._note_mtu(options)
        if not value:
            return
        prefix, payload = value[0], value[1:]
        self._parts.append(payload)
        if prefix == CHUNK_LAST:
            message = b"".join(self._parts)
            self._parts = []
            self._log(f"reassembled {len(message)} bytes")
            self._loop.call_soon_threadsafe(self._incoming.put_nowait, message)
        elif prefix != CHUNK_MORE:
            self._parts = []
            self._log(f"discarding message: bad chunk prefix 0x{prefix:02x}")

    def _on_subscribed(self, notifying: bool) -> None:
        self._log(f"Server2Client notifications {'on' if notifying else 'off'}")
        if notifying:
            self._loop.call_soon_threadsafe(self._subscribed.set)

    def _note_mtu(self, options) -> None:
        """The only place a BlueZ GATT server is told the negotiated MTU."""
        mtu = options.get("mtu")
        if mtu and int(mtu) != self._mtu:
            self._mtu = int(mtu)
            self._log(f"MTU is {self._mtu}")

    # --- GLib thread -------------------------------------------------------

    def _start_glib(self) -> None:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self._bus = dbus.SystemBus()
        self._glib_loop = GLib.MainLoop()
        self._glib_thread = threading.Thread(
            target=self._glib_loop.run, name="mdoc-bluez", daemon=True)
        self._glib_thread.start()

    def _stop_glib(self) -> None:
        if self._glib_loop is not None:
            self._glib_loop.quit()
            self._glib_loop = None

    async def _run_on_glib(self, function):
        """Run `function` on the GLib thread and await its result.

        dbus-python is not thread-safe, so every call into it — registering the
        application, emitting a notification — has to be funnelled here.
        """
        future = self._loop.create_future()

        def invoke():
            try:
                result = function()
            except Exception as exc:  # noqa: BLE001 — forwarded to the awaiter
                self._loop.call_soon_threadsafe(future.set_exception, exc)
            else:
                self._loop.call_soon_threadsafe(future.set_result, result)
            return False  # GLib.idle_add: do not repeat

        GLib.idle_add(invoke)
        return await future

    # --- registration, on the GLib thread ----------------------------------

    def _build_and_register(self) -> None:
        """Export the GATT tree and ask BlueZ to take it.

        Both Register* calls are made asynchronously, and that is not a style
        preference. `RegisterApplication` makes BlueZ turn around and call
        `GetManagedObjects` on *us* over the same connection; a blocking call
        would still be holding the GLib thread when that arrives, so we could
        never answer it and BlueZ would eventually give up with NoReply. The
        reply handlers resolve futures that `open()` awaits.
        """
        adapter_path = f"/org/bluez/{self._adapter}"
        adapter = dbus.Interface(
            self._bus.get_object(BLUEZ, adapter_path), PROPERTIES_IFACE)
        adapter.Set(ADAPTER_IFACE, "Powered", dbus.Boolean(True))

        self._app = _Application(
            self._bus, APP_PATH,
            on_queried=lambda n: self._log(f"BlueZ read {n} managed object(s)"))
        service_path = APP_PATH + "/service0"
        self._app.service = _Service(self._bus, service_path, self._service_uuid)

        # Table 11. State is written by the reader *and* notified by us (we
        # send End on teardown), so it carries both flags.
        self._state = _Characteristic(
            self._bus, service_path + "/char0", STATE_UUID,
            ["write-without-response", "notify"], service_path,
            on_write=self._on_state_write)
        self._client_to_server = _Characteristic(
            self._bus, service_path + "/char1", CLIENT_TO_SERVER_UUID,
            ["write-without-response"], service_path,
            on_write=self._on_data_write)
        self._server_to_client = _Characteristic(
            self._bus, service_path + "/char2", SERVER_TO_CLIENT_UUID,
            ["notify"], service_path,
            on_notifying=self._on_subscribed)
        for characteristic in (self._state, self._client_to_server,
                               self._server_to_client):
            self._app.add_characteristic(characteristic)

        self._advertisement = _Advertisement(
            self._bus, APP_PATH + "/advertisement0", self._service_uuid)

        gatt = dbus.Interface(
            self._bus.get_object(BLUEZ, adapter_path), GATT_MANAGER_IFACE)
        gatt.RegisterApplication(
            APP_PATH, {},
            reply_handler=lambda: self._settle(self._app_registered, None),
            error_handler=lambda exc: self._settle(self._app_registered, exc))

        advertising = dbus.Interface(
            self._bus.get_object(BLUEZ, adapter_path),
            LE_ADVERTISING_MANAGER_IFACE)
        advertising.RegisterAdvertisement(
            self._advertisement.path, {},
            reply_handler=lambda: self._settle(self._advertisement_registered, None),
            error_handler=lambda exc: self._settle(self._advertisement_registered, exc))

    def _settle(self, future: asyncio.Future, error: Exception | None) -> None:
        """Resolve a registration future from the GLib thread."""
        def finish():
            if future.done():
                return
            if error is None:
                future.set_result(None)
            else:
                future.set_exception(BleHolderError(str(error)))

        self._loop.call_soon_threadsafe(finish)

    def _unregister(self) -> None:
        """Hand the tree back. Blocking is safe here — BlueZ replies directly
        rather than calling into us, so there is no re-entrancy to deadlock on."""
        if not self._registered:
            return
        adapter_path = f"/org/bluez/{self._adapter}"
        try:
            dbus.Interface(
                self._bus.get_object(BLUEZ, adapter_path),
                LE_ADVERTISING_MANAGER_IFACE
            ).UnregisterAdvertisement(self._advertisement.path)
        finally:
            dbus.Interface(
                self._bus.get_object(BLUEZ, adapter_path), GATT_MANAGER_IFACE
            ).UnregisterApplication(APP_PATH)
        self._registered = False

    def _log(self, message: str) -> None:
        if self._verbose:
            print(f"[bluez] {message}")
