# Copyright 2019 Klas Lindfors <klali@avm.se>
# Copyright 2021 Børge Nordli <bnordli@gmail.com>

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Plejd service code."""

import asyncio
import binascii
from datetime import datetime, timedelta
import logging
import os
import re
import struct
from typing import Any, Callable, Dict, List, Optional

from dbus_next.aio.proxy_object import ProxyInterface

from homeassistant.const import (
    ATTR_NAME,
    ATTR_STATE,
    EVENT_HOMEASSISTANT_STOP,
    STATE_OFF,
    STATE_ON,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_point_in_utc_time
import homeassistant.util.dt as dt_util

from .const import (
    BLUEZ_ADAPTER_IFACE,
    BLUEZ_DEVICE_IFACE,
    BLUEZ_SERVICE_NAME,
    BUTTON_EVENT,
    CONF_CRYPTO_KEY,
    CONF_DBUS_ADDRESS,
    CONF_DISCOVERY_TIMEOUT,
    CONF_ENDPOINTS,
    CONF_OFFSET_MINUTES,
    DBUS_OM_IFACE,
    DBUS_PROP_IFACE,
    GATT_CHRC_IFACE,
    GATT_SERVICE_IFACE,
    PLEJD_AUTH_UUID,
    PLEJD_DATA_UUID,
    PLEJD_LAST_DATA_UUID,
    PLEJD_LIGHTLEVEL_UUID,
    PLEJD_PING_UUID,
    PLEJD_SVC_UUID,
    SCENE_EVENT,
    TIME_DELTA_SYNC,
)

_LOGGER = logging.getLogger(__name__)


class PlejdBus:
    """Representation of the message bus connected to Plejd."""

    _chars: Dict[str, ProxyInterface] = {}

    def __init__(self, address: str) -> None:
        """Initialize the bus."""
        self._address = address

    async def write_data(self, char: str, data: bytes) -> None:
        """Write data to one characteristic."""
        await self._chars[char].call_write_value(data, {})

    async def read_data(self, char: str) -> bytes:
        """Read data from one characteristic."""
        return await self._chars[char].call_read_value({})

    async def add_callback(self, method: str, handler: Callable[[bytes], None]) -> None:
        """Register a callback on a characteristic."""

        @callback
        def unwrap_value(iface: str, changed_props: dict, invalidated_props) -> None:
            if iface != GATT_CHRC_IFACE:
                return
            if not len(changed_props):
                return
            value = changed_props.get("Value", None)
            if not value:
                return
            handler(value.value)

        self._chars[method + "_prop"].on_properties_changed(unwrap_value)
        await self._chars[method].call_start_notify()

    async def _get_interface(self, path: str, interface: str) -> ProxyInterface:
        introspection = await self._bus.introspect(BLUEZ_SERVICE_NAME, path)
        object = self._bus.get_proxy_object(BLUEZ_SERVICE_NAME, path, introspection)
        return object.get_interface(interface)

    async def connect(self) -> bool:
        """Connect to the message bus."""
        from dbus_next import BusType
        from dbus_next.aio import MessageBus

        messageBus = MessageBus(bus_type=BusType.SYSTEM, bus_address=self._address)
        try:
            self._bus = await messageBus.connect()
        except FileNotFoundError:
            _LOGGER.error(
                "Failed to connect to the dbus messagebus at '%s', make sure that it exists."
                % (self._address)
            )
            return False
        self._om = await self._get_interface("/", DBUS_OM_IFACE)
        self._adapter = await self._get_adapter()
        if not self._adapter:
            _LOGGER.error("No bluetooth adapter discovered")
            return False
        return True

    async def _get_adapter(self) -> ProxyInterface:
        om_objects = await self._om.call_get_managed_objects()
        for path, interfaces in om_objects.items():
            if BLUEZ_ADAPTER_IFACE in interfaces.keys():
                _LOGGER.debug(f"Discovered bluetooth adapter {path}")
                return await self._get_interface(path, BLUEZ_ADAPTER_IFACE)

    async def connect_device(self, timeout: int, endpoints: List[str]) -> bool:
        """Disconnect all currently connected devices and connect to the closest plejd device."""
        from dbus_next import Variant
        from dbus_next.errors import DBusError

        om_objects = await self._om.call_get_managed_objects()
        for path, interfaces in om_objects.items():
            if BLUEZ_DEVICE_IFACE in interfaces.keys():
                dev = await self._get_interface(path, BLUEZ_DEVICE_IFACE)
                connected = await dev.get_connected()
                if connected:
                    _LOGGER.debug(f"Disconnecting {path}")
                    await dev.call_disconnect()
                    _LOGGER.debug(f"Disconnected {path}")
                await self._adapter.call_remove_device(path)

        plejds = []

        @callback
        def on_interfaces_added(path, interfaces):
            if (
                BLUEZ_DEVICE_IFACE in interfaces
                and PLEJD_SVC_UUID in interfaces[BLUEZ_DEVICE_IFACE]["UUIDs"].value
            ):
                plejds.append({"path": path})

        self._om.on_interfaces_added(on_interfaces_added)

        scan_filter = {
            "UUIDs": Variant("as", [PLEJD_SVC_UUID]),
            "Transport": Variant("s", "le"),
        }
        await self._adapter.call_set_discovery_filter(scan_filter)
        await self._adapter.call_start_discovery()
        await asyncio.sleep(timeout)

        if len(plejds) == 0:
            _LOGGER.warning("No plejd devices found")
            return False

        _LOGGER.debug(f"Found {len(plejds)} plejd devices")
        for plejd in plejds:
            dev = await self._get_interface(plejd["path"], BLUEZ_DEVICE_IFACE)
            plejd["RSSI"] = await dev.get_rssi()
            plejd["obj"] = dev
            _LOGGER.debug(f"Discovered plejd {plejd['path']} with RSSI {plejd['RSSI']}")
 
        # Filter list of plejds if we are interested in specific endpoints
        if len(endpoints) > 0:
            _LOGGER.debug("Ignoring any device that is not one of %s" % (str(endpoints)))
            plejds = [plejd for plejd in plejds if plejd['path'].split('/dev_')[1].replace('_','') in endpoints]

        plejds.sort(key=lambda a: a["RSSI"], reverse=True)
        for plejd in plejds:
            try:
                _LOGGER.debug(f"Connecting to {plejd['path']}")
                await plejd["obj"].call_connect()
                _LOGGER.debug(f"Connected to {plejd['path']}")
                break
            except DBusError as e:
                _LOGGER.warning(f"Error connecting to plejd: {e}")
        await self._adapter.call_stop_discovery()
        await asyncio.sleep(timeout)
        return True

    async def get_plejd_address(self) -> Optional[bytes]:
        """Get the plejd address and also collect characteristics."""
        om_objects = await self._om.call_get_managed_objects()
        chrcs = []

        for path, interfaces in om_objects.items():
            if GATT_CHRC_IFACE in interfaces.keys():
                chrcs.append(path)

        for path, interfaces in om_objects.items():
            if GATT_SERVICE_IFACE not in interfaces.keys():
                continue

            service = await self._get_interface(path, GATT_SERVICE_IFACE)
            uuid = await service.get_uuid()
            if uuid != PLEJD_SVC_UUID:
                continue

            dev = await service.get_device()
            x = re.search("dev_([0-9A-F_]+)$", dev)
            if not x:
                _LOGGER.error(f"Unsupported device address '{dev}'")
                return None
            addr = binascii.a2b_hex(x.group(1).replace("_", ""))[::-1]

            # Process the characteristics.
            chrc_paths = [d for d in chrcs if d.startswith(path + "/")]
            for chrc_path in chrc_paths:
                chrc = await self._get_interface(chrc_path, GATT_CHRC_IFACE)
                chrc_prop = await self._get_interface(chrc_path, DBUS_PROP_IFACE)

                uuid = await chrc.get_uuid()

                if uuid == PLEJD_DATA_UUID:
                    self._chars["data"] = chrc
                elif uuid == PLEJD_LAST_DATA_UUID:
                    self._chars["last_data"] = chrc
                    self._chars["last_data_prop"] = chrc_prop
                elif uuid == PLEJD_AUTH_UUID:
                    self._chars["auth"] = chrc
                elif uuid == PLEJD_PING_UUID:
                    self._chars["ping"] = chrc
                elif uuid == PLEJD_LIGHTLEVEL_UUID:
                    self._chars["lightlevel"] = chrc
                    self._chars["lightlevel_prop"] = chrc_prop

            return addr

        return None


class PlejdService:
    """Representation of the Plejd service."""

    _address: str
    _key: bytes
    _plejd_address: Optional[bytes] = None
    _bus: Optional[PlejdBus] = None

    def __init__(
        self,
        hass: HomeAssistant,
        config: Dict[str, Any],
        devices: Dict[int, Any],
        scenes: Dict[int, str],
    ) -> None:
        """Initialize the service."""
        self._hass = hass
        self._config = config
        self._address = config.get(CONF_DBUS_ADDRESS, "")
        self._key = binascii.a2b_hex(config.get(CONF_CRYPTO_KEY, "").replace("-", ""))
        self._devices = devices
        self._scenes = scenes
        self._remove_timer = lambda: None
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, self._stop_plejd)

    async def connect(self) -> bool:
        """Connect to the Plejd service."""
        self._bus = PlejdBus(self._address)
        if not await self._bus.connect():
            return False
        if not await self._bus.connect_device(
            self._config.get(CONF_DISCOVERY_TIMEOUT, 0),
            self._config.get(CONF_ENDPOINTS, [])
        ):
            return False

        self._plejd_address = await self._bus.get_plejd_address()
        if not self._plejd_address:
            _LOGGER.warning("Failed connecting to plejd service")
            return False
        if not await self._authenticate():
            return False

        @callback
        def handle_notification_cb(value: bytes) -> None:
            if not self._plejd_address:
                _LOGGER.warning("Tried to write to plejd when not connected")
                return
            dec = self._enc_dec(self._plejd_address, value)
            _LOGGER.debug(f"Received message {dec.hex()}")
            # Format
            # 012345...
            # i..ccdddd
            # i = device_id
            #     00: button broadcast
            #     01: time broadcast
            #     02: scene/timer broadcast
            # c = command
            #     001b: time
            #     0016: button clicked, data = id + button + unknown
            #     0021: scene triggered, data = scene id
            #     0097: state update, data = state, dim
            #     00c8, 0098: state + dim update
            # d = data
            id = dec[0]
            command = dec[3:5]
            if command == b"\x00\x1b":
                # 001b: time
                if id != 0x01:
                    # Disregard time updates sent from the app
                    return
                n = dt_util.now().replace(tzinfo=None)
                time = datetime.fromtimestamp(struct.unpack_from("<I", dec, 5)[0])
                n = n + timedelta(minutes=self._config.get(CONF_OFFSET_MINUTES, 0))
                delta = abs(time - n)
                _LOGGER.debug(f"Plejd network reports time as '{time}'")
                s = delta.total_seconds()
                if s > TIME_DELTA_SYNC:
                    _LOGGER.info(
                        f"Plejd time delta is {s} seconds, setting time to '{n}'."
                    )
                    ntime = b"\x00\x01\x10\x00\x1b"
                    ntime += struct.pack("<I", int(n.timestamp())) + b"\x00"
                    self._hass.async_create_task(self._write(ntime))
            elif command == b"\x00\x16":
                # 0016: button clicked
                id = dec[5]
                button = dec[6]
                # If right button is clicked and configured, use that one instead.
                if button % 2 and id + 1 in self._devices:
                    id += 1
                data = {
                    "plejd_id": id,
                    "button": button,
                    "position": "right" if button % 2 else "left",
                    ATTR_STATE: STATE_ON if button < 2 else STATE_OFF,
                }
                if id in self._devices:
                    data[ATTR_NAME] = self._devices[id].name
                self._hass.bus.fire(BUTTON_EVENT, data)
                return
            elif command == b"\x00\x21":
                # 0021: scene or timer triggered
                id = dec[5] % 128
                state = dec[5] < 128
                data = {
                    "plejd_id": id % 128,
                    ATTR_STATE: STATE_ON if state else STATE_OFF,
                }
                if id in self._scenes:
                    data[ATTR_NAME] = self._scenes[id]
                self._hass.bus.fire(SCENE_EVENT, data)
                return
            elif command == b"\x00\x97":
                # 0097: state update
                device = self._devices.get(id)
                if device is None:
                    _LOGGER.debug(f"No match for device '{id:02x}'")
                    return
                state = bool(dec[5])
                device.update_state(state)
            elif command == b"\x00\xc8" or command == b"\x00\x98":
                # 00c8, 0098: state + dim update
                device = self._devices.get(id)
                if device is None:
                    _LOGGER.debug(f"No match for device '{id:02x}'")
                    return
                state = bool(dec[5])
                # Plejd brightness is two bytes, but HA brightness is one byte,
                # so we just take the most significant bit.
                brightness = dec[7]
                device.update_state(state, brightness)
            else:
                _LOGGER.debug(f"No match for command '{command.hex()}'")

        @callback
        def handle_state_cb(value: bytes) -> None:
            _LOGGER.debug(f"Received state {value.hex()}")
            # One or two messages of format
            # 0123456789
            # is???bb???
            # i = device_id
            # s = state (0 or 1)
            # b = brightness
            if len(value) != 20 and len(value) != 10:
                _LOGGER.warning(
                    f"Unknown length data received for state: '{value.hex()}'"
                )
                return

            msgs = [value[0:10]]
            if len(value) == 20:
                msgs.append(value[10:20])

            for m in msgs:
                if m[0] not in self._devices:
                    continue
                state = bool(m[1])
                # Plejd brightness is two bytes, but HA brightness is one byte,
                # so we just take the most significant bit
                brightness = m[6]
                device = self._devices[m[0]]
                if not brightness:
                    device.update_state(state)
                else:
                    device.update_state(state, brightness)

        await self._bus.add_callback("last_data", handle_notification_cb)
        await self._bus.add_callback("lightlevel", handle_state_cb)

        return True

    def trigger_scene(self, id: int) -> None:
        """Trigger the scene with the specific id."""
        payload = binascii.a2b_hex(f"0201100021{id:02x}")
        _LOGGER.debug(f"Trigger scene {id}")
        self._hass.async_create_task(self._write(payload))

    async def request_update(self) -> None:
        """Request an update of all devices."""
        if not self._bus:
            _LOGGER.warning("Tried to write to plejd when not connected")
            return
        await self._bus.write_data("lightlevel", b"\x01")

    async def check_connection(self, now=None) -> None:
        """Send a ping and reconnect if it failed. Then schedule another check in the future."""
        if not await self._send_ping():
            await self.connect()
        self._remove_timer = async_track_point_in_utc_time(
            self._hass, self.check_connection, dt_util.utcnow() + timedelta(seconds=300)
        )

    async def _stop_plejd(self, event) -> None:
        self._remove_timer()

    async def _authenticate(self) -> bool:
        if not self._bus:
            _LOGGER.warning("Tried to write to plejd when not connected")
            return False
        from dbus_next.errors import DBusError

        try:
            await self._bus.write_data("auth", b"\x00")
            challenge = await self._bus.read_data("auth")
            await self._bus.write_data("auth", self._chalresp(challenge))
        except DBusError as e:
            _LOGGER.warning(f"Plejd authentication error: {e}")
            return False
        return True

    async def _send_ping(self) -> bool:
        if not self._bus:
            _LOGGER.warning("Tried to ping plejd when not connected")
            return False
        from dbus_next.errors import DBusError

        ping = os.urandom(1)
        try:
            await self._bus.write_data("ping", ping)
            pong = await self._bus.read_data("ping")
        except DBusError as e:
            _LOGGER.warning(f"Plejd ping error: {e}")
            return False
        if (ping[0] + 1) & 0xFF != pong[0]:
            _LOGGER.warning(f"Plejd ping failed {ping[0]:02x} - {pong[0]:02x}")
            return False

        _LOGGER.debug(f"Successfully pinged with {ping[0]:02x}")
        return True

    async def _write(self, payload: bytes) -> None:
        from dbus_next.errors import DBusError
        async def _retry(now):
            await self._write(payload)

        if not self._bus or not self._plejd_address:
            _LOGGER.warning("Tried to write to plejd when not connected")
            return

        try:
            data = self._enc_dec(self._plejd_address, payload)
            await self._bus.write_data("data", data)
        except DBusError as e:
            _LOGGER.warning(f"Write failed: '{e}'")
            if str(e) == "In Progress":
                _LOGGER.debug("Postponing write")
                async_track_point_in_utc_time(self._hass, _retry, dt_util.utcnow() + timedelta(seconds = 5))
            else:
                _LOGGER.warning(f"Reconnecting")
                await self.connect()
                data = self._enc_dec(self._plejd_address, payload)
                await self._bus.write_data("data", data)

    def _chalresp(self, chal: bytes) -> bytes:
        import hashlib

        k = int.from_bytes(self._key, "big")
        c = int.from_bytes(chal, "big")

        intermediate = hashlib.sha256((k ^ c).to_bytes(16, "big")).digest()
        part1 = int.from_bytes(intermediate[:16], "big")
        part2 = int.from_bytes(intermediate[16:], "big")
        resp = (part1 ^ part2).to_bytes(16, "big")
        return resp

    def _enc_dec(self, address: bytes, data: bytes) -> bytes:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        buf = bytearray(address * 2)
        buf += address[:4]

        ct = (
            Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())
            .encryptor()
            .update(buf)
        )

        output = b""
        for i in range(len(data)):
            output += struct.pack("B", data[i] ^ ct[i % 16])

        return output
