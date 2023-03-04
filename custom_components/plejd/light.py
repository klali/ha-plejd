# Copyright 2019 Klas Lindfors <klali@avm.se>

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

import logging

import voluptuous as vol

from homeassistant.core import callback
from homeassistant.components.light import (ATTR_BRIGHTNESS, PLATFORM_SCHEMA, SUPPORT_BRIGHTNESS, LightEntity)
from homeassistant.const import CONF_NAME, CONF_DEVICES, EVENT_HOMEASSISTANT_START, EVENT_HOMEASSISTANT_STOP, STATE_ON
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_track_point_in_utc_time
from homeassistant.helpers.restore_state import RestoreEntity
import homeassistant.util.dt as dt_util
from homeassistant.exceptions import PlatformNotReady


import asyncio

import re
import binascii
import os
import struct
from datetime import timedelta, datetime, timezone

CONF_CRYPTO_KEY = 'crypto_key'
CONF_DISCOVERY_TIMEOUT = 'discovery_timeout'
CONF_DBUS_ADDRESS = 'dbus_address'
CONF_OFFSET_MINUTES = 'offset_minutes'
CONF_ENDPOINTS = 'endpoints'

DEFAULT_DISCOVERY_TIMEOUT = 2
DEFAULT_DBUS_PATH = 'unix:path=/run/dbus/system_bus_socket'
TIME_DELTA_SYNC = 60 # if delta is more than a minute, sync time

DATA_PLEJD = 'plejdObject'

PLEJD_DEVICES = {}

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_CRYPTO_KEY): cv.string,
    vol.Required(CONF_DEVICES, default={}): {
        cv.string: vol.Schema({
            vol.Required(CONF_NAME): cv.string
            })
        },
    vol.Optional(CONF_DISCOVERY_TIMEOUT, default=DEFAULT_DISCOVERY_TIMEOUT): cv.positive_int,
    vol.Optional(CONF_DBUS_ADDRESS, default=DEFAULT_DBUS_PATH): cv.string,
    vol.Optional(CONF_OFFSET_MINUTES, default=0): int,
    vol.Optional(CONF_ENDPOINTS, default=[]): vol.All(cv.ensure_list, [cv.string]),
    })


BLUEZ_SERVICE_NAME = 'org.bluez'
DBUS_OM_IFACE =      'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE =    'org.freedesktop.DBus.Properties'

BLUEZ_ADAPTER_IFACE = 'org.bluez.Adapter1'
BLUEZ_DEVICE_IFACE = 'org.bluez.Device1'
GATT_SERVICE_IFACE = 'org.bluez.GattService1'
GATT_CHRC_IFACE =    'org.bluez.GattCharacteristic1'

PLEJD_SVC_UUID =     '31ba0001-6085-4726-be45-040c957391b5'
PLEJD_LIGHTLEVEL_UUID = '31ba0003-6085-4726-be45-040c957391b5'
PLEJD_DATA_UUID =    '31ba0004-6085-4726-be45-040c957391b5'
PLEJD_LAST_DATA_UUID = '31ba0005-6085-4726-be45-040c957391b5'
PLEJD_AUTH_UUID =    '31ba0009-6085-4726-be45-040c957391b5'
PLEJD_PING_UUID =    '31ba000a-6085-4726-be45-040c957391b5'

class PlejdLight(LightEntity, RestoreEntity):
    def __init__(self, name, identity):
        self._name = name
        self._id = identity
        self._brightness = None

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._state = old.state == STATE_ON
            if old.attributes.get(ATTR_BRIGHTNESS) is not None:
                brightness = int(old.attributes[ATTR_BRIGHTNESS])
                self._brightness = brightness << 8 | brightness
        else:
            self._state = False

    @property
    def should_poll(self):
        return False

    @property
    def name(self):
        return self._name

    @property
    def is_on(self):
        return self._state

    @property
    def assumed_state(self):
        return True

    @property
    def brightness(self):
        if self._brightness:
            return self._brightness >> 8
        else:
            return None

    @property
    def supported_features(self):
        return SUPPORT_BRIGHTNESS

    @property
    def unique_id(self):
        return self._id

    @callback
    def update_state(self, state, brightness=None):
        self._state = state
        self._brightness = brightness
        if brightness:
            _LOGGER.debug("%s(%02x) turned %r with brightness %04x" % (self._name, self._id, state, brightness))
        else:
            _LOGGER.debug("%s(%02x) turned %r" % (self._name, self._id, state))
        self.async_schedule_update_ha_state()

    async def async_turn_on(self, **kwargs):
        pi = self.hass.data[DATA_PLEJD]
        if "characteristics" not in pi:
            _LOGGER.warning("Tried to turn on light when plejd is not connected")
            return

        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if(brightness is None):
            self._brightness = None
            payload = binascii.a2b_hex("%02x0110009701" % (self._id))
        else:
            # since ha brightness is just one byte we shift it up and or it in to be able to get max val
            self._brightness = brightness << 8 | brightness
            payload = binascii.a2b_hex("%02x0110009801%04x" % (self._id, self._brightness))

        _LOGGER.debug("Turning on %s(%02x) with brigtness %02x" % (self._name, self._id, brightness or 0))
        await plejd_write(pi, payload)

    async def async_turn_off(self, **kwargs):
        pi = self.hass.data[DATA_PLEJD]
        if "characteristics" not in pi:
            _LOGGER.warning("Tried to turn off light when plejd is not connected")
            return

        payload = binascii.a2b_hex("%02x0110009700" % (self._id))
        _LOGGER.debug("Turning off %s(%02x)" % (self._name, self._id))
        await plejd_write(pi, payload)

async def connect(pi):
    from dbus_next import Message, MessageType, BusType, Variant
    from dbus_next.aio import MessageBus
    from dbus_next.errors import DBusError

    pi["characteristics"] = None

    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM, bus_address=pi["dbus_address"]).connect()
    except FileNotFoundError as e:
        _LOGGER.error("Failed to connect the dbus messagebus at '%s', make sure that exists" % (pi["dbus_address"]))
        return

    om_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, '/')
    om = bus.get_proxy_object(BLUEZ_SERVICE_NAME, '/', om_introspection).get_interface(DBUS_OM_IFACE)

    om_objects = await om.call_get_managed_objects()
    for path, interfaces in om_objects.items():
        if BLUEZ_ADAPTER_IFACE in interfaces.keys():
            _LOGGER.debug("Discovered bluetooth adapter %s" % (path))
            adapter_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, path)
            adapter = bus.get_proxy_object(BLUEZ_SERVICE_NAME, path, adapter_introspection).get_interface(BLUEZ_ADAPTER_IFACE)
            break

    if not adapter:
        _LOGGER.error("No bluetooth adapter localized")
        return

    for path, interfaces in om_objects.items():
        if BLUEZ_DEVICE_IFACE in interfaces.keys():
            device_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, path)
            dev = bus.get_proxy_object(BLUEZ_SERVICE_NAME, path, device_introspection).get_interface(BLUEZ_DEVICE_IFACE)
            connected = await dev.get_connected()
            if connected:
                _LOGGER.debug("Disconnecting %s" % (path))
                await dev.call_disconnect()
            await adapter.call_remove_device(path)

    plejds = []

    @callback
    def on_interfaces_added(path, interfaces):
        if BLUEZ_DEVICE_IFACE in interfaces:
            if PLEJD_SVC_UUID in interfaces[BLUEZ_DEVICE_IFACE]['UUIDs'].value:
                plejds.append({'path': path})

    om.on_interfaces_added(on_interfaces_added)

    scan_filter = {
            "UUIDs": Variant('as', [PLEJD_SVC_UUID]),
            "Transport": Variant('s', "le"),
            }
    await adapter.call_set_discovery_filter(scan_filter)
    await adapter.call_start_discovery()
    await asyncio.sleep(pi["discovery_timeout"])

    for plejd in plejds:
        device_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, plejd['path'])
        dev = bus.get_proxy_object(BLUEZ_SERVICE_NAME, plejd['path'], device_introspection).get_interface(BLUEZ_DEVICE_IFACE)
        plejd['RSSI'] = await dev.get_rssi()
        plejd['obj'] = dev
        _LOGGER.debug("Discovered plejd %s with RSSI %d" % (plejd['path'], plejd['RSSI']))

    # Filter list of plejds if we are interested in specific endpoints
    if len(pi['endpoints']) > 0:
        _LOGGER.debug("Ignoring any device that is not one of %s" % (str(pi['endpoints'])))
        plejds = [plejd for plejd in plejds if plejd['path'].split('/dev_')[1].replace('_','') in pi['endpoints']]

    if len(plejds) == 0:
        _LOGGER.warning("No plejd devices found")
        return

    plejds.sort(key = lambda a: a['RSSI'], reverse = True)
    for plejd in plejds:
        try:
            _LOGGER.debug("Connecting to %s" % (plejd["path"]))
            await plejd['obj'].call_connect()
            break
        except DBusError as e:
            _LOGGER.warning("Error connecting to plejd: %s" % (str(e)))

    await asyncio.sleep(pi["discovery_timeout"])

    objects = await om.call_get_managed_objects()
    chrcs = []

    for path, interfaces in objects.items():
        if GATT_CHRC_IFACE not in interfaces.keys():
            continue
        chrcs.append(path)


    async def process_plejd_service(service_path, chrc_paths, bus):
        service_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, service_path)
        service = bus.get_proxy_object(BLUEZ_SERVICE_NAME, service_path, service_introspection).get_interface(GATT_SERVICE_IFACE)
        uuid = await service.get_uuid()
        if uuid != PLEJD_SVC_UUID:
            return None

        dev = await service.get_device()
        x = re.search('dev_([0-9A-F_]+)$', dev)
        addr = binascii.a2b_hex(x.group(1).replace("_", ""))[::-1]

        chars = {}

        # Process the characteristics.
        for chrc_path in chrc_paths:
            chrc_introspection = await bus.introspect(BLUEZ_SERVICE_NAME, chrc_path)
            chrc_obj = bus.get_proxy_object(BLUEZ_SERVICE_NAME, chrc_path, chrc_introspection)
            chrc = chrc_obj.get_interface(GATT_CHRC_IFACE)
            chrc_prop = chrc_obj.get_interface(DBUS_PROP_IFACE)

            uuid = await chrc.get_uuid()

            if uuid == PLEJD_DATA_UUID:
                chars["data"] = chrc
            elif uuid == PLEJD_LAST_DATA_UUID:
                chars["last_data"] = chrc
                chars["last_data_prop"] = chrc_prop
            elif uuid == PLEJD_AUTH_UUID:
                chars["auth"] = chrc
            elif uuid == PLEJD_PING_UUID:
                chars["ping"] = chrc
            elif uuid == PLEJD_LIGHTLEVEL_UUID:
                chars["lightlevel"] = chrc
                chars["lightlevel_prop"] = chrc_prop

        return (addr, chars)

    plejd_service = None
    for path, interfaces in objects.items():
        if GATT_SERVICE_IFACE not in interfaces.keys():
            continue

        chrc_paths = [d for d in chrcs if d.startswith(path + "/")]

        plejd_service = await process_plejd_service(path, chrc_paths, bus)
        if plejd_service:
            break

    if not plejd_service:
        _LOGGER.warning("Failed connecting to plejd service")
        return

    if await plejd_auth(pi["key"], plejd_service[1]["auth"]) == False:
        return

    pi["address"] = plejd_service[0]
    pi["characteristics"] = plejd_service[1]

    @callback
    def handle_notification_cb(iface, changed_props, invalidated_props):
        if iface != GATT_CHRC_IFACE:
            return
        if not len(changed_props):
            return
        value = changed_props.get('Value', None)
        if not value:
            return

        dec = plejd_enc_dec(pi["key"], pi["address"], value.value)
        # check if this is a device we care about
        if dec[0] in PLEJD_DEVICES:
            device = PLEJD_DEVICES[dec[0]]
        elif dec[0] == 0x01 and dec[3:5] == b'\x00\x1b':
            n = dt_util.now().replace(tzinfo=None)
            time = datetime.fromtimestamp(struct.unpack_from('<I', dec, 5)[0])
            n = n + timedelta(minutes=pi["offset_minutes"])
            delta = abs(time - n)
            _LOGGER.debug("Plejd network reports time as '%s'", time)
            s = delta.total_seconds()
            if s > TIME_DELTA_SYNC:
                _LOGGER.info("Plejd time delta is %d seconds, setting time to '%s'.", s, n)
                ntime = b"\x00\x01\x10\x00\x1b"
                ntime += struct.pack('<I', int(n.timestamp())) + b"\x00"
                pi["hass"].async_create_task(plejd_write(pi, ntime))
            return
        else:
            _LOGGER.debug("No match for device '%02x' (%s)" % (dec[0], binascii.b2a_hex(dec)))
            return
        dim = None
        state = None
        if dec[3:5] == b'\x00\xc8' or dec[3:5] == b'\x00\x98':
            # 00c8 and 0098 both mean state+dim
            state = dec[5]
            dim = int.from_bytes(dec[6:8], 'little')
        elif dec[3:5] == b'\x00\x97':
            # 0097 is state only
            state = dec[5]
        else:
            _LOGGER.debug("No match for command '%s' (%s)" % (binascii.b2a_hex(dec[3:5]), binascii.b2a_hex(dec)))
            return

        device.update_state(bool(state), dim)

    @callback
    def handle_lightlevel_cb(iface, changed_props, invalidated_props):
        if iface != GATT_CHRC_IFACE:
            return
        if not len(changed_props):
            return
        value = changed_props.get('Value', None)
        if not value:
            return

        value = value.value
        if len(value) != 20 and len(value) != 10:
            _LOGGER.debug("Unknown length data received for lightlevel: '%s'" % (binascii.b2a_hex(value)))
            return

        msgs = [value[0:10]]
        if len(value) == 20:
            msgs.append(value[10:20])

        for m in msgs:
            if m[0] not in PLEJD_DEVICES:
                continue
            device = PLEJD_DEVICES[m[0]]
            device.update_state(bool(m[1]), int.from_bytes(m[5:7], 'little'))

    await adapter.call_stop_discovery()

    pi["characteristics"]["last_data_prop"].on_properties_changed(handle_notification_cb)
    await pi["characteristics"]["last_data"].call_start_notify()
    pi["characteristics"]["lightlevel_prop"].on_properties_changed(handle_lightlevel_cb)
    await pi["characteristics"]["lightlevel"].call_start_notify()

    return

def plejd_chalresp(key, chal):
    import hashlib
    k = int.from_bytes(key, 'big')
    c = int.from_bytes(chal, 'big')

    intermediate = hashlib.sha256((k ^ c).to_bytes(16, 'big')).digest()
    part1 = int.from_bytes(intermediate[:16], 'big')
    part2 = int.from_bytes(intermediate[16:], 'big')
    resp = (part1 ^ part2).to_bytes(16, 'big')
    return resp

def plejd_enc_dec(key, addr, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    buf = bytearray(addr * 2)
    buf += addr[:4]

    ct = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor().update(buf)

    output = b""
    for i in range(len(data)):
        output += struct.pack("B", data[i] ^ ct[i % 16])

    return output

async def plejd_ping(pi):
    from dbus_next.errors import DBusError

    ping = os.urandom(1)
    char = pi["characteristics"]["ping"]
    try:
        await char.call_write_value(ping, {})
        pong = await char.call_read_value({})
    except DBusError as e:
        _LOGGER.warning("Plejd ping errored: %s" % (str(e)))
        return False
    if((ping[0] + 1) & 0xff != pong[0]):
        _LOGGER.warning("Plejd ping failed %02x - %02x" % (ping[0], pong[0]))
        return False

    _LOGGER.debug("Successfully pinged with %02x" % (ping[0]))
    return True

async def plejd_auth(key, char):
    from dbus_next.errors import DBusError
    try:
        await char.call_write_value(b"\x00", {})
        chal = await char.call_read_value({})
        r = plejd_chalresp(key, chal)
        await char.call_write_value(r, {})
    except DBusError as e:
        _LOGGER.warning("Plejd authentication errored: %s" % (str(e)))
        return False
    return True

async def plejd_write(pi, payload):
    from dbus_next.errors import DBusError
    async def _write(now):
        await plejd_write(pi, payload)
    try:
        data = plejd_enc_dec(pi["key"], pi["address"], payload)
        await pi["characteristics"]["data"].call_write_value(data, {})
    except DBusError as e:
        _LOGGER.warning("Write failed: '%s'" % (e))
        if str(e) == "In Progress":
            _LOGGER.debug("Postponing write")
            async_track_point_in_utc_time(pi["hass"], _write, dt_util.utcnow() + timedelta(seconds = 5))
        else:
            await connect(pi)
            data = plejd_enc_dec(pi["key"], pi["address"], payload)
            await pi["characteristics"]["data"].call_write_value(data, {})

async def plejd_update(pi):
    await pi["characteristics"]["lightlevel"].call_write_value(b"\x01", {})

async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    cryptokey = binascii.a2b_hex(config.get(CONF_CRYPTO_KEY).replace('-', ''))
    plejdinfo = {"key": cryptokey, "hass": hass, "offset_minutes": config.get(CONF_OFFSET_MINUTES), "endpoints": config.get(CONF_ENDPOINTS)}

    hass.data[DATA_PLEJD] = plejdinfo

    async def _ping(now):
        pi = hass.data[DATA_PLEJD]
        if(await plejd_ping(pi) == False):
            await connect(pi)
        plejdinfo["remove_timer"] = async_track_point_in_utc_time(hass, _ping, dt_util.utcnow() + timedelta(seconds = 300))

    async def _stop_plejd(event):
        if "remove_timer" in plejdinfo:
            plejdinfo["remove_timer"]()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _stop_plejd)

    plejdinfo["discovery_timeout"] = config[CONF_DISCOVERY_TIMEOUT]
    plejdinfo["dbus_address"] = config[CONF_DBUS_ADDRESS]

    await connect(plejdinfo)
    if plejdinfo["characteristics"] is not None:
        await _ping(dt_util.utcnow())
    else:
        raise PlatformNotReady

    devices = []
    for identity, entity_info in config[CONF_DEVICES].items():
        i = int(identity)
        _LOGGER.debug("Adding device %d (%s)" % (i, entity_info[CONF_NAME]))
        new = PlejdLight(entity_info[CONF_NAME], i)
        PLEJD_DEVICES[i] = new
        devices.append(new)

    async_add_entities(devices)

    await plejd_update(plejdinfo)
    _LOGGER.debug("All plejd setup completed")
