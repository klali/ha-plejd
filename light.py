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

from homeassistant.components.light import (ATTR_BRIGHTNESS, PLATFORM_SCHEMA, SUPPORT_BRIGHTNESS, Light)
from homeassistant.const import CONF_NAME, EVENT_HOMEASSISTANT_START, EVENT_HOMEASSISTANT_STOP
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import track_point_in_utc_time
import homeassistant.util.dt as dt_util

import re
import binascii
import os
import struct
import sys
from datetime import timedelta, datetime
from threading import Thread

CONF_CRYPTO_KEY = 'crypto_key'
CONF_DEVICES = 'devices'
CONF_NAME = 'name'

DATA_PLEJD = 'plejdObject'

PLEJD_DEVICES = {}

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_CRYPTO_KEY): cv.string,
    vol.Optional(CONF_DEVICES, default={}): {
        cv.string: vol.Schema({
            vol.Required(CONF_NAME): cv.string
            })
        },
    })

BLUEZ_SERVICE_NAME = 'org.bluez'
DBUS_OM_IFACE =      'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE =    'org.freedesktop.DBus.Properties'

BLUEZ_ADAPTER_IFACE = 'org.bluez.Adapter1'
BLUEZ_DEVICE_IFACE = 'org.bluez.Device1'
GATT_SERVICE_IFACE = 'org.bluez.GattService1'
GATT_CHRC_IFACE =    'org.bluez.GattCharacteristic1'

PLEJD_SVC_UUID =     '31ba0001-6085-4726-be45-040c957391b5'
PLEJD_DATA_UUID =    '31ba0004-6085-4726-be45-040c957391b5'
PLEJD_LAST_DATA_UUID = '31ba0005-6085-4726-be45-040c957391b5'
PLEJD_AUTH_UUID =    '31ba0009-6085-4726-be45-040c957391b5'
PLEJD_PING_UUID =    '31ba000a-6085-4726-be45-040c957391b5'
PLEJD_SERVICE = "31ba0001-6085-4726-be45-040c957391b5"

class PlejdLight(Light):
    def __init__(self, name, identity):
        self._name = name
        self._state = False
        self._id = identity

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

    def update_state(self, state, brightness=None):
        self._state = state
        self._brightness = brightness
        if brightness:
            _LOGGER.debug("%s(%02x) turned %r with brightness %04x" % (self._name, self._id, state, brightness))
        else:
            _LOGGER.debug("%s(%02x) turned %r" % (self._name, self._id, state))
        self.schedule_update_ha_state()

    def turn_on(self, **kwargs):
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

        _LOGGER.debug("turning on %s(%02x) with brigtness %02x" % (self._name, self._id, brightness or 0))
        plejd_write(pi, payload)

    def turn_off(self, **kwargs):
        pi = self.hass.data[DATA_PLEJD]
        if "characteristics" not in pi:
            _LOGGER.warning("Tried to turn off light when plejd is not connected")
            return

        payload = binascii.a2b_hex("%02x0110009700" % (self._id))
        _LOGGER.debug("turning off %s(%02x)" % (self._name, self._id))
        plejd_write(pi, payload)

def connect(pi):
    import dbus
    from gi.repository import GLib
    from dbus.mainloop.glib import DBusGMainLoop

    GLib.threads_init()
    dbus.mainloop.glib.threads_init()

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    mainloop = GLib.MainLoop()
    om = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/'), DBUS_OM_IFACE)

    plejds = []
    adapter = None

    for path, interfaces in om.GetManagedObjects().items():
        if BLUEZ_ADAPTER_IFACE not in interfaces.keys():
            continue
        obj = bus.get_object(BLUEZ_SERVICE_NAME, path)
        adapter = dbus.Interface(obj, BLUEZ_ADAPTER_IFACE)
        break

    if not adapter:
        _LOGGER.error("No bluetooth adapter localized")
        return

    for path, interfaces in om.GetManagedObjects().items():
        if BLUEZ_DEVICE_IFACE not in interfaces.keys():
            continue
        obj = bus.get_object(BLUEZ_SERVICE_NAME, path)
        obj_props = obj.GetAll(BLUEZ_DEVICE_IFACE, dbus_interface=DBUS_PROP_IFACE)
        if obj_props["Alias"].startswith("P mesh"):
            if obj_props["Connected"]:
                _LOGGER.debug("Disconnecting %s" % (path))
                dbus.Interface(obj, BLUEZ_DEVICE_IFACE).Disconnect()
            adapter.RemoveDevice(obj)

    def interfaces_added_cb(object_path, interfaces):
        if BLUEZ_DEVICE_IFACE not in interfaces.keys():
            return
        obj = bus.get_object(BLUEZ_SERVICE_NAME, object_path)
        obj_props = obj.GetAll(BLUEZ_DEVICE_IFACE, dbus_interface=DBUS_PROP_IFACE)
        if obj_props["Alias"].startswith("P mesh"):
            _LOGGER.debug("Discovered %s with RSSI %d" % (object_path, obj_props["RSSI"]))
            plejds.append((obj, int(obj_props["RSSI"]), object_path))

    def timeout_discovery():
        mainloop.quit()

    om.connect_to_signal('InterfacesAdded', interfaces_added_cb)

    scan_filter = {
            "UUIDs": [PLEJD_SVC_UUID],
            "Transport": "le",
            }
    adapter.SetDiscoveryFilter(scan_filter)
    adapter.StartDiscovery()

    timer = GLib.timeout_add_seconds(2, timeout_discovery)
    mainloop.run()

    if len(plejds) == 0:
        _LOGGER.warning("No plejds discovered")
        return

    plejds.sort(key = lambda a: a[1], reverse = True)
    _LOGGER.info("Connecting %s" % (plejds[0][2]))
    dbus.Interface(plejds[0][0], BLUEZ_DEVICE_IFACE).Connect()

    timer = GLib.timeout_add_seconds(2, timeout_discovery)
    mainloop.run()

    objects = om.GetManagedObjects()
    chrcs = []

    # List characteristics found
    for path, interfaces in objects.items():
        if GATT_CHRC_IFACE not in interfaces.keys():
            continue
        chrcs.append(path)

    def process_plejd_service(service_path, chrc_paths, bus):
        service = bus.get_object(BLUEZ_SERVICE_NAME, service_path)
        service_props = service.GetAll(GATT_SERVICE_IFACE,
                                       dbus_interface=DBUS_PROP_IFACE)

        uuid = service_props['UUID']
        if uuid != PLEJD_SVC_UUID:
            return False

        dev = service_props['Device']
        x = re.search('dev_([0-9A-F_]+)$', dev)
        addr = binascii.a2b_hex(x.group(1).replace("_", ""))[::-1]

        chars = {}

        # Process the characteristics.
        for chrc_path in chrc_paths:
            chrc = bus.get_object(BLUEZ_SERVICE_NAME, chrc_path)
            chrc_props = chrc.GetAll(GATT_CHRC_IFACE,
                                     dbus_interface=DBUS_PROP_IFACE)

            uuid = chrc_props['UUID']

            if uuid == PLEJD_DATA_UUID:
                chars["data"] = (chrc, chrc_props)
            elif uuid == PLEJD_LAST_DATA_UUID:
                chars["last_data"] = (chrc, chrc_props)
            elif uuid == PLEJD_AUTH_UUID:
                chars["auth"] = (chrc, chrc_props)
            elif uuid == PLEJD_PING_UUID:
                chars["ping"] = (chrc, chrc_props)

        return (addr, chars)

    plejd_service = None
    # List sevices found
    for path, interfaces in objects.items():
        if GATT_SERVICE_IFACE not in interfaces.keys():
            continue

        chrc_paths = [d for d in chrcs if d.startswith(path + "/")]

        plejd_service = process_plejd_service(path, chrc_paths, bus)
        if plejd_service:
            break

    if not plejd_service:
        _LOGGER.warning("Failed connecting to plejd service")
        return

    pi["address"] = plejd_service[0]
    pi["characteristics"] = plejd_service[1]
    pi["loop"] = mainloop

    def handle_notification_cb(iface, changed_props, invalidated_props):
        if iface != GATT_CHRC_IFACE:
            return
        if not len(changed_props):
            return
        value = changed_props.get('Value', None)
        if not value:
            return
        value = ''.join([chr(byte) for byte in value]).encode('latin1')
        dec = plejd_enc_dec(pi["key"], pi["address"], value)
        # check if this is a device we care about
        if dec[0] in PLEJD_DEVICES:
            device = PLEJD_DEVICES[dec[0]]
        elif dec[0] == 0x01 and dec[3:5] == b'\x00\x1b':
            time = struct.unpack_from('<I', dec, 5)[0]
            _LOGGER.debug("plejd network reports time as '%s'", datetime.fromtimestamp(time))
            return
        else:
            _LOGGER.debug("no match for device '%02x' (%s)" % (dec[0], binascii.b2a_hex(dec)))
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
            _LOGGER.debug("no match for command '%s' (%s)" % (binascii.b2a_hex(dec[3:5]), binascii.b2a_hex(dec)))
            return
        if(state == 0):
            state = False
        else:
            state = True

        device.update_state(state, dim)

    class PlejdNotificationThread(Thread):
        def __init__(self):
            Thread.__init__(self)
            self.stopped = True
            _LOGGER.debug("setting up notification thread")

        def stop(self):
            _LOGGER.debug("stopping notification thread")
            self.stopped = True
            pi["loop"].quit()

        def run(self):
            _LOGGER.debug("starting notification thread")
            self.stopped = False
            while True:
                pi["loop"].run()
                if self.stopped:
                    break

            _LOGGER.debug("exiting notification thread")

    plejd_auth(pi)
    if plejd_ping(pi) == False:
        return

    plejd_last_data = pi["characteristics"]["last_data"][0]

    last_data_iface = dbus.Interface(plejd_last_data, DBUS_PROP_IFACE)
    last_data_iface.connect_to_signal("PropertiesChanged", handle_notification_cb)
    plejd_last_data.StartNotify(dbus_interface=GATT_CHRC_IFACE)

    pi["thread"] = PlejdNotificationThread()
    pi["thread"].start()

    _LOGGER.debug("all plejd setup completed")

def disconnect(plejdinfo):
    if "thread" in plejdinfo:
        plejdinfo["thread"].stop()
        del plejdinfo["thread"]
    if "loop" in plejdinfo:
        plejdinfo["loop"].quit()
        del plejdinfo["loop"]

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

def plejd_ping(pi):
    ping = os.urandom(1)
    char = pi["characteristics"]["ping"][0]
    pong = []

    def plejd_ping_error_cb(error):
        _LOGGER.warning("plejd ping errored: %s" % (str(error)))
        pong.append(ping[0])

    def plejd_ping_cb(value):
        pong.append(value[0])
        pi["loop"].quit()

    def plejd_ping_start_cb():
        char.ReadValue([], reply_handler=plejd_ping_cb,
                error_handler=plejd_ping_error_cb,
                dbus_interface=GATT_CHRC_IFACE)

    char.WriteValue([ping[0]], {}, reply_handler=plejd_ping_start_cb,
            error_handler=plejd_ping_error_cb,
            dbus_interface=GATT_CHRC_IFACE)

    pi["loop"].run()

    if((ping[0] + 1) & 0xff != pong[0]):
        _LOGGER.warning("plejd ping failed %02x - %02x" % (ping[0], pong[0]))
        return False

    _LOGGER.debug("Successfully pinged with %02x" % (ping[0]))
    return True

def plejd_auth(pi):
    char = pi["characteristics"]["auth"][0]

    def plejd_auth_error_cb(error):
        _LOGGER.warning("plejd authentication errored: %s" % (str(error)))

    def plejd_auth_finish_cb():
        _LOGGER.debug("plejd authentication finished")
        pi["loop"].quit()

    def plejd_auth_cb(value):
        chal = ''.join([chr(byte) for byte in value]).encode('latin1')
        r = plejd_chalresp(pi["key"], chal)
        char.WriteValue(r, {}, reply_handler=plejd_auth_finish_cb,
                error_handler=plejd_auth_error_cb,
                dbus_interface=GATT_CHRC_IFACE)

    def plejd_auth_start_cb():
        char.ReadValue([], reply_handler=plejd_auth_cb,
                error_handler=plejd_auth_error_cb,
                dbus_interface=GATT_CHRC_IFACE)

    char.WriteValue([0], {}, reply_handler=plejd_auth_start_cb,
            error_handler=plejd_auth_error_cb,
            dbus_interface=GATT_CHRC_IFACE)

    pi["loop"].run()

def plejd_write(pi, payload):
    from dbus.exceptions import DBusException
    try:
        data = plejd_enc_dec(pi["key"], pi["address"], payload)
        pi["characteristics"]["data"][0].WriteValue(list(data), {}, dbus_interface=GATT_CHRC_IFACE)
    except DBusException as e:
        _LOGGER.warning("Write failed: '%s'" % (e))
        connect(pi)
        data = plejd_enc_dec(pi["key"], pi["address"], payload)
        pi["characteristics"]["data"][0].WriteValue(list(data), {}, dbus_interface=GATT_CHRC_IFACE)

def setup_platform(hass, config, add_entities, discovery_info=None):
    cryptokey = binascii.a2b_hex(config.get(CONF_CRYPTO_KEY).replace('-', ''))
    plejdinfo = {"key": cryptokey}

    hass.data[DATA_PLEJD] = plejdinfo

    def _ping(now):
        pi = hass.data[DATA_PLEJD]
        if(plejd_ping(pi) == False):
            connect(pi)
        track_point_in_utc_time(hass, _ping, dt_util.utcnow() + timedelta(seconds = 300))

    def _start_plejd(event):
        connect(plejdinfo)
        if "thread" in plejdinfo:
            _ping(dt_util.utcnow())

    hass.bus.listen_once(EVENT_HOMEASSISTANT_START, _start_plejd)

    def _shutdown_plejd(event):
        disconnect(plejdinfo)

    hass.bus.listen_once(EVENT_HOMEASSISTANT_STOP, _shutdown_plejd)

    devices = []
    for identity, entity_info in config[CONF_DEVICES].items():
        i = int(identity)
        _LOGGER.debug("adding device %d (%s)" % (i, entity_info[CONF_NAME]))
        new = PlejdLight(entity_info[CONF_NAME], i)
        PLEJD_DEVICES[i] = new
        devices.append(new)

    add_entities(devices)
