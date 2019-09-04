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

import binascii
import hashlib
import os
import struct
import sys
from datetime import timedelta
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

PLEJD_SERVICE = "31ba0001-6085-4726-be45-040c957391b5"
DATA_UUID = "31ba0004-6085-4726-be45-040c957391b5"
LAST_DATA_UUID = "31ba0005-6085-4726-be45-040c957391b5"
AUTH_UUID = "31ba0009-6085-4726-be45-040c957391b5"
PING_UUID = "31ba000a-6085-4726-be45-040c957391b5"

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
        return self._brightness >> 8

    @property
    def supported_features(self):
        return SUPPORT_BRIGHTNESS

    def update_state(self, state, brightness=0xffff):
        _LOGGER.debug("%s(%02x) turned %r with brightness %04x" % (self._name, self._id, state, brightness))
        self._state = state
        self._brightness = brightness
        self.schedule_update_ha_state()

    def turn_on(self, **kwargs):
        pi = self.hass.data[DATA_PLEJD]
        if "handles" not in pi:
            _LOGGER.warning("Tried to turn on light when plejd is not connected")
            return

        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if(brightness is None):
            payload = binascii.a2b_hex("%02x0110009701" % (self._id))
        else:
            # since ha brightness is just one byte we shift it up and or it in to be able to get max val
            self._brightness = brightness << 8 | brightness
            payload = binascii.a2b_hex("%02x0110009801%04x" % (self._id, self._brightness))

        _LOGGER.debug("turning on %s(%02x) with brigtness %02x" % (self._name, self._id, brightness or 0))
        plejd_write(pi, pi["handles"]["data"], plejd_enc_dec(pi["key"], pi["address"], payload))

    def turn_off(self, **kwargs):
        pi = self.hass.data[DATA_PLEJD]
        if "handles" not in pi:
            _LOGGER.warning("Tried to turn off light when plejd is not connected")
            return

        payload = binascii.a2b_hex("%02x0110009700" % (self._id))
        _LOGGER.debug("turning off %s(%02x)" % (self._name, self._id))
        plejd_write(pi, pi["handles"]["data"], plejd_enc_dec(pi["key"], pi["address"], payload))

def connect(pi):
    from bluepy.btle import Scanner, DefaultDelegate, Peripheral, ADDR_TYPE_RANDOM, UUID, BTLEException
    device = None
    addr = None

    _LOGGER.debug("Starting plejd connection")

    disconnect(pi)

    scanner = Scanner()

    for i in range(1, 10):
        devs = sorted(list(scanner.scan(1)), key=lambda d: d.rssi)[::-1]

        for d in devs:
            for (adtype, desc, value) in d.getScanData():
                if(adtype == 8 and value == "P mesh"):
                    try:
                        dev = Peripheral(d, addrType = ADDR_TYPE_RANDOM)
                        if dev.getServiceByUUID(UUID(PLEJD_SERVICE)):
                            device = dev
                        else:
                            dev.disconnect()

                        break
                    except BTLEException as e:
                        _LOGGER.warning("failed connecting to device '%s' : '%s'" % (d.addr, e))
            if device:
                break

        if device is None:
            _LOGGER.warning("no device found on iteration %d" % (i))
        else:
            break

    if device == None:
        _LOGGER.warning("Failed to find a Plejd device to connect to")
        return

    _LOGGER.debug("Connected to Plejd device '%s'" % (device.addr))

    pi["device"] = device
    pi["address"] = binascii.a2b_hex(device.addr.replace(':', ''))[::-1]
    pi["handles"] = {}
    pi["handles"]["last_data"] = pi["device"].getCharacteristics(uuid=UUID(LAST_DATA_UUID))[0].getHandle()
    pi["handles"]["auth"] = pi["device"].getCharacteristics(uuid=UUID(AUTH_UUID))[0].getHandle()
    pi["handles"]["ping"] = pi["device"].getCharacteristics(uuid=UUID(PING_UUID))[0].getHandle()
    pi["handles"]["data"] = pi["device"].getCharacteristics(uuid=UUID(DATA_UUID))[0].getHandle()

    class PlejdDelegate(DefaultDelegate):
        def handleNotification(self, handle, value):
            if handle == pi["handles"]["last_data"]:
                dec = plejd_enc_dec(pi["key"], pi["address"], value)
                # check if this is a device we care about
                if dec[0] in PLEJD_DEVICES:
                    device = PLEJD_DEVICES[dec[0]]
                else:
                    _LOGGER.debug("no match for device '%02x' (%s)" % (dec[0], binascii.b2a_hex(dec)))
                    return
                dim = 0xffff
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

        import time

        def run(self):
            from bluepy.btle import BTLEInternalError
            _LOGGER.debug("starting notification thread")
            self.stopped = False
            while True:
                try:
                    pi["device"].waitForNotifications(1)
                except BTLEInternalError as e:
                    _LOGGER.warning("Encountered bluepy internal error: '%s'" % (e))
                if self.stopped:
                    break

            _LOGGER.debug("exiting notification thread")

    authenticate(pi)
    # the notification handle is last_data + 2
    pi["device"].writeCharacteristic(pi["handles"]["last_data"] + 2, b'\x02\x00')
    pi["device"].withDelegate(PlejdDelegate())
    pi["thread"] = PlejdNotificationThread()
    pi["thread"].start()

    _LOGGER.debug("all plejd setup completed")

def disconnect(plejdinfo):
    if "thread" in plejdinfo:
        plejdinfo["thread"].stop()
        del plejdinfo["thread"]
    if "device" in plejdinfo:
        plejdinfo["device"].disconnect()
        del plejdinfo["device"]

def plejd_chalresp(key, chal):
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
    from bluepy.btle import BTLEException, BTLEDisconnectError, BTLEInternalError
    handle = pi["handles"]["ping"]
    ping = os.urandom(1)
    try:
        pi["device"].writeCharacteristic(handle, ping, True)
        pong = pi["device"].readCharacteristic(handle)
    except (BTLEException,BTLEDisconnectError,BTLEInternalError) as e:
        _LOGGER.warning("read/write failed in ping: '%s'" % (e))
        return False
    if((ping[0] + 1) & 0xff != pong[0]):
        return False
    _LOGGER.debug("Succesfully pinged with %x" % (ping[0]))
    return True

def authenticate(pi):
    handle = pi["handles"]["auth"]
    pi["device"].writeCharacteristic(handle, b'\x00', True)
    resp = plejd_chalresp(pi["key"], pi["device"].readCharacteristic(handle))
    pi["device"].writeCharacteristic(handle, resp, False)
    return True

def plejd_write(pi, handle, data, wait=False):
    from bluepy.btle import BTLEException, BTLEDisconnectError, BTLEInternalError
    try:
        pi["device"].writeCharacteristic(handle, data, wait)
    except (BTLEException,BTLEDisconnectError,BTLEInternalError) as e:
        _LOGGER.warning("Write failed: '%s'" % (e))
        connect(pi)
        pi["device"].writeCharacteristic(handle, data, wait)

def setup_platform(hass, config, add_entities, discovery_info=None):
    cryptokey = binascii.a2b_hex(config.get(CONF_CRYPTO_KEY))
    plejdinfo = {"key": cryptokey}

    hass.data[DATA_PLEJD] = plejdinfo

    def _ping(now):
        pi = hass.data[DATA_PLEJD]
        if(plejd_ping(pi) == False):
            connect(pi)
        track_point_in_utc_time(hass, _ping, dt_util.utcnow() + timedelta(seconds = 300))

    def _start_plejd(event):
        connect(plejdinfo)
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
