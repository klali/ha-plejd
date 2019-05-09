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
import uuid
from datetime import timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import pygatt
from pygatt.backends import BLEAddressType

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

DATA_UUID = uuid.UUID("31ba0004-6085-4726-be45-040c957391b5")
LAST_DATA_UUID = uuid.UUID("31ba0005-6085-4726-be45-040c957391b5")
AUTH_UUID = uuid.UUID("31ba0009-6085-4726-be45-040c957391b5")
PING_UUID = uuid.UUID("31ba000a-6085-4726-be45-040c957391b5")

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
        _LOGGER.debug("%s turned %r with brightness %04x" % (self._name, state, brightness))
        self._state = state
        self._brightness = brightness
        self.schedule_update_ha_state()

    def turn_on(self, **kwargs):
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if(brightness is None):
            self._brightness = 0xffff
        else:
            # since ha brightness is just one byte we shift it up and or it in to be able to get max val
            self._brightness = brightness << 8 | brightness

        pi = self.hass.data[DATA_PLEJD]

        payload = binascii.a2b_hex("%02x0110009801%04x" % (self._id, self._brightness))
        plejd_write(pi, DATA_UUID, plejd_enc_dec(pi["key"], pi["address"], payload))

    def turn_off(self, **kwargs):
        pi = self.hass.data[DATA_PLEJD]

        payload = binascii.a2b_hex("%02x0110009700" % (self._id))
        plejd_write(pi, DATA_UUID, plejd_enc_dec(pi["key"], pi["address"], payload))

def connect(pi):
    device = None
    addr = None
    if "adapter" in pi:
        pi["adapter"].stop()
    else:
        pi["adapter"] = pygatt.GATTToolBackend(search_window_size=2048)

    for i in range(1, 10):
        pi["adapter"].start()
        devs = pi["adapter"].scan(timeout=5)

        for d in devs:
            if d['name'] == "P mesh":
                try:
                    dev = pi["adapter"].connect(d["address"], address_type=BLEAddressType.random, timeout=2)
                    for uuid in dev.discover_characteristics().keys():
                        if uuid == DATA_UUID:
                            device = dev
                            addr = d["address"]
                            break;
                    if device:
                        break
                except :
                    _LOGGER.warning("failed connecting to '%s'" % (d["address"]))

        if device is None:
            _Logger.warning("no device found on iteration %d" % (i))
            pi["adapter"].stop()
        else:
            break

    pi["device"] = device
    pi["address"] = binascii.a2b_hex(addr.replace(':', ''))[::-1]

    def plejd_handler_cb(handle, value):
        if handle == 22:
            dec = plejd_enc_dec(pi["key"], pi["address"], value)
            # check if this is a device we care about
            if dec[0] in PLEJD_DEVICES:
                device = PLEJD_DEVICES[dec[0]]
            else:
                _LOGGER.debug("no match for device '%d' (%s)" % (dec[0], binascii.b2a_hex(dec)))
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
                _LOGGER.debug("no match for command '%s'" % (binascii.b2a_hex(dec[3:5])))
                return
            if(state == 0):
                state = False
            else:
                state = True

            device.update_state(state, dim)

    authenticate(pi)
    pi["device"].subscribe(LAST_DATA_UUID, callback=plejd_handler_cb, indication=True)

def disconnect(plejdinfo):
    if "adapter" in plejdinfo:
        plejdinfo["adapter"].stop()

def plejd_chalresp(key, chal):
    k = int.from_bytes(key, 'big')
    c = int.from_bytes(chal, 'big')

    intermediate = hashlib.sha256((k ^ c).to_bytes(16, 'big')).digest()
    part1 = int.from_bytes(intermediate[:16], 'big')
    part2 = int.from_bytes(intermediate[16:], 'big')
    resp = (part1 ^ part2).to_bytes(16, 'big')
    return resp

def plejd_enc_dec(key, addr, data):
    buf = bytearray(addr * 2)
    buf += addr[:4]

    ct = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor().update(buf)

    output = b""
    for i in range(len(data)):
        output += struct.pack("B", data[i] ^ ct[i % 16])

    return output

def plejd_ping(pi):
    ping = os.urandom(1)
    plejd_write(pi, PING_UUID, ping)
    pong = pi["device"].char_read(PING_UUID)
    if((ping[0] + 1) & 0xff != pong[0]):
        return False
    return True

def authenticate(i):
    i["device"].char_write(AUTH_UUID, b'\x00')
    resp = plejd_chalresp(i["key"], i["device"].char_read(AUTH_UUID))
    i["device"].char_write(AUTH_UUID, resp)
    return True

def plejd_write(pi, uuid, data):
    try:
        pi["device"].char_write(uuid, data)
    except pygatt.exceptions.NotificationTimeout as e:
        _LOGGER.warning("Write timed-out")
        connect(pi)
        pi["device"].char_write(uuid, data)

def setup_platform(hass, config, add_entities, discovery_info=None):
    cryptokey = binascii.a2b_hex(config.get(CONF_CRYPTO_KEY))
    plejdinfo = {"key": cryptokey}

    hass.data[DATA_PLEJD] = plejdinfo

    # pygatt assumes the notification handle is +1, plejd has +2,
    #  thus we monkey-patch that function here to get the right handle
    #  for notifications
    def plejd_notification_handles(self, uuid):
        value_handle = self.get_handle(uuid)
        characteristic_config_handle = value_handle + 2
        return value_handle, characteristic_config_handle

    pygatt.BLEDevice._notification_handles = plejd_notification_handles

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
        plejdinfo["adapter"].stop()

    hass.bus.listen_once(EVENT_HOMEASSISTANT_STOP, _shutdown_plejd)

    devices = []
    for identity, entity_info in config[CONF_DEVICES].items():
        i = int(identity)
        _LOGGER.debug("adding device %d (%s)" % (i, entity_info[CONF_NAME]))
        new = PlejdLight(entity_info[CONF_NAME], i)
        PLEJD_DEVICES[i] = new
        devices.append(new)

    add_entities(devices)
