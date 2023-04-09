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
"""Constants for the Plejd integration."""

DOMAIN = "plejd"
BUTTON_EVENT = DOMAIN + "_button_event"
SCENE_EVENT = DOMAIN + "_scene_event"
SCENE_SERVICE = "trigger_scene"

CONF_CRYPTO_KEY = "crypto_key"
CONF_DISCOVERY_TIMEOUT = "discovery_timeout"
CONF_DBUS_ADDRESS = "dbus_address"
CONF_ENDPOINTS = "endpoints"
CONF_OFFSET_MINUTES = "offset_minutes"
CONF_SCENES = "scenes"
CONF_ONOFF = [" (onoff)", "*"]

DEFAULT_DISCOVERY_TIMEOUT = 2
DEFAULT_DBUS_PATH = "unix:path=/run/dbus/system_bus_socket"
TIME_DELTA_SYNC = 60  # if delta is more than a minute, sync time

BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"

BLUEZ_ADAPTER_IFACE = "org.bluez.Adapter1"
BLUEZ_DEVICE_IFACE = "org.bluez.Device1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"

PLEJD_SVC_UUID = "31ba0001-6085-4726-be45-040c957391b5"
PLEJD_LIGHTLEVEL_UUID = "31ba0003-6085-4726-be45-040c957391b5"
PLEJD_DATA_UUID = "31ba0004-6085-4726-be45-040c957391b5"
PLEJD_LAST_DATA_UUID = "31ba0005-6085-4726-be45-040c957391b5"
PLEJD_AUTH_UUID = "31ba0009-6085-4726-be45-040c957391b5"
PLEJD_PING_UUID = "31ba000a-6085-4726-be45-040c957391b5"
