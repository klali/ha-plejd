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
"""Plejd integration."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.const import (
    ATTR_ID,
    ATTR_NAME,
    CONF_BINARY_SENSORS,
    CONF_LIGHTS,
    CONF_SENSORS,
    CONF_SWITCHES,
)
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import PlatformNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_CRYPTO_KEY,
    CONF_DBUS_ADDRESS,
    CONF_DISCOVERY_TIMEOUT,
    CONF_ENDPOINTS,
    CONF_OFFSET_MINUTES,
    CONF_SCENES,
    DEFAULT_DBUS_PATH,
    DEFAULT_DISCOVERY_TIMEOUT,
    DOMAIN,
    SCENE_SERVICE,
)
from .plejd_service import PlejdService

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["binary_sensor", "light", "sensor", "switch"]

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_CRYPTO_KEY): cv.string,
                vol.Optional(
                    CONF_DISCOVERY_TIMEOUT, default=DEFAULT_DISCOVERY_TIMEOUT
                ): cv.positive_int,
                vol.Optional(CONF_DBUS_ADDRESS, default=DEFAULT_DBUS_PATH): cv.string,
                vol.Optional(CONF_ENDPOINTS, default=[]): vol.All(cv.ensure_list, [cv.string]),
                vol.Optional(CONF_OFFSET_MINUTES, default=0): int,
                vol.Optional(CONF_LIGHTS, default={}): {cv.positive_int: cv.string},
                vol.Optional(CONF_SWITCHES, default={}): {cv.positive_int: cv.string},
                vol.Optional(CONF_BINARY_SENSORS, default={}): {
                    cv.positive_int: cv.string
                },
                vol.Optional(CONF_SENSORS, default={}): {cv.positive_int: cv.string},
                vol.Optional(CONF_SCENES, default={}): {cv.positive_int: cv.string},
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

SCENE_SERVICE_SCHEMA = vol.Schema(
    {vol.Optional(ATTR_ID): cv.positive_int, vol.Optional(ATTR_NAME): cv.string}
)


async def async_setup(hass: HomeAssistant, config: ConfigType):
    """Activate the Plejd integration from configuration yaml."""
    if DOMAIN not in config:
        return True

    plejdconfig = config[DOMAIN]
    devices: dict[int, Entity] = {}
    scenes: dict[int, str] = plejdconfig[CONF_SCENES]
    service = PlejdService(hass, plejdconfig, devices, scenes)
    plejdinfo = {
        "config": plejdconfig,
        "devices": devices,
        "service": service,
        "scenes": scenes,
    }
    hass.data[DOMAIN] = plejdinfo
    for platform in PLATFORMS:
        hass.helpers.discovery.load_platform(platform, DOMAIN, {}, config)

    if not await service.connect():
        raise PlatformNotReady
    await service.check_connection()

    @callback
    def handle_scene_service(call: ServiceCall) -> None:
        """Handle the trigger scene service."""
        id = call.data.get(ATTR_ID)
        if id is not None:
            service.trigger_scene(id)
            return
        name = call.data.get(ATTR_NAME, "")
        for id, scene_name in scenes.items():
            if name.lower() == scene_name.lower():
                service.trigger_scene(id)
                return
        _LOGGER.warning(
            f"Scene triggered with unknown name '{name}'. Known scenes: {', '.join(s for s in scenes.values())}"
        )

    hass.services.async_register(
        DOMAIN, SCENE_SERVICE, handle_scene_service, schema=SCENE_SERVICE_SCHEMA
    )
    _LOGGER.debug("Plejd platform setup completed")
    hass.async_create_task(service.request_update())
    return True
