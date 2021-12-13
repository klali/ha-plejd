# Copyright 2019 Klas Lindfors <klali@avm.se>
# Modified 2021 by Børge Nordli <bnordli@gmail.com>

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
"""The Plejd light platform."""

import binascii
import logging
from typing import Optional

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    COLOR_MODE_BRIGHTNESS,
    COLOR_MODE_ONOFF,
    LightEntity,
)
from homeassistant.const import CONF_LIGHTS, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .plejd_service import PlejdService

_LOGGER = logging.getLogger(__name__)


class PlejdLight(LightEntity, RestoreEntity):
    """Representation of a Plejd light."""

    _attr_should_poll = False
    _attr_assumed_state = False
    _hex_id: str
    _last_brightness: Optional[int] = None

    def __init__(self, name: str, identity: int, service: PlejdService) -> None:
        """Initialize the light."""
        self._attr_name = name
        self._attr_unique_id = str(identity)
        self._hex_id = f"{identity:02x}"
        self._service = service

    async def async_added_to_hass(self) -> None:
        """Read the current state of the light when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._attr_is_on = old.state == STATE_ON
            if old.attributes.get(ATTR_BRIGHTNESS) is not None:
                self._attr_brightness = old.attributes[ATTR_BRIGHTNESS]
                self._attr_supported_color_modes = {COLOR_MODE_BRIGHTNESS}
            else:
                self._attr_supported_color_modes = {COLOR_MODE_ONOFF}
        else:
            self._attr_is_on = False

    @callback
    def update_state(self, state: bool, brightness: Optional[int] = None) -> None:
        """Update the state of the light."""
        self._attr_is_on = state
        if self._attr_brightness or (
            brightness and self._last_brightness and brightness != self._last_brightness
        ):
            brightness = brightness or 0
            _LOGGER.debug(
                f"{self.name} ({self.unique_id}) turned {self.state} with brightness {brightness}"
            )
            self._attr_brightness = brightness
            self._attr_supported_color_modes = {COLOR_MODE_BRIGHTNESS}
        else:
            if brightness:
                _LOGGER.debug(
                    f"{self.name} ({self.unique_id}) turned {self.state} with (ignored) brightness {brightness}"
                )
            else:
                _LOGGER.debug(f"{self.name} ({self.unique_id}) turned {self.state}")
            self._attr_supported_color_modes = {COLOR_MODE_ONOFF}
        self._last_brightness = brightness
        self.async_schedule_update_ha_state()

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the light on."""
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if self._attr_brightness:
            brightness = brightness or 0
            # Plejd brightness is two bytes, but HA brightness is one byte.
            payload = binascii.a2b_hex(
                f"{self._hex_id}0110009801{brightness:02x}{brightness:02x}"
            )
            _LOGGER.debug(
                f"Turning on {self.name} ({self.unique_id}) with brightness {brightness}"
            )
            self._attr_brightness = brightness
        else:
            payload = binascii.a2b_hex(f"{self._hex_id}0110009701")
            _LOGGER.debug(f"Turning on {self.name} ({self.unique_id})")
        await self._service._write(payload)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the light off."""
        payload = binascii.a2b_hex(f"{self._hex_id}0110009700")
        _LOGGER.debug(f"Turning off {self.name} ({self.unique_id})")
        await self._service._write(payload)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Plejd light platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service: PlejdService = plejdinfo["service"]
    lights = []

    for id, light_name in plejdinfo["config"][CONF_LIGHTS].items():
        if id in plejdinfo["devices"]:
            _LOGGER.warning(f"Found duplicate definition for Plejd device {id}.")
            continue
        _LOGGER.debug(f"Adding light {id} ({light_name})")
        light = PlejdLight(light_name, id, service)
        plejdinfo["devices"][id] = light
        lights.append(light)

    add_entities(lights)
