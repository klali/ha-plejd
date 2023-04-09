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
"""The Plejd binary sensor platform."""

import logging

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import CONF_BINARY_SENSORS, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .plejd_service import PlejdService

_LOGGER = logging.getLogger(__name__)


class PlejdButton(BinarySensorEntity, RestoreEntity):
    """Representation of a Plejd button."""

    _attr_should_poll = False
    _attr_assumed_state = False

    def __init__(self, name: str, identity: int, service: PlejdService) -> None:
        """Initialize the binary sensor."""
        self._attr_name = name
        self._attr_unique_id = str(identity)
        self._service = service

    async def async_added_to_hass(self) -> None:
        """Read the current state of the button when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._attr_is_on = old.state == STATE_ON

    @callback
    def update_state(self, state: bool) -> None:
        """Update the state of the button."""
        self._attr_is_on = state
        _LOGGER.debug(f"{self.name} ({self.unique_id}) turned {self.state}")
        self.async_schedule_update_ha_state()


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Plejd binary sensor platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service: PlejdService = plejdinfo["service"]
    buttons = []

    for id, sensor_name in plejdinfo["config"][CONF_BINARY_SENSORS].items():
        if id in plejdinfo["devices"]:
            _LOGGER.warning(f"Found duplicate definition for Plejd device {id}.")
            continue
        _LOGGER.debug(f"Adding binary sensor {id} ({sensor_name})")
        button = PlejdButton(sensor_name, id, service)
        plejdinfo["devices"][id] = button
        buttons.append(button)

    add_entities(buttons)
