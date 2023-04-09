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
"""The Plejd switch platform."""

import binascii
import logging
from typing import Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import CONF_SWITCHES, STATE_ON
from homeassistant.core import callback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .plejd_service import PlejdService

_LOGGER = logging.getLogger(__name__)


class PlejdSwitch(SwitchEntity, RestoreEntity):
    """Representation of a Plejd switch."""

    _attr_should_poll = False
    _attr_assumed_state = False
    _hex_id: str
    _brightness: Optional[int] = None

    def __init__(self, name: str, identity: int, service: PlejdService):
        """Initialize the switch."""
        self._attr_name = name
        self._attr_unique_id = str(identity)
        self._hex_id = f"{identity:02x}"
        self._service = service

    async def async_added_to_hass(self) -> None:
        """Read the current state of the switch when it is added to Home Assistant."""
        await super().async_added_to_hass()
        old = await self.async_get_last_state()
        if old is not None:
            self._attr_is_on = old.state == STATE_ON

    @callback
    def update_state(self, state: bool, brightness: Optional[int] = None) -> None:
        """Update the state of the switch."""
        self._attr_is_on = state
        _LOGGER.debug(f"{self.name} ({self.unique_id}) turned {self.state}")
        self.async_schedule_update_ha_state()

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the switch on."""
        payload = binascii.a2b_hex(f"{self._hex_id}0110009701")
        _LOGGER.debug(f"Turning on {self.name} ({self.unique_id})")
        await self._service._write(payload)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the switch off."""
        payload = binascii.a2b_hex(f"{self._hex_id}0110009700")
        _LOGGER.debug(f"Turning off {self.name} ({self.unique_id})")
        await self._service._write(payload)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Plejd switch platform."""
    if discovery_info is None:
        return

    plejdinfo = hass.data[DOMAIN]
    service: PlejdService = plejdinfo["service"]
    switches = []

    for id, switch_name in plejdinfo["config"][CONF_SWITCHES].items():
        if id in plejdinfo["devices"]:
            _LOGGER.warning(f"Found duplicate definition for Plejd device {id}.")
            continue
        _LOGGER.debug(f"Adding switch {id} ({switch_name})")
        switch = PlejdSwitch(switch_name, id, service)
        plejdinfo["devices"][id] = switch
        switches.append(switch)

    add_entities(switches)
