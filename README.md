# Plejd component for Home Assistant

This is a Plejd component for Home Assistant, interfacing with the Bluetooth LE
protocol. All devices are configured locally, without communicating with the
Plejd web API. The crypto key must be extracted from the app image (see below
for instructions).

## Upgrade notes

If you are upgrading from version 1 to version 2 of this component, you should
read the [upgrade notes](upgrade_notes.md).

## Entities

Relay outputs can be configured as either `light`s or `switch`es. Dimmer outputs
should generally be configured as (dimmable) `light`s. They can also be used as
plain `switch`es. Rotary buttons are `sensor`s (measuring percentages) while
push buttons are `binary_sensor`s.

## Events

Plejd buttons send `plejd_button_event`s when pressed and Plejd scenarios and
timers send `plejd_scene_event`s when triggered. These events can be identified
by either by the `plejd_id` field, or the `name` field, if configured.

## Services

Plejd scenarios can be triggered using the `plejd.trigger_scene` service. They
will have to be defined through the Plejd app, though.

## Time

The component will keep the time of the Plejd system up to date.

## Supported Plejd devices

| Name      | `light` _or_ `switch` | `binary_sensor` | `sensor` | `plejd_button_event` | Tested? |
| --------- | --------------------- | --------------- | -------- |--------------------- | ------- |
| CTR-01    |     1x (dimmable)     |                 |          |                      | No      |
| DIM-01-2P |     1x (dimmable)     |                 |          |                      |         |
| DIM-02    |     2x (dimmable)     |                 |          |                      |         |
| LED-10    |     1x (dimmable)     |                 |          |                      | No      |
| REL-01-2P |          1x           |                 |          |                      | No      |
| REL-02    |          2x           |                 |          |                      |         |
| RTR-01 *  |                       |                 |    1x*   |         Yes*         |         |
| VRI-02 *  |     1x (dimmable)     |                 |    1x*   |         Yes*         |         |
| WPH-01    |                       |       2x        |          |         Yes          |         |
| WRT-01    |                       |                 |    1x    |         Yes          |         |

Note: For RTR-01 and VRI-02, when the rotary is configured to control an output
on the attached puck, Home Assistant will not receive events from the button
(only the controlled light), so it cannot be a separate `sensor`, and
`plejd_button_event`s will not be triggered.

Home Assistant initially sets all `light`s to non-dimmable, but if it notices a
change in a light's brightness, the light will forever be set as dimmable. (To
revert this, go to Developer Tools for this entity, set `supported_color_modes`
to `- onoff` and remove the `brightness` line.)

## Tested platforms
This component has been tested on the following platforms:
* Raspberry Pi 3b+ running ubuntu (18.04) and Home Assistant in venv.
* Raspberry Pi 4b running Pi OS Lite and Home Assistant in docker.
* Intel NUC NUC7i7BNH (Bluetooth 4.2 Intel 8265) running ESXi 6.7 and linux guest.

There's been reports that bluez version 5.37 is problematic while 5.48 works fine.

## Requirements
* A Bluetooth adapter that supports Bluetooth Low Energy (BLE).
* Obtaining the Plejd crypto key and the device ids.

## Gathering crypto and device information

Obtaining the crypto key and the device ids is a crucial step to get this
running, for this it is required to get the .site json file from the plejd app
on Android or iOS.

### Steps for Android

1. Turn on USB debugging and connect the phone to a computer.
2. Extract a backup from the phone:
```
$ adb backup com.plejd.plejdapp
```
3. Unpack the backup:
```
$ dd if=backup.ab bs=1 skip=24 | zlib-flate -uncompress | tar -xv
```
4. Recover the .site file:
```
$ cp apps/com.plejd.plejdapp/f/*/*.site site.json
```

### Steps for iOS

1. Open a backup in iBackup viewer.
2. Select raw files, look for AppDomainGroup-group.com.plejd.consumer.light.
3. In AppDomainGroup-group.com.plejd.consumer.light/Documents there should be two folders.
4. The folder that isn't named ".config" contains the .site file.

### Gather crypto key and ids for devices

When the site.json file has been recovered the cryptokey and the output
addresses can be extracted:

1. Extract the CryptoKey:
```
$ cat site.json | jq '.PlejdMesh.CryptoKey' | sed 's/-//g'
```
2. Extract the outputAddresses:
```
$ cat site.json | jq '.PlejdMesh._outputAddresses' | grep -v '\$type' | jq '.[][]'
```

These steps can obviously be done manually instead of extracting the fields
using jq and shell tricks. Device ids can also be found by configuring debug
logging and see when unknown devices appear in the log, while scenario and
timer ids can be found by listening for `plejd_scene_event`s.

## Installing component

### Hassbian

Make sure the Home Assistant user has permissions to use Bluetooth, this might
require putting it in the Bluetooth group.

To run this as a custom component, copy all files in `custom_components/plejd`,
to a `custom_components/plejd` folder under your Home Assistant directory.

### Hass.io Docker container

Hass.io default installation script will map `/usr/share/hassio/homeassistant`
to the `/config` directory inside the docker container.
Create a `custom_components` directory if it doesn't exist (it doesn't by default):
```
mkdir -p /usr/share/hassio/homeassistant/custom_components/plejd
```
Checkout the git repo and rename folder
```
cd /usr/share/hassio/homeassistant/custom_components/plejd
git checkout https://github.com/klali/ha-plejd.git
mv custom_components/plejd/* .
```

## Configuring component

Put the crypto key in your `secrets.yaml` file:
`plejd_crypto: "********************************"`

And configure the component in your `configuration.yaml`:
```
plejd:
  crypto_key: !secret plejd_crypto
  lights:
    11: bedroom
    13: kitchen_1
    14: kitchen_2
    16: bathroom
  switches:
    19: heater
  binary_sensors:
    17: button bedroom left
    18: button bedroom right
  sensors:
    21: bathroom rotary
  scenes:
    1: morning
    2: evening
    3: night
```

All dictionary items map from (integral) plejd ids to the name they should
have in Home Assistant.

## Restarting Home Assistant

The last step is to restart Home Assistant service, in the Home Assistant web
UI, go to Configuration -> General -> Server management and hit restart.

## Troubleshooting

Generally it is helpful to turn on debug logging for the component for any type
of troubleshooting, this will show what the component receives and interprets
from the plejd network. To do this add something like the following to your
configuration:
```
logger:
  logs:
    custom_components.plejd: debug
```


## License

```
Copyright 2019 Klas Lindfors <klali@avm.se>
Copyright 2021 Børge Nordli <bnordli@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
