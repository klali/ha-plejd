# Plejd component for Home Assistant

This is a simple Plejd component for Home Assistant, interfacing with the
bluetooth le protocol.

## Getting started

## Tested platforms
This component has been tested on the following platforms:
 - Raspberry pi 3b+ running hassbian (Bluetooth 4.2 Cypress CYW43455 chip)
 - Intel NUC NUC7i7BNH (Bluetooth 4.2 Intel 8265) running ESXi 6.7 and linux guest

## Requirements
* A bluetooth adapter that supports Bluetooth Low Energy (BLE)
* Obtaining the Plejd crypto key and the device ids.

## Gathering crypto and device information

Obtaining the crypto key and the device ids is a crucial step to get this
running, for this it is required to get the .site json file from the plejd app
on android or iOS.

### Steps for android:

1. Turn on USB debugging and connect the phone to a computer.
2. Extract a backup from the phone:
```
$ adb backup com.plejd.plejdapp
```
3. Unpack the backup:
```
$ dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" | tar -xv
```
4. Recover the .site file:
```
$ cp apps/com.plejd.plejdapp/f/*/*.site site.json
```

### Steps for iOS:

1. Open a backup in iBackup viewer.
2. Select raw files, look for AppDomainGroup-group.com.plejd.consumer.light.
3. In AppDomainGroup-group.com.plejd.consumer.light/Documents there should be two folders.
4. The folder that isn't named ".config" contains the .site file.

### Gather cryto key and ids for devices

When the site.json file has been recovered the cryptokey and the output
addresses can be extracted:

1. Extract the cryptoKey:
```
$ cat site.json | jq '.PlejdMesh.CryptoKey' | sed 's/-//g'
```
2. Extract the outputAddresses:
```
$ cat site.json  | jq '.PlejdMesh.outputAdresses' | grep -v '\$type' | jq '.[][]'
```

These steps can obviously be done manually instead of extracting the fields
using jq and shell tricks.


## Installing component

### Hassbian:

Make sure to have bluepy installed in your python environment. Bluepy comes
with a helper called bluepy-helper, to allow scanning for devices this has
to be given additional capabilities:
```
$ sudo setcap 'cap\_net\_raw,cap\_net\_admin+eip' /srv/homeassistant/lib/python3.5/site-packages/bluepy/bluepy-helper
```

Run this as a custom component, put the files light.py, manifest.json and
\_\_init\_\_.py in custom\_components/plejd in your configuration.yaml add
something like:

```
light:
  - platform: plejd
    crypto_key: !secret plejd
    devices:
      11:
        name: bedroom
      13:
        name: kitchen_1
      14:
        name: kitchen_2
      16:
        name: bathroom
```

### HASS.IO Docker container

Hass.io default installation script will map /usr/share/hassio/homeassistant to the /config directory inside the docker container.
create a custom\_components directory if it doesn't exist (it doesn't by default).
```
mkdir -p /usr/share/hassio/homeassistant/custom_components
```
Checkout the git repo and rename folder
```
cd /usr/share/hassio/homeassistant/custom_components
git checkout https://github.com/klali/ha-plejd.git
mv ha-plejd plejd
```
Update your configuration.yaml file
```
light:
  - platform: plejd
    crypto_key: !secret plejd
    devices:
      11:
        name: bedroom
      13:
        name: kitchen_1
      14:
        name: kitchen_2
      16:
        name: bathroom

```
Last step is to restart homeassistant service, in the homeassistant web ui, go to Configuration -> General -> Server management and hit restart.


## License

```
Copyright 2019 Klas Lindfors <klali@avm.se>

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
