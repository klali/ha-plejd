# Upgrade notes

Read this if you are upgrading this component between major versions.

## Upgrading from version 1 to version 2

Example of an old configuration:
```
light:
  - platform: plejd
    crypto_key: !secret plejd_crypto
    devices:
      11:
        name: bedroom
      13:
        name: kitchen
```
The corresponding new configuration:
```
plejd:
  crypto_key: !secret plejd_crypto
  lights:
    11: bedroom
    13: kitchen
```

# Full configuration samples

## Version 1

Version 1 of this component had only a light platform, and was configured this
way:

```
light:
  - platform: plejd
    crypto_key: !secret plejd_crypto
    devices:
      11:
        name: bedroom
      13:
        name: kitchen
```

## Version 2

Version 2 is a complete component with support for more domains and is
configured this way:

```
plejd:
  crypto_key: !secret plejd_crypto
  lights:
    11: bedroom
    13: kitchen
  switches:
    19: heater
  binary_sensors:
    17: button bedroom left
    18: button bedroom right
  sensors:
    21: bathroom rotary
  scenes:
    1: night
```
