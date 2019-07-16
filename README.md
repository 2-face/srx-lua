# Wireshark Dissector for NULL loopback traffic collected on Juniper vSRX

## Table of Contents
+ [About](#about)
+ [Usage](#usage)

## About <a name = "about"></a>
Original NULL loopback dissector cannot decode packets collected with ```monitor traffic``` on Juniper vSRX firewall. This LUA dissector enables to decode such packets.

## Usage <a name = "usage"></a>
Copy LUA dissector as follows (OSX example). Find appropriate directory on other platforms.
```shell session
cp srx-null-loopback-dissector.lua /Applications/Wireshark.app/Contents/PlugIns/wireshark/
```