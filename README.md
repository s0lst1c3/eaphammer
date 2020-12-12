![logo](https://rawcdn.githack.com/s0lst1c3/eaphammer/ab8202de4a298957a2bc5662f986cdfb195490e4/docs/img/logo.png)

by Gabriel Ryan ([s0lst1c3](https://twitter.com/s0lst1c3))(gabriel[at]solstice|d0t|sh)

[![Foo](https://rawcdn.githack.com/toolswatch/badges/8bd9be6dac2a1d445367001f2371176cc50a5707/arsenal/usa/2017.svg)](https://www.blackhat.com/us-17/arsenal.html#eaphammer)

Current release: [v1.13.5](https://github.com/s0lst1c3/eaphammer/releases/tag/v1.13.5)

Supports _Python 3.5+_.

Overview
--------

EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. It is designed to be used in full scope wireless assessments and red team engagements. As such, focus is placed on providing an easy-to-use interface that can be leveraged to execute powerful wireless attacks with minimal manual configuration. 
To illustrate just how fast this tool is, our Quick Start section provides an example of how to execute a credential stealing evil twin attack against a WPA/2-EAP network in just commands.

## Disclaimer

EAPHammer (the "Software") and associated documentation is provided “AS IS”. The Developer makes no other warranties, express or implied, and hereby disclaims all implied warranties, including any warranty of merchantability and warranty of fitness for a particular purpose. Any actions or activities related to the use of the Software are the sole responsibility of the end user. The Developer will not be held responsible in the event that any criminal charges are brought against any individuals using or misusing the Software. It is up to the end user to use the Software in an authorized manner and to ensure that their use complies with all applicable laws and regulations.

## Quick Start Guide - Kali

Begin by cloning the __eaphammer__ repo using the following command:

	git clone https://github.com/s0lst1c3/eaphammer.git

Next run the kali-setup file as shown below to complete the eaphammer setup process. This will install dependencies and compile the project:

	./kali-setup

To setup and execute a credential stealing evil twin attack against a WPA/2-EAP network:

	# generate certificates
	./eaphammer --cert-wizard

	# launch attack
	./eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds

## Quick Start Guide - Parot OS (Security)

Begin by cloning the __eaphammer__ repo using the following command:

	git clone https://github.com/s0lst1c3/eaphammer.git

Next run the parot-setup file as shown below to complete the eaphammer setup process. This will install dependencies and compile the project:

	./parot-setup

To setup and execute a credential stealing evil twin attack against a WPA/2-EAP network:

	# generate certificates
	./eaphammer --cert-wizard

	# launch attack
	./eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds


## Usage and Setup Instructions

For complete usage and setup instructions, please refer to the project's wiki page:

- [https://github.com/s0lst1c3/eaphammer/wiki](https://github.com/s0lst1c3/eaphammer/wiki)

Features
--------

- Steal RADIUS credentials from WPA-EAP and WPA2-EAP networks.
- Perform hostile portal attacks to steal AD creds and perform indirect wireless pivots
- Perform captive portal attacks
- Built-in Responder integration
- Support for Open networks and WPA-EAP/WPA2-EAP
- No manual configuration necessary for most attacks.
- No manual configuration necessary for installation and setup process
- Leverages latest version of hostapd (2.8)
- Support for evil twin and karma attacks
- Generate timed Powershell payloads for indirect wireless pivots
- Integrated HTTP server for Hostile Portal attacks
- Support for SSID cloaking
- Fast and automated PMKID attacks against PSK networks using hcxtools
- Password spraying across multiple usernames against a single ESSID

### New (as of Version 1.13.5)(latest): 
EAPHammer now has a modular captive portal with keylogging and payload delivery capabilities, as well as an integrated website cloaner for easily creating portal modules.

### WPA/2-PSK handshake captures (added as for version 1.7.0)
EAPHammer now supports WPA/2-PSK along with WPA handshake captures.

### OWE (added as of Version 1.5.0):
EAPHammer now supports rogue AP attacks against OWE and OWE-Transition mode networks.

### PMF (added as of Version 1.4.0)
EAPHammer now supports 802.11w (Protected Management Frames), Loud Karma attacks, and Known Beacon attacks (documentation coming soon).

### GTC Downgrade Attacks
EAPHammer will now automatically attempt a GTC Downgrade attack against connected clients in an attempt to capture plaintext credentials (see: https://www.youtube.com/watch?v=-uqTqJwTFyU&feature=youtu.be&t=22m34s). 

### Improved Certificate Handling
EAPHammer's Cert Wizard has been expanded to provide users with the ability to create, import, and manage SSL certificates in a highly flexible manner. Cert Wizard's previous functionality has been preserved as Cert Wizard's Interactive Mode, which uses the same syntax as previous versions. See [XIV - Cert Wizard](https://github.com/s0lst1c3/eaphammer/wiki/XIV.-Cert-Wizard) for additional details.

### TLS / SSL Backwards Compatibility
EAPHammer now uses a local build of libssl that exists independently of the systemwide install. This local version is compiled with support for SSLv3, allowing EAPHammer to be used against legacy clients without compromising the integrity of the attacker's operating system.

### Supported EAP Methods
EAPHammer supports the following EAP methods:

- EAP-PEAP/MSCHAPv2
- EAP-PEAP/GTC
- EAP-PEAP/MD5
- EAP-TTLS/PAP
- EAP-TTLS/MSCHAP
- EAP-TTLS/MSCHAPv2
- EAP-TTLS/MSCHAPv2 (no EAP)
- EAP-TTLS/CHAP
- EAP-TTLS/MD5
- EAP-TTLS/GTC
- EAP-MD5


### 802.11a and 802.11n Support

EAPHammer now supports attacks against 802.11a and 802.11n networks. This includes the ability to create access points that support the following features:

- Both 2.4 GHz and 5 GHz channel support
- Full MIMO support (multiple input, multiple output)
- Frame  aggregation
- Support for 40 MHz channel widths using channel bonding
- High Throughput Mode
- Short Guard Interval (Short GI)
- Modulation & coding scheme (MCS)
- RIFS
- HT power management

Upcoming Features
-----------------

- Perform seamless MITM attacks with partial HSTS bypasses
- directed rogue AP attacks (deauth then evil twin from PNL, deauth then karma + ACL)
- Integrated website cloner for cloning captive portal login pages
- Integrated HTTP server for captive portals

## Contributing

Contributions are encouraged and more than welcome. Please attempt to adhere to the provided issue and feature request templates.

## Versioning

We use [SemVer](http://semver.org/) for versioning (or at least make an effort to). For the versions available, see  [https://github.com/s0lst1c3/eaphammer/releases](https://github.com/s0lst1c3/eaphammer/releases). 

## License

This project is licensed under the GNU Public License 3.0 - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments
This tool either builds upon, is inspired by, or directly incorporates nearly fifteen years of prior research and development from the following awesome people:

* Brad Antoniewicz
* Joshua Wright
* Robin Wood
* Dino Dai Zovi
* Shane Macauly
* Domanic White
* Ian de Villiers
* Michael Kruger
* Moxie Marlinspike
* David Hulton
* Josh Hoover
* James Snodgrass
* Adam Toscher
* George Chatzisofroniou
* Mathy Vanhoef

For a complete description of what each of these people has contributed to the current wireless security landscape and this tool, please see:

* [https://github.com/s0lst1c3/eaphammer/wiki/Acknowledgements](https://github.com/s0lst1c3/eaphammer/wiki/Acknowledgements)

EAPHammer leverages a modified  version of [hostapd-wpe](https://github.com/opensecurityresearch/hostapd-wpe) (shoutout to [Brad Anton](https://github.com/brad-anton) for creating the original), _dnsmasq_, [asleap](https://github.com/joswr1ght/asleap), [hcxpcaptool](https://github.com/ZerBea/hcxtools) and [hcxdumptool](https://github.com/ZerBea/hcxdumptool) for PMKID attacks, [Responder](https://github.com/SpiderLabs/Responder), and _Python 3.5+_.

Finally, huge shoutout to the [SpecterOps](https://specterops.io/) crew for supporting this project and being a constant source of inspiration.

