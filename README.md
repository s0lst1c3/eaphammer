eaphammer
=========

by Gabriel Ryan ([s0lst1c3](https://twitter.com/s0lst1c3))(gryan[at]specterops.io)

[![Foo](https://rawcdn.githack.com/toolswatch/badges/8bd9be6dac2a1d445367001f2371176cc50a5707/arsenal/usa/2017.svg)](https://www.blackhat.com/us-17/arsenal.html#eaphammer)

Supports _Python 3.5+_.

Overview
--------

EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. It is designed to be used in full scope wireless assessments and red team engagements. As such, focus is placed on providing an easy-to-use interface that can be leveraged to execute powerful wireless attacks with minimal manual configuration. 
To illustrate just how fast this tool is, our Quick Start section provides an example of how to execute a credential stealing evil twin attack against a WPA/2-EAP network in just commands.

## Quick Start Guide (Kali)

Begin by cloning the __eaphammer__ repo using the following command:

	git clone https://github.com/s0lst1c3/eaphammer.git

Next run the kali-setup file as shown below to complete the eaphammer setup process. This will install dependencies and compile the project:

	./kali-setup

To setup and execute a credential stealing evil twin attack against a WPA/2-EAP network:

	# generate certificates
	./eaphammer --cert-wizard

	# launch attack
	./eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds

## Usage and Setup Instructions

For complete usage and setup instructions, please refer to the project's wiki page:

- [https://github.com/s0lst1c3/eaphammer/wiki](https://github.com/s0lst1c3/eaphammer/wiki)

## Contributing

Contributions are encouraged and more than welcome. Please attempt to adhere to the provided issue and feature request templates.

## Versioning

We use [SemVer](http://semver.org/) for versioning (or at least make an effort to). For the versions available, see  [https://github.com/s0lst1c3/eaphammer/releases](https://github.com/s0lst1c3/eaphammer/releases). 

## License

This project is licensed under the GNU Public License 3.0 - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments
This tool either builds upon, is inspired by, or directly incorporates over ten years of prior research and development from the following awesome people:

- [Josh Wright and Brad Antoniewicz - Attacks Against Weak EAP Methods](http://www.willhackforsushi.com/presentations/PEAP_Shmoocon2008_Wright_Antoniewicz.pdf)
- [Dom White and Ian de Villier - More Attacks Against Weak EAP Methods](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1%2F2/)
- [Moxie Marlinspike and David Hulton - Attacks Against MS-CHAPv2](http://web.archive.org/web/20160203043946/https:/www.cloudcracker.com/blog/2012/07/29/cracking-ms-chap-v2/)

Leverages a [lightly modified](https://github.com/s0lst1c3/hostapd-eaphammer) version of [hostapd-wpe](https://github.com/opensecurityresearch/hostapd-wpe) (shoutout to [Brad Anton](https://github.com/brad-anton) for creating the original), _dnsmasq_, [asleap](https://github.com/joswr1ght/asleap), [hcxpcaptool](https://github.com/ZerBea/hcxtools) and [hcxdumptool](https://github.com/ZerBea/hcxdumptool) for PMKID attacks, [Responder](https://github.com/SpiderLabs/Responder), and _Python 3.5+_.


