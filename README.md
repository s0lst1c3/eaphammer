eaphammer
=========

by Gabriel Ryan ([s0lst1c3](https://twitter.com/s0lst1c3))

Overview
--------

EAPHammer is a toolkit for performing targetted evil twin attacks against WPA2-Enterprise networks. It is designed to be used in full scope wireless assessments and red team engagements. As such, focus is placed on providing an easy-to-use interface that can be leveraged to execute powerful wireless attacks with minimal manual configuration. Leverages hostapd-wpe, dnsmasq, dnsspoof, Responder, and Python 2.7.

Features
--------

- Steal RADIUS credentials from WPA-EAP and WPA2-EAP networks.
- Perform hostile portal attacks to steal AD creds and perform indirect wireless pivots
- Perform captive portal attacks
- Built-in Responder integration
- Support for Open networks and WPA-EAP/WPA2-EAP
- No manual configuration necessary for most attacks.
- No manual configuration necessary for installation and setup process

Upcoming Features
-----------------

- Perform seemeless MITM attacks with partial HSTS bypasses
- Support attacks against WPA-PSK/WPA2-PSK
- Support for SSID cloaking
- Generate timed payloads for indirect wireless pivots
- Integrated PowerShell payload generation
- impacket integration for SMB relay attacks
- directed rogue AP attacks (deauth then evil twin from PNL, deauth then karma + ACL)
- Updated hostapd-wpe that works with the latest version of Hostapd

Will this tool ever support Karma attacks?

- At some point yes, but for now the focus has been on directed evil twin attacks.
- If Karma attacks are like a wireless grenade launcher, this tool is more like an easy-to-use wireless sniper rifle

Setup Guide
===========


Begin by cloning the __eaphammer__ repo using the following command.

	git clone git@github.com:s0lst1c3/eaphammer.git

Next, use your package manager to install the depencies listed in `kali-dependencies.txt`.

Finally, run the setup.py file as shown below to complete the eaphammer setup process.

	python setup.py

Usage Guide
===========

x.509 Certificate Generation
----------------------------

Eaphammer provides an easy-to-use wizard for generating x.509 certificates. To launch eaphammer's certificate wizard, just use the command shown below.

	./eaphammer --cert-wizard

Stealing RADIUS Credentials From EAP Networks
---------------------------------------------

Lorem ipsem blah blah blah.

For more granular control over your rogue access point attack, please refer to the options described in the [Additional Options](#additional-options) section of this document.

Stealing AD Credentials Using Hostile Portal Attacks
----------------------------------------------------

Lorem ipsem blah blah blah.

Performing Indirect Wireless Pivots Using Hostile Portal Attacks
----------------------------------------------------------------

Lorem ipsem blah blah blah.

Performing Captive Portal Attacks
---------------------------------

Lorem ipsem blah blah blah.

Additional Options
------------------

Info about additional flags here.
