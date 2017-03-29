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
- Integrated website cloner for cloning captive portal login pages
- Integrated HTTP server

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

To steal RADIUS credentials by executing an evil twin attack against an EAP network, use the --creds flag as shown below.

	./eaphammer --bssid 1C:7E:E5:97:79:B1 --essid Example --channel 2 --interface wlan0 --auth ttls --creds

The flags shown above are self explanatory. For more granular control over the attack, you can use the --wpa flag to specify WPA vs WPA2 and the --auth flag to specify the eap type. Note that for cred reaping attacks, you should always specify an auth type manually since the the --auth flag defaults to "open" when omitted.

	./eaphammer --bssid 00:11:22:33:44:00 --essid h4x0r --channel 4 --wpa 2 --auth ttls --interface wlan0 --creds

Please refer to the options described in [Additional Options](#additional-options) section of this document for additional details about these flags.

Stealing AD Credentials Using Hostile Portal Attacks
----------------------------------------------------

Eaphammer can perform hostile portal attacks that can force LLMNR/NBT-NS enabled Windows clients into surrendering password hashes. The attack works by forcing associations using an evil twin attack, then forcing associated clients to attempt NetBIOS named resolution using a [Redirect To SMB](https://www.cylance.com/redirect-to-smb) attack. While this occurs, eaphammer runs [Responder](https://github.com/SpiderLabs/Responder) in the background to perform a nearly instantaneous LLMNR/NBT-NS poisoning attack against the affected wireless clients. The result is an attack that causes affected devices to not only connect to the rogue access point, but send NTLM hashes to the rogue access point as well.

Performing Indirect Wireless Pivots Using Hostile Portal Attacks
----------------------------------------------------------------

Lorem ipsem blah blah blah.

Performing Captive Portal Attacks
---------------------------------

To perform a captive portal attack using eaphammer, use the --captive-portal flag as shown below.

	./eaphammer --bssid 1C:7E:E5:97:79:B1 --essid HappyMealz --channel 6 --interface wlan0 --captive-portal

This will cause eaphammer to execute an evil twin attack in which the HTTP(S) traffic of all affected wireless clients are redirected to a website you control. Eaphammer will leverage Apache2 to serve web content out of /var/www/html if used with the default Apache2 configuration. Future iterations of eaphammer will provide an integrated HTTP server and website cloner for attacks against captive portal login pages.

Additional Options
------------------

- __--cert-wizard__ - Use this flag to create a new RADIUS cert for your AP.
- __-h, --help__ - Display detailed help message and exit.
- __-i, --interface__ - Specify the a PHY interface on which to create your AP.
- __-e ESSID, --essid ESSID__ - Specify access point ESSID.
- __-b BSSID, --bssid BSSID__ - Specify access point BSSID.
- __--hw-mode HW-MODE__ - Specify access point hardware mode (default: g).
- __-c CHANNEL, --channel CHANNEL__ - Specify access point channel.
- __--wpa {1,2}__ - Specify WPA type (default: 2).
- __--auth {peap,ttls,open}__ - Specify auth type (default: open).
- __--creds__ - Harvest EAP creds using an evil twin attack.
- __--hostile-portal__ - Force clients to connect to hostile portal.
- __--captive-portal__ - Force clients to connect to a captive portal.
