eaphammer
=========

by Gabriel Ryan ([s0lst1c3](https://twitter.com/s0lst1c3))

[![Black Hat Arsenal](https://cdn.rawgit.com/toolswatch/badges/master/arsenal/2017.svg)](https://www.blackhat.com/us-17/arsenal.html#eaphammer)

Overview
--------

EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. It is designed to be used in full scope wireless assessments and red team engagements. As such, focus is placed on providing an easy-to-use interface that can be leveraged to execute powerful wireless attacks with minimal manual configuration. To illustrate how fast this tool is, here's an example of how to setup and execute a credential stealing evil twin attack against a WPA2-TTLS network in just two commands:

	# generate certificates
	./eaphammer --cert-wizard

	# launch attack
	./eaphammer -i wlan0 --channel 4 --auth wpa --essid CorpWifi --creds

Leverages a [lightly modified](https://github.com/s0lst1c3/hostapd-eaphammer) version of [hostapd-wpe](https://github.com/opensecurityresearch/hostapd-wpe) (shoutout to [Brad Anton](https://github.com/brad-anton) for creating the original), _dnsmasq_, [asleap](https://github.com/joswr1ght/asleap), [hcxpcaptool](https://github.com/ZerBea/hcxtools) and [hcxdumptool](https://github.com/ZerBea/hcxdumptool) for PMKID attacks, [Responder](https://github.com/SpiderLabs/Responder), and _Python 2.7_.

Features
--------

- Steal RADIUS credentials from WPA-EAP and WPA2-EAP networks.
- Perform hostile portal attacks to steal AD creds and perform indirect wireless pivots
- Perform captive portal attacks
- Built-in Responder integration
- Support for Open networks and WPA-EAP/WPA2-EAP
- No manual configuration necessary for most attacks.
- No manual configuration necessary for installation and setup process
- Leverages latest version of hostapd (2.6)
- Support for evil twin and karma attacks
- Generate timed Powershell payloads for indirect wireless pivots
- Integrated HTTP server for Hostile Portal attacks
- Support for SSID cloaking
- Fast and automated PMKID attacks against PSK networks using hcxtools

New (as of Version 0.4.0)(latest)
---------------------------------

- EAPHammer now supports password spraying across multiple usernames against a single ESSID

802.11a and 802.11n Support
---------------------------

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

Table of Contents
=================

   * [Setup Guide](#setup-guide)
      * [I. Kali Setup Instructions](#i-kali-setup-instructions)
      * [II. Other Distros](#ii-other-distros)
   * [Usage Guide](#usage-guide)
      * [I - x.509 Certificate Generation](#i---x509-certificate-generation)
      * [II - Stealing RADIUS Credentials Using EAPHammer](#ii---stealing-radius-credentials-using-eaphammer)
      * [III - Stealing AD Credentials Using Hostile Portal Attacks](#iii---stealing-ad-credentials-using-hostile-portal-attacks)
      * [IV - Indirect Wireless Pivots](#iv---indirect-wireless-pivots)
         * [IV.1 - Performing Indirect Wireless Pivots Using Hostile Portal Attacks](#iv1---performing-indirect-wireless-pivots-using-hostile-portal-attacks)
         * [IV.2 - Indirect Wireless Pivots - A Generalized Strategy](#iv2---indirect-wireless-pivots---a-generalized-strategy)
      * [V - Performing Captive Portal Attacks](#v---performing-captive-portal-attacks)
      * [VI - Attacking 802.11n Networks](#vi---attacking-80211n-networks)
         * [VI.1 - 802.11n Basics - Creating Rogue APs with 20Mhz Channel Widths](#vi1---80211n-basics---creating-rogue-aps-with-20mhz-channel-widths)
         * [VI.2 - Controlling Channel Width, Enabling MIMO / Channel Bonding](#vi2---controlling-channel-width-enabling-mimo--channel-bonding)
         * [VI.3 - Advanced Usage: Specifying Primary and Secondary Channels, Channel Bonding](#vi3---advanced-usage-specifying-primary-and-secondary-channels-channel-bonding)
         * [VI.4 - Advanced Usage: Max Spatial Streams, SMPS, and More](#vi4---advanced-usage-max-spatial-streams-smps-and-more)
      * [VII - Hardware Modes: 802.11b / 802.11g / 802.11a / 802.11n / etc](#vii---hardware-modes-80211b--80211g--80211a--80211n--etc)
      * [VIII - Attacking WPA-EAP and WPA2-EAP Networks](#viii---attacking-wpa-eap-and-wpa2-eap-networks)
         * [VIII.1 - Considerations When Attacking WPA2-EAP Networks](#viii1---considerations-when-attacking-wpa2-eap-networks)
         * [VIII.2 - Using AutoCrack](#viii2---using-autocrack)
         * [VIII.3 - EAPHammer User Database](#viii3---eaphammer-user-database)
            * [VIII.3.a - Basic Usage](#viii3a---basic-usage)
               * [VIII.3.aa - Listing Users](#viii3aa---listing-users)
               * [VIII.3.ab - Adding Users](#viii3ab---adding-users)
               * [VIII.3.ac - Deleting Users](#viii3ac---deleting-users)
               * [VIII.3.ad - Updating Users](#viii3ad---updating-users)
               * [VIII.3.ae - Search Filters](#viii3ae---search-filters)
            * [VIII.4.b - Advanced Usage](#viii4b---advanced-usage)
      * [IX - ESSID Cloaking](#ix---essid-cloaking)
      * [X - Using Karma](#x---using-karma)
	  * [XI - PMKID Attacks Against WPA-PSK and WPA2-PSK Networks](#xi---pmkid-attacks-against-wpa-psk-and-wpa2-psk-networks)
	  * [XII - Password Spraying](#xii---password-spraying)
      * [XIII - Advanced Granular Controls](#xiii---advanced-granular-controls)

Setup Guide
===========

I. Kali Setup Instructions
--------------------------


Begin by cloning the __eaphammer__ repo using the following command.

	git clone https://github.com/s0lst1c3/eaphammer.git

Next run the kali-setup file as shown below to complete the eaphammer setup process. This will install dependencies and compile hostapd.

	./kali-setup

II. Other Distros
-----------------

If you are not using Kali, you can still compile eaphammer. I just haven't written a setup script for your distro yet, which means you'll have to do it manually. Ask yourself whether you understand the following:

- python-devel vs python-dev
- service vs systemctl
- network-manager vs NetworkManager
- httpd vs apache2

If you looked at this list and immediately realized that each pair of items was to some extent equivalent (well, except for service vs systemctl, but you catch my drift), you'll probably have no problems getting this package to work on the distro of your choice. If not, please just stick with Kali until support is added for other distros.

With that out of the way, here are the generic setup instructions:

Use your package manager to install each of the dependencies listed in `kali-dependencies.txt`. Package names can vary slightly from distro to distro, so you may get a "package not found" error or similar. If this occurs, just use Google to find out what the equivalent package is for your distro and install that instead.

Once you have installed each of the dependencies listed in `kali-dependencies.txt`, you'll need to install some additional packages that ship with Kali by default. These packages are listed below. If you're on a distro that uses httpd instead of apache2, install that instead.

- dsniff
- apache2

Compile hostapd using the following commands:

	cd hostapd-eaphammer/hostapd
	make hostapd-eaphammer_lib

Open settings/core/eaphammer.ini in the text editor of your choice and edit the following lines so that to values that work for your distro:

	# change this to False if you cannot/will not use systemd
	use_systemd = True

	# change this to 'NetworkManager' if necessary
	network_manager = 'network-manager'

	# change this 'httpd' if necessary
	httpd = 'apache2'


Usage Guide
==========

EAPHammer is designed to be easy to use, so you should be able to get pretty far using the example based documenation that makes up most of this Readme. 

EAPHammer has four modes of operation:

- __--cert-wizard__ - Use this flag to create a new RADIUS cert for your AP (needed for any attack that involves EAP). See: [I - x.509 Certificate Generation](#i---x509-certificate-generation)
- __--creds__ - Harvest RADIUS credentials using rogue access point attack. See: [II - Stealing RADIUS Credentials Using EAPHammer](#ii---stealing-radius-credentials-using-eaphammer)
- __--hostile-portal__ - Rapidly steal active directory credentials, perform indirect wireless pivots. See: [III - Stealing AD Credentials Using Hostile Portal Attacks](#iii---stealing-ad-credentials-using-hostile-portal-attacks) and [IV - Indirect Wireless Pivots](#iv---indirect-wireless-pivots)
- __--captive-portal__ - Force clients to connect to a captive portal. See: [V - Performing Captive Portal Attacks](#v---performing-captive-portal-attacks).

Further documentation for each one of these modes can be found in the sections referenced in the list above. You can access EAPHammer's built in help menus by using either the -h or -hh flags as shown below:

	# display basic help
	./eaphammer -h

	# display advanced help
	./eaphammer -hh

## I - x.509 Certificate Generation

Certificates are required to perform any attack against networks that use EAP-PEAP, EAP-TTLS, or any other form of EAP in which the inner authentication occurs through a secure tunnel. Fortunately, EAPHammer provides an easy-to-use wizard for generating x.509 certificates. To launch eaphammer's certificate wizard, just use the command shown below.

	./eaphammer --cert-wizard

## II - Stealing RADIUS Credentials Using EAPHammer

*Note: you will need to generate a certificate in order to perform this attack. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

To steal RADIUS credentials by executing an evil twin attack against an EAP network, use the --creds flag as shown below.

	./eaphammer --bssid 1C:7E:E5:97:79:B1 --essid Example --channel 2 --interface wlan0 --creds

## III - Stealing AD Credentials Using Hostile Portal Attacks

*Note: you will need to generate a certificate in order to perform this attack against most EAP networks. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

*Note: you will need RADIUS creds in order to perform this attack against EAP implementations that use mutual authentication protocols such as MS-CHAPv2 for inner authentication. Please refer to* [VIII.1 - Considerations When Attacking WPA2-EAP Networks](#VIII.1---Considerations-When-Attacking-WPA2-EAP-Networks) *for additional information.*

Hostile Portal Attacks are a weaponization of the captive portals typically used to restrict access to open networks in environments such as hotels and coffee shops. Instead of redirecting HTTP traffic to a login page, as with a captive portal, the hostile portal redirects HTTP traffic to an SMB share located on the attacker's machine. The result is that after the victim is forced to associate with the attacker using a rogue access point attack, any HTTP traffic generated by the victim will cause the victim's device to attempt NTLM authentication with the attacker. This is, in essence, an assisted [Redirect To SMB](https://www.cylance.com/redirect-to-smb) attack. The attacker also performs LLMNR/NBT-NS poisoning against the victim.

This attack gets you lots and lots of Active Directory credentials, simply by forcing clients to connect and authenticate with you. The results are similar to what you'd get using a tool such as [Responder](https://github.com/lgandx/Responder), with some distinct advantages:

- __Stealthy__: This is a rogue AP attack, so no direct network is required
- __Large Area of Effect__: This is an attack that works across multiple subnets -- you can pwn everything that is connected to the wireless network.
- __Efficient__: This is an active attack in which the attacker forces clients to authenticate. There is no waiting for a network event to occur, as with LLMNR/NBT-NS poisoning.

The --hostile-portal flag can be used to execute a hostile portal attack, as shown in the examples below.

	./eaphammer --interface wlan0 --bssid 1C:7E:E5:97:79:B1 --essid EvilC0rp --channel 6 --auth wpa --hostile-portal

	./eaphammer --interface wlan0 --essid TotallyLegit --hw-mode n --channel 36 --auth open --hostile-portal


## IV - Indirect Wireless Pivots

*Note: you will need to generate a certificate in order to perform this attack against most EAP networks. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

*Note: you will need RADIUS creds in order to perform this attack against EAP implementations that use mutual authentication protocols such as MS-CHAPv2 for inner authentication. Please refer to* [VIII.1 - Considerations When Attacking WPA2-EAP Networks](#VIII.1---Considerations-When-Attacking-WPA2-EAP-Networks) *for additional information.*

An Indirect Wireless Pivot is a technique for bypassing port-based access control mechanisms using rogue access point attacks. The attack requires the attacker to use two wireless network interfaces. The first network interface is used to obtain an IP address on the target network. Presumably, this first network interface is placed in quarantine by the NAC when this occurs. The attacker then uses a rogue AP attack to coerce a victim into connecting to the attacker's second wireless interface. The attacker then exploits the victim in some way, allowing the attacker to place a timed payload on the victim's device. The attacker then shuts down the rogue access point, allowing the victim to reassociate with the target network. The attacker then waits for the timed payload to execute and send a reverse shell back to the first interface, allowing the attacker to escape the quarantine.

EAPHammer can be used to perform Indirect Wireless Pivots, as described in the following sections.

### IV.1 - Performing Indirect Wireless Pivots Using Hostile Portal Attacks

Before you begin the attack, make sure you have the following:

1. RADIUS creds for a number of victim devices (see [VIII.1 - Considerations When Attacking WPA2-EAP Networks](#VIII.1---Considerations-When-Attacking-WPA2-EAP-Networks))
2. Two network interfaces: we will call these **Interface A** and **Interface B**.

__Step 1__ - Connect to the target network using **Interface A**

__Step 2__ - Use the payload\_generator to generate a timed payload to execute on the victim. If your payload is a reverse shell, make sure to configure it so that it connects back to **Interface A**.

	./payload_generator --delay DELAY_IN_SECONDS --command COMMAND --args ARGS

__Step 3__ - Execute a Hostile Portal Attack using EAPHammer, making sure to add the --pivot flag as shown below. Make sure to use **Interface B** to execute the attack.

	./eaphammer -i wlan0 --essid EvilCorp --channel 3 --hostile-portal --pivot

__Step 4__ - After at least two victims have connected to your rogue access point, start your SMB Relay server as shown below. The following example uses [impacket](https://github.com/CoreSecurity/impacket)'s smbrelayx script, but you can realistically use any SMB Relay server you want. MultiRelay (which is part of [Responder](https://github.com/lgandx/Responder)) and [snarf.js](https://github.com/purpleteam/snarf) are both solid choices. The SMB Relay server should be configured to listen on **Interface B**, and to execute the timed payload you created in Step 2 when the attack succeeds. The target of the attack should be the IP address of one of the devices that is connected to your rogue access point.

	smbrelayx.py -h TARGET_IP -c TIMED_PAYLOAD

__Step 5__ - When your SMB Relay script executes, shutdown EAPHammer by pressing the Enter key on your keyboard.

__Step 6__ - Wait for the timed payload to execute and send a reverse shell back to **Interface A**.

### IV.2 - Indirect Wireless Pivots - A Generalized Strategy

Be creative. The specific details of this attack aren't important, and the steps provided in the previous section are merely one example of how to perform an Indirect Wireless Pivot. As long as you use the following general steps, the attack should work:

1. Connect to the target network using your first network interface
2. Use a rogue access point attack to force an authorized device to connect to your second network interface
3. Exploit the connected device in some way to place an implant or timed payload on the device
4. Allow the connected device to reassociate with the target network
5. Wait for your payload to execute

The takeaway here is that you are removing an authorized device from its protected environment, exploiting it in some way, then allowing it to reassociate with the target network.


## V - Performing Captive Portal Attacks

*Note: you will need to generate a certificate in order to perform this attack against most EAP networks. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

*Note: you will need RADIUS creds in order to perform this attack against EAP implementations that use mutual authentication protocols such as MS-CHAPv2 for inner authentication. Please refer to* [VIII.1 - Considerations When Attacking WPA2-EAP Networks](#VIII.1---Considerations-When-Attacking-WPA2-EAP-Networks) *for additional information.*

To perform a captive portal attack using eaphammer, use the --captive-portal flag as shown below.

	./eaphammer --bssid 1C:7E:E5:97:79:B1 --essid HappyMealz --channel 149 --interface wlan0 --captive-portal

This will cause eaphammer to execute an evil twin attack in which the HTTP(S) traffic of all affected wireless clients are redirected to a website you control. Eaphammer will leverage Apache2 to serve web content out of /var/www/html if used with the default Apache2 configuration. Future iterations of eaphammer will provide an integrated HTTP server and website cloner for attacks against captive portal login pages.

## VI - Attacking 802.11n Networks

*Note: It is highly recommended to read  [VII - Hardware Modes: 802.11b / 802.11g / 802.11a / 802.11n / etc](#vii---hardware-modes-80211b--80211g--80211a--80211n--etc) prior to this section.*
*Note: at the moment, EAPHammer does not support DSSS. This section is written with the implicit understanding that OFDM is being used. If you don't know what any of this means, that's totally fine. I just added this note to save myself time answering nitpicky Github issues.*

This section describes how to use EAPHammer to attack networks that use 802.11n. Since attacking these networks effectively requires a basic understanding of 802.11n concepts such as MIMO and channel bonding, it's probably a good idea to give yourself a crash course on 802.11n by reading this short article (or similar):

- [https://www.computerworld.com/article/2481909/emerging-technology/what-every-it-professional-should-know-about-802-11n--part-1-.html](https://www.computerworld.com/article/2481909/emerging-technology/what-every-it-professional-should-know-about-802-11n--part-1-.html)

There are more in-depth tutorials on 802.11n out there, but the one referenced above will get you by. If you're already familiar with 802.11n, feel free to skip it.

### VI.1 - 802.11n Basics - Creating Rogue APs with 20Mhz Channel Widths

To perform a basic rogue AP attack using 802.11n, use the --hw-mode n flag as shown below:

	./eaphammer -i wlan0 --essid lulz0rz --hw-mode n --channel 1

This will spawn a rogue access point that uses 802.11n with a 20MHz channel width. The actual hardware mode used by the rogue AP will automatically be set to one of the following values:

- __a__ - Used when you select a 2.4GHz channel
- __g__ - Used when you select a 5GHz channel

### VI.2 - Controlling Channel Width, Enabling MIMO / Channel Bonding

The --channel-width flag is used to manually specify the access point's channel width when 802.11n mode is enabled. The access point's channel width can be set to either 20MHz or 40Mhz, as shown in the next two examples.

To create a rogue 802.11n AP with a 20Mhz channel width:

	./eaphammer -i wlan0 --essid lulz0rz --hw-mode n --channel 1 --channel-width 20

To create a rogue 892.11n AP with a 40MHz channel width:

	./eaphammer -i wlan0 --essid lulz0rz --hw-mode n --channel 1 --channel-width 40

If 802.11n mode is enabled and the --channel-width flag is not used, eaphammer will create a rogue AP with a default 20MHz channel width.

### VI.3 - Advanced Usage: Specifying Primary and Secondary Channels, Channel Bonding

*Note: this is an Advanced Usage section. The command line options demonstrated in this section can be revealed using eaphammer's advanced help module: ./eaphammer -hh*

As we described in [VI.1 - 802.11n Basics - Creating Rogue APs with 20Mhz Channel Widths](#VI.1---802.11n-Basics---Creating-Rogue-APs-with-20Mhz-Channel-Widths), access points with a channel width greater than 20MHz are created using a process known as Channel Bonding. Simply put: Channel Bonding is the process of combining two 20MHz channels to create a channel that is 40MHz wide. This allows for greater throughput. The two 20MHz channels are referred to as the primary and secondary channel, respectively.

The primary channel is specified using the --channel flag. The secondary channel is automatically calculated at a 20MHz offset from the primary channel. 

You can use the --ht40 flag to manually place the secondary channel either above or below the primary channel on the frequency spectrum.

	# secondary channel above primary channel
	./eaphammer -e spikeyfruit -i wlan0 -c 1 --hw-mode n --ht40 plus

	# secondary channel below primary channel
	./eaphammer -e spikeyfruit -i wlan0 -c 6 --hw-mode n --ht40 minus

The primary and secondary channel that you choose must combine to create a valid 40Mhz channel. For example, the following command will fail because resulting 40Mhz channel would fall below the 2.4GHz spectrum:

	# this will not work: can't have a secondary channel less that 1
	./eaphammer -e oops --hw-mode n --channel 1 --channel-width 40 --ht40 minus

To make things easier, you can let eaphammer choose a valid secondary channel for you. This is done either by using --ht40 auto or by omitting the --ht40 flag completely:

	# automatically selects a valid secondary channel
	./eaphammer -e easyPeasy --hw-mode n --channel 1 --channel-width 40 --ht40 auto

	# also automatically selects a valid secondary channel (with less typing)
	./eaphammer -e ezpz --hw-mode n --channel 1 --channel-width 40 

### VI.4 - Advanced Usage: Max Spatial Streams, SMPS, and More

There is a more complete list of 802.11n options intended for advanced users that offer more granular control over eaphammer. To see them, as well as brief descriptions of what they do, use the -hh flag as shown in the following command:

	./eaphammer -hh

Note that if you plan on using these advanced options, you should also read the [XI - Advanced Granular Controls](#xi---advanced-granular-controls) section of this document.  

## VII - Hardware Modes: 802.11b / 802.11g / 802.11a / 802.11n / etc

The --hw-mode flag can be used to manually select a hardware mode for eaphammer to use. For example, the following command creates a rogue access point that uses 802.11b:

	./eaphammer -i wlan0 -e oldskool --creds --hw-mode b

The primary modes you'll most likely need to concern yourself with are:
	
- __802.11b__ - Older specification, 2.4GHz only
- __802.11a__ - Used for creating 5GHz access points
- __802.11g__ - Used for creating 2.4GHz access points
- __802.11n__ - Can be used on both the 2.4GHz and 5GHz spectrums. 

802.11n is complicated enough that it has been given its own section within this document, which you should read if you plan to use it. See: [VI - Attacking 802.11n Networks](#vi---attacking-80211n-networks)

If the --hw-mode flag is not used, eaphammer will automatically select 802.11a or 802.11g depending on whether you have specified a 2.4GHz or 5GHz channel. For example:

	# --hw-mode flag omitted, 2.4GHz channel selected. EAPHammer will automatically set hw_mode to g
	./eaphammer -i wlan0 -e safewifis --creds --channel 2

	# --hw-mode flag omitted, 5GHz channel selected. EAPHammer will automatically set hw_mode to a
	./eaphammer -i wlan0 -e safewifis --creds --channel 36

## VIII - Attacking WPA-EAP and WPA2-EAP Networks

To execute a rogue access point attack against a network that uses WPA2-EAP, just use the --auth flag as shown below:

	./eaphammer -i wlan0 -e mysecurenetwork --auth wpa

By default, eaphammer will use WPA2 rather than WPA. However, you can specify the WPA version manually using the ---wpa-version flag as shown below:

	# use WPA2
	./eaphammer -i wlan0 -e equihax --auth wpa --wpa-version 2

	# use WPA
	./eaphammer -i wlan0 -e panera --auth wpa --wpa-version 1

There is no need to specify an EAP type, as eaphammer will negotiate the EAP type on a victim-by-victim basis as they connect to the rogue AP. EAPHammer will automatically use the least secure EAP type supported by the client in order to make cracking attempts easier.


### VIII.1 - Considerations When Attacking WPA2-EAP Networks

For the most part, attacks against WPA2-EAP networks require creds in order to work. The exception for this that you don't need creds to steal creds (because that's just redundant). The reason for this is that the more advanced forms of WPA2-EAP use MS-CHAPv2, which requires mutual authentication between the wireless client and the access point. In other words, if you cannot prove knowledge of the victim's password, you will not be able to get the victim to fully associate with you.

Fortunately, you have a couple of options available to you. The first option is to simply steal a bunch of RADIUS creds using the --creds flag (see [II - Stealing RADIUS Credentials Using EAPHammer](#ii---stealing-radius-credentials-using-eaphammer) for instructions on how to do this. You can then crack the creds offline, then return and finish the attack later. This method will work regardless of the strength of the user's password due to weaknesses found in MS-CHAPv2 (see [Defeating PPTP VPNs and WPA2 Enterprise with MS-CHAPv2 | DC20 | Moxie Marlinspike and David Hulton](https://www.youtube.com/watch?v=sIidzPntdCM)). You will also have to add the cracked RADIUS creds to EAPHammer's database. Please refer to [VI.2 - EAPHammer User Database](#viii3---eaphammer-user-database) for instructions on how to do this.

For victims with weak passwords, you can use the --autocrack flag in order to perform an auto crack 'n add attack (see [VI.1 - Using AutoCrack](#vi1---using-autocrack) for usage instructions, see [Improvements In Rogue AP Attacks - MANA 1/2](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1%2F2/) for details on how this attack works).

### VIII.2 - Using AutoCrack

"Autocrack 'n add" is a technique introduced by Dominic White and Ian de Villiers in 2014 which was first introduced into their [Mana Toolkit](https://github.com/sensepost/mana). When autocrack ‘n add is used, the captured MS-CHAPv2 challenge and response is immediately sent to a cracking rig (local or remote) before the authentication response is sent to the victim. The cracked credentials are then appended to the end of the eap\_user file. If the challenge and response are cracked fast enough, the cracked credentials are added to eap\_user file before hostapd attempts to retrieve them. Even if the challenge and response cannot be cracked in time, the attack will succeed when the client attempts to reauthenticate provided the password can be cracked within a short period of time. When weak passwords are used, this process can take seconds. See the original [Improvements In Rogue AP Attacks - MANA 1/2](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1%2F2/) blog post for a more detailed explanation of this attack.

To use EAPHammer's builtin AutoCrack capability, just include the --autocrack flag with whatever attack you are attempting to perform. For example, to enable AutoCrack while performing a Hostile Portal attack, you can use the following command:

	./eaphammer -i wlan0 --essid EvilC0rp -c 6 --auth peap  --hostile-portal --autocrack

Note that at this time, EAPHammer only supports performing an autocrack 'n add using EAPHammer's internal hash cracking capability. Unless you're using a cracking rig to run EAPHammer, this is going to be very slow. Support for sending hashes to a remote cracking rig will be added in the future.

### VIII.3 - EAPHammer User Database

For now, EAPHammer's database is really just an interface to hostapd's eap\_user file. This will change in subsequent versions.

For most use cases, just stick with the [VIII.3.a - Basic Usage](#viii3a---basic-usage) section found below.

#### VIII.3.a - Basic Usage

##### VIII.3.aa - Listing Users

To list entries in the database, use the --list flag as shown below:

	./ehdb --list

You can also filter for users that match specific attributes. Please see [VIII.3.ae - Search Filters](#viii3ae---search-filters) for additional information.

##### VIII.3.ab - Adding Users

At minimum, each user that you add to the database needs to have the following attributes:

 - Identity (RADIUS jardon. A fancy way of saying "username")
 - Password OR nt password hash

To add an identity and password to the database:

	./ehdb --add --identity USERNAME --password Passw0rd!

To add an identity and NT password hash to the database:

	./ehdb --add --identity USERNAME --password Passw0rd!

There are other attributes that you can specify as well (see [VIII.3.b - Advanced Usage](#viii3b---advanced-usage)). However,
the default attributes will work in the vast majority of situations, so try not to worry about those
unless you absolutely have to.

##### VIII.3.ac - Deleting Users

To remove an identity from the database:

	./ehdb --delete --identity-is USERNAME

To remove all identities from the datbase:

	./ehdb --delete --delete-all

You can also delete multiple users at once by using search filters. Please see [VIII.3.ae - Search Filters](#viii3ae---search-filters) for additional information.

##### VIII.3.ad - Updating Users

To update a user's password (or other attribute), just use the --add flag. The existing user entry will be updated to reflect your modifications.

##### VIII.3.ae - Search Filters

You can use search filters to narrow the output of the --list flag and to delete multiple users using the --delete flag.

Filter options for --list and --delete:

 - __--by-phase PHASE__ - Filter by phase (1 or 2).
 - __--identity-is IDENTITY__ - Filter by identity (exact match)
 - __--in-identity KEYWORD__ - Filter for any identities containing a specified keyword.
 - __--methods-any METHODS__ - Filter for users that can authenticate using any of the provided methods (comma separated list).
 - __--methods-all METHODS__ - Filter for users that can authenticate using all of the provided methods (comma separated list).
 - __--has-password__ - Filter for users that have a password in the database.
 - __--has-nt-hash__ - Filter for users that have a nt hash in the database.
 - __--invert__ - Invert the results of the search.

#### VIII.4.b - Advanced Usage

Aside from --identity, --password, and --nt-hash, you probably won't need to use these options except for rare edge cases. However, they are there if you need them.

Options for adding a user to database:

 - __--identity IDENTITY__ - The username for the user you wish to add.
 - __--password PASSWORD__ - Specify the user's password. You should probably specify a password for your user unless you are specifying an nt password hash.
 - __--nt-hash NT\_HASH__ - Specify the nt hash of the user's password. You should probably specify the nt hash for your user unless you are specifying a password instead.
 - __--methods METHODS__ - Leave this as the default unless you really know what you are doing. A comma seperated list of the authentication methods that should be used when the user attempts to connect. EAPHammer will attempt to use each of these methods one by one until the victim accepts one.
 - __--phase {1,2}__ - You should probably leave this as the default.



## IX - ESSID Cloaking

EAPHammer supports the creation of hidden wireless networks. Just add one of the following three flags to whatever attack you're performing:

 - __--cloaking full__ - Send empty string as ESSID in beacons and ignore broadcast probes.
 - __--cloaking zeroes__ - Replace all characters in ESSID with ASCII 0 in becaons and ignore broadcast probes.
 - __--cloaking none__ - Do not use ESSID cloaking (default).

For example, to add full ESSID cloaking to a Hostile Portal attack:

	./eaphammer -i wlan0 -e TotallyLegit -c 1 --auth open --hostile-portal --cloaking full

There are a couple of reason why you might want to use ESSID cloaking:

1. The network you are targeting uses ESSID cloaking (although in a lot of cases you'll get better results without cloaking your rogue access point. Try it without cloaking first).
2. You are performing a Karma attack and trying to be stealthy.

## X - Using Karma

EAPHammer supports Karma attacks. Just add the --karma flag to whatever attack you're performing.

Warning: EAPHammer does not yet support the use of ACLs to limit the scope of Karma attacks. Using the --karma flag will cause EAPHammer to attack everything within range of your wireless card. The author of this software takes no responsibility for any legal issues, ruined careers, lost friendships, or hurt feelings that result from using the --karma flag.

With that out of the way, here's a usage example:

	./eaphammer -i wlan0 --essid lulz --cloaking full -c 1 --auth open --hostile-portal --karma

## XI - PMKID Attacks Against WPA-PSK and WPA2-PSK Networks

The PMKID attack is a new technique, released in August 2018 by Jens Steube, that can be used to breach WPA-PSK and WPA2-PSK networks. It can be used against 802.11i/p/q/r networks that have roaming functions enabled, which essentially amounts to most modern wireless routers. The PMKID attack offers several advantages over the traditional 4-way handshake captures:
	
- It's a client-less attack -- the attack is directed at the access point.
- It's fast (for several reason, see original post by Jens Steube)
- It works at longer ranges (lost EAPOL frames due to distance are no longer as much of a concern)

More information about how this attack works is available here:

- [https://hashcat.net/forum/thread-7717.html](https://hashcat.net/forum/thread-7717.html)

The PMKID attack can be executed using the --pmkid flag. To target a specific access point, use the --bssid flag as shown below:

	./eaphammer --pmkid --interface wlan0 --bssid de:ad:13:37:be:ef 

Notice how in the command shown above, we don't have to specify a channel. That's because EAPHammer will actually locate the AP's channel for you.

With that said, if you want to specify the channel manually, you can do so using the --channel flag as follows:

	./eaphammer --pmkid --interface wlan0 --bssid de:ad:13:37:be:ef --channel 10

Alternatively, you can use the --essid flag to tell EAPHammer to target any access point that is part of a specific network. EAPHammer will automatically locate an in-scope access point and identify its BSSID and channel. To perform this style of attack, use the following command:

	./eaphammer --pmkid --interface wlan0 --essid RED_WHEELBARROW

## XII - Password Spraying
EAPHammer allows the user to check for password reuse across multiple RADIUS accounts using its password spraying feature. To leverage this feature, use the --eap-spray flag as shown below:

	./eaphammer --eap-spray --interface-pool wlan0 wlan1 wlan2 wlan3 wlan4 --essid example-wifi --password bananas --user-list users.txt

Most of these flags are pretty self-exlanatory. The --eap-spray flag tells eaphammer to perform a password spraying attack. The --essid flag is used to specify the target network, the --password flag is used to specify the password to spray, and the --user-list flag is used to supply a user list file to eaphammer. A user list file is like a wordlist, but contains usernames instead of password candidates. Eaphammer will attempt to authenticate against the network specified by --essid using every username in the file specified by --user-list paired with the password specified by --password.

The --inteface-pool flag could be a bit confusing, so let's talk about it in greater detail. A password spraying attack is essentially a network-based bruteforce operation. Although network-based bruteforce attacks are algorithmically similar to their local counterparts, such as dictionary attacks against password hashes, they're a lot slower from a performance perspective. Each login attempt made in our password spraying attack is a network-bound operation. To make matters worse, the EAP authentication process itself takes multiple seconds to complete. We theoretically can speed up this process using multithreading (Python's GIL isn't an issue here), but we still have to deal with the fact that a single wireless interface can only perform a single authentication attempt at a time.  The oslution is to create a pool of worker threads, and give each thread in the pool its own wireless interface to work with. The --interface-pool flag is used to provide eaphammer with a list of wireless interfaces with which to create this thread pool.

Generally speaking, the more interfaces you use, the faster the attack. Be aware, however, that sending too much traffic to the access point will overwhelm it, causing your attack to take more time rather than less.
	
## XIII - Advanced Granular Controls

To view a complete list of granular configuration options supported by eaphammer, use the -hh flag as shown below:

	./eaphammer -hh

If these configuration files are not enough, eaphammer can also be configured using the .ini files found in the project's settings directory. Some important things to know about how eaphammer handles config files:

- Command line options _always_ take precedence over parameters set in eaphammer's config files. What this means is that if you try to specify a particular config value, such as the access point's ESSID, using both command line options and a config file, the value passed through the command line interface will take precedence. 
- The parameters set in the config files serve as default values each corresponding command line option.

You can also load a hostapd config file manually using the --manual-config flag. When the --manual-config flag is used, eaphammer will completely ignore both command line options and config file parameters. Example:

	./eaphammer -i wlan0 --manual-config hostapd.conf

You can also save hostapd configurations for reuse using the --save-config flag. You can then reuse the config file using the --manual-config flag as shown in the previous example. The following command executes a rogue access point and saves the config for later use:
 
	./eaphammer -i wlan0 -e pleaseRecycle --creds --save-config myconfig.conf

You can even use the --save-config-only flag to generate a config file without actually executing an attack:

	./eaphammer -i wlan0 -e saveForLater --creds --save-config-only myconfig.conf

