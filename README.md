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
	./eaphammer -i wlan0 --channel 4 --auth ttls --wpa 2 --essid CorpWifi --creds

Leverages a [lightly modified](https://github.com/s0lst1c3/hostapd-eaphammer) version of [hostapd-wpe](https://github.com/opensecurityresearch/hostapd-wpe) (shoutout to [Brad Anton](https://github.com/brad-anton) for creating the original), _dnsmasq_, [Responder](https://github.com/SpiderLabs/Responder), and _Python 2.7_.

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

Upcoming Features
-----------------

- Perform seemeless MITM attacks with partial HSTS bypasses
- Support attacks against WPA-PSK/WPA2-PSK
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
      * [VI - Attacking WPA2-EAP Networks](#vi---attacking-wpa2-eap-networks)
         * [VI.1 - Using AutoCrack](#vi1---using-autocrack)
         * [VI.2 - EAPHammer User Database](#vi2---eaphammer-user-database)
            * [VI.2.a - Basic Usage](#vi2a---basic-usage)
               * [VI.2.aa - Listing Users](#vi2aa---listing-users)
               * [VI.2.ab - Adding Users](#vi2ab---adding-users)
               * [VI.2.ac - Deleting Users](#vi2ac---deleting-users)
               * [VI.2.ad - Updating Users](#vi2ad---updating-users)
               * [VI.2.ae - Search Filters](#vi2ae---search-filters)
            * [VI.2.b - Advanced Usage](#vi2b---advanced-usage)
      * [VII - ESSID Cloaking](#vii---essid-cloaking)
      * [VIII - Using Karma](#viii---using-karma)
      * [IX - Additional EAPHammer Options](#ix---additional-eaphammer-options)


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

	cd hostapd-eaphammer
	make

Open config.py in the text editor of your choice and edit the following lines so that to values that work for your distro:

	# change this to False if you cannot/will not use systemd
	use_systemd = True

	# change this to 'NetworkManager' if necessary
	network_manager = 'network-manager'

	# change this 'httpd' if necessary
	httpd = 'apache2'

# Usage Guide

## I - x.509 Certificate Generation

Certificates are required to perform any attack against networks that use EAP-PEAP, EAP-TTLS, or any other form of EAP in which the inner authentication occurs through a secure tunnel. Fortunately, EAPHammer provides an easy-to-use wizard for generating x.509 certificates. To launch eaphammer's certificate wizard, just use the command shown below.

	./eaphammer --cert-wizard

## II - Stealing RADIUS Credentials Using EAPHammer

*Note: you will need to generate a certificate in order to perform this attack. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

To steal RADIUS credentials by executing an evil twin attack against an EAP network, use the --creds flag as shown below.

	./eaphammer --bssid 1C:7E:E5:97:79:B1 --essid Example --channel 2 --interface wlan0 --auth ttls --creds

The flags shown above are self explanatory. For more granular control over the attack, you can use the --wpa flag to specify WPA vs WPA2 and the --auth flag to specify the eap type. Note that for cred reaping attacks, you should always specify an auth type manually since the the --auth flag defaults to "open" when omitted.

	./eaphammer --bssid 00:11:22:33:44:00 --essid h4x0r --channel 4 --wpa 2 --auth ttls --interface wlan0 --creds

Please refer to the options described in [VIII - Additional EAPHammer Options](#vii---additional-eaphammer-options) section of this document for additional details about these flags.

## III - Stealing AD Credentials Using Hostile Portal Attacks

*Note: you will need to generate a certificate in order to perform this attack against most EAP networks. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

*Note: you will need RADIUS creds in order to perform this attack against EAP implementations that use mutual authentication protocols such as MS-CHAPv2 for inner authentication. Please refer to* [VI - Attacking WPA2-EAP Networks](#vi---attacking-wpa2-eap-networks) *for additional information.*

Hostile Portal Attacks are a weaponization of the captive portals typically used to restrict access to open networks in environments such as hotels and coffee shops. Instead of redirecting HTTP traffic to a login page, as with a captive portal, the hostile portal redirects HTTP traffic to an SMB share located on the attacker's machine. The result is that after the victim is forced to associate with the attacker using a rogue access point attack, any HTTP traffic generated by the victim will cause the victim's device to attempt NTLM authentication with the attacker. This is, in essence, an assisted [Redirect To SMB](https://www.cylance.com/redirect-to-smb) attack. The attacker also performs LLMNR/NBT-NS poisoning against the victim.

This attack gets you lots and lots of Active Directory credentials, simply by forcing clients to connect and authenticate with you. The results are similar to what you'd get using a tool such as [Responder](https://github.com/lgandx/Responder), with some disctict advantages:

- __Stealthy__: This is a rogue AP attack, so no direct network is required
- __Large Area of Effect__: This is an attack that works across multiple subnets -- you can pwn everything that is connected to the wireless network.
- __Efficient__: This is an active attack in which the attacker forces clients to authenticate. There is no waiting for a network event to occur, as with LLMNR/NBT-NS poisoning.

The --hostile-portal flag can be used to execute a hostile portal attack, as shown in the examples below.

	./eaphammer --interface wlan0 --bssid 1C:7E:E5:97:79:B1 --essid EvilC0rp --channel 6 --auth peap --wpa 2 --hostile-portal

	./eaphammer --interface wlan0 --essid TotallyLegit --channel 1 --auth open --hostile-portal

## IV - Indirect Wireless Pivots

*Note: you will need to generate a certificate in order to perform this attack against most EAP networks. Please refer to* [I - x.509 Certificate Generation](#i---x509-certificate-generation) *for instructions on how to do this.*

*Note: you will need RADIUS creds in order to perform this attack against EAP implementations that use mutual authentication protocols such as MS-CHAPv2 for inner authentication. Please refer to* [VI - Attacking WPA2-EAP Networks](#vi---attacking-wpa2-eap-networks) *for additional information.*

An Indirect Wireless Pivot is a technique for bypassing port-based access control mechanisms using rogue access point attacks. The attack requires the attacker to use two wireless network interfaces. The first network interface is used to obtain an IP address on the target network. Presumably, this first network interface is placed in quarantine by the NAC when this occurs. The attacker then uses a rogue AP attack to coerce a victim into connecting to the attacker's second wireless interface. The attacker then exploits the victim in some way, allowing the attacker to place a timed payload on the victim's device. The attacker then shuts down the rogue access point, allowing the victim to reassociate with the target network. The attacker then waits for the timed payload to execute and send a reverse shell back to the first interface, allowing the attacker to escape the quarantine.

EAPHammer can be used to perform Indirect Wireless Piviots, as described in the following sections.

### IV.1 - Performing Indirect Wireless Pivots Using Hostile Portal Attacks

Before you begin the attack, make sure you have the following:

1. RADIUS creds for a number of victim devices (see [VI - Attacking WPA2-EAP Networks](#vi---attacking-wpa2-eap-networks))
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

*Note: you will need RADIUS creds in order to perform this attack against EAP implementations that use mutual authentication protocols such as MS-CHAPv2 for inner authentication. Please refer to* [VI - Attacking WPA2-EAP Networks](#vi---attacking-wpa2-eap-networks) *for additional information.*

To perform a captive portal attack using eaphammer, use the --captive-portal flag as shown below.

	./eaphammer --bssid 1C:7E:E5:97:79:B1 --essid HappyMealz --channel 6 --interface wlan0 --captive-portal

This will cause eaphammer to execute an evil twin attack in which the HTTP(S) traffic of all affected wireless clients are redirected to a website you control. Eaphammer will leverage Apache2 to serve web content out of /var/www/html if used with the default Apache2 configuration. Future iterations of eaphammer will provide an integrated HTTP server and website cloner for attacks against captive portal login pages.

## VI - Attacking WPA2-EAP Networks

For the most part, attacks against WPA2-EAP networks require creds in order to work. The exception for this that you don't need creds to steal creds (because that's just redundant). The reason for this is that the more advanced forms of WPA2-EAP use MS-CHAPv2, which requires mutual authentication between the wireless client and the access point. In other words, if you cannot prove knowldge of the victim's password, you will not be able to get the victim to fully associate with you.

Fortunately, you have a couple of options available to you. The first option is to simply steal a bunch of RADIUS creds using the --creds flag (see [II - Stealing RADIUS Credentials Using EAPHammer](#ii---stealing-radius-credentials-using-eaphammer) for instructions on how to do this. You can then crack the creds offline, then return and finish the attack later. This method will work regardless of the strength of the user's password due to weaknesses found in MS-CHAPv2 (see [Defeating PPTP VPNs and WPA2 Enterprise with MS-CHAPv2 | DC20 | Moxie Marlinspike and David Hulton](https://www.youtube.com/watch?v=sIidzPntdCM)). You will also have to add the cracked RADIUS creds to EAPHammer's database. Please refer to [VI.2 - EAPHammer User Database](#vi2---eaphammer-user-database) for instructions on how to do this.

For victims with weak passwords, you can use the --local-autocrack flag in order to perform an auto crack 'n add attack (see [VI.1 - Using AutoCrack](#vi1---using-autocrack) for usage instructions, see [Improvements In Rogue AP Attacks - MANA 1/2](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1%2F2/) for details on how this attack works).

### VI.1 - Using AutoCrack

"Autocrack 'n add" is a technique introduced by Dominic White and Ian de Villiers in 2014 which was first introduced into their [Mana Toolkit](https://github.com/sensepost/mana). When autocrack ‘n add is used, the captured MS-CHAPv2 challenge and response is immediately sent to a cracking rig (local or remote) before the authentication response is sent to the victim. The cracked credentials are then appended to the end of the eap\_user file. If the challenge and response are cracked fast enough, the cracked credentials are added to eap\_user file before hostapd attempts to retrieve them. Even if the challenge and response cannot be cracked in time, the attack will succeed when the client attempts to reauthenticate provided the password can be cracked within a short period of time. When weak passwords are used, this process can take seconds. See the original [Improvements In Rogue AP Attacks - MANA 1/2](https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1%2F2/) blog post for a more detailed explanation of this attack.

To use EAPHammer's builtin AutoCrack capability, just include the --local-autocrack flag with whatever attack you are attempting to perform. For example, to enable AutoCrack while performing a Hostile Portal attack, you can use the following command:

	./eaphammer -i wlan0 --essid EvilC0rp -c 6 --auth peap  --hostile-portal --local-autocrack

Note that at this time, EAPHammer only supports performing an autocrack 'n add using EAPHammer's internal hash cracking capability. Unless you're using a cracking rig to run EAPHammer, this is going to be very slow. Support for sending hashes to a remote cracking rig will be added in the near future.

### VI.2 - EAPHammer User Database

For now, EAPHammer's database is really just an interface to hostapd's eap\_user file. This will change in subsequent versions.

For most use cases, just stick with the [VI.2.a - Basic Usage](#vi2a---basic-usage) section found below.

#### VI.2.a - Basic Usage

##### VI.2.aa - Listing Users

To list entries in the database, use the --list flag as shown below:

	./ehdb --list

You can also filter for users that match specific attributes. Please see [VI.2.ae - Search Filters](#vi2ae---search-filters) for additional information.

##### VI.2.ab - Adding Users

At minimum, each user that you add to the database needs to have the following attributes:

 - Identity (RADIUS jardon. A fancy way of saying "username")
 - Password OR nt password hash

To add an identity and password to the database:

	./ehdb --add --identity USERNAME --password Passw0rd!

To add an identity and NT password hash to the database:

	./ehdb --add --identity USERNAME --password Passw0rd!

There are other attributes that you can specify as well (see [VI.2.b - Advanced Usage](#vi2b---advanced-usage)). However,
the default attributes will work in the vast majority of situations, so try not to worry about those
unless you absolutely have to.

##### VI.2.ac - Deleting Users

To remove an identity from the database:

	./ehdb --delete --identity-is USERNAME

To remove all identities from the datbase:

	./ehdb --delete --delete-all

You can also delete multiple users at once by using search filters. Please see [VI.2.ae - Search Filters](#vi2ae---search-filters) for additional information.

##### VI.2.ad - Updating Users

To update a user's password (or other attribute), just use the --add flag. The existing user entry will be updated to reflect your modifications.

##### VI.2.ae - Search Filters

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

#### VI.2.b - Advanced Usage

Aside from --identity, --password, and --nt-hash, you probably won't need to use these options except for rare edge cases. However, they are there if you need them.

Options for adding a user to database:

 - __--identity IDENTITY__ - The username for the user you wish to add.
 - __--password PASSWORD__ - Specify the user's password. You should probably specify a password for your user unless you are specifying an nt password hash.
 - __--nt-hash NT\_HASH__ - Specify the nt hash of the user's password. You should probably specify the nt hash for your user unless you are specifying a password instead.
 - __--methods METHODS__ - Leave this as the default unless you really know what you are doing. A comma seperated list of the authentication methods that should be used when the user attempts to connect. EAPHammer will attempt to use each of these methods one by one until the victim accepts one.
 - __--phase {1,2}__ - You should probably leave this as the default.

## VII - ESSID Cloaking

EAPHammer supports the creation of hidden wireles networks. Just add one of the following three flags to whatever attack you're performing:

 - __--cloaking full__ - Send empty string as ESSID in beacons and ignore broadcast probes.
 - __--cloaking zeroes__ - Replace all characters in ESSID with ASCII 0 in becaons and ignore broadcast probes.
 - __--cloaking none__ - Do not use ESSID cloaking (default).

For example, to add full ESSID cloaking to a Hostile Portal attack:

	./eaphammer -i wlan0 -e TotallyLegit -c 1 --auth open --hostile-portal --cloaking full

There are a couple of reason why you might want to use ESSID cloaking:

1. The network you are targeting uses ESSID cloaking (although in a lot of cases you'll get better results without cloaking your rogue access point. Try it without cloaking first).
2. You are performing a Karma attack and trying to be stealthy.

## VIII - Using Karma

EAPHammer supports Karma attacks. Just add the --karma flag to whatever attack you're performing.

Warning: EAPHammer does not yet support the use of ACLs to limit the scope of Karma attacks. Using the --karma flag will cause EAPHammer to attack everything within range of your wireless card. The author of this software takes no responsibility for any legal issues, ruined careers, lost friendships, or hurt feelings that result from using the --karma flag.

With that out of the way, here's a usage example:

	./eaphammer -i wlan0 --essid lulz --cloaking full -c 1 --auth open --hostile-portal --karma

## IX - Additional EAPHammer Options

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
- __--cloaking__ - Use ESSID cloaking (see [VII - ESSID Cloaking](#vii---essid-cloaking))
- __--karma__ - Enable Karma (see [VIII - Using Karma](#viii---using-karma))
