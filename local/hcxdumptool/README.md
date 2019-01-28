hcxdumptool
==============

Small tool to capture packets from wlan devices.
After capturing, upload the "uncleaned" cap here (https://wpa-sec.stanev.org/?submit)
to see if your ap or the client is vulnerable by using common wordlists.
Convert the cap to hccapx and/or to WPA-PMKID-PBKDF2 hashline (16800) with hcxpcaptool (hcxtools)
and check if wlan-key or plainmasterkey was transmitted unencrypted.


Brief description
--------------

Stand-alone binary - designed to run on Raspberry Pi's with installed Arch Linux.
It should work on other Linux systems (notebooks, desktops) and distributions, too.


Detailed description
--------------

| Tool           | Description                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------ |
| hcxdumptool    | Tool to run several tests to determine if access points or clients are vulnerable                      |
| pioff          | Turns Raspberry Pi off via GPIO switch                                                                 |


Compile
--------------

Simply run:

```
make
make install (as super user)
```

or (with GPIO support - hardware mods required)

```
make GPIOSUPPORT=on
make GPIOSUPPORT=on install (as super user)
```

Compile for Android
--------------

You need:
* Android NDK installed in your system and in path variable

* This repository cloned with all submodules (`--recursive` flag in `git clone` or `git submodules update` command run)

Just run `ndk-build` - built executables for some architectures should be created inside `libs` directory.
Copy it to your phone and enjoy.


Requirements
--------------

* Operatingsystem: Arch Linux (strict), Kernel >= 4.14 (strict). It should work on other Linux systems (notebooks, desktops) and distributions, too (no support for other distributions). Don't use Kernel 4.4 (rt2x00 driver regression)

* libpthread and pthread-dev installed

* Raspberry Pi: additionally libwiringpi and wiringpi dev installed (Raspberry Pi GPIO support)

* Chipset must be able to run in monitor mode (strict by: ip and iw). Recommended: RALINK chipset (good receiver sensitivity), rt2x00 driver (stable and fast)

* Raspberry Pi A, B, A+, B+ (Recommended: A+ = very low power consumption or B+), but notebooks and desktops could work, too.

* GPIO hardware mod recommended
 

Supported adapters (strict)
--------------

* USB ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter

* USB ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter

* USB ID 148f:5370 Ralink Technology, Corp. RT5370 Wireless Adapter

* USB ID 0bda:8187 Realtek Semiconductor Corp. RTL8187 Wireless Adapter

* USB ID 0bda:8189 Realtek Semiconductor Corp. RTL8187B Wireless 802.11g 54Mbps Network Adapter

* Bus 005 Device 011: ID 7392:a812 Edimax Technology Co., Ltd (Edimax AC600 USB / Manufacturer: Realtek)
  get driver from here: https://github.com/kimocoder/rtl8812au

* Bus 001 Device 002: ID 148f:2573 Ralink Technology, Corp. RT2501/RT2573 Wireless Adapter


Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| bash_profile | Autostart for Raspberry Pi (copy to /root/.bash_profile) |
| pireadcard   | Back up a Pi SD card                                     |
| piwritecard  | Restore a Pi SD card                                     |
| makemonnb    | Example script to activate monitor mode                  |
| killmonnb    | Example script to deactivate monitor mode                |


Hardware mod - see docs gpiowait.odg (hcxdumptool)
--------------

LED flashes 5 times if hcxdumptool successfully started

LED flashes every 5 seconds if everything is fine

Press push button at least > 5 seconds until LED turns on (LED turns on if hcxdumptool terminates)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use hcxdumptool and hcxpioff together!


Hardware mod - see docs gpiowait.odg (hcxpioff)
--------------

LED flashes every 10 seconds 2 times if hcxpioff successfully started

Press push button at least > 10 seconds until LED turns on (hcxpioff will shut down Raspberry Pi safely)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use hcxdumptool or hcxpioff together!


Warning
--------------

You must use hcxdumptool only on networks you have permission to do this, because

* hcxdumptool is able to prevent complete wlan traffic

* hcxdumptool is able to capture PMKIDs from access points (only one single PMKID from an access point required)

* hcxdumptool is able to capture handshakes from not connected clients (only one single M2 from the client is required)

* hcxdumptool is able to capture handshakes from 5GHz clients on 2.4GHz (only one single M2 from the client is required)

* hcxdumptool is able to capture extended EAPOL (RADIUS, GSM-SIM, WPS)

* hcxdumptool is able to capture passwords from the wlan traffic

* hcxdumptool is able to capture plainmasterkeys from the wlan traffic

* hcxdumptool is able to capture usernames and identities from the wlan traffic

* Do not use a logical interface and leave the physical interface in managed mode.

* Do not use hcxdumptool in combination with aircrack-ng, reaver, bully or other tools which takes access to the interface.

* Stop all services which takes access to the physical interface (NetworkManager, wpa_supplicant,...).

* Do not use tools like macchanger, as they are useless, because hcxdumptool uses its own random mac address space.
