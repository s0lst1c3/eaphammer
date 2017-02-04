# eaphammer
EAPHammer adds an easy to use command line interface to hostapd-wpe and its config files.

First time setup:

	# install dependencies
	apt-get install `cat kali-dependencies.txt | tr '\n' ' '`

	# run setup script
	python setup.py

To create a new self-signed certificate:

	python eaphammer.py --cert-wizard

To execute an evil twin attack using hostapd-wpe:

	python eaphammer.py --bssid <bssid> --essid <essid> --channel <channel> --interface <interface>
