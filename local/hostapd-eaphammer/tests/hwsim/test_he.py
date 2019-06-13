# HE tests
# Copyright (c) 2019, The Linux Foundation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_he_open(dev, apdev):
    """HE AP with open mode configuration"""
    params = {"ssid": "he",
              "ieee80211ax": "1",
              "he_bss_color": "42",
              "he_mu_edca_ac_be_ecwmin": "7",
              "he_mu_edca_ac_be_ecwmax": "15"}
    hapd = hostapd.add_ap(apdev[0], params)
    if hapd.get_status_field("ieee80211ax") != "1":
        raise Exception("STATUS did not indicate ieee80211ac=1")
    dev[0].connect("he", key_mgmt="NONE", scan_freq="2412")
