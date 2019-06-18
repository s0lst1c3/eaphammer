#!/bin/bash
sudo modprobe mac80211_hwsim radios=4
rfkill unblock wifi
