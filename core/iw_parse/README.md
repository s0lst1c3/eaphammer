iw_parse
========

Parse the output of iwlist scan to get the name, address, quality, channel, and encryption type of all networks broadcasting within your Wireless NIC's reach.

Dependencies
------------

* [pip](http://www.pip-installer.org/en/latest/installing.html "pip installation guide") - If you don't have pip installed, followed the link.


Installation
------------

```bash
pip install iw_parse
```

Usage
-----

```bash
iwlist <INTERFACE_NAME> scan | iw_parse
```

Replace `<INTERFACE_NAME>` with the system name for your wireless NIC. It is usually something like `wlan0`. The command `iwconfig` will list all of your network interfaces.

Example:

```bash
iwlist wlan0 scan | iw_parse
```

The result should look something like:

```
Name             Address             Quality   Channel   Encryption
wireless1        20:AA:4B:34:2C:F5   100 %     11        WEP
wireless2        00:26:F2:1E:FC:03    84 %     1         WPA v.1
wireless3        00:1D:D3:6A:3C:60    66 %     6         WEP
wireless4        20:10:7A:E5:02:98    64 %     1         WEP
wireless5        CC:A4:62:B7:D2:B0    54 %     8         WPA v.1
wireless6        30:46:9A:53:3C:76    47 %     11        WPA v.1
wireless7        A0:21:B7:5F:84:B0    44 %     11        WEP
wireless8        04:A1:51:18:E8:E0    41 %     6         WPA v.1
```

Example from Python shell:

```python
>>> import iw_parse
>>> networks = iw_parse.get_interfaces(interface='wlan0')
>>> print networks
[{'Address': 'F8:1E:DF:F9:B0:0B',
  'Channel': '3',
  'Encryption': 'WEP',
  'Name': 'Francis',
  'Bit Rates': '144 Mb/s',
  'Signal Level': '42',
  'Name': 'Francis',
  'Quality': '100'},
 {'Address': '86:1B:5E:33:17:D4',
  'Channel': '6',
  'Encryption': 'Open',
  'Bit Rates': '54 Mb/s',
  'Signal Level': '72',
  'Name': 'optimumwifi',
  'Quality': '100'},
    ...
```

Acknowledgements
----------------

* The vast majority of iw_parse was written by Hugo Chargois.

License
-------

iw_parse is free--as in BSD. Hack your heart out, hackers.
