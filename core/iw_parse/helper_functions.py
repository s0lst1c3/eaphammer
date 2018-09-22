def find_channel_from_bssid(bssid, networks):
    for n in networks:
        if n['Address'].lower() == bssid.lower():
            return int(n['Channel'])
    return None

def find_bssid_from_essid(essid, networks):
    for n in networks:
        if n['Name'] == essid:
            return n['Address'].lower()
    return None

def find_essid_from_bssid(bssid, networks):
    for n in networks:
        if n['Address'].lower() == bssid.lower():
            return n['Name']
    return None
