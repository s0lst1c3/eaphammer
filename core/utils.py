import os
import time

from settings import settings
from tqdm import tqdm

def ip_replace_last_octet(ip_addr, new_val):

    return '.'.join(ip_addr.split('.')[:-1]+[new_val])

def extract_iface_from_hostapd_conf(hostapd_conf_path):

    with open(hostapd_conf_path) as fd:
        for line in fd:
            if line.startswith('interface='):
                interface = line.strip().split('=')[1]
                return interface
    

def parse_boolean(raw_str):

    raw_str = raw_str.strip().lower()
    if raw_str == 'false':
        return False
    if raw_str == '0':
        return False
    if raw_str == 'no':
        return False
    return True

def sleep_bar(sleep_time, text=''):

    sleep_time = int(sleep_time)

    print()

    if text:

        print(text)
        print()

    interval = sleep_time % 1
    if interval == 0:
        interval = 1
        iterations = sleep_time
    else:
        iterations = sleep_time / interval

    for i in tqdm(list(range(iterations))):
        time.sleep(interval)

    print()

def set_ipforward(value):

    with open(settings.dict['core']['eaphammer']['general']['proc_ipforward'], 'w') as fd:
        fd.write('%d' % int(value))

class Iptables(object):

    @staticmethod
    def accept_all():
        os.system('iptables --policy INPUT ACCEPT')
        os.system('iptables --policy FORWARD ACCEPT')
        os.system('iptables --policy OUTPUT ACCEPT')

    @staticmethod
    def flush(table=None):
        if table is None:
            os.system('iptables -F')
        else:
            os.system('iptables -t %s -F' % table)

    @staticmethod
    def route_http2_addr(addr, iface):

        os.system(('iptables -t nat -A PREROUTING -i %s '
                        '-p tcp --dport 80 -j DNAT  '
                            '--to-destination  %s:80') % (iface, addr))
        os.system('iptables -t nat -A PREROUTING -i %s '
                        '-p tcp --dport 443 -j DNAT '
                            '--to-destination  %s:443' % (iface, addr))
        os.system('iptables -t nat -A POSTROUTING -j MASQUERADE')

    @staticmethod
    def route_dns2_addr(addr, iface):
        os.system('iptables -t nat -A PREROUTING -i %s '
                        '-p udp --dport 53 -j DNAT --to %s' % (iface, addr))

    @staticmethod
    def save_rules(rules_file=None):
        print("[*] Saving current iptables configuration...")
        if rules_file is None:
            os.system('iptables-save > /tmp/rules_file.txt')
        else:
            os.system('iptables-save > ' + rules_file)

    @staticmethod
    def restore_rules(rules_file=None):
        print("[*] Restoring previous iptables configuration...")
        if rules_file is None:
            os.system('iptables-restore </tmp/rules_file.txt')
        else:
            os.system('iptables-restore > ' + rules_file)

