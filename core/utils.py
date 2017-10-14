import os
import time
import config

from tqdm import tqdm

def sleep_bar(sleep_time, text=''):

    print
    
    if text:

        print text
        print

    interval = sleep_time % 1
    if interval == 0:
        interval = 1
        iterations = sleep_time
    else:
        iterations = sleep_time / interval

    for i in tqdm(range(iterations)):
        time.sleep(interval)

    print
        
class nmcli(object):

    @staticmethod
    def set_managed(iface):
        os.system('nmcli device set %s managed yes' % iface)
        sleep_bar(1, '[*] Reticulating radio frequency splines...')

    @staticmethod
    def set_unmanaged(iface):
        os.system('nmcli device set %s managed no' % iface)
        sleep_bar(1, '[*] Reticulating radio frequency splines...')

def set_ipforward(value):

    with open(config.proc_ipforward, 'w') as fd:
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
                            '--to-destination  %s:80' % (iface, addr))
        os.system('iptables -t nat -A POSTROUTING -j MASQUERADE')

    @staticmethod
    def route_dns2_addr(addr, iface):
        os.system('iptables -t nat -A PREROUTING -i %s '
                        '-p udp --dport 53 -j DNAT --to %s' % (iface, addr))

    @staticmethod
    def save_rules(rules_file=None):
        print "[*] Saving current iptables configuration..."
        if rules_file is None:
            os.system('iptables-save > /tmp/rules_file.txt')
        else:
            os.system('iptables-save > ' + rules_file)
    
    @staticmethod
    def restore_rules(rules_file=None):
        print "[*] Restoring previous iptables configuration..."
        if rules_file is None:
            os.system('iptables-restore </tmp/rules_file.txt')
        else:
            os.system('iptables-restore > ' + rules_file)


        
