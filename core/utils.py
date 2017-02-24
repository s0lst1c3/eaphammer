import os
import time
import config

class Service(object):

    @classmethod
    def start(cls):

        if config.use_systemd:
            os.system('systemctl start %s' % cls.service_name)
        else:
            os.system('service %s start' % cls.service_name)
        
        time.sleep(cls.sleep_time)

    @classmethod
    def status(cls):

        if config.use_systemd:
            os.system('echo "`systemctl status %s`"' % cls.service_name)
        else:
            os.system('service %s status' % cls.service_name)
        time.sleep(cls.sleep_time)

    @classmethod
    def stop(cls):

        if config.use_systemd:
            os.system('systemctl stop %s' % cls.service_name)
        else:
            os.system('service %s stop' % cls.service_name)
        time.sleep(cls.sleep_time)

    @classmethod
    def kill(cls):

        os.system('for i in `pgrep %s`; do kill $i; done' % cls.service_name)
        time.sleep(cls.sleep_time)

    @classmethod
    def hardstart(cls, args='', background=True):
        if background:
            os.system('%s %s &' % (cls.bin_path, args))
        else:
            os.system('%s %s' % (cls.bin_path, args))
        time.sleep(cls.sleep_time)

class NetworkManager(Service):
    
    service_name =  config.network_manager
    bin_path = None
    sleep_time = config.network_manager_sleep

class Hostapd(Service):

    service_name = None
    bin_path = config.hostapd_bin
    sleep_time = config.hostapd_sleep

class Dnsmasq(Service):

    service_name = config.dnsmasq
    bin_path = config.dnsmasq_bin
    sleep_time = config.dnsmasq_sleep

class Dnsspoof(Service):

    service_name = config.dnsspoof
    bin_path = config.dnsspoof_bin
    sleep_time = config.dnsspoof_sleep

def wlan_clean():

    os.system('nmcli radio wifi off')
    os.system('rfkill unblock wlan')
    time.sleep(config.wlan_clean_sleep)

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

        os.system('iptables -t nat -A PREROUTING -i %s -p tcp --dport 80 -j DNAT  --to-destination  %s:80' % (iface, addr))
        os.system('iptables -t nat -A PREROUTING -i %s -p tcp --dport 443 -j DNAT --to-destination  %s:80' % (iface, addr))
        os.system('iptables -t nat -A POSTROUTING -j MASQUERADE')

    @staticmethod
    def route_dns2_addr(addr, iface):
        os.system('iptables -t nat -A PREROUTING -i %s -p udp --dport 53 -j DNAT --to %s' % (iface, addr))
        
