from . import utils
import os
import time

class Interface(object):

    def __init__(self, interface):
        self.interface = interface

    def up(self):
        print('[*] Bringing %s up...' % self.interface)
        os.system('ip link set %s up' % self.interface)
        print('[*] Complete!')
        time.sleep(.5)

    def down(self):
        print('[*] Bringing %s down...' % self.interface)
        os.system('ip link set %s down' % self.interface)
        print('[*] Complete!')
        time.sleep(.5)

    def mode_monitor(self):
        print('[*] Placing %s into monitor mode...' % self.interface)
        os.system('iw dev %s set type monitor' % self.interface)
        print('[*] Complete!')
        time.sleep(.5)

    def mode_managed(self):
        print('[*] Placing %s into managed mode...' % self.interface)
        os.system('iw dev %s set type managed' % self.interface)
        print('[*] Complete!')
        time.sleep(.5)

    def nm_off(self):
        print('[*] Reticulating radio frequency splines...')
        os.system('nmcli device set %s managed no' % self.interface)
        utils.sleep_bar(1, '[*] Using nmcli to tell NetworkManager not to manage %s...' % self.interface)
        print('[*] Success: %s no longer controlled by NetworkManager.' % self.interface)

    def nm_on(self):
        os.system('nmcli device set %s managed yes' % self.interface)
        utils.sleep_bar(1, '[*] Using nmcli to give NetworkManager control of %s...' % self.interface)
        print('[*] Success: %s is now managed by NetworkManager.' % self.interface)

    def set_ip_and_netmask(self, ip, netmask):
        os.system('ifconfig %s %s netmask %s' % (self.interface, ip, netmask))

    def __str__(self):
        return self.interface
