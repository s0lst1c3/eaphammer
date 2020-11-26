import subprocess
import os
import time

from core.wpa_supplicant_conf import WPASupplicantConf

class WPA_Supplicant(object):

    def __init__(self, interface, conf):
        self.interface = interface
        self.conf = conf

    def test_creds(self):

        p = subprocess.Popen(['wpa_supplicant', '-i', self.interface, '-c', self.conf.path], shell=False, stdout=subprocess.PIPE, preexec_fn=os.setsid)
        while True:
            line = p.stdout.readline().decode("utf-8")
            print(line.replace('%s:' % self.interface, '[%s]' % self.interface), end=' ')
            if 'CTRL-EVENT-EAP-SUCCESS' in line:
                p.kill()
                time.sleep(1)
                return True
            elif 'CTRL-EVENT-EAP-FAILURE' in line:
                p.kill()
                time.sleep(1)
                return False
