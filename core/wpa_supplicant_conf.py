import os
import random
import string

class WPASupplicantConf(object):

    def __init__(self, essid, identity, password, write_dir):

        self.essid = essid
        self.identity = identity
        self.password = password
        self.write_dir = write_dir
        self._set_path()

    def _set_path(self):
        randstring = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(32))
        self.filename = '.'.join([randstring, 'wpa_supplicant'])
        self.path = os.path.join(self.write_dir, self.filename)

    def write(self):
        with open(self.path, 'w') as fd:
            fd.write('''
network={
    ssid="%s"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="%s"
    phase2="auth=MSCHAPV2"
    password="%s"
}
'''     % (self.essid, self.identity, self.password))

    def remove(self):
        try:
            os.remove(self.path)
        except OSError as e:
            print("Error: %s - %s" % (e.filename, e.strerror))
