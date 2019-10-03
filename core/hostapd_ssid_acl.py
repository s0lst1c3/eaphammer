import os
import shutil
import sys

class HostapdSSIDACL(object):

    def __init__(self,
                settings,
                options):

        self.debug = options['debug']

        assert not (options['ssid_whitelist'] is not None and options['ssid_blacklist'] is not None)

        if options['ssid_whitelist'] is not None:
            self.input_path = options['ssid_whitelist']
            self.output_path = settings.dict['paths']['hostapd']['ssid_whitelist']
            self.mode = 'ssid_whitelist'
        elif options['ssid_blacklist'] is not None:
            self.input_path = options['ssid_blacklist']
            self.output_path = settings.dict['paths']['hostapd']['ssid_blacklist']
            self.mode = 'ssid_blacklist'
        else:
            raise Exception('[HostapdSSIDACL] this should never happen')
            

        if self.debug:
            print('[HostapdSSIDACL] self.input_path: ', self.input_path)
            print('[HostapdSSIDACL] self.output_path: ', self.output_path)
            print('[HostapdSSIDACL] self.mode: ', self.output_path)

    def remove(self):

        if not self.debug:

            try:

                os.remove(self.output_path)

            except FileNotFoundError:

                print('[HostapdSSIDACL] Cannot remove file that does not exist')

    def path(self, path=None):

        if path is not None:
            self.output_path = path

        return self.output_path

    def generate(self):

        try:

            shutil.copy(self.input_path, self.output_path)

        except FileNotFoundError:

            sys.exit('[HostapdSSIDACL] ACL file not found: {}'.format(self.input_path))

        return self.path()
