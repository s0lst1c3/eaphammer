import os
import shutil
import sys

class HostapdMACACL(object):

    def __init__(self,
                settings,
                options):

        self.debug = options['debug']

        assert not (options['mac_whitelist'] is not None and options['mac_blacklist'] is not None)

        if options['mac_whitelist'] is not None:
            self.input_path = options['mac_whitelist']
            self.output_path = settings.dict['paths']['hostapd']['mac_whitelist']
            self.mode = 'mac_whitelist'
        elif options['mac_blacklist'] is not None:
            self.input_path = options['mac_blacklist']
            self.output_path = settings.dict['paths']['hostapd']['mac_blacklist']
            self.mode = 'mac_blacklist'
        else:
            raise Exception('[HostapdACL] this should never happen')
            

        if self.debug:
            print('[HostapdACL] self.input_path: ', self.input_path)
            print('[HostapdACL] self.output_path: ', self.output_path)
            print('[HostapdACL] self.mode: ', self.output_path)

    def remove(self):

        if not self.debug:

            try:

                os.remove(self.output_path)

            except FileNotFoundError:

                print('[HostapdACL] Cannot remove file that does not exist')

    def path(self, path=None):

        if path is not None:
            self.output_path = path

        return self.output_path

    def generate(self):

        try:

            shutil.copy(self.input_path, self.output_path)

        except FileNotFoundError:

            sys.exit('[HostapdACL] ACL file not found: {}'.format(self.input_path))

        return self.path()
