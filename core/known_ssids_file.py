import os
import shutil
import sys

class KnownSSIDSFile(object):

    def __init__(self,
                settings,
                options):

        self.debug = options['debug']
        self.known_ssids = []
        self.output_path = settings.dict['paths']['hostapd']['known_ssids']

        # having to do this makes me wish that python had a
        # logic XOR operator... or even a NAND operator for 
        # that matter...
        assert not (options['known_ssids_file'] is None and options['known_ssids'] is None)
        assert not (options['known_ssids_file'] is not None and options['known_ssids'] is not None)

        if options['known_ssids_file'] is not None:

            with open(options['known_ssids_file']) as fd:

                for line in fd:
    
                    # remove '\n' from end of line
                    ssid = line.rstrip('\n')
                    if ssid.strip() != ssid:
                        print('[eaphammer] WARNING: whitespace detected '
                            'at beginning or end of known-ssids-file. '
                            'Assuming this is intentional.')
                    self.known_ssids.append(ssid)

        elif options['known_ssids'] is not None:

            self.known_ssids = options['known_ssids']

        else:
            raise Exception('[KnownSSIDSFile] this should never happen')
            

        if self.debug:
            print('[KnownSSIDSFile] self.known_ssids: ', self.known_ssids)
            print('[KnownSSIDSFile] self.output_path: ', self.output_path)

    def remove(self):

        if not self.debug:

            try:

                os.remove(self.output_path)

            except FileNotFoundError:

                print('[KnownSSIDSFile] Cannot remove file that does not exist')

    def path(self, path=None):

        if path is not None:
            self.output_path = path

        return self.output_path

    def generate(self):


        with open(self.output_path, 'w') as fd:
            for ssid in self.known_ssids:
                fd.write('{}\n'.format(ssid))

        return self.path()
