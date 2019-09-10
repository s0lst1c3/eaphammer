from core.lazy_file_reader import LazyFileReader

import os
import json
import shutil
import sys

class EAPUserFile(object):


    def __init__(self,
                settings,
                options):

        self.debug = options['debug']

        self.output_path = settings.dict['paths']['hostapd']['eap_user']

        if options['eap_user_file'] is not None:
            self.manual_path = options['eap_user_file']
        else:
            self.manual_path = None

            self.header = LazyFileReader(
                    settings.dict['paths']['hostapd']['eap_user_header'],
            )

            self.phase1_accounts = LazyFileReader(
                    settings.dict['paths']['hostapd']['phase1_accounts'],
            )

            self.phase2_accounts = LazyFileReader(
                    settings.dict['paths']['hostapd']['phase2_accounts'],
            )

            if self.debug:

                print(json.dumps(settings.dict['core']['eap_user_methods'], indent=4))

            # negotiate will be set to one of the following strings:
            # 'balanced', 'gtc_downgrade', 'speed', 'weakest', 'manual'
            negotiate = options['negotiate']
            if negotiate == 'manual':

                if options['eap_methods_phase_1'] is not None:

                    self.phase_1_methods = self._sanitize_methods(
                            options['eap_methods_phase_1'],
                            peap_version=options['peap_version'],
                    )

                if options['eap_methods_phase_2'] is not None:

                    self.phase_2_methods = self._sanitize_methods(
                            options['eap_methods_phase_2'],
                    )
        
            else:

                eap_user_methods = settings.dict['core']['eap_user_methods']
                self.phase_1_methods = self._sanitize_methods(
                        eap_user_methods['phase1'][negotiate],
                        peap_version=eap_user_methods['peap_version'].get(negotiate, None)
                )
                self.phase_2_methods = self._sanitize_methods(
                        eap_user_methods['phase2'][negotiate],
                )

        if self.debug:

            print('[EAPUserFile] phase 1 methods:', json.dumps(self.phase_1_methods, indent=4))
            print('[EAPUserFile] phase 2 methods:', json.dumps(self.phase_2_methods, indent=4))



    def _sanitize_methods(self, methods_str, phase=-1, peap_version=None):

        methods = []
        for m in (m.strip().upper() for m in methods_str.split(',')):
            if m == 'PEAP' and peap_version is not None:
                m = '{} [ver={}]'.format(m, peap_version)
            methods.append(m)

        return ','.join(methods)

    def _create_phase_1_line(self):

        return '*\t{}'.format(self.phase_1_methods)

    def _create_phase_2_line(self):

        return '"t"\t{}\t"t" [2]'.format(self.phase_2_methods)

    def remove(self):

        if not self.debug:

            try:

                os.remove(self.output_path)

            except FileNotFoundError:

                print('[EAPUserFile] Cannot remove file that does not exist')

    def path(self, path=None):

        if path is not None:
            self.output_path = path

        return self.output_path

    def generate(self):

        phase_1_line = self._create_phase_1_line()
        phase_2_line = self._create_phase_2_line()

        if self.debug:
        
            print('[EAPUserFile] phase 1 methods line:', phase_1_line)
            print('[EAPUserFile] phase 2 methods line:', phase_2_line)

        if self.manual_path is None:

            assert self.header is not None
            assert self.phase1_accounts is not None
            assert self.phase2_accounts is not None

            if self.debug:

                print('[EAPUserFile] header file path:', self.header.path())
                print('[EAPUserFile] phase1 accounts file path:', self.phase1_accounts.path())
                print('[EAPUserFile] phase2 accounts file path:', self.phase2_accounts.path())
                print('[EAPUserFile] Writing to:', self.output_path)

            with open(self.output_path, 'w') as output_handle:

                output_handle.write('{}\n\n'.format(self.header.read()))
                output_handle.write('{}\n\n'.format(self.phase1_accounts.read()))
                output_handle.write('{}\n\n'.format(phase_1_line))
                output_handle.write('{}\n\n'.format(phase_2_line))
                output_handle.write('{}\n\n'.format(self.phase2_accounts.read()))

        else:

            try:

                shutil.copy(self.manual_path, self.output_path)

            except FileNotFoundError:

                sys.exit('[*] Manually specified EAP user file not found: {}'.format(self.manual_path))

        return self.path()
