import os
import sys
import ctypes
import threading
import time

import core.utils

class HostapdEaphammer(object):

    def __init__(self, settings, options):

        self.exec_path = settings.dict['paths']['hostapd']['bin']
        self.debug = core.utils.parse_boolean(settings.dict['core']['hostapd']['args']['debug'])
        self.lib_path = settings.dict['paths']['hostapd']['lib']

        if options['manual_config'] is None:
            self.runtime_config_path = settings.dict['paths']['hostapd']['conf']
        else:
            self.runtime_config_path = options['manual_config']

        self.debug = options['debug']

        self.sleep_time = int(settings.dict['core']['hostapd']['wrapper']['sleep_time'])

    def start(self):

        argv = [
            bytes(self.exec_path.encode('ascii')),
            bytes('-N'.encode('ascii')),
        ]
        if self.debug:
            argv.append(bytes('-d'.encode('ascii')))
        argv.append(bytes(self.runtime_config_path.encode('ascii')))

        argc = len(argv)
        argv_mem = ctypes.c_char_p * argc
        argv = argv_mem(*argv)

        self.libhostapd = ctypes.cdll.LoadLibrary(self.lib_path)

        try:

            self.thread = threading.Thread(target=self.libhostapd.main, args=(argc, argv))
            self.thread.start()

            print()
            print('[hostapd] AP starting...')
            print()
            time.sleep(self.sleep_time)

        except KeyboardInterrupt:

            self.stop()

    def stop(self):


        print('[hostapd] Terminating event loop...')
        self.libhostapd.eloop_terminate()

        print('[hostapd] Event loop terminated.')

        if self.thread.is_alive():

            print('[hostapd] Hostapd worker still running... waiting for it to join.')
            print()
            self.thread.join(5)
            print()
            print('[hostapd] Worker joined.')

        print('[hostapd] AP disabled.')
        print()
