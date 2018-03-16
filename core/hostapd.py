import os
import sys
import ctypes
import threading
import time

import core.utils

class HostapdEaphammer(object):

    def __init__(self, config):

        self.exec_path = config.dict['paths']['hostapd']['bin']
        self.debug = core.utils.parse_boolean(config.dict['core']['hostapd']['general']['debug'])
        self.runtime_config_path = config.dict['paths']['hostapd']['conf']
        self.lib_path = config.dict['paths']['hostapd']['lib']

        self.sleep_time = int(config.dict['core']['hostapd']['general']['sleep_time'])

    def start(self):

        argv = [
            self.exec_path,
            '-N',
        ]
        if self.debug:
            argv.append('-d')
        argv.append(self.runtime_config_path)
    
        argc = len(argv)
        argv_mem = ctypes.c_char_p * argc
        argv = argv_mem(*argv)

        self.libhostapd = ctypes.cdll.LoadLibrary(self.lib_path)

        try:

            self.thread = threading.Thread(target=self.libhostapd.main, args=(argc, argv))
            self.thread.start()

            print
            print '[hostapd] AP starting...'
            print
            time.sleep(self.sleep_time)

        except KeyboardInterrupt:
            
            self.stop()

    def stop(self):


        print '[hostapd] Terminating event loop...'
        self.libhostapd.eloop_terminate()

        print '[hostapd] Event loop terminated.'
        
        if self.thread.is_alive():
        
            print '[hostapd] Hostapd worker still running... waiting for it to join.'
            print
            self.thread.join(5)
            print
            print '[hostapd] Worker joined.'

        print '[hostapd] AP disabled.'
        print
