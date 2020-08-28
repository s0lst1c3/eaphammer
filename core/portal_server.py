import os
import json

import core.wskeyloggerd
import time

from multiprocessing import Process

from settings import settings

class PortalServer(object):

    instance = None

    @staticmethod
    def get_instance():
        if PortalServer.instance is None:
            instance = PortalServer()

        return instance

    @staticmethod
    def _start(options):

        core.wskeyloggerd.run(options)

    def configure(self, options):

        self.options = options

    def start(self):

        #self._start(self.options)

        self.proc = Process(target=self._start, args=(self.options,))
        self.proc.daemon = True
        self.proc.start()
        time.sleep(1)

    def stop(self):

        self.proc.terminate()
        self.proc.join()

