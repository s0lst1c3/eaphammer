import os
import subprocess


from settings import settings

class Responder(object):

    instance = None

    @staticmethod
    def get_instance():
        if Responder.instance is None:
            instance = Responder()

        return instance

    def start(self, iface):

        responder_bin = settings.dict['paths']['responder']['bin']
        self.process = subprocess.Popen([responder_bin, '-wrf', '--lm', '-I', iface])

    def stop(self):

        self.process.terminate()

if __name__ == '__main__':

    responder = Responder.get_instance()
    responder.configure()
    responder.start()

    input('responder started.')

    responder.stop()
