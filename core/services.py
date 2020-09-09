import os
import time
import settings

from core.utils import sleep_bar

services_settings = settings.settings.dict['core']['eaphammer']['services']

class Service(object):

    @classmethod
    def start(cls, verbose=True):

        if services_settings['use_systemd']:
            os.system('systemctl start %s' % cls.service_name)
        else:
            os.system('service %s start' % cls.service_name)

        if verbose:
            sleep_bar(cls.sleep_time,
                '[*] Starting %s service.' % cls.service_name)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def status(cls, verbose=True):

        if services_settings['use_systemd']:
            os.system('echo "`systemctl status %s`"' % cls.service_name)
        else:
            os.system('service %s status' % cls.service_name)

        if verbose:
            sleep_bar(cls.sleep_time,
                '[*] Getting status of %s service.' % cls.service_name)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def stop(cls, verbose=True):

        if services_settings['use_systemd']:
            os.system('systemctl stop %s' % cls.service_name)
        else:
            os.system('service %s stop' % cls.service_name)

        if verbose:
            sleep_bar(cls.sleep_time,
                    '[*] stopping %s service.' % cls.service_name)
        else:
            time.sleep(cls.sleep_time)


    @classmethod
    def kill(cls, verbose=True):

        killname = os.path.basename(os.path.normpath(cls.bin_path))
        os.system('for i in `pgrep %s`; do kill $i; done' % killname)

        if verbose:
            sleep_bar(cls.sleep_time,
                '[*] Killing all processes for: %s' % killname)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def hardstart(cls, args='', background=True, verbose=True):

        if background:
            os.system('%s %s &' % (cls.bin_path, args))
        else:
            os.system('%s %s' % (cls.bin_path, args))

        if verbose:
            sleep_bar(cls.sleep_time,
                '[*] Starting process: %s' % cls.bin_path)
        else:
            time.sleep(int(cls.sleep_time))

class NetworkManager(Service):

    service_name = services_settings['network_manager']
    bin_path = None
    sleep_time = services_settings['network_manager_sleep']

#class Hostapd(Service):
#
#    service_name = None
#    bin_path = settings.settings.dict['paths']['hostapd']['bin']
#    sleep_time = services_settings['hostapd_sleep']

class Httpd(Service):

    service_name = services_settings['httpd']
    bin_path = services_settings['httpd_bin']
    sleep_time = services_settings['httpd_sleep']

class Dnsmasq(Service):

    service_name = services_settings['dnsmasq']
    bin_path = services_settings['dnsmasq_bin']
    sleep_time = services_settings['dnsmasq_sleep']

class WPASupplicant(Service):

    service_name = services_settings['wpa_supplicant']
    bin_path = services_settings['wpa_supplicant_bin']
    sleep_time = services_settings['wpa_supplicant_sleep']

class Avahi(Service):

    service_name = services_settings['avahi']
    bin_path = services_settings['avahi_bin']
    sleep_time = services_settings['avahi_sleep_time']

class Dhcpcd(Service):

    service_name = services_settings['dhcpcd']
    bin_path = services_settings['dhcpcd_bin']
    sleep_time = services_settings['dhcpcd_sleep_time']

