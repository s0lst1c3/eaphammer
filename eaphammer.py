import sys
import os
import config

from core import cert_manager, conf_manager
from argparse import ArgumentParser

def cert_wizard():

    while True:

        print '[*] Please enter two letter country code for certs (i.e. US, FR)'
        country = raw_input(': ').upper()
        if len(country) == 2:
            break
        print '[!] Invalid input.'

    print '[*] Please enter state or province for certs (i.e. Ontario, New Jersey)'
    state = raw_input(': ')

    print '[*] Please enter locale for certs (i.e. London, Hong Kong)'
    locale = raw_input(': ')

    print '[*] Please enter organization for certs (i.e. Evil Corp)'
    org = raw_input(': ')

    print '[*] Please enter email for certs (i.e. cyberz@h4x0r.lulz)'
    email = raw_input(': ')

    print '[*] Please enter common name (CN) for certs.'
    cn = raw_input(': ')

    cert_manager.ca_cnf.configure(country, state, locale, org, email, cn)
    cert_manager.server_cnf.configure(country, state, locale, org, email, cn)
    cert_manager.client_cnf.configure(country, state, locale, org, email, cn)

    cert_manager.bootstrap()


def set_options():


    parser = ArgumentParser()

    parser.add_argument('--cert-wizard',
                    dest='cert_wizard',
                    action='store_true',
                    help='Use this flag to create a new RADIUS cert for your AP')

    parser.add_argument('-i', '--interface',
                    dest='interface',
                    type=str,
                    help='The phy interface on which to create the AP')

    parser.add_argument('-e', '--essid',
                    dest='essid',
                    default='eaphammer',
                    type=str,
                    help='Specify access point ESSID')

    parser.add_argument('-b', '--bssid',
                    dest='bssid',
                    default='00:11:22:33:44:00',
                    type=str,
                    help='Specify access point BSSID')

    parser.add_argument('--hw-mode',
                    dest='hw_mode',
                    type=str,
                    default='g',
                    help='Specify access point hardware mode (default: g).')

    parser.add_argument('-c', '--channel',
                    dest='channel',
                    type=int,
                    default=1,
                    choices=range(1,12),
                    help='Specify access point channel')

    parser.add_argument('--wpa',
                    dest='wpa',
                    type=int,
                    choices=[1, 2],
                    default=2,
                    help='Specify WPA type (default: 2).')

    args = parser.parse_args()

    options = args.__dict__

    if options['cert_wizard'] is not None:

        if options['interface'] is None:

            print 'Please specify a valid PHY interface using the --interface flag'
            sys.exit()

    return options

if __name__ == '__main__':

    options = set_options()

    if options['cert_wizard']:
        cert_wizard()
    else:

        conf_manager.hostapd_cnf.configure(interface=options['interface'],
                                        ssid=options['essid'],
                                        hw_mode=options['hw_mode'],
                                        bssid=options['bssid'],
                                        channel=options['channel'],
                                        wpa=options['wpa'])

        os.system('%s %s' % (config.hostapd_bin, config.hostapd_cnf))
