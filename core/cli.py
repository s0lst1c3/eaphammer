import argparse
import os
import sys

from settings import settings

BASIC_OPTIONS = [
    'cert_wizard',
    'reap_creds',
    'hostile_portal',
    'captive_portal',
    'debug',
    'interface',
    'essid',
    'bssid',
    'channel',
    'hw_mode',
    'cloaking',
    'auth',
    'karma',
    'channel_width',
    'auth_alg',
    'wpa_version',
    'autocrack',
    'remote_rig',
    'wordlist',
    'pivot',
]

def set_options():


    parser = argparse.ArgumentParser()

    modes_group = parser.add_argument_group('Modes')
    modes_group_ = modes_group.add_mutually_exclusive_group()

    modes_group_.add_argument('--cert-wizard',
                              dest='cert_wizard',
                              action='store_true',
                              help=('Use this flag to create a new '
                                    'RADIUS cert for your AP'))

    modes_group_.add_argument('--creds',
                              dest='reap_creds',
                              action='store_true',
                              help='Harvest EAP creds using evil twin attack')

    modes_group_.add_argument('--hostile-portal',
                              dest='hostile_portal',
                              action='store_true',
                              help='Force clients to connect '
                                   'to hostile portal')

    modes_group_.add_argument('--captive-portal',
                              dest='captive_portal',
                              action='store_true',
                              help='Force clients to connect '
                                   'to a captive portal')

    parser.add_argument('--manual-config',
                        dest='manual_config',
                        type=str,
                        default=None,
                        metavar='config_file',
                        help='Bypass eaphammer\'s hostapd '
                             'configuration manager and load '
                             'your own hostapd.conf file instead.')

    parser.add_argument('--save-config',
                        dest='save_config',
                        action='store_true',
                        default=None,
                        help='Save hostapd config file on exist.')

    parser.add_argument('--save-config-only',
                        dest='save_config_only',
                        action='store_true',
                        default=None,
                        help='Don\'t actually run anything. Instead, '
                             'just generate a hostapd config file using '
                             'user supplied parameters then exit.')

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true',
                        help='Enable debug output.')

    parser.add_argument('--advanced-help', '-hh',
                        dest='advanced_help',
                        action='store_true',
                        help='Show extended help options then exit.')


    access_point_group = parser.add_argument_group('Access Point')

    access_point_group.add_argument('-i', '--interface',
                                    dest='interface',
                                    default=None,
                                    type=str,
                                    help='The phy interface on which '
                                         'to create the AP')

    access_point_group.add_argument('-e', '--essid',
                                    dest='essid',
                                    default=None,
                                    type=str,
                                    help='Specify access point ESSID')

    access_point_group.add_argument('-b', '--bssid',
                                    dest='bssid',
                                    default=None,
                                    type=str,
                                    help='Specify access point BSSID')

    access_point_group.add_argument('-c', '--channel',
                                    dest='channel',
                                    type=int,
                                    default=None,
                                    help='Specify access point channel '
                                         '(default: 1).')

    access_point_group.add_argument('--hw-mode',
                                    dest='hw_mode',
                                    type=str,
                                    default=None,
                                    help='Specify access point hardware mode '
                                         '(defaults: g for 2.4GHz channels, '
                                         'a for 5GHz channels).')

    access_point_group.add_argument('--cloaking',
                                    dest='cloaking',
                                    choices=['none', 'full', 'zeroes'],
                                    default=None,
                                    help='Send empty SSID in beacons and ignore probe request '
                                         'frames that do not specify full SSID (i.e. require '
                                         'stations to know SSID). Choices: [1. none - do '
                                         'not use SSID cloaking. ] [2. full - Send empty string'
                                         ' in beacon and ignore probe requests for broadcast '
                                         'SSID ] [3. zeroes - Replace all characters in SSID '
                                         'with ASCII 0 and ignore probe requests for '
                                         'broadcast SSID.]')

    access_point_group.add_argument('--auth',
                                    dest='auth',
                                    type=str,
                                    choices=['open', 'wpa'],
                                    default=None,
                                    help='Specify authentication mechanism (hostile and captive portal default: open )(creds default: wpa).')


    access_point_group.add_argument('--karma',
                                    dest='karma',
                                    action='store_true',
                                    help='Enable karma.')


    ap_advanced_subgroup = parser.add_argument_group('AP Advanced Options')

    ap_advanced_subgroup.add_argument('--wmm',
                                      dest='wmm',
                                      action='store_true',
                                      help='Enable wmm (further configuration of wmm performed in hostapd.ini)')

    ap_advanced_subgroup.add_argument('--driver',
                                      dest='driver',
                                      default=None,
                                      type=str,
                                      help='Specify driver.')

    ap_advanced_subgroup.add_argument('--beacon-interval',
                                      dest='beacon_interval',
                                      default=None,
                                      type=int,
                                      metavar='TUs',
                                      help='Send beacon packets every n Time Units (TUs). '
                                           'A single TU is equal to 1024 microseconds. '
                                           '(default: 100)')

    ap_advanced_subgroup.add_argument('--dtim-period',
                                      dest='dtim_period',
                                      default=None,
                                      type=int,
                                      metavar='n',
                                      help='Transmit broadcast frames after every n beacons, '
                                           'where n is an integer between 1 and 255. (default: 1)')

    ap_advanced_subgroup.add_argument('--max-num-stations',
                                      dest='max_num_stations',
                                      default=None,
                                      type=int,
                                      help='The maximum number of stations that can '
                                           'connect to the AP at any one time. (default: 255)')

    ap_advanced_subgroup.add_argument('--rts-threshold',
                                      dest='rts_threshold',
                                      default=None,
                                      type=int,
                                      metavar='OCTETS',
                                      help='Sets the RTS threshold in octets. (default: 2347)')

    ap_advanced_subgroup.add_argument('--fragm-threshold',
                                      dest='fragm_threshold',
                                      default=None,
                                      type=int,
                                      metavar='OCTETS',
                                      help='Sets the fragmentation threshold in octets. '
                                           '(default: 2346)')


    hwm80211n_subgroup = parser.add_argument_group('802.11n Options', 'Used when --hw-mode is set to "n"')

    hwm80211n_subgroup.add_argument('--channel-width',
                                    dest='channel_width',
                                    type=int,
                                    choices=[20,40],
                                    default=None,
                                    metavar='MGhz',
                                    help='Set the channel width in MGHz (single 20 MGHz '
                                         'spatial stream or two 20 MGHz spatial streams '
                                         'totalling 40 MGHz). (default: 20)')

    hwm80211n_advanced_subgroup = parser.add_argument_group('802.11n Advanced Options')

    hwm80211n_advanced_subgroup.add_argument('--smps',
                                             dest='smps',
                                             type=str,
                                             choices=['off','dynamic','static'],
                                             default=None,
                                             help='Spatial Multiplexing (SM) Power Save')

    hwm80211n_advanced_subgroup.add_argument('--ht40',
                                             dest='ht40',
                                             type=str,
                                             choices=['plus', 'minus', 'auto'],
                                             default=None,
                                             help='Specifies whether the secondary channel should be '
                                                  'higher (plus) or lower (minus) than the primary '
                                                  'channel. (default: auto)')

    hwm80211n_advanced_subgroup.add_argument('--max-spatial-streams',
                                             dest='max_spatial_streams',
                                             type=str,
                                             choices=[1,2,3],
                                             default=None,
                                             help='Specifies maximum number of spatial streams. '
                                                  '(default: 2)')

    hwm80211n_advanced_subgroup.add_argument('--obss-interval',
                                             dest='obss_interval',
                                             type=None,
                                             default=None,
                                             help='Look this up if you don\'t know what it '
                                                  'does. You probably don\'t need it. (default: 0)')

    hwm80211n_advanced_subgroup.add_argument('--greenfield',
                                             dest='greenfield',
                                             action='store_true',
                                             help='Enable greenfield mode.')

    hwm80211n_advanced_subgroup.add_argument('--ht-delayed-block-ack',
                                             dest='ht_delayed_block_ack',
                                             action='store_true',
                                             help='Use HT Delayed Block ACK.')

    hwm80211n_advanced_subgroup.add_argument('--short-gi',
                                             dest='short_gi',
                                             action='store_true',
                                             help='Enable short GI (20 or 40 depending on channel width')

    hwm80211n_advanced_subgroup.add_argument('--lsig-txop-prot',
                                             dest='lsig_txop_prot',
                                             action='store_true',
                                             help='Enable L-SIG TXOP Protection support.')

    hwm80211n_advanced_subgroup.add_argument('--require-ht',
                                             dest='require_ht',
                                             action='store_true',
                                             help='Reject associations from clients that do not support HT.')

    hwm80211n_advanced_subgroup.add_argument('--dsss-cck-40',
                                             dest='dsss_cck_40',
                                             action='store_true',
                                             help='Enable DSSS/CCK Mode in 40MHz.')

    hwm80211n_advanced_subgroup.add_argument('--disable-tx-stbc',
                                             dest='disable_tx_stbc',
                                             action='store_true',
                                             help='Disable TX-STBC.')

    hwm80211n_advanced_subgroup.add_argument('--ldpc',
                                             dest='ldpc',
                                             action='store_true',
                                             help='Enable LDPC Coding capability.')

    hwm80211n_advanced_subgroup.add_argument('--use-max-a-msdu-length',
                                             dest='use_max_a_msdu_length',
                                             action='store_true',
                                             help='Set A-MSDU length to maximum allowable '
                                                  'value (7935 octets). If not set, 3839 '
                                                  'octets are used.')

    wpa_group = parser.add_argument_group('WPA Options', 'Only applicable if --auth wpa is used')

    wpa_group.add_argument('--auth-alg',
                           dest='auth_alg',
                           type=str,
                           choices=['shared', 'open', 'both'],
                           default=None,
                           help='Authentication type (open or shared key). (default: shared)')

    wpa_group.add_argument('--wpa-version',
                           dest='wpa_version',
                           type=str,
                           choices=['1', '2'],
                           default=None,
                           help='Set WPA version. (default: 2)')

    eap_group = parser.add_argument_group('EAP Options', 'Only applicable if --auth wpa is used')

    eap_group.add_argument('--autocrack',
                           dest='autocrack',
                           action='store_true',
                           help='Enable autocrack \'n add.')

    autocrack_group = parser.add_argument_group('Autocrack Options', 'Only applicable if --auth wpa  --autocrack is used')

    eap_group.add_argument('--remote-cracking-rig',
                           dest='remote_rig',
                           type=str,
                           metavar='server:port',
                           help='Use remote cracking rig for autocrack feature.')

    eap_group.add_argument('--wordlist',
                           dest='wordlist',
                           default=os.path.join(settings.dict['paths']['directories']['wordlists'], settings.dict['core']['eaphammer']['general']['default_wordlist']),
                           type=str,
                           help='Specify the wordlist to use with '
                                'the autocrack feature.')

    hp_group = parser.add_argument_group('Hostile Portal Options', 'Only applicable if --hostile-portal is used')

    eap_group.add_argument('--pivot',
                           dest='pivot',
                           action='store_true',
                           help='Runs responder without SMB server enabled.')

    try:

        if '-hh' not in sys.argv and '--advanced-help' not in sys.argv:
            for a in parser._actions:
                if a.dest != 'help' and a.dest not in BASIC_OPTIONS:
                    a.help = argparse.SUPPRESS

        args = parser.parse_args()

        options = args.__dict__
        
        if options['advanced_help']:
            parser.print_help()
            sys.exit()


        if (options['cert_wizard'] is False and
            options['manual_config'] is None and
            options['advanced_help'] is False and
            options['interface'] is None):

            parser.print_usage()
            print
            print '[!] Please specify a valid PHY',
            print 'interface using the --interface flag'
            sys.exit()
    except SystemExit:

        print
        print '[!] Use -h or --help to display a list of basic options.'
        print '[!] Use -hh or --advanced-help to display full list of extended options.'
        print

        raise

    return options
