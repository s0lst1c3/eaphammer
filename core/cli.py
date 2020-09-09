import argparse
import os
import sys

from settings import settings

from cert_wizard import cert_utils

# Python3 FTW
from pathlib import Path

BASIC_OPTIONS = [

    'cert_wizard',
    'list_templates',
    'reap_creds',
    'capture_wpa_handshakes',
    'psk_capture_file',
    'pmkid',
    'mac_whitelist',
    'mac_blacklist',
    'ssid_whitelist',
    'ssid_blacklist',
    'hostile_portal',
    'dl_form_message',
    'captive_portal',
    'payload',
    'debug',
    'interface',
    'essid',
    'bssid',
    'pmf',
    'owe_transition_bssid',
    'add_download_form',
    'owe_transition_ssid',
    'portal_user_template',
    'channel',
    'hw_mode',
    'cloaking',
    'auth',
    'lhost',
    'lport',
    'karma',
    'mana',
    'loud',
    'create_template',
    'delete_template',
    'name',
    'description',
    'author',
    'known_beacons',
    'channel_width',
    'auth_alg',
    'wpa_version',
    'wpa_passphrase',
    'autocrack',
    'remote_rig',
    'wordlist',
    'pivot',
    'captive_portal_server_only',
    'eap_spray',
    'password',
    'interface_pool',
    'user_list',
    'bootstrap',
    'known_ssids_file',
    'known_ssids',
    'negotiate',
]

ROGUE_AP_ATTACKS = [

    'hostile_portal',
    'captive_portal',
    'reap_creds',
]

def set_options():


    parser = argparse.ArgumentParser()

    modes_group = parser.add_argument_group('Modes')
    modes_group_ = modes_group.add_mutually_exclusive_group()

    modes_group_.add_argument('--cert-wizard',
                              dest='cert_wizard',
                              choices=[
                                'create',
                                'import',
                                'interactive',
                                'list',
                                'dh',
                              ],
                              default=False,
                              nargs='?',
                              const='interactive',
                              help='Use this flag to run in Cert Wizard mode. '
                                   'Use "--cert-wizard create" to create '
                                   'a new certificate. Use "--cert-wizard '
                                   'interactive" or simply "--cert-wizard" '
                                   'to run Cert Wizard in interactive mode. '
                                   'Use "--cert-wizard import" to import '
                                   'a set of certificates into eaphammer\'s '
                                   'static configuration. Use "--cert-wizard '
                                   'list" to list all previously imported '
                                   'certs, as well as the active cert '
                                   'configuration. Use "--cert-wizard dh" '
                                   'to manually regenerate eaphammer\'s dh '
                                   'parameters.')

    modes_group_.add_argument('--list-templates',
                              dest='list_templates',
                              action='store_true',
                              help=('List available templates for the '
                                    'captive portal'))

    modes_group_.add_argument('--create-template',
                              dest='create_template',
                              action='store_true',
                              help=('Create a template by cloaning '
                                    'a login page'))

    modes_group_.add_argument('--delete-template',
                              dest='delete_template',
                              action='store_true',
                              help=('Delete a captive portal template.'))

    modes_group_.add_argument('--bootstrap',
                              dest='bootstrap',
                              action='store_true',
                              help=('Shorthand for "--cert-wizard create '
                                    '--self-signed"'))

    modes_group_.add_argument('--creds', '--brad',
                              dest='reap_creds',
                              action='store_true',
                              help='Harvest EAP creds using evil twin attack')

    modes_group_.add_argument('--pmkid',
                              dest='pmkid',
                              action='store_true',
                              help=('Perform clientless attack against PSK '
                                    'network using ZerBea\'s hcxtools.'))

    modes_group_.add_argument('--troll-defender',
                              dest='troll_defender',
                              action='store_true',
                              help=('Trigger Windows Defender on nearby '
                                    'devices by spawning an AP with SSID '
                                    'set to C:\Temp\Invoke-Mimikatz.ps1'))

    modes_group_.add_argument('--eap-spray',
                              dest='eap_spray',
                              action='store_true',
                              help='Check for password reuse by spraying a '
                                   'single password across a series of '
                                   'usernames against target ESSID.')

    modes_group_.add_argument('--hostile-portal',
                              dest='hostile_portal',
                              action='store_true',
                              help='Force clients to connect '
                                   'to hostile portal')

    modes_group_.add_argument('--captive-portal-server-only',
                              dest='captive_portal_server_only',
                              action='store_true',
                              help='Run the captive portal server as a'
                                   'standalone service.')

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

    cert_wizard_group = parser.add_argument_group('Cert Wizard')

    cert_wizard_group.add_argument('--server-cert',
                                   dest='server_cert',
                                   default=None,
                                   type=str,
                                   help='Specify path to server cert file. '
                                        'Can be used with '
                                        '"--cert-wizard import" to import '
                                        'a cert or cert chain, or with '
                                        'any attack to override eaphammer\'s '
                                        'static configuration. '
                                        'File must be in PEM format and may '
                                        'contain full certificate chain '
                                        'and/or private key. If file does '
                                        'not contain private key, the '
                                        '--private-key flag should be used. '
                                        'Likewise, if the file does not '
                                        'contain a CA certificate chain, '
                                        'the --ca-cert flag should be used.')

    cert_wizard_group.add_argument('--ca-cert',
                                   dest='ca_cert',
                                   default=None,
                                   type=str,
                                   help='Specify path to ca cert file.')


    cert_wizard_group.add_argument('--private-key',
                                   dest='private_key',
                                   default=None,
                                   type=str,
                                   help='Specify path to private key file.')

    cert_wizard_group.add_argument('--private-key-passwd',
                                   dest='private_key_passwd',
                                   default=None,
                                   type=str,
                                   help='Specify private key password.')

    cert_wizard_group.add_argument('--self-signed',
                                   dest='self_signed',
                                   action='store_true',
                                   default=False,
                                   help=('Combine with "--cert-wizard create" '
                                        'to create a self-signed cert.'))

    cert_wizard_group.add_argument('--cn',
                                   dest='cn',
                                   default=None,
                                   type=str,
                                   help='Specify certificate CN when running '
                                        '--bootstrap or '
                                        '"--cert-wizard create".')
    

    cert_wizard_group.add_argument('--country',
                                   dest='country',
                                   default=None,
                                   type=str,
                                   help='Specify certificate country when '
                                        'running --bootstrap or '
                                        '"--cert-wizard create".')

    cert_wizard_group.add_argument('--state',
                                   dest='state',
                                   default=None,
                                   type=str,
                                   help='Specify certificate state or province '
                                        'when running --bootstrap or '
                                        '"--cert-wizard create".')

    cert_wizard_group.add_argument('--locale',
                                   dest='locale',
                                   default=None,
                                   type=str,
                                   help='Specify certificate locale (city) '
                                        'attribute when running --bootstrap or '
                                        '"--cert-wizard create".')

    cert_wizard_group.add_argument('--org',
                                   dest='org',
                                   default=None,
                                   type=str,
                                   help='Specify certificate organization when '
                                        'running --bootstrap or '
                                        '"--cert-wizard create".')

    cert_wizard_group.add_argument('--org-unit',
                                   dest='org_unit',
                                   default=None,
                                   type=str,
                                   help='Specify certificate org unit when '
                                        'running --bootstrap or '
                                        '"--cert-wizard create".')

    cert_wizard_group.add_argument('--email',
                                   dest='email',
                                   default=None,
                                   type=str,
                                   help='Specify certificate emailAddress '
                                        'attribute when running --bootstrap or '
                                        '"--cert-wizard create".')

    cw_advanced_group = parser.add_argument_group('Cert Wizard '
                                                  'Advanced Options')

    cw_advanced_group.add_argument('--not-before',
                                   dest='not_before',
                                   default=0,
                                   type=int,
                                   help='Specify datetime on which '
                                        'cert should become active.')

    cw_advanced_group.add_argument('--not-after',
                                   dest='not_after',
                                   default=cert_utils.DEFAULT_EXP,
                                   type=int,
                                   help='Specify datetime on which cert '
                                        'should become active.')

    cw_advanced_group.add_argument('--algorithm',
                                   dest='algorithm',
                                   default=cert_utils.DEFAULT_ALGORITHM,
                                   type=str,
                                   help='Specify algorithm with '
                                        'which to sign cert.')

    cw_advanced_group.add_argument('--key-length',
                                   dest='key_length',
                                   default=cert_utils.DEFAULT_KEY_LEN,
                                   type=int,
                                   help='Specify default certificate '
                                        'key length.')

    cw_advanced_group.add_argument('--dh-file',
                                   dest='dh_file',
                                   default=None,
                                   type=str,
                                   help='Manually specify path '
                                        'to dh_file at runtime.')

    cw_advanced_group.add_argument('--ca-key',
                                   dest='ca_key',
                                   default=None,
                                   type=str,
                                   help='Specify path to CA private key file.')

    cw_advanced_group.add_argument('--ca-key-passwd',
                                   dest='ca_key_passwd',
                                   default=None,
                                   type=str,
                                   help='Specify CA key password.')

    access_point_group = parser.add_argument_group('Access Point')

    access_point_group.add_argument('--lhost',
                    dest='lhost',
                    type=str,
                    default='10.0.0.1',
                    required=False,
                    help='Your AP\'s IP address')

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
                                    help='Send empty SSID in beacons and '
                                         'ignore probe request '
                                         'frames that do not specify '
                                         'full SSID (i.e. require '
                                         'stations to know SSID). '
                                         'Choices: [1. none - do '
                                         'not use SSID cloaking. ] '
                                         '[2. full - Send empty string'
                                         ' in beacon and ignore probe '
                                         'requests for broadcast '
                                         'SSID ] [3. zeroes - Replace '
                                         'all characters in SSID '
                                         'with ASCII 0 and ignore '
                                         'probe requests for '
                                         'broadcast SSID.]')

    access_point_group.add_argument('--auth',
                                    dest='auth',
                                    type=str,
                                    choices=[
                                        'open',
                                        'wpa-psk',
                                        'wpa-eap',
                                        'owe',
                                        'owe-transition',
                                        'owe-psk',
                                    ],
                                    default=None,
                                    help='Specify authentication mechanism '
                                         '(hostile and captive portal '
                                         'default: open )'
                                         '(creds default: wpa-eap).')

    access_point_group.add_argument('--pmf',
                                    dest='pmf',
                                    type=str,
                                    choices=['disable', 'enable', 'require'],
                                    default=None,
                                    help='Enable, disaable, or require the use of '
                                         'Protected Management Frames (PMF) '
                                         '(802.11w) (default: disable) '
                                         '(OWE default: require).')

    access_point_group.add_argument('--karma', '--mana',
                                    dest='karma',
                                    action='store_true',
                                    help='Enable karma.')

    access_point_group.add_argument('--mac-whitelist',
                                    dest='mac_whitelist',
                                    type=str,
                                    default=None,
                                    help='Enable MAC address whitelisting '
                                         'and specify path to whitelist '
                                         'file.')

    access_point_group.add_argument('--mac-blacklist',
                                    dest='mac_blacklist',
                                    type=str,
                                    default=None,
                                    help='Enable MAC address blacklisting '
                                         'and specify path to blacklist '
                                         'file.')

    access_point_group.add_argument('--ssid-whitelist',
                                    dest='ssid_whitelist',
                                    type=str,
                                    default=None,
                                    help='Enable MAC address whitelisting '
                                         'and specify path to whitelist '
                                         'file.')

    access_point_group.add_argument('--ssid-blacklist',
                                    dest='ssid_blacklist',
                                    type=str,
                                    default=None,
                                    help='Enable MAC address blacklisting '
                                         'and specify path to blacklist '
                                         'file.')

    karma_group = parser.add_argument_group('Karma Options')

    karma_group.add_argument('--loud', '--singe',
                                    dest='loud',
                                    action='store_true',
                                    help='Enable loud karma mode.')

    karma_group.add_argument('--known-beacons',
                                    dest='known_beacons',
                                    action='store_true',
                                    help='Enable persistent known beacons attack.')

    default_ssid_list = os.path.join(
        settings.dict['paths']['directories']['wordlists'],
        settings.dict['core']['eaphammer']['general']['default_ssid_list'],
    )
    karma_group.add_argument('--known-ssids-file',
                           dest='known_ssids_file',
                           default=None,
                           type=str,
                           help='Specify the wordlist to use with '
                                'the --known-beacons features.')

    karma_group.add_argument('--known-ssids',
                           dest='known_ssids',
                           nargs='+',
                           default=None,
                           type=str,
                           help='Specify known ssids via the CLI')

    ap_advanced_subgroup = parser.add_argument_group('AP Advanced Options')

    ap_advanced_subgroup.add_argument('--wmm',
                                      dest='wmm',
                                      action='store_true',
                                      help='Enable wmm (further configuration '
                                           'of wmm performed in hostapd.ini)')

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
                                      help='Send beacon packets every n '
                                           'Time Units (TUs). '
                                           'A single TU is equal to '
                                           '1024 microseconds. '
                                           '(default: 100)')

    ap_advanced_subgroup.add_argument('--dtim-period',
                                      dest='dtim_period',
                                      default=None,
                                      type=int,
                                      metavar='n',
                                      help='Transmit broadcast frames after '
                                           'every n beacons, '
                                           'where n is an integer between '
                                           '1 and 255. (default: 1)')

    ap_advanced_subgroup.add_argument('--max-num-stations',
                                      dest='max_num_stations',
                                      default=None,
                                      type=int,
                                      help='The maximum number of '
                                           'stations that can '
                                           'connect to the AP at '
                                           'any one time. (default: 255)')

    ap_advanced_subgroup.add_argument('--rts-threshold',
                                      dest='rts_threshold',
                                      default=None,
                                      type=int,
                                      metavar='OCTETS',
                                      help='Sets the RTS threshold in '
                                           'octets. (default: 2347)')

    ap_advanced_subgroup.add_argument('--fragm-threshold',
                                      dest='fragm_threshold',
                                      default=None,
                                      type=int,
                                      metavar='OCTETS',
                                      help='Sets the fragmentation '
                                           'threshold in octets. '
                                           '(default: 2346)')

    hwm80211n_subgroup = parser.add_argument_group(
                                    '802.11n Options',
                                    'Used when --hw-mode is set to "n"',
    )

    hwm80211n_subgroup.add_argument('--channel-width',
                                    dest='channel_width',
                                    type=int,
                                    choices=[20,40],
                                    default=None,
                                    metavar='MGhz',
                                    help='Set the channel width '
                                         'in MGHz (single 20 MGHz '
                                         'spatial stream or two 20 '
                                         'MGHz spatial streams '
                                         'totalling 40 MGHz). (default: 20)')

    hwm80211n_advanced_subgroup = parser.add_argument_group(
                                        '802.11n Advanced Options',
    )

    hwm80211n_advanced_subgroup.add_argument('--smps',
                                             dest='smps',
                                             type=str,
                                             choices=['off','dynamic','static'],
                                             default=None,
                                             help='Spatial Multiplexing '
                                                  '(SM) Power Save')

    hwm80211n_advanced_subgroup.add_argument('--ht40',
                                             dest='ht40',
                                             type=str,
                                             choices=['plus', 'minus', 'auto'],
                                             default=None,
                                             help='Specifies whether the '
                                                  'secondary channel should be '
                                                  'higher (plus) or lower '
                                                  '(minus) than the primary '
                                                  'channel. (default: auto)')

    hwm80211n_advanced_subgroup.add_argument('--max-spatial-streams',
                                             dest='max_spatial_streams',
                                             type=int,
                                             choices=[1,2,3],
                                             default=None,
                                             help='Specifies maximum '
                                                  'number of spatial streams. '
                                                  '(default: 2)')

    hwm80211n_advanced_subgroup.add_argument('--obss-interval',
                                             dest='obss_interval',
                                             type=None,
                                             default=None,
                                             help='Look this up if you don\'t '
                                                  'know what it does. You '
                                                  'probably don\'t need '
                                                  'it. (default: 0)')

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
                                             help='Enable short GI (20 or 40 '
                                                  'depending on channel width')

    hwm80211n_advanced_subgroup.add_argument('--lsig-txop-prot',
                                             dest='lsig_txop_prot',
                                             action='store_true',
                                             help='Enable L-SIG '
                                                  'TXOP Protection support.')

    hwm80211n_advanced_subgroup.add_argument('--require-ht',
                                             dest='require_ht',
                                             action='store_true',
                                             help='Reject associations from '
                                                  'clients that do '
                                                  'not support HT.')

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
                                             help='Set A-MSDU length to '
                                                  'maximum allowable '
                                                  'value (7935 octets). '
                                                  'If not set, 3839 '
                                                  'octets are used.')

    psk_group = parser.add_argument_group(
                            'WPA-PSK Options',
                            'Only applicable if --auth wpa-psk is used',
    )
    psk_group.add_argument('--wpa-passphrase',
                           dest='wpa_passphrase',
                           type=str,
                           default=None,
                           help='Set WPA Passphrase for AP.')

    wpa_group = parser.add_argument_group(
                            'WPA Options',
                            'Only applicable if --auth wpa-psk or wpa-eap are used',
    )

    wpa_group.add_argument('--capture-wpa-handshakes',
                           dest='capture_wpa_handshakes',
                           type=str,
                           choices=['yes', 'no'],
                           default=None,
                           help='Capture 4-way WPA handshakes '
                                '(wpa-psk default: yes) '
                                '(wpa-eap and sae defaults: no)')

    wpa_group.add_argument('--psk-capture-file',
                           dest='psk_capture_file',
                           type=str,
                           default=None,
                           help='Path to which to write WPA handshake'
                                'files (default: automatically generated '
                                'from nonce and current timestamp)')

    wpa_group.add_argument('--auth-alg',
                           dest='auth_alg',
                           type=str,
                           choices=['shared', 'open', 'both'],
                           default=None,
                           help='Authentication type (open or shared key). '
                                '(default: shared)')

    wpa_group.add_argument('--wpa-version',
                           dest='wpa_version',
                           type=str,
                           choices=['1', '2'],
                           default=None,
                           help='Set WPA version. (default: 2)')

    owe_transition_group = parser.add_argument_group(
                        'OWE Transition Mode Options',
                        ('Only applicable if --auth '
                            'owe-transition is used'),
    )

    owe_transition_group.add_argument('--transition-bssid',
                        dest='owe_transition_bssid',
                        type=str,
                        default=None,
                        help='Set BSSID for OPEN AP')

    owe_transition_group.add_argument('--transition-ssid',
                        dest='owe_transition_ssid',
                        type=str,
                        default=None,
                        help='Set SSID for OPEN AP')

    eap_group = parser.add_argument_group(
                        'EAP Options',
                        'Only applicable if --auth wpa-eap is used',
    )

    eap_group.add_argument('--autocrack',
                           dest='autocrack',
                           action='store_true',
                           help='Enable autocrack \'n add.')

    eap_group.add_argument('--negotiate',
                           dest='negotiate',
                           choices=[
                                'balanced',
                                'speed',
                                'weakest',
                                'gtc-downgrade',
                                'manual',
                           ],
                           type=str,
                           default='balanced',
                           help='Specify EAP negotiation approach.')

    eap_group.add_argument('--eap-user-file',
                           dest='eap_user_file',
                           default=None,
                           type=str,
                           help=('Manually specify path to '
                                 'eap_user_file (instead of '
                                 'using EAPHammer\'s accounting '
                                 'system)'))

    eap_group.add_argument('--phase-1-methods',
                          dest='eap_methods_phase_1',
                          default='PEAP,TTLS,TLS,FAST',
                          type=str,
                          help=('Manually specify EAP phase 1 methods for '
                                'for wildcard user EAP negotiate.'))

    eap_group.add_argument('--phase-2-methods',
                          dest='eap_methods_phase_2',
                          default=('GTC,TTLS-PAP,MD5,TTLS-CHAP,'
                                   'TTLS-MSCHAP,MSCHAPV2,'
                                   'TTLS-MSCHAPV2,TTLS'),
                          type=str,
                          help=('Manually specify EAP phase 2 methods for '
                                'for wildcard user EAP negotiate.'))

    eap_group.add_argument('--peap-version',
                           dest='peap_version',
                           choices=[1, 2],
                           type=int,
                           default=None,
                           help='Specify EAP negotiation approach.')

    autocrack_group = parser.add_argument_group(
                                'Autocrack Options',
                                'Only applicable if --auth wpa-eap  '
                                '--autocrack is used',
    )

    autocrack_group.add_argument('--remote-cracking-rig',
                           dest='remote_rig',
                           type=str,
                           metavar='server:port',
                           help='Use remote cracking rig '
                                'for autocrack feature.')

    default_wordlist = os.path.join(
        settings.dict['paths']['directories']['wordlists'],
        settings.dict['core']['eaphammer']['general']['default_wordlist'],
    )
    eap_group.add_argument('--wordlist',
                           dest='wordlist',
                           default=default_wordlist,
                           type=str,
                           help='Specify the wordlist to use with '
                                'the autocrack feature.')

    ctmp_group = parser.add_argument_group('Create / Delete Template Options', 
                            ('Only applicable if --create-template '
                             'or --delete-template is used.'))

    ctmp_group.add_argument('--url',
                    dest='url',
                    type=str,
                    default=None,
                    required=False,
                    help='Specify url from which to clone captive portal')

    ctmp_group.add_argument('--name',
                    dest='name',
                    type=str,
                    default=None,
                    required=False,
                    help='Specify name of resulting portal template module')

    ctmp_group.add_argument('--description',
                    dest='description',
                    type=str,
                    default='',
                    required=False,
                    help='Specify description of resulting portal template module')

    ctmp_group.add_argument('--author',
                    dest='author',
                    type=str,
                    default='',
                    required=False,
                    help='Specify author of resulting portal template module')

    ctmp_group.add_argument('--add-download-form',
                    dest='add_download_form',
                    action='store_true',
                    help='Add a download form to your captive portal.')

    ctmp_group.add_argument('--dl-form-message',
                    dest='dl_form_message',
                    type=str,
                    default='Please download our secure profile to continue.',
                    required=False,
                    help='Specify download form text.')

    cptl_group = parser.add_argument_group('Captive Portal Options', 
                            'Only applicable if --captive-portal is used')

    cptl_group.add_argument('--lport',
                    dest='lport',
                    type=int,
                    default=80,
                    required=False,
                    help='Port on which to run captive portal.')

    cptl_group.add_argument('--payload',
                    dest='payload',
                    type=str,
                    default='profile.msi',
                    required=False,
                    help='Specify payload name (defaults to payload.msi test file)')

    cptl_group.add_argument('--portal-template',
                    dest='portal_user_template',
                    type=str,
                    default='login',
                    required=False,
                    help='Specify template directory')

    cptl_group.add_argument('--portal-debug',
                    dest='portal_debug',
                    action='store_true',
                    required=False,
                    help='Show debug for portal server only')

    cptl_group.add_argument('--portal-https',
                    dest='portal_https',
                    action='store_true',
                    required=False,
                    help='Use HTTPS')

    cptl_group.add_argument('--portal-priv-key',
                    dest='portal_private_key',
                    type=str,
                    required=False,
                    help='private key')

    cptl_group.add_argument('--portal-fullchain',
                    dest='portal_fullchain',
                    type=str,
                    required=False,
                    help='fullchain')

    cptl_group.add_argument('--portal-cert',
                    dest='portal_cert',
                    type=str,
                    required=False,
                    help='cert')

    hp_group = parser.add_argument_group('Hostile Portal Options', 
                            'Only applicable if --hostile-portal is used')

    hp_group.add_argument('--pivot',
                           dest='pivot',
                           action='store_true',
                           help='Runs responder without SMB server enabled.')

    eap_spray_group = parser.add_argument_group('EAP Spray')

    eap_spray_group.add_argument('-I', '--interface-pool',
                            dest='interface_pool',
                            metavar='iface_n',
                            type=str,
                            nargs='+',
                            default=None,
                            help='List of interfaces available '
                                 'for password spray attack.')

    eap_spray_group.add_argument('--user-list',
                            dest='user_list',
                            default=None,
                            type=str,
                            help='Like a wordlist, except contains '
                                 'usernames instead of passwords. '
                                 'Each username should be '
                                 'placed on a separate line.')

    eap_spray_group.add_argument('--password',
                            dest='password',
                            default=None,
                            type=str,
                            help='Specify password to be '
                                 'sprayed across list of users.')

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
            options['eap_spray'] is False and
            options['bootstrap'] is False and
            options['list_templates'] is False and
            options['captive_portal_server_only'] is False and
            options['delete_template'] is False and
            options['create_template'] is False and
            options['interface'] is None):

            parser.print_usage()
            print()
            print('[!] Please specify a valid PHY', end=' ')
            print('interface using the --interface flag')
            sys.exit()

        cw_val = options['cert_wizard']
        if cw_val is not None:

            if (options['bootstrap'] or 
                cw_val == 'create' and 
                options['self_signed']):
        
                if options['cn'] is None:
                    parser.print_usage()
                    print()
                    print('[!] Please specify a valid CN '
                          'in order to use --bootstrap mode.', end='')
                    sys.exit()
    
            if cw_val == 'create' and not options['self_signed']:

                if options['ca_cert'] is None:
                    parser.print_usage()
                    print()
                    print('[!] Please specify valid CA cert using the '
                          '--ca-cert flag. If CA private key is not '
                          'included in CA cert file, it must also be '
                          'specified using the --ca-key flag.', end='')
                    sys.exit()


                if options['cn'] is None:
                    parser.print_usage()
                    print()
                    print('[!] Please specify a valid CN in order to use '
                          '--bootstrap mode.', end='')
                    sys.exit()

            if cw_val == 'import':

                if options['server_cert'] is None:
                    parser.print_usage()
                    print()
                    msg = ('[!] Please specify path a server '
                           'certificate using the --server-cert flag.')
                    print(msg, end='')
                    sys.exit()

        if options['delete_template']:

            if options['name'] is None:
                parser.print_usage()
                print()
                msg = ('[!] Please specify a name for your template '
                        'using the --name flag.')
                print(msg, end='')
                sys.exit()

        if options['create_template']:

            if options['name'] is None:
                parser.print_usage()
                print()
                msg = ('[!] Please specify a name for your template '
                        'using the --name flag.')
                print(msg, end='')
                sys.exit()

            if options['url'] is None:
                parser.print_usage()
                print()
                msg = ('[!] Please specify a url from which to clone '
                       'clone your template using the --url flag.')
                print(msg, end='')
                sys.exit()

        if options['loud'] and not options['karma']:

            parser.print_usage()
            print()
            msg = ('[!] Cannot use --loud flag without --karma flag.')
            print(msg, end='')
            sys.exit()

        # sanity checks for known beacons attack
        if options['known_beacons']:

            if not options['karma']:

                parser.print_usage()
                print()
                msg = ('[!] Cannot use --known-beacons flag without --karma flag.')
                print(msg, end='')
                sys.exit()

            if options['known_ssids_file'] is None and \
                    options['known_ssids'] is None:

                parser.print_usage()
                print()
                msg = ('[!] Cannot use --known-beacons '
                        'without list of known SSIDS. '
                        'Please specify path to known SSIDS '
                        'file with the --known-ssids-file flag, '
                        'or provide a list of known SSIDS '
                        'using the --known-ssids flag.')
                print(msg, end='')
                sys.exit()
                
            if options['known_ssids_file'] is not None and \
                    options['known_ssids'] is not None:

                parser.print_usage()
                print()
                msg = ('[!] Cannot use --known-ssids-file '
                        'and --known-ssids flags simultaneously.')
                print(msg, end='')
                sys.exit()

            if options['known_ssids_file'] is not None and \
                not Path(options['known_ssids_file']).is_file():

                parser.print_usage()
                print()
                msg = ('[!] Specified known SSID file not found: {}'.format(options['known_ssids_file']))
                print(msg, end='')
                sys.exit()
                

        if any([ options[a] for a in ROGUE_AP_ATTACKS ]):

                if options['server_cert'] is None:
                    if options['ca_cert']:
                        parser.print_usage()
                        print()
                        msg = ('[!] Cannot use --ca-cert flag at '
                               'attack runtime without using '
                               '--server-cert flag.')
                        print(msg, end='')
                        sys.exit()
                        

                    if options['private_key']:
                        parser.print_usage()
                        print()
                        msg = ('[!] Cannot use --ca-cert flag at '
                               'attack runtime without using '
                               '--server-cert flag.')
                        print(msg, end='')
                        sys.exit()

                    if options['private_key_passwd']:
                        parser.print_usage()
                        print()
                        msg = ('[!] Cannot use --private-key flag at '
                               'attack runtime without using '
                               '--server-cert flag.')
                        print(msg, end='')
                        sys.exit()

        if (options['pmkid'] and 
            options['bssid'] is None and 
            options['essid'] is None):

            parser.print_usage()
            print()
            msg = ('[!] Please specify a valid target '
                   'using the --bssid or --essid flags.')
            print(msg, end=' ')
            sys.exit()

        if options['eap_spray']:
            invalid_args = False
            if options['user_list'] is None:
                print()
                msg = ('[!] Please specify a valid user '
                       'list file using the --user-list flag.')
                print(msg, end=' ')
                invalid_args = True

            if options['essid'] is None:
                print()
                msg = ('[!] Please specify a valid target '
                       'using the --essid flag.')
                print(msg, end=' ')
                invalid_args = True

            if options['password'] is None:
                print()
                msg = ('[!] Please specify password to '
                       'spray using the --password flag.')
                print(msg, end=' ')
                invalid_args = True

            if options['interface_pool'] is None:
                print()
                msg = ('[!] Please specify a list of wireless'
                       'interfaces using the --interface-pool flag.')
                print(msg, end=' ')
                invalid_args = True
            if invalid_args:
                sys.exit()

        if options['mac_whitelist'] is not None and options['mac_blacklist'] is not None:

            parser.print_usage()
            print()
            msg = ('[!] Cannot use --mac-whitelist and '
                   '--mac-blacklist flags simultaneously.')
            print(msg, end='')
            sys.exit()

        if options['ssid_whitelist'] is not None and options['ssid_blacklist'] is not None:

            parser.print_usage()
            print()
            msg = ('[!] Cannot use --ssid-whitelist and '
                   '--ssid-blacklist flags simultaneously.')
            print(msg, end='')
            sys.exit()

        # these sanity checks probably needs to be moved somewhere else,
        # but whatever. fuckit shipit.
        if options['ssid_whitelist']:
            with open(options['ssid_whitelist']) as input_handle:
                for index,line in enumerate(input_handle):
                    ssid = line.strip()
                    if len(ssid) > 32:
                        parser.print_usage()
                        print()
                        msg = ('[!] In SSID whitelist file {} line {}: '
                               'Length of SSID {} is too long. SSIDS must '
                               'have a length of no more than 32 '  
                               'characters.'.format(options['ssid_whitelist'],
                                                index+1, ssid))
                        print(msg, end='')
                        sys.exit()

        if options['ssid_blacklist']:
            with open(options['ssid_blacklist']) as input_handle:
                for index,line in enumerate(input_handle):
                    ssid = line.strip()
                    if len(ssid) > 32:
                        parser.print_usage()
                        print()
                        msg = ('[!] In SSID blacklist file {} line {}: '
                               'Length of SSID {} is too long. SSIDS must '
                               'have a length of no more than 32 '  
                               'characters.'.format(options['ssid_blacklist'],
                                                index+1, ssid))
                        print(msg, end='')
                        sys.exit()


    except SystemExit:

        print()
        print('[!] Use -h or --help to display a list of basic options.')
        msg = ('[!] Use -hh or --advanced-help to '
               'display full list of extended options.')
        print(msg)
        print()

        raise

    if options['manual_config'] is not None:

        with open(options['manual_config']) as fd:

            for line in fd:
                if 'interface' in line:
                    options['interface'] = line.strip().split('=')[1]
        if options['interface'] is None:
            print()
            msg = ('[!] Please specify a valid PHY '
                   'interface in your config file.')
            print(msg)
            sys.exit()

    if options['negotiate'] == 'gtc-downgrade':
        options['negotiate'] = 'gtc_downgrade'

    return options
