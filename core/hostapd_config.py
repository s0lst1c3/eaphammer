import os
import json
import shutil

class HostapdConfig(object):

    def __init__(self, settings, options):

        self.path = settings.dict['paths']['hostapd']['conf']
        self.save_path = settings.dict['paths']['hostapd']['save']

        configs = {

            'general' : self.populate_general(settings, options),
        }


        if options['hw_mode'] is None:
            hw_mode = settings.dict['core']['hostapd']['general']['hw_mode']
        else:
            hw_mode = options['hw_mode']

        if hw_mode == 'n':
            configs['80211n'] = self.populate_80211n(settings, options)

        if options['reap_creds'] and options['auth'] is None:
            options['auth'] = 'wpa-eap'

        if options['auth'] == 'wpa-eap':
            configs['wpa'] = self.populate_wpa(settings, options)
            configs['eap'] = self.populate_eap(settings, options)
        elif options['auth'] == 'wpa-psk':
            configs['wpa'] = self.populate_wpa(settings, options)
            configs['psk'] = self.populate_psk(settings, options)

        if options['wmm']:
            configs['wmm'] = self.populate_wmm(settings, options)

        if options['auth'] == 'owe':
            configs['owe'] = self.populate_owe(settings, options)

        if options['auth'] == 'owe-transition':
            configs['owe_transition'] = self.populate_owe_transition(settings, options)
            configs['populate_owe_transition_open_bss'] = self.populate_owe_transition_open_bss(settings, options)

        self.dict = configs

        if options['debug']:
            print('\n\n[debug] HostapdConf:')
            print(json.dumps(self.dict, indent=4, sort_keys=True))

    def save(self):

        shutil.move(self.path, self.save_path)
        print('[*] Config saved to:', self.save_path)

    def write(self):

        with open(self.path, 'w') as output_handle:

            for section in self.dict:

                output_handle.write('# %s ---\n\n' % section)
                for key,value in list(self.dict[section].items()):
                    output_handle.write('%s=%s\n' % (key,value))
                output_handle.write('\n')

    def remove(self):
        try:
            os.remove(self.path)
        except OSError:
            print('[*] Can\'t remove non-existant config file.')
            pass

    def populate_eap(self, settings, options):

        eap_configs = {
            'eap_user_file' : settings.dict['paths']['hostapd']['eap_user'],
            'eaphammer_logfile' : settings.dict['paths']['hostapd']['log'],

            'eap_server' : settings.dict['core']['hostapd']['eap']['eap_server'],
            'eap_fast_a_id' : settings.dict['core']['hostapd']['eap']['eap_fast_a_id'],
            'eap_fast_a_id_info' : settings.dict['core']['hostapd']['eap']['eap_fast_a_id_info'],
            'eap_fast_prov' : settings.dict['core']['hostapd']['eap']['eap_fast_prov'],
            'ieee8021x' : settings.dict['core']['hostapd']['eap']['ieee8021x'],
            'pac_key_lifetime' : settings.dict['core']['hostapd']['eap']['pac_key_lifetime'],
            'pac_key_refresh_time' : settings.dict['core']['hostapd']['eap']['pac_key_refresh_time'],
            'pac_opaque_encr_key' : settings.dict['core']['hostapd']['eap']['pac_opaque_encr_key'],
            'wpa_key_mgmt' : settings.dict['core']['hostapd']['eap']['wpa_key_mgmt'],
        }

        if options['capture_wpa_handshakes'] is None:
            eap_configs['capture_wpa_handshakes'] = settings.dict['core']['hostapd']['eap']['capture_wpa_handshakes']
        elif options['capture_wpa_handshakes'] == 'yes':
            eap_configs['capture_wpa_handshakes'] = '1'
        elif options['capture_wpa_handshakes'] == 'no':
            eap_configs['capture_wpa_handshakes'] = '0'
        else:
            raise Exception('This should never happen.')

        if options['psk_capture_file'] is None:
            eap_configs['psk_capture_file'] = settings.dict['paths']['psk']['psk_capture_file']
        else:
            eap_configs['psk_capture_file'] = options['psk_capture_file'] 

        print('[*] WPA handshakes will be saved to {}'.format(eap_configs['psk_capture_file']))
        
        if options['dh_file'] is not None:
            # if the user specified a dh file manually, use this
            eap_configs['dh_file'] = options['dh_file']
        else:
            eap_configs['dh_file'] = settings.dict['paths']['certs']['dh']


        # All certificate options within hostapd's default configuration file are
        # are completely ignored if even one certificate option is passed
        # via the CLI. This is done to prevent the default config and CLI flags
        # from interfering with one another.
        override_conf = False
        if options['ca_cert'] is not None:
            override_conf = True
        if options['server_cert'] is not None:
            override_conf = True
        if options['private_key'] is not None:
            override_conf = True
        if options['private_key_passwd'] is not None:
            override_conf = True

        if override_conf:
        
            # we're going to assume that any certs or keys that the user has given us are
            # valid. onus is on them to get that right.

            # doesn't make sense to do this without specifying a server cert
            if options['server_cert'] is not None:
                eap_configs['server_cert'] = options['server_cert']
            else:
                raise Exception('Certificate conf override detected but not server cert specified.')

            # if no private key is specified, assume it is included in the server_cert file
            # (think: fullchain.pem)
            if options['private_key'] is None:
                eap_configs['private_key'] = options['server_cert']
            else:
                eap_configs['private_key'] = options['private_key']

            # if no ca cert is specified, assume it is included in the server_cert file
            # and therefore is not needed (think: Let's Encrypt)
            if options['ca_cert'] is None:
                eap_configs['ca_cert'] = options['server_cert']
            else:
                eap_configs['ca_cert'] = options['ca_cert']

            # if there's a private key password, we specify that here
            eap_configs['private_key_passwd'] = options['private_key_passwd']

        else:

            # if we're not overriding the active configuration, use the currently active
            # certificate chain

            eap_configs['server_cert'] = settings.dict['paths']['certs']['active_full_chain']
            eap_configs['private_key'] = settings.dict['paths']['certs']['active_full_chain']

        return eap_configs

    def populate_wpa(self, settings, options):

        wpa_configs = { }

        if options['auth_alg'] is None:
            wpa_configs['auth_algs'] = settings.dict['core']['hostapd']['wpa']['auth_algs']
        elif options['auth_alg'] == 'open':
            wpa_configs['auth_algs'] = '1'
        elif options['auth_alg'] == 'shared':
            wpa_configs['auth_algs'] = '2'
        elif options['auth_alg'] == 'both':
            wpa_configs['auth_algs'] = '3'
        else:
            raise ValueError('Invalid value.')

        if options['wpa_version'] is None:
            wpa_configs['wpa'] = settings.dict['core']['hostapd']['wpa']['wpa']
        else:
            wpa_configs['wpa'] = options['wpa_version']

        wpa_configs['wpa_pairwise'] = settings.dict['core']['hostapd']['wpa']['wpa_pairwise']

        return wpa_configs

    def populate_psk(self, settings, options):

        psk_configs = { }

        if options['wpa_passphrase'] is None:
            psk_configs['wpa_passphrase'] = settings.dict['core']['hostapd']['psk']['wpa_passphrase']
        else:
            psk_configs['wpa_passphrase'] = options['wpa_passphrase']

        if options['capture_wpa_handshakes'] is None:
            psk_configs['capture_wpa_handshakes'] = settings.dict['core']['hostapd']['psk']['capture_wpa_handshakes']
        elif options['capture_wpa_handshakes'] == 'yes':
            psk_configs['capture_wpa_handshakes'] = '1'
        elif options['capture_wpa_handshakes'] == 'no':
            psk_configs['capture_wpa_handshakes'] = '0'
        else:
            raise Exception('This should never happen.')

        if options['psk_capture_file'] is None:
            psk_configs['psk_capture_file'] = settings.dict['paths']['psk']['psk_capture_file']
        else:
            psk_configs['psk_capture_file'] = options['psk_capture_file'] 

        print('[*] WPA handshakes will be saved to {}'.format(psk_configs['psk_capture_file']))
        

        return psk_configs


    def populate_wmm(self, settings, options):

        return {

            'wmm_enabled' : settings.dict['core']['hostapd']['wmm']['wmm_enabled'],
            'wmm_ac_bk_cwmin' : settings.dict['core']['hostapd']['wmm']['wmm_ac_bk_cwmin'],
            'wmm_ac_bk_cwmax' : settings.dict['core']['hostapd']['wmm']['wmm_ac_bk_cwmax'],
            'wmm_ac_bk_aifs' : settings.dict['core']['hostapd']['wmm']['wmm_ac_bk_aifs'],
            'wmm_ac_bk_txop_limit' : settings.dict['core']['hostapd']['wmm']['wmm_ac_bk_txop_limit'],
            'wmm_ac_bk_acm' : settings.dict['core']['hostapd']['wmm']['wmm_ac_bk_acm'],
            'wmm_ac_be_aifs' : settings.dict['core']['hostapd']['wmm']['wmm_ac_be_aifs'],
            'wmm_ac_be_cwmin' : settings.dict['core']['hostapd']['wmm']['wmm_ac_be_cwmin'],
            'wmm_ac_be_cwmax' : settings.dict['core']['hostapd']['wmm']['wmm_ac_be_cwmax'],
            'wmm_ac_be_txop_limit' : settings.dict['core']['hostapd']['wmm']['wmm_ac_be_txop_limit'],
            'wmm_ac_be_acm' : settings.dict['core']['hostapd']['wmm']['wmm_ac_be_acm'],
            'wmm_ac_vi_aifs' : settings.dict['core']['hostapd']['wmm']['wmm_ac_be_aifs'],
            'wmm_ac_vi_cwmin' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vi_cwmin'],
            'wmm_ac_vi_cwmax' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vi_cwmax'],
            'wmm_ac_vi_txop_limit' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vi_txop_limit'],
            'wmm_ac_vi_acm' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vi_acm'],
            'wmm_ac_vo_aifs' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vo_aifs'],
            'wmm_ac_vo_cwmin' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vo_cwmin'],
            'wmm_ac_vo_cwmax' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vo_cwmax'],
            'wmm_ac_vo_txop_limit' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vo_txop_limit'],
            'wmm_ac_vo_acm' : settings.dict['core']['hostapd']['wmm']['wmm_ac_vo_acm'],
        }

    def populate_80211n(self, settings, options):

        dot11n_configs = {}

        dot11n_configs['ieee80211n'] = settings.dict['core']['hostapd']['80211n']['ieee80211n']

        if options['require_ht']:
            dot11n_configs['require_ht'] = '1'
        else:
            dot11n_configs['require_ht'] = settings.dict['core']['hostapd']['80211n']['require_ht']

        if options['obss_interval'] is None:
            try:
                dot11n_configs['obss_interval'] = settings.dict['core']['hostapd']['80211n']['obss_interval']
            except KeyError:
                pass
        else:
            dot11n_configs['obss_interval'] = options['obss_interval']

        # --------------------------------------------------------------------------------
        # ht_capab is populated exclusively through the use of command line arguments
        # --------------------------------------------------------------------------------

        ht_capab = ''

        channel_width = options['channel_width']
        if channel_width is None:
            channel_width = 20

        ht40 = options['ht40']
        if ht40 is None:
            ht40 = 'auto'

        if channel_width == 40:

            if ht40 == 'plus':
                ht_capab += '[HT40+]'
            elif ht40 == 'minus':
                ht_capab += '[HT40-]'
            elif ht40 == 'auto':

                if options['channel'] is None:
                    channel = int(settings.dict['core']['hostapd']['general']['channel'])
                else:
                    channel = options['channel']

                if channel >= 1 and channel <= 7:
                    ht_capab += '[HT40+]'
                elif channel > 7 and channel <= 14:
                    ht_capab += '[HT40-]'
                elif channel in [36,44,149,157]:
                    ht_capab += '[HT40+]'
                elif channel in [40,48,153,161]:
                    ht_capab += '[HT40-]'
                else:
                    raise ValueError('Invalid channel selected')

            else:
                raise Exception('Invalid option detected')

        if options['smps'] is not None:
            if options['smps'] == 'dynamic':
                ht_capab += '[SMPS-DYNAMIC]'
            elif options['smps'] == 'static':
                ht_capab += '[SMPS-STATIC]'

        if options['greenfield']:
            ht_capab += '[GF]'

        if options['ht_delayed_block_ack']:
            ht_capab += '[DELAYED-BA]'

        if options['short_gi']:
            if options['channel_width'] == 40:
                ht_capab += '[SHORT-GI-40]'
            else:
                ht_capab += '[SHORT-GI-20]'

        if options['max_spatial_streams'] is None:
            ht_capab += '[RX-STBC12]'
        elif options['max_spatial_streams'] == 1:
            ht_capab += '[RX-STBC1]'
        elif options['max_spatial_streams'] == 2:
            ht_capab += '[RX-STBC12]'
        elif options['max_spatial_streams'] == 3:
            ht_capab += '[RX-STBC123]'

        if options['lsig_txop_prot']:
            ht_capab += '[LSIG-TXOP-PROT]'

        if options['dsss_cck_40']:
            ht_capab += '[DSSS_CCK-40]'

        if not options['disable_tx_stbc']:
            ht_capab += '[TX-STBC]'

        if options['use_max_a_msdu_length']:
            ht_capab += '[MAX-AMSDU-7935]'

        if options['ldpc']:
            ht_capab += '[LDPC]'

        dot11n_configs['ht_capab'] = ht_capab

        # end ht_capab

        return dot11n_configs

    def populate_general(self, settings, options):

        general_configs = {
            'interface' : options['interface'],
        }

        if options['essid'] is None:
            general_configs['ssid'] = settings.dict['core']['hostapd']['general']['ssid']
        else:
            general_configs['ssid'] = options['essid']

        if options['bssid'] is None:
            general_configs['bssid'] = settings.dict['core']['hostapd']['general']['bssid']
        else:
            general_configs['bssid'] = options['bssid']

        if options['channel'] is None:
            general_configs['channel'] = settings.dict['core']['hostapd']['general']['channel']
        else:
            general_configs['channel'] = options['channel']


        if options['autocrack'] is None:
            general_configs['use_autocrack'] = str(int(settings.dict['core']['hostapd']['general']['use_autocrack']))
        else:
            general_configs['use_autocrack'] = str(int(options['autocrack']))


        if options['cloaking'] is None:
            if options['auth'] == 'owe-transition':
                general_configs['ignore_broadcast_ssid'] = settings.dict['core']['hostapd']['owe_transition']['owe_transition_ignore_broadcast_ssid']
            else:
                general_configs['ignore_broadcast_ssid'] = settings.dict['core']['hostapd']['general']['ignore_broadcast_ssid']

        else:

            if options['cloaking'] == 'full':
                general_configs['ignore_broadcast_ssid'] = '1'
            elif options['cloaking'] == 'zeroes':
                general_configs['ignore_broadcast_ssid'] = '2'
            else:
                general_configs['ignore_broadcast_ssid'] = '0'

        options_hw_mode = options['hw_mode']
        settings_hw_mode = settings_hw_mode = settings.dict['core']['hostapd']['general']['hw_mode']
        # if user does not specify a hardware mode, from from the config ifle
        if options_hw_mode is None:

            # validate hw_mode loaded from config file
            if int(general_configs['channel']) > 0 and int(general_configs['channel']) < 15:

                if settings_hw_mode not in ['b', 'g']:

                    print('[!] The hw_mode specified in hostapd.ini is invalid for the selected channel (%s, %s)' % (settings_hw_mode, str(general_configs['channel'])))

                    print('[!] Falling back to hw_mode: g')
                    settings_hw_mode = 'g'

            elif settings_hw_mode != 'a':

                print('[!] The hw_mode specified in hostapd.ini is invalid for the selected channel (%s, %s)' % (settings_hw_mode, str(general_configs['channel'])))

                print('[!] Falling back to hw_mode: a')
                settings_hw_mode = 'a'

            general_configs['hw_mode'] = settings_hw_mode


        # if user selects hw_mode=n, automagically select the correct hw_mode (a or g)
        # for the current channel
        elif options_hw_mode == 'n':

            print('[*] 802.11n mode activated...')

            if general_configs['channel'] > 0 and general_configs['channel'] < 15:
                general_configs['hw_mode'] = 'g'
            else:
                general_configs['hw_mode'] = 'a'

            print('[*] Automatically setting hw_mode to %s based on channel selection' % general_configs['hw_mode'])

        # if the user selects a hw_mode other than n, validate and set it
        elif options_hw_mode is not None:

            # sanity check: make sure hw_mode is compatible with selected channel
            if int(general_configs['channel']) >= 1 and int(general_configs['channel']) <= 14:

                if options_hw_mode not in ['b', 'g']:

                    print('[!] The selected hw_mode is invalid for the selected channel (%s, %s)' % (options_hw_mode, str(general_configs['channel'])))

                    print('[!] Falling back to hw_mode: g')

                    options_hw_mode = 'g'

            elif options_hw_mode != 'a':

                print('[!] The selected hw_mode is invalid for the selected channel (%s, %s)' % (options_hw_mode, str(general_configs['channel'])))

                print('[!] Falling back to hw_mode: a')
                settings_hw_mode = 'a'

            general_configs['hw_mode'] = options_hw_mode

        else:

            # we shouldn't ever get to this point
            raise ValueError('Invalid value for options[\'hw_mode\']')

        if options['max_num_stations'] is None:
            general_configs['max_num_sta'] = settings.dict['core']['hostapd']['general']['max_num_sta']
        else:
            general_configs['max_num_sta'] = options['max_num_stations']

        if options['rts_threshold'] is None:
            general_configs['rts_threshold'] = settings.dict['core']['hostapd']['general']['rts_threshold']
        else:
            general_configs['rts_threshold'] = options['rts_threshold']

        if options['fragm_threshold'] is None:
            general_configs['fragm_threshold'] = settings.dict['core']['hostapd']['general']['fragm_threshold']
        else:
            general_configs['fragm_threshold'] = options['fragm_threshold']

        if options['dtim_period'] is None:
            general_configs['dtim_period'] = settings.dict['core']['hostapd']['general']['dtim_period']
        else:
            general_configs['dtim_period'] = options['dtim_period']

        if options['beacon_interval'] is None:
            general_configs['beacon_int'] = settings.dict['core']['hostapd']['general']['beacon_int']
        else:
            general_configs['beacon_int'] = options['beacon_interval']

        general_configs['autocrack_fifo_path'] = settings.dict['paths']['hostapd']['fifo']


        general_configs['country_code'] = settings.dict['core']['hostapd']['general']['country_code']

        #general_configs['ctrl_interface'] = settings.dict['core']['hostapd']['general']['ctrl_interface']
        general_configs['ctrl_interface'] = settings.dict['paths']['hostapd']['ctrl_interface']

        general_configs['ctrl_interface_group'] = settings.dict['core']['hostapd']['general']['ctrl_interface_group']

        general_configs['logger_syslog'] = settings.dict['core']['hostapd']['general']['logger_syslog']
        general_configs['logger_syslog_level'] = settings.dict['core']['hostapd']['general']['logger_syslog_level']
        general_configs['logger_stdout'] = settings.dict['core']['hostapd']['general']['logger_stdout']
        general_configs['logger_stdout_level'] = settings.dict['core']['hostapd']['general']['logger_stdout_level']

        if options['mac_whitelist'] is not None:
            general_configs['accept_mac_file'] = settings.dict['paths']['hostapd']['mac_whitelist']
            general_configs['macaddr_acl'] = '1'
        elif options['mac_blacklist'] is not None:
            general_configs['deny_mac_file'] = settings.dict['paths']['hostapd']['mac_blacklist']
            general_configs['macaddr_acl'] = '0'

        if options['ssid_whitelist'] is not None:
            general_configs['ssid_acl_file'] = settings.dict['paths']['hostapd']['ssid_whitelist']
            general_configs['ssid_acl_mode'] = '0'
        elif options['ssid_blacklist'] is not None:
            general_configs['ssid_acl_file'] = settings.dict['paths']['hostapd']['ssid_blacklist']
            general_configs['ssid_acl_mode'] = '1'

        if options['karma']:
            general_configs['use_karma'] = '1'
        else:
            general_configs['use_karma'] = settings.dict['core']['hostapd']['general']['use_karma']

        if options['loud']:
            general_configs['loud_karma'] = '1'
        else:
            general_configs['loud_karma'] = settings.dict['core']['hostapd']['general']['loud_karma']

        if options['known_beacons']:
            general_configs['known_beacons'] = '1'
            general_configs['known_ssids_file'] = settings.dict['paths']['hostapd']['known_ssids']
        else:
            general_configs['known_beacons'] = settings.dict['core']['hostapd']['general']['known_beacons']

        if options['pmf'] is None:
            if options['auth'] == 'owe':
                general_configs['ieee80211w'] = settings.dict['core']['hostapd']['owe']['owe_ieee80211w']
            elif options['auth'] == 'owe-transition':
                general_configs['ieee80211w'] = settings.dict['core']['hostapd']['owe_transition']['owe_transition_ieee80211w']
            #if options['auth'] == 'owe-psk':
            #    general_configs['ieee80211w'] = settings.dict['core']['hostapd']['owe']['owe_psk_ieee80211w']

            else:
                general_configs['ieee80211w'] = settings.dict['core']['hostapd']['general']['ieee80211w']
        elif options['pmf'] == 'disable':
            general_configs['ieee80211w'] = '0'
        elif options['pmf'] == 'enable':
            general_configs['ieee80211w'] = '1'
        elif options['pmf'] == 'require':
            general_configs['ieee80211w'] = '2'
        else:
            raise Exception('[hostapd_conf] PMF not set to known value. This should never happen.')


        return general_configs

    def populate_owe(self, settings, options):

        owe_configs = {
                
            'wpa' : settings.dict['core']['hostapd']['owe']['wpa'],
            'wpa_key_mgmt' : settings.dict['core']['hostapd']['owe']['wpa_key_mgmt'],
            'rsn_pairwise' : settings.dict['core']['hostapd']['owe']['rsn_pairwise'],
        }

        return owe_configs

    def populate_owe_transition(self, settings, options):

        owe_transition_configs = {

            'wpa' : settings.dict['core']['hostapd']['owe_transition']['wpa'],
            'wpa_key_mgmt' : settings.dict['core']['hostapd']['owe_transition']['wpa_key_mgmt'],
            'rsn_pairwise' : settings.dict['core']['hostapd']['owe_transition']['rsn_pairwise'],
        }

        if options['owe_transition_ssid'] is None:
            owe_transition_configs['owe_transition_ssid'] = '"{}"'.format(settings.dict['core']['hostapd']['owe_transition']['owe_transition_ssid'])
        else:
            owe_transition_configs['owe_transition_ssid'] = '"{}"'.format(options['owe_transition_ssid'])

        if options['owe_transition_bssid'] is None:
            owe_transition_configs['owe_transition_bssid'] = settings.dict['core']['hostapd']['owe_transition']['owe_transition_bssid']
        else:
            owe_transition_configs['owe_transition_bssid'] = options['owe_transition_ssid']

        return owe_transition_configs

    def populate_owe_transition_open_bss(self, settings, options):

        owe_transition_open_bss_configs = {

            'bss' : '{}_0'.format(options['interface']),
        }

        # set bssid and ssid values for open BSS ------------------
        if options['owe_transition_ssid'] is None:
            owe_transition_open_bss_configs['ssid'] = settings.dict['core']['hostapd']['owe_transition']['owe_transition_ssid']
        else:
            owe_transition_open_bss_configs['ssid'] = options['owe_transition_ssid']

        if options['owe_transition_bssid'] is None:
            owe_transition_open_bss_configs['bssid'] = settings.dict['core']['hostapd']['owe_transition']['owe_transition_bssid']
        else:
            owe_transition_open_bss_configs['bssid'] = options['owe_transition_ssid']

        # set owe_transition_bssid and owe_transition_ssid values for open BSS ---
        if options['essid'] is None:
            owe_transition_open_bss_configs['owe_transition_ssid'] = '"{}"'.format(settings.dict['core']['hostapd']['general']['ssid'])
        else:
            owe_transition_open_bss_configs['owe_transition_ssid'] = '"{}"'.format(options['essid'])

        if options['bssid'] is None:
            owe_transition_open_bss_configs['owe_transition_bssid'] = settings.dict['core']['hostapd']['general']['bssid']
        else:
            owe_transition_open_bss_configs['owe_transition_bssid'] = options['bssid']

        return owe_transition_open_bss_configs

