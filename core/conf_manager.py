import os
import config
import cnf_templates

class hostapd_wpe_cnf(object):

    path = config.hostapd_cnf
    template = cnf_templates.hostapd_wpe_cnf

    @classmethod
    def configure(cls,
            interface=None,
            ca_pem=config.ca_pem,
            eap_user_file=config.eap_user_file, 
            server_pem=config.server_pem,
            private_key=config.private_key,
            dh_file=config.dh_file,
            logpath=config.hostapd_log,
            ssid=None,
            hw_mode=None,
            channel=None,
            wpa=None,
            bssid=None):

        assert interface is not None
        assert ca_pem is not None
        assert server_pem is not None
        assert private_key is not None
        assert dh_file is not None
        assert ssid is not None
        assert hw_mode is not None
        assert channel is not None
        assert wpa is not None
        assert bssid is not None
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, eap_user_file, ca_pem,
                    server_pem, private_key, dh_file,
                        ssid, hw_mode, channel, logpath, wpa, bssid))

class hostapd_open_cnf(object):

    path = config.hostapd_cnf
    template = cnf_templates.hostapd_open_cnf

    @classmethod
    def configure(cls,
            interface=None,
            ssid=None,
            hw_mode=None,
            channel=None,
            bssid=None):

        assert interface is not None
        assert ssid is not None
        assert hw_mode is not None
        assert channel is not None
        assert bssid is not None
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, ssid, hw_mode, channel, bssid))
