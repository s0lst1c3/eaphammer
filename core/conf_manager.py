import os
import config
import cnf_templates

class hostapd_cnf(object):

    path = config.hostapd_cnf
    template = cnf_templates.hostapd_cnf

    @classmethod
    def configure(cls,
            interface=None,
            ca_pem=config.ca_pem,
            server_pem=config.server_pem,
            private_key=config.private_key,
            dh_file=config.dh_file,
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
                (interface, ca_pem, server_pem,
                    private_key, dh_file, ssid,
                        hw_mode, channel, wpa, bssid))
