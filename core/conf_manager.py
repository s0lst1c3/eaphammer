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
            bssid=None,
            karma=False,
            cloaking=None,
            use_autocrack=False,
            eaphammer_fifo_path=None):

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
        assert cloaking is not None
        assert eaphammer_fifo_path is not None

        cloaking = hostapd_parse_essid_cloaking(cloaking)
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, eap_user_file, ca_pem,
                    server_pem, private_key, dh_file,
                        ssid, hw_mode, channel, logpath,
                            wpa, cloaking, bssid,
								int(karma), int(use_autocrack),
                                	eaphammer_fifo_path))

def hostapd_parse_essid_cloaking(cloaking):

    return {
        'none' : 0,
        'full' : 1,
        'zeroes' : 2
    }[cloaking]

class hostapd_open_cnf(object):

    path = config.hostapd_cnf
    template = cnf_templates.hostapd_open_cnf

    @classmethod
    def configure(cls,
            interface=None,
            ssid=None,
            hw_mode=None,
            channel=None,
            bssid=None,
			cloaking=None,
            karma=False):

        assert interface is not None
        assert ssid is not None
        assert hw_mode is not None
        assert channel is not None
        assert bssid is not None
        assert cloaking is not None

        cloaking = hostapd_parse_essid_cloaking(cloaking)
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, ssid, hw_mode, channel,
					bssid, int(karma), cloaking))

class dnsmasq_dhcp_only_cnf(object):

    path = config.dnsmasq_cnf
    template = cnf_templates.dnsmasq_dhcp_only

    @classmethod
    def configure(cls,
            interface=None,
            log_file=None,
            dhcp_script=None):

        assert interface is not None
        assert log_file is not None
        assert dhcp_script is not None
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, log_file, dhcp_script))

class dnsmasq_captive_portal_cnf(object):

    path = config.dnsmasq_cnf
    template = cnf_templates.dnsmasq_captive_portal

    @classmethod
    def configure(cls,
            interface=None,
            log_file=None,
            dhcp_script=None):

        assert interface is not None
        assert log_file is not None
        assert dhcp_script is not None
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, log_file, dhcp_script))

def f(s):
    return 'On' if s else 'Off'

class responder_cnf(object):

    path = config.responder_cnf
    template = cnf_templates.responder_cnf

    @classmethod
    def configure(cls,
            sql=True,
            smb=True,
            kerberos=True,
            ftp=True,
            pop=True,
            smtp=True,
            imap=True,
            http=False,
            https=False,
            dns=False,
            ldap=True,
            db_file=config.responder_db):

        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (f(sql), f(smb), f(kerberos), f(ftp),
                    f(pop), f(smtp), f(imap), f(http),
                        f(https), f(dns), f(ldap), db_file))
