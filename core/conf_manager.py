import os
from . import cnf_templates
import core.utils

from settings import settings
from core.utils import ip_replace_last_octet

def responder_parse_on_off(s):

    return 'On' if s else 'Off'

class dnsmasq_dhcp_only_cnf(object):

    path = settings.dict['paths']['dnsmasq']['conf']
    template = cnf_templates.dnsmasq_dhcp_only

    @classmethod
    def configure(cls,
            interface=None,
            lhost=None,
            log_file=settings.dict['paths']['dnsmasq']['log'],
            dhcp_script=settings.dict['paths']['dhcp']['script']):

        assert interface is not None
        assert log_file is not None
        assert dhcp_script is not None
        assert lhost is not None

        dhcp_start = ip_replace_last_octet(lhost, '100')
        dhcp_end = ip_replace_last_octet(lhost, '254')

        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, dhcp_start, dhcp_end, lhost, 
                 lhost, log_file, dhcp_script))

class dnsmasq_captive_portal_cnf(object):

    path = settings.dict['paths']['dnsmasq']['conf']
    template = cnf_templates.dnsmasq_captive_portal

    @classmethod
    def configure(cls,
            interface=None,
            lhost=None,
            log_file=settings.dict['paths']['dnsmasq']['log'],
            dhcp_script=settings.dict['paths']['dhcp']['script']):

        assert interface is not None
        assert log_file is not None
        assert dhcp_script is not None
        assert lhost is not None

        dhcp_start = ip_replace_last_octet(lhost, '100')
        dhcp_end = ip_replace_last_octet(lhost, '254')

        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (interface, dhcp_start, dhcp_end,
                 lhost, lhost, log_file, dhcp_script, lhost))


class responder_cnf(object):

    path = settings.dict['paths']['responder']['conf']
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
            db_file=settings.dict['core']['responder']['Responder Core']['database']):

        f = responder_parse_on_off

        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (f(sql), f(smb), f(kerberos), f(ftp),
                    f(pop), f(smtp), f(imap), f(http),
                        f(https), f(dns), f(ldap), db_file))
