import os
import cnf_templates

from settings import settings

class cert_cnf(object):

    @classmethod
    def configure(cls,
            country=None,
            state=None,
            locale=None,
            org=None,
            email=None,
            cn=None):
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (country, state, locale, org, email, cn))

class client_cnf(cert_cnf):

    path = settings.dict['paths']['hostapd']['client_cnf']
    template = cnf_templates.client_cnf

class server_cnf(cert_cnf):

    path = settings.dict['paths']['hostapd']['server_cnf']
    template = cnf_templates.server_cnf

class ca_cnf(cert_cnf):

    path = settings.dict['paths']['hostapd']['ca_cnf']
    template = cnf_templates.ca_cnf

def bootstrap():
    
    os.system(settings.dict['paths']['hostapd']['bootstrap'])

