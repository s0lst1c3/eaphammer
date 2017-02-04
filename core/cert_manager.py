import os
import config
import cnf_templates

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

    path = config.client_cnf
    template = cnf_templates.client_cnf

class server_cnf(cert_cnf):

    path = config.server_cnf
    template = cnf_templates.server_cnf

class ca_cnf(cert_cnf):

    path = config.ca_cnf
    template = cnf_templates.ca_cnf

def bootstrap():
    
    os.system(config.bootstrap_file)

if __name__ == '__main__':

    ca_cnf.configure('US', 'Vermont', 'locale9', 'org9', 'email9', 'cn9')

    server_cnf.configure('US', 'Vermont', 'locale9', 'org9', 'email9', 'cn9')

    client_cnf.configure('US', 'Vermont', 'locale9', 'org9', 'email9', 'cn9')

    bootstrap()
