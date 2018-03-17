import os
import json

from datetime import datetime

class OutputFile(object):

    def __init__(self, name='', ext=''):
        datestring = datetime.strftime(datetime.now(), '%Y-%m-%d-%H-%M-%S')
        if name != '':
            self.str = '%s-%s' % (name, datestring)
        else:
            self.str = datestring
        if ext != '':
            self.str = '%s.%s' % (datestring, ext.replace('.', ''))

    def string(self):
        return self.str

    def __str__(self):
        return self.str

# define directories
ROOT_DIR = os.path.split(os.path.dirname(os.path.abspath(__file__)))[0]
CONF_DIR = os.path.join(ROOT_DIR, 'settings')
SAVE_DIR = os.path.join(ROOT_DIR, 'saved-configs')
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
SCRIPT_DIR = os.path.join(ROOT_DIR, 'scripts')
DB_DIR = os.path.join(ROOT_DIR, 'db')
TMP_DIR = os.path.join(ROOT_DIR, 'tmp')
WORDLIST_DIR = os.path.join(ROOT_DIR, 'wordlists')
HOSTAPD_DIR = os.path.join(ROOT_DIR, 'hostapd-eaphammer', 'hostapd')
CERTS_DIR = os.path.join(ROOT_DIR, 'certs')


# hostapd paths

HOSTAPD_BIN = os.path.join(HOSTAPD_DIR, 'hostapd-eaphammer')
HOSTAPD_LIB = os.path.join(HOSTAPD_DIR, 'libhostapd-eaphammer.so')
HOSTAPD_LOG = os.path.join(LOG_DIR, 'hostapd-eaphammer.log')

output_file = OutputFile(name='hostapd', ext='conf').string()
HOSTAPD_CONF = os.path.join(TMP_DIR, output_file)
HOSTAPD_SAVE = os.path.join(SAVE_DIR, output_file)
FIFO_PATH = os.path.join(TMP_DIR, OutputFile(ext='fifo').string())

EAP_USER_FILE = os.path.join(DB_DIR, 'eaphammer.eap_user')
EAP_USER_HEADER = os.path.join(DB_DIR, 'eap_user_header.txt')
CA_CNF = os.path.join(CERTS_DIR, 'ca.cnf')
SERVER_CNF = os.path.join(CERTS_DIR, 'server.cnf')
CLIENT_CNF = os.path.join(CERTS_DIR, 'client.cnf')
BOOTSTRAP_FILE = os.path.join(CERTS_DIR, 'bootstrap')
CA_PEM = os.path.join(CERTS_DIR, 'ca.pem')
SERVER_PEM = os.path.join(CERTS_DIR, 'server.pem')
PRIVATE_KEY = os.path.join(CERTS_DIR, 'server.pem')
DH_FILE = os.path.join(CERTS_DIR, 'dh')


# everything else
DNSMASQ_LOG = os.path.join(LOG_DIR, 'dnsmasq.log')

DNSMASQ_CONF = os.path.join(TMP_DIR, OutputFile(name='dnsmasq', ext='conf').string())
RESPONDER_CONF = os.path.join(TMP_DIR, OutputFile(name='Responder', ext='conf').string())

DHCP_SCRIPT = os.path.join(SCRIPT_DIR, 'dhcp_script.py')


paths = {

    'directories' : {

        'root' : ROOT_DIR,
        'conf' : CONF_DIR,
        'log' : LOG_DIR,
        'scripts' : SCRIPT_DIR,
        'db' : DB_DIR,
        'tmp' : TMP_DIR,
        'wordlists' : WORDLIST_DIR,
        'hostapd' : HOSTAPD_DIR,
        'certs' : CERTS_DIR,
        'saves' : SAVE_DIR,
    },

    'hostapd' : {

        'bin' : HOSTAPD_BIN,
        'lib' : HOSTAPD_LIB,
        'log' : HOSTAPD_LOG,
        'eap_user'  : EAP_USER_FILE,
        'eap_user_header'  : EAP_USER_HEADER,
        'ca_cnf' : CA_CNF,
        'server_cnf' : SERVER_CNF,
        'client_cnf' : CLIENT_CNF,
        'bootstrap' : BOOTSTRAP_FILE,
        'ca_pem' : CA_PEM,
        'server_pem' : SERVER_PEM,
        'private_key' : PRIVATE_KEY,
        'dh' : DH_FILE,
        'fifo' : FIFO_PATH,
        'conf' : HOSTAPD_CONF,
        'save' : HOSTAPD_SAVE,
    },

    'dnsmasq' : {

        'log' : DNSMASQ_LOG,
        'conf' : DNSMASQ_CONF,
    },
    'responder' : {

        'conf' : RESPONDER_CONF,
    },
    'dhcp' : {

        'script' : DHCP_SCRIPT,
    },
}

