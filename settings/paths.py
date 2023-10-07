import os
import json
import random
import string

from datetime import datetime

class OutputFile(object):

    def __init__(self, name='', ext='', length=32):
        datestring = datetime.strftime(datetime.now(), '%Y-%m-%d-%H-%M-%S')
        randstring = ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(length))
        self.str = ''
        if name != '':
            self.str += '%s-' % name
        self.str += '-'.join([datestring, randstring])
        if ext != '':
            self.str += '.%s' % ext.replace('.', '')

    def string(self):
        return self.str

    def __str__(self):
        return self.str

# define directories
ROOT_DIR = os.path.split(os.path.dirname(os.path.abspath(__file__)))[0]
CONF_DIR = os.path.join(ROOT_DIR, 'settings')
SAVE_DIR = os.path.join(ROOT_DIR, 'saved-configs')
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
RUN_DIR = os.path.join(ROOT_DIR, 'run')
SCRIPT_DIR = os.path.join(ROOT_DIR, 'scripts')
DB_DIR = os.path.join(ROOT_DIR, 'db')
TMP_DIR = os.path.join(ROOT_DIR, 'tmp')
WORDLIST_DIR = os.path.join(ROOT_DIR, 'wordlists')
LOCAL_DIR = os.path.join(ROOT_DIR, 'local')
HOSTAPD_DIR = os.path.join(LOCAL_DIR, 'hostapd-eaphammer', 'hostapd')
CERTS_DIR = os.path.join(ROOT_DIR, 'certs')
LOOT_DIR = os.path.join(ROOT_DIR, 'loot')
THIRDPARTY_DIR = os.path.join(ROOT_DIR, 'thirdparty')
ASLEAP_DIR = os.path.join(LOCAL_DIR, 'asleap')
HCXDUMPTOOL_DIR = os.path.join(LOCAL_DIR, 'hcxdumptool')
HCXTOOLS_DIR = os.path.join(LOCAL_DIR, 'hcxtools')
RESPONDER_DIR = os.path.join(LOCAL_DIR, 'Responder')
WSKEYLOGGER_DIR = os.path.join(ROOT_DIR, 'core/wskeyloggerd')

# wskeyloggerd paths
WSKEYLOGGER_TEMPLATES = os.path.join(WSKEYLOGGER_DIR, 'templates')
WSKEYLOGGER_PAR_TEMPL = os.path.join(WSKEYLOGGER_TEMPLATES, 'dont_touch')
WSKEYLOGGER_USR_TEMPL = os.path.join(WSKEYLOGGER_TEMPLATES, 'user_defined')
WSKEYLOGGER_USR_SL = os.path.join(ROOT_DIR, 'templates')

WSKEYLOGGER_STATIC = os.path.join(WSKEYLOGGER_DIR, 'static')
WSKEYLOGGER_STATIC_SL = os.path.join(ROOT_DIR, 'static')
WSKEYLOGGER_PAYLOADS = os.path.join(ROOT_DIR, 'payloads')

# responder paths
RESPONDER_BIN = os.path.join(RESPONDER_DIR, 'Responder.py')
RESPONDER_DB = os.path.join(DB_DIR, 'Responder.db')
RESPONDER_SESSION_LOG = os.path.join(LOG_DIR, 'Responder-Session.log')
RESPONDER_POISONERS_LOG = os.path.join(LOG_DIR, 'Poisoners-Session.log')
RESPONDER_ANALYZER_LOG = os.path.join(LOG_DIR, 'Analyzer-Session.log')
RESPONDER_CONFIG_LOG = os.path.join(LOG_DIR, 'Config-Responder.log')
RESPONDER_HTML = os.path.join(RESPONDER_DIR, 'files/AccessDenied.html')
RESPONDER_EXE = os.path.join(RESPONDER_DIR, 'files/BindShell.exe')
RESPONDER_CERT = os.path.join(RESPONDER_DIR, 'certs/responder.crt')
RESPONDER_KEY = os.path.join(RESPONDER_DIR, 'certs/responder.key')

# asleap paths
ASLEAP_BIN = os.path.join(ASLEAP_DIR, 'asleap')

# hcxdumptool paths
HCXDUMPTOOL_BIN = os.path.join(HCXDUMPTOOL_DIR, 'hcxdumptool')
output_file = OutputFile(name='hcxdumptool-output', ext='txt').string()
HCXDUMPTOOL_OFILE = os.path.join(TMP_DIR, output_file)
output_file = OutputFile(name='hcxdumptool-filter', ext='txt').string()
HCXDUMPTOOL_FILTER = os.path.join(TMP_DIR, output_file)

# wpa handshake cpature file paths
#options['psk_capture_file']
output_file = OutputFile(name='wpa_handshake_capture', ext='hccapx').string()
PSK_CAPTURE_FILE = os.path.join(LOOT_DIR, output_file)

# openssl paths
OPENSSL_BIN = os.path.join(LOCAL_DIR, 'openssl/local/bin/openssl')

# hcxtools paths
HCXPCAPTOOL_BIN = os.path.join(HCXTOOLS_DIR, 'hcxpcaptool')
output_file = OutputFile(name='hcxpcaptool-output', ext='txt').string()
HCXPCAPTOOL_OFILE = os.path.join(TMP_DIR, output_file)

# hostapd paths
HOSTAPD_BIN = os.path.join(HOSTAPD_DIR, 'hostapd-eaphammer')
HOSTAPD_LIB = os.path.join(HOSTAPD_DIR, 'libhostapd-eaphammer.so')
HOSTAPD_LOG = os.path.join(LOG_DIR, 'hostapd-eaphammer.log')
#output_file = 'hostapd-control-interface' # fuckit
output_file = OutputFile(name='ctrl-iface', length=8).string()
HOSTAPD_CTRL_INTERFACE = os.path.join(RUN_DIR, output_file)

# eap_spray paths
EAP_SPRAY_LOG = os.path.join(LOG_DIR, 'eap_spray.log')

output_file = OutputFile(name='hostapd', ext='conf').string()
HOSTAPD_CONF = os.path.join(TMP_DIR, output_file)
HOSTAPD_SAVE = os.path.join(SAVE_DIR, output_file)
FIFO_PATH = os.path.join(TMP_DIR, OutputFile(ext='fifo').string())

#EAP_USER_FILE = os.path.join(DB_DIR, 'eaphammer.eap_user')
output_file = OutputFile(ext='eap_user').string()
EAP_USER_FILE = os.path.join(TMP_DIR, output_file)
#EAP_USER_HEADER = os.path.join(DB_DIR, 'eap_user_header.txt')
EAP_USER_HEADER = os.path.join(DB_DIR, 'eap_user.header')
PHASE1_ACCOUNTS = os.path.join(DB_DIR, 'phase1.accounts')
PHASE2_ACCOUNTS = os.path.join(DB_DIR, 'phase2.accounts')

# known ssids file
output_file = OutputFile(ext='known_ssids').string()
KNOWN_SSIDS_FILE = os.path.join(TMP_DIR, output_file)

# ACL Files
output_file = OutputFile(ext='accept').string()
HOSTAPD_MAC_WHITELIST = os.path.join(TMP_DIR, output_file)
output_file = OutputFile(ext='deny').string()
HOSTAPD_MAC_BLACKLIST = os.path.join(TMP_DIR, output_file)

output_file = OutputFile(ext='accept').string()
HOSTAPD_SSID_WHITELIST = os.path.join(TMP_DIR, output_file)
output_file = OutputFile(ext='deny').string()
HOSTAPD_SSID_BLACKLIST = os.path.join(TMP_DIR, output_file)

# cert paths
CA_CERTS_DIR = os.path.join(CERTS_DIR, 'ca')
SERVER_CERTS_DIR = os.path.join(CERTS_DIR, 'server')
ACTIVE_CERTS_DIR = os.path.join(CERTS_DIR, 'active')
ACTIVE_FULL_CHAIN = os.path.join(ACTIVE_CERTS_DIR, 'fullchain.pem')

DH_FILE = os.path.join(CERTS_DIR, 'dh')

# everything else
DNSMASQ_LOG = os.path.join(LOG_DIR, 'dnsmasq.log')

DNSMASQ_CONF = os.path.join(TMP_DIR, OutputFile(name='dnsmasq', ext='conf').string())
RESPONDER_CONF = os.path.join(RESPONDER_DIR, 'Responder.conf')

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
        'local' : LOCAL_DIR,
        'hostapd' : HOSTAPD_DIR,
        'asleap' : ASLEAP_DIR,
        'certs' : CERTS_DIR,
        'saves' : SAVE_DIR,
        'hcxdumptool' : HCXDUMPTOOL_DIR,
        'hcxtools' : HCXTOOLS_DIR,
        'loot' : LOOT_DIR,
        'responder' : RESPONDER_DIR,
    },

    'hcxtools' : {

        'hcxpcaptool' : {

            'bin' : HCXPCAPTOOL_BIN,
            'ofile' : HCXPCAPTOOL_OFILE,
        },
    },
    'psk' : {
        'psk_capture_file' : PSK_CAPTURE_FILE ,
    },

    'hcxdumptool' : {

        'bin' : HCXDUMPTOOL_BIN,
        'ofile' : HCXDUMPTOOL_OFILE,
        'filter' : HCXDUMPTOOL_FILTER,
    },

    'asleap' : {

        'bin' : ASLEAP_BIN,
    },

    'eap_spray' : {

        'log' : EAP_SPRAY_LOG,
    },

    'hostapd' : {

        'bin' : HOSTAPD_BIN,
        'lib' : HOSTAPD_LIB,
        'log' : HOSTAPD_LOG,
        'eap_user'  : EAP_USER_FILE,
        'eap_user_header'  : EAP_USER_HEADER,
        'phase1_accounts' : PHASE1_ACCOUNTS,
        'phase2_accounts' : PHASE2_ACCOUNTS,
        'fifo' : FIFO_PATH,
        'ctrl_interface' : HOSTAPD_CTRL_INTERFACE,
        'conf' : HOSTAPD_CONF,
        'save' : HOSTAPD_SAVE,
        'mac_whitelist' : HOSTAPD_MAC_WHITELIST,
        'mac_blacklist' : HOSTAPD_MAC_BLACKLIST,
        'ssid_whitelist' : HOSTAPD_SSID_WHITELIST,
        'ssid_blacklist' : HOSTAPD_SSID_BLACKLIST,
        'known_ssids' : KNOWN_SSIDS_FILE,
    },

    'certs' : {

        'dh' : DH_FILE,
        'server_certs_dir' : SERVER_CERTS_DIR,
        'ca_certs_dir' : CA_CERTS_DIR,
        'active_certs_dir' : ACTIVE_CERTS_DIR,
        'active_full_chain' : ACTIVE_FULL_CHAIN,

    },

    'openssl' : {

        'bin' : OPENSSL_BIN,
    },

    'dnsmasq' : {

        'log' : DNSMASQ_LOG,
        'conf' : DNSMASQ_CONF,
    },
    'responder' : {

        'conf' : RESPONDER_CONF,
        'bin' : RESPONDER_BIN,
        'db' : RESPONDER_DB,
        'session_log' : RESPONDER_SESSION_LOG,
        'poisoners_log' : RESPONDER_POISONERS_LOG,
        'analyzer_log' : RESPONDER_ANALYZER_LOG,
        'config_log' : RESPONDER_CONFIG_LOG,
        'html' : RESPONDER_HTML,
        'exe' : RESPONDER_EXE,
        'cert' : RESPONDER_CERT,
        'key' : RESPONDER_KEY,
    },
    'dhcp' : {

        'script' : DHCP_SCRIPT,
    },
    'wskeyloggerd' : {
        'templates' : WSKEYLOGGER_TEMPLATES,
        'par_templates' : WSKEYLOGGER_PAR_TEMPL,
        'usr_templates' : WSKEYLOGGER_USR_TEMPL,
        'usr_templates_sl' : WSKEYLOGGER_USR_SL,
        'static' : WSKEYLOGGER_STATIC,
        'static_sl' : WSKEYLOGGER_STATIC_SL,
        'payloads' : WSKEYLOGGER_PAYLOADS,
    },
}

