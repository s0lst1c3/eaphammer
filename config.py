import os

__version__ = '0.0.9'

root_dir, conf_file = os.path.split(os.path.abspath(__file__))

conf_dir = root_dir + '/conf'
logdir = root_dir + '/logs'
script_dir = root_dir + '/scripts'
db_dir = root_dir + '/db'
wordlist_dir = root_dir + '/wordlists'
default_wordlist = wordlist_dir +  '/rockyou.txt'
wordlist_source = 'https://github.com/danielmiessler/SecLists/raw/master/Passwords/rockyou.txt.tar.gz'

fifo_path = db_dir + '/eaphammer_fifo.node'

payload_path = root_dir + '/payloads/base.ps1'

responder_db = db_dir + '/Responder.db'
responder_cnf = conf_dir + '/Responder.conf'

hostapd_submodule_dir = root_dir + '/hostapd-eaphammer'
hostapd_dir = hostapd_submodule_dir + '/hostapd'
eap_users_file = db_dir + '/hostapd-wpe.eap_user'
hostapd_bin = hostapd_dir + '/hostapd-wpe'
hostapd_cnf = conf_dir + '/hostapd-wpe.conf'
eap_user_file = db_dir + '/hostapd-wpe.eap_user'
eap_user_header = db_dir + '/eap_user_header.txt'
hostapd_log = logdir + '/hostapd-wpe.log'

certs_dir = root_dir + '/certs'
ca_cnf = certs_dir + '/ca.cnf'
server_cnf = certs_dir + '/server.cnf'
client_cnf = certs_dir + '/client.cnf'
bootstrap_file = certs_dir + '/bootstrap'

ca_pem = certs_dir + '/ca.pem'
server_pem = certs_dir + '/server.pem'
private_key = certs_dir + '/server.pem'
dh_file = certs_dir + '/dh'

# service configs ---------------------------------------
use_systemd = True
network_manager = 'network-manager'
dnsmasq = 'dnsmasq'
dnsmasq_bin = 'dnsmasq'
dnsmasq_cnf = conf_dir + '/dnsmasq.conf'
dnsmasq_log = logdir + '/dnsmasq.log'
dhcp_script = script_dir + '/dhcp_script.py'

dnsspoof = None
dnsspoof_bin = 'dnsspoof'
dnsspoof_cnf = conf_dir + '/dnsspoof.conf'

httpd = 'apache2'
httpd_bin = None
sleep_time = 3

wpa_supplicant = 'wpa_supplicant'
wpa_supplicant_bin = None

proc_ipforward = '/proc/sys/net/ipv4/ip_forward'

# don't touch these
wlan_clean_sleep = 1
hostapd_sleep = 4
network_manager_sleep = 4
dnsmasq_sleep = 2
dnsspoof_sleep = 2
wpa_supplicant_sleep = 4

# database stuff
wildcard = '*\tPEAP,TTLS,TLS,FAST'
hardcoded_fuckery = '"t"\tTTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2\t"t"\t[2]'
