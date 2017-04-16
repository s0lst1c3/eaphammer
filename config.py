__version__ = '0.0.4'

conf_dir = './conf'
logdir = './logs'

hostapd_version = '2.2'
hostapd_submodule_dir = './hostapd-'+hostapd_version
hostapd_dir = hostapd_submodule_dir + '/hostapd'
hostapd_bin = hostapd_dir + '/hostapd-wpe'
#hostapd_cnf = hostapd_dir + '/hostapd-wpe.conf'
hostapd_cnf = conf_dir + '/hostapd-wpe.conf'
eap_user_file = hostapd_dir + '/hostapd-wpe.eap_user'
hostapd_log = logdir + '/hostapd-wpe.log'

hostapd_wpe_dir = './hostapd-wpe'
hostapd_wpe_patch = hostapd_wpe_dir + '/hostapd-wpe.patch'
certs_dir = hostapd_wpe_dir + '/certs'
ca_cnf = certs_dir + '/ca.cnf'
server_cnf = certs_dir + '/server.cnf'
client_cnf = certs_dir + '/client.cnf'
bootstrap_file = certs_dir + '/bootstrap'

ca_pem = certs_dir + '/ca.pem'
server_pem = certs_dir + '/server.pem'
private_key = certs_dir + '/server.pem'
dh_file = certs_dir + '/dh'

# service configs
use_systemd = True
network_manager = 'network-manager'
dnsmasq = 'dnsmasq'
dnsmasq_bin = 'dnsmasq'
dnsmasq_cnf = conf_dir + '/dnsmasq.conf'

dnsspoof = None
dnsspoof_bin = 'dnsspoof'
dnsspoof_cnf = conf_dir + '/dnsspoof.conf'

httpd = 'apache2'
httpd_bin = None
sleep_time = 3

proc_ipforward = '/proc/sys/net/ipv4/ip_forward'

# don't touch these
wlan_clean_sleep = 1
hostapd_sleep = 4
network_manager_sleep = 4
dnsmasq_sleep = 2
dnsspoof_sleep = 2


