hostapd_version = '2.2'
hostapd_submodule_dir = './hostapd-'+hostapd_version
hostapd_dir = hostapd_submodule_dir + '/hostapd'

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

hostapd_cnf = hostapd_dir + '/hostapd-wpe.conf'
