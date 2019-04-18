import cert_wizard.importer.validators as validators
from cert_wizard import cert_utils

def combined_ca_and_server_separate_key(server_cert_path,
                                        private_key_path,
                                        passwd=None):
    # case 6

    print('[CW] Checking to ensure private key and server cert are valid...')
    validators.combined_ca_and_server_separate_key(
                                        server_cert_path,
                                        private_key_path,
    )
    print('[CW] Complete!')

    print('[CW] Loading private key from {}'.format(private_key_path))
    private_key = cert_utils.load_private_key_from_pem(
                                        private_key_path,
                                        passwd=passwd,
    )
    print('[CW] Complete!')

    print('[CW] Loading full certificate chain from {}'.format(server_cert_path))
    full_chain_certs = cert_utils.load_certs_from_file(server_cert_path)
    full_chain = [ private_key ] + [ cert for cert in full_chain_certs ]
    print('[CW] Complete!')

    print('[CW] Writing private key and full certificate chain to file...')
    full_chain_path = cert_utils.write_full_chain_pem(full_chain)
    print('[CW] Complete!')
    print('[CW] Private key and full certificate chain written to: {}'.format(full_chain_path))

    return full_chain_path

def combined_ca_and_server_integrated_key(server_cert_path, passwd=None):
    # case 4 - key above
    # case 5 - key below

    print('[CW] Checking to ensure private key and server cert are valid...')
    validators.combined_ca_and_server_integrated_key(server_cert_path)
    print('[CW] Complete!')

    print('[CW] Loading private key from {}'.format(server_cert_path))
    private_key = cert_utils.load_private_key_from_pem(
                                        server_cert_path,
                                        passwd=passwd,
    )
    print('[CW] Complete!')

    print('[CW] Loading full certificate chain from {}'.format(server_cert_path))
    full_chain_certs = cert_utils.load_certs_from_file(server_cert_path)
    full_chain = [ private_key ] + [ cert for cert in full_chain_certs ]
    print('[CW] Complete!')

    print('[CW] Writing private key and full certificate chain to file...')
    full_chain_path = cert_utils.write_full_chain_pem(full_chain)
    print('[CW] Complete!')
    print('[CW] Private key and full certificate chain written to: {}'.format(full_chain_path))

    return full_chain_path

def separate_ca_and_server_integrated_key(server_cert_path,
                                          ca_cert_path,
                                          passwd=None):


    # case 2 - key above
    # case 3 - key below

    print('[CW] Checking to ensure server and CA cert are valid...')
    validators.separate_ca_and_server_integrated_key(
                                            server_cert_path,
                                            ca_cert_path,
    )
    print('[CW] Complete!')

    # extract server cert and private key from server cert
    print('[CW] Loading private key and server cert from {}'.format(server_cert_path))
    server_cert = cert_utils.load_cert_from_pem(server_cert_path)
    private_key = cert_utils.load_private_key_from_pem(
                                            server_cert_path,
                                            passwd=passwd,
    )
    print('[CW] Complete!')

    print('[CW] Loading CA certificate chain from {}'.format(ca_cert_path))
    ca_cert_chain = cert_utils.load_pems_from_file(ca_cert_path, passwd=passwd)
    print('[CW] Complete!')

    print('[CW] Constructing full certificate chain with integrated key...')
    full_chain = [private_key, server_cert] + [cert for cert in ca_cert_chain]
    print('[CW] Complete!')

    print('[CW] Writing private key and full certificate chain to file...')
    full_chain_path = cert_utils.write_full_chain_pem(full_chain)
    print('[CW] Complete!')
    print('[CW] Private key and full certificate chain written to: {}'.format(full_chain_path))

    return full_chain_path

def all_separate(server_cert_path,
                 private_key_path,
                 ca_cert_path,
                 passwd=None):

    print('Case 1: Import all separate')

    print('[CW] Ensuring server cert, CA cert, and private key are valid...')
    validators.all_separate(
                    server_cert_path,
                    private_key_path,
                    ca_cert_path,
    )
    print('[CW] Complete!')

    print('[CW] Loading private key from {}'.format(private_key_path))
    private_key = cert_utils.load_private_key_from_pem(
                                            private_key_path,
                                            passwd=passwd,
    )
    print('[CW] Complete!')

    print('[CW] Loading server cert from {}'.format(server_cert_path))
    server_cert = cert_utils.load_cert_from_pem(server_cert_path)
    print('[CW] Complete!')

    print('[CW] Loading CA certificate chain from {}'.format(ca_cert_path))
    ca_cert_chain = cert_utils.load_pems_from_file(ca_cert_path, passwd=passwd)
    print('[CW] Complete!')

    print('[CW] Constructing full certificate chain with integrated key...')
    full_chain = [private_key, server_cert] + [cert for cert in ca_cert_chain]
    print('[CW] Complete!')

    print('[CW] Writing private key and full certificate chain to file...')
    full_chain_path = cert_utils.write_full_chain_pem(full_chain)
    print('[CW] Complete!')
    print('[CW] Private key and full certificate chain written to: {}'.format(full_chain_path))

    return full_chain_path
