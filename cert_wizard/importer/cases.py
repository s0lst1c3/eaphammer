import cert_wizard.importer.validators as validators
from cert_wizard import cert_utils

def combined_ca_and_server_separate_key(server_cert_path,
                                        private_key_path,
                                        passwd=None):
    # case 6

    validators.combined_ca_and_server_separate_key(
                                        server_cert_path,
                                        private_key_path,
    )

    private_key = cert_utils.load_private_key_from_pem(
                                        private_key_path,
                                        passwd=passwd,
    )
    full_chain_certs = cert_utils.load_certs_from_file(server_cert_path)

    full_chain = [ cert for cert in full_chain_certs ] + [ private_key ]

    full_chain_path = cert_utils.write_full_chain_pem(full_chain)

    return full_chain_path

def combined_ca_and_server_integrated_key(server_cert_path, passwd=None):
    # case 4 - key above
    # case 5 - key below

    validators.combined_ca_and_server_integrated_key(server_cert_path)

    private_key = cert_utils.load_private_key_from_pem(
                                        server_cert_path,
                                        passwd=passwd,
    )
    full_chain_certs = cert_utils.load_certs_from_file(server_cert_path)

    full_chain = [ cert for cert in full_chain_certs ] + [ private_key ]

    full_chain_path = cert_utils.write_full_chain_pem(full_chain)

    return full_chain_path

def separate_ca_and_server_integrated_key(server_cert_path,
                                          ca_cert_path,
                                          passwd=None):


    # case 2 - key above
    # case 3 - key below

    validators.separate_ca_and_server_integrated_key(
                                            server_cert_path,
                                            ca_cert_path,
    )

    # extract server cert and private key from server cert
    server_cert = cert_utils.load_cert_from_pem(server_cert_path)
    private_key = cert_utils.load_private_key_from_pem(
                                            server_cert_path,
                                            passwd=passwd,
    )

    ca_cert_chain = cert_utils.load_pems_from_file(ca_cert_path, passwd=passwd)

    full_chain = [cert for cert in ca_cert_chain] + [server_cert, private_key]

    full_chain_path = cert_utils.write_full_chain_pem(full_chain)

    return full_chain_path

def all_separate(server_cert_path,
                 private_key_path,
                 ca_cert_path,
                 passwd=None):

    print('Case 1: Import all separate')

    print('Calling validator')
    validators.all_separate(
                    server_cert_path,
                    private_key_path,
                    ca_cert_path,
    )

    private_key = cert_utils.load_private_key_from_pem(
                                            private_key_path,
                                            passwd=passwd,
    )
    server_cert = cert_utils.load_cert_from_pem(server_cert_path)
    ca_cert_chain = cert_utils.load_pems_from_file(ca_cert_path, passwd=passwd)

    full_chain = [cert for cert in ca_cert_chain] + [server_cert, private_key]

    full_chain_path = cert_utils.write_full_chain_pem(full_chain)

    return full_chain_path
