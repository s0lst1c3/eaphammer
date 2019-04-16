import cert_wizard.cert_utils as cert_utils
import os

from cert_wizard.importer import cases 

from settings import settings

# --cert-wizard import
def import_cert(server_cert_path,
                private_key_path=None,
                ca_cert_path=None,
                passwd=None):

    # case 1 - all separate 
    if private_key_path is not None and ca_cert_path is not None:

        server_pem_path = cases.all_separate(
                                        server_cert_path,
                                        private_key_path,
                                        ca_cert_path,
                                        passwd=passwd,
        )

    # case 2 - separate ca and server certs integrated key above
    # case 3 - separate ca and serer certs integrated key below
    if private_key_path is None and ca_cert_path is not None:

        server_pem_path = cases.separate_ca_and_server_integrated_key(
                                                        server_cert_path,
                                                        ca_cert_path,
                                                        passwd=passwd,
        )

    # case 4 - combined ca and server certs integrated key above
    # case 5 - combined ca and server certs integrated key below
    if private_key_path is None and ca_cert_path is None:
        server_pem_path = cases.combined_ca_and_server_integrated_key(
                                                            server_cert_path,
                                                            passwd=passwd,
        )
    
    # case 6 - combined ca and server certs separate key
    if private_key_path is not None and ca_cert_path is None:
        server_pem_path = cases.combined_ca_and_server_separate_key(
                                            server_cert_path,
                                            private_key_path,
                                            passwd=passwd,
        )

    print('[CW] Activating full certificate chain...')
    cert_utils.activate_fullchain(server_pem_path)
    print('[CW] Complete!')

    return server_pem_path

def list_certs(server=False, ca=False):
    cert_utils.list_certs(server=server, ca=ca)

# --bootstrap OR --gen-cert server --self-signed
def bootstrap(cn,
            country=None,
            state_province=None,
            city=None, 
            organization=None,
            org_unit=None,
            email_address=None,
            not_before=0,
            key_length=cert_utils.DEFAULT_KEY_LEN,
            not_after=cert_utils.DEFAULT_EXP,
            algorithm=cert_utils.DEFAULT_ALGORITHM):
    
    print('[CW] Creating CA cert and key pair...')
    ca_cert, ca_key_pair = cert_utils.create_ca_cert(
                            cn,
                            country=country,
                            state_province=state_province,
                            city=city,
                            organization=organization,
                            org_unit=org_unit,
                            email_address=email_address,
                            not_before=not_before,
                            not_after=not_after,
                            key_length=key_length,
                            algorithm=algorithm,
    )
    print('[CW] Complete!')

    print('[CW] Writing CA cert and key pair to disk...')
    cert_utils.write_ca_cert_pem(ca_cert, ca_key_pair)
    print('[CW] Complete!')

    print('[CW] Creating server private key...')
    server_key_pair = cert_utils.create_key_pair(key_length)
    print('[CW] Complete!')

    print('[CW] Using server private key to create CSR...')
    req = cert_utils.create_csr(
                    server_key_pair,
                    cn,
                    country=country,
                    state_province=state_province,
                    city=city,
                    organization=organization,
                    org_unit=org_unit,
                    email_address=email_address,
                    not_before=not_before,
                    not_after=not_after,
                    algorithm=algorithm,
    )
    print('[CW] Complete!')

    print('[CW] Creating server cert using CSR and signing it with CA key...')
    server_cert = cert_utils.create_server_cert(req,
                ca_cert,
                ca_key_pair,
                not_before=not_before,
                not_after=not_after,
                algorithm=algorithm)
    print('[CW] Complete!')

    print('[CW] Writing server cert and key pair to disk...')
    full_chain = [ server_key_pair, server_cert, ca_cert ]
    full_chain_path = cert_utils.write_full_chain_pem(full_chain)
    print('[CW] Complete!')

    print('[CW] Activating full certificate chain...')
    cert_utils.activate_fullchain(full_chain_path)
    print('[CW] Complete!')

    return full_chain_path

# --gen-cert server --signing-cert <path to ca_cert pem>
def create_server_cert(signing_cert_path,
            cn,
            signing_key_path=None,
            signing_key_passwd=None,
            country=None,
            state_province=None,
            city=None, 
            organization=None,
            org_unit=None,
            email_address=None,
            not_before=0,
            key_length=cert_utils.DEFAULT_KEY_LEN,
            not_after=cert_utils.DEFAULT_EXP,
            algorithm=cert_utils.DEFAULT_ALGORITHM):
    
    print('[CW] Loading CA cert and key from disk...')
    ca_cert = cert_utils.load_cert_from_pem(signing_cert_path)
    if signing_key_path is None:
        ca_key = cert_utils.load_private_key_from_pem(
                                            signing_cert_path,
                                            passwd=signing_key_passwd,
        )
    else:
        ca_key = cert_utils.load_private_key_from_pem(
                                            signing_key_path,
                                            passwd=signing_key_passwd,
        )
    print('[CW] Complete!')

    print('[CW] Creating server private key...')
    server_key_pair = cert_utils.create_key_pair(key_length)
    print('[CW] Complete!')

    print('[CW] Using server private key to create CSR...')
    req = cert_utils.create_csr(
                    server_key_pair,
                    cn,
                    country=country,
                    state_province=state_province,
                    city=city,
                    organization=organization,
                    org_unit=org_unit,
                    email_address=email_address,
                    not_before=not_before,
                    not_after=not_after,
                    algorithm=algorithm,
    )
    print('[CW] Complete!')

    print('[CW] Creating server cert using CSR and signing it with CA key...')
    server_cert = cert_utils.create_server_cert(req,
                ca_cert,
                ca_key,
                not_before=not_before,
                not_after=not_after,
                algorithm=algorithm)
    print('[CW] Complete!')

    print('[CW] Writing server cert and key pair to disk...')
    full_chain = [ server_key_pair, server_cert, ca_cert ]
    full_chain_path = cert_utils.write_full_chain_pem(full_chain)
    print('[CW] Complete!')

    print('[CW] Activating full certificate chain...')
    cert_utils.activate_fullchain(full_chain_path)
    print('[CW] Complete!')

    return full_chain_path

def interactive():

    while True:

        print('[*] Please enter two letter country '
                            'code for certs (i.e. US, FR)')

        country = input(': ').upper()
        if len(country) == 2:
            break
        print('[!] Invalid input.')

    print('[*] Please enter state or province for '
                        'certs (i.e. Ontario, New Jersey)')
    state_province = input(': ')

    print('[*] Please enter locale for certs (i.e. London, Hong Kong)')
    city = input(': ')

    print('[*] Please enter organization for certs (i.e. Evil Corp)')
    organization = input(': ')

    print('[*] Please enter org unit for certs (i.e. Hooman Resource Says)')
    org_unit = input(': ')

    print('[*] Please enter email for certs (i.e. cyberz@h4x0r.lulz)')
    email_address = input(': ')

    print('[*] Please enter common name (CN) for certs.')
    cn = input(': ')

    return bootstrap(
            cn,
            country=country,
            state_province=state_province,
            city=city, 
            organization=organization,
            org_unit=org_unit,
            email_address=email_address,
            not_before=0,
            key_length=cert_utils.DEFAULT_KEY_LEN,
            not_after=cert_utils.DEFAULT_EXP,
            algorithm=cert_utils.DEFAULT_ALGORITHM,
    )

def rebuild_dh_file(length):

    openssl_bin = settings.dict['paths']['openssl']['bin']
    dh_file = settings.dict['paths']['certs']['dh']

    length = length
    print('\n[*] Rebuilding DH parameters file with length of {}...\n'.format(length))
    os.system('{} dhparam -out {} {}'.format(openssl_bin, dh_file, length))
    print('\ncomplete!\n')

