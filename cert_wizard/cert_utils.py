import glob
import os
import pem
import random
import shutil

from OpenSSL import crypto, SSL
from settings.settings import settings

DEFAULT_EXP = 94608000
DEFAULT_EXP_CA_CERT = 6307200
DEFAULT_ALGORITHM = 'sha256'
DEFAULT_KEY_LEN = 2048

CA_CERTS_DIR = settings.dict['paths']['certs']['ca_certs_dir']
SERVER_CERTS_DIR = settings.dict['paths']['certs']['server_certs_dir']
ACTIVE_FULL_CHAIN_PATH = settings.dict['paths']['certs']['active_full_chain']

def activate_fullchain(full_chain_path):
    shutil.copyfile(full_chain_path, ACTIVE_FULL_CHAIN_PATH)

def _list_certs_printer(key, subject_val, issuer_val):
    msg = '\t{0:<12} -> {1:<36}{0:<12} -> {2}'
    print(msg.format(str(key), str(subject_val), str(issuer_val)))

def _list_certs_helper(cert_dir):
    for cert_path in glob.glob('{}/*.pem'.format(cert_dir)):
        cert = load_cert_from_pem(cert_path)
        issuer = cert.get_issuer()
        subject = cert.get_subject()


        print(cert_path+'\n')

        print('\tSubject:'+' '*44+'Issuer:')
        _list_certs_printer('CN', subject.CN, issuer.CN)
        _list_certs_printer('C', subject.C, issuer.C)
        _list_certs_printer('ST', subject.ST, issuer.ST)
        _list_certs_printer('L', subject.L, issuer.L)
        _list_certs_printer('OU', subject.OU, issuer.OU)
        _list_certs_printer(
                'emailAddress',
                subject.emailAddress,
                issuer.emailAddress,
        )
        print('\n')

def list_certs(server=False, ca=False):

    # display everything by default unless we are filtering
    if not server and not ca:
        server = ca = True

    if server:
        _list_certs_helper(SERVER_CERTS_DIR)
    if ca:
        _list_certs_helper(CA_CERTS_DIR)

def create_key_pair(key_length):
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, key_length)
    return key_pair

def load_certs_from_file(pem_path):
    
    for raw_pem in pem.parse_file(pem_path):
        if type(raw_pem) == pem._core.Certificate:
            yield crypto.load_certificate(crypto.FILETYPE_PEM, str(raw_pem))
        elif type(raw_pem) == pem._core.PrivateKey:
            continue
        elif type(raw_pem) == pem._core.RSAPrivateKey:
            continue
        else:
            raise Exception("Invalid PEM file")

def load_pems_from_file(pem_path, passwd=None):

    if passwd is not None:
        passwd = passwd.encode('ascii')
    
    for raw_pem in pem.parse_file(pem_path):
        if type(raw_pem) == pem._core.Certificate:
            yield crypto.load_certificate(crypto.FILETYPE_PEM, str(raw_pem))
        elif type(raw_pem) == pem._core.PrivateKey:
            yield crypto.load_privatekey(
                    crypto.FILETYPE_PEM,
                    str(raw_pem),
                    passphrase=passwd,
            )
        elif type(raw_pem) == pem._core.RSAPrivateKey:
            yield crypto.load_privatekey(
                    crypto.FILETYPE_PEM,
                    str(raw_pem),
                    passphrase=passwd,
            )
        else:
            raise Exception("Invalid PEM file")

def count_pems_in_file(pem_path):
    for index, raw_pem in enumerate(pem.parse_file(pem_path)):
        pass
    return index+1

def count_certs_in_file(pem_path):
    counter = 0
    for raw_pem in pem.parse_file(pem_path):
        if type(raw_pem) == pem._core.Certificate:
            counter += 1
    return counter

def count_keys_in_file(pem_path):
    counter = 0
    for raw_pem in pem.parse_file(pem_path):
        if type(raw_pem) == pem._core.PrivateKey:
            counter += 1
        elif type(raw_pem) == pem._core.RSAPrivateKey:
            counter += 1
    return counter

def load_from_pem_helper(pem_path):
    with open(pem_path) as fd:
        return fd.read()

def load_private_key_from_pem(private_key_pem_path, passwd=None):

    if passwd is not None:
        passwd = passwd.encode('ascii')

    private_key_pem = load_from_pem_helper(private_key_pem_path)
    return crypto.load_privatekey(
                    crypto.FILETYPE_PEM,
                    private_key_pem,
                    passphrase=passwd,
    )

def load_cert_from_pem(cert_pem_path):
    cert_pem = load_from_pem_helper(cert_pem_path)
    return crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

def generate_pem_output_path(cn, output_dir):

    output_file = '{}.pem'.format(cn)
    output_path = os.path.join(output_dir, output_file)

    counter = 1
    while os.path.exists(output_path):
        output_file = '{}-{}.pem'.format(cn, counter)
        output_path = os.path.join(output_dir, output_file)
        counter += 1

    return output_path

def write_server_cert_pem(server_cert, ca_cert=None, server_key_pair=None):

    output_path = generate_pem_output_path(
                        ca_cert.get_subject().CN,
                        SERVER_CERTS_DIR,
    )

    if ca_cert is not None:
        ca_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
    if server_key_pair is not None:
        private_key_pem = crypto.dump_privatekey(
                                        crypto.FILETYPE_PEM,
                                        server_key_pair,
        )
    server_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert)

    msg = '[CW] New server cert and private key written to: {}'
    print(msg.format(output_path))

    with open(output_path, 'w') as fd:
        if ca_cert is not None:
            fd.write(ca_cert_pem.decode('utf-8'))
        fd.write(server_cert_pem.decode('utf-8'))
        if server_key_pair is not None:
            fd.write(private_key_pem.decode('utf-8'))

    return output_path

def write_full_chain_pem(full_chain):

    #full_chain = [
    #    [ private_key, server_cert, ca_cert_1, ca_cert_2, ... , ca_cert_n ]

    output_path = generate_pem_output_path(
                                full_chain[1].get_subject().CN,
                                SERVER_CERTS_DIR,
    )

    with open(output_path, 'w') as fd:

        for member in full_chain:

            if type(member) == crypto.X509:
                member_pem = crypto.dump_certificate(
                                        crypto.FILETYPE_PEM,
                                        member,
                )
            elif type(member) == crypto.PKey:
                member_pem = crypto.dump_privatekey(
                                        crypto.FILETYPE_PEM,
                                        member,
                )
            else:
                msg = 'Invalid full chain member of type {}'
                raise Exception(msg.format(type(member)))

            fd.write(member_pem.decode('utf-8'))

    return output_path

def write_ca_cert_pem(ca_cert, key_pair):

    output_path = generate_pem_output_path(
                            ca_cert.get_subject().CN,
                            CA_CERTS_DIR,
    )

    msg = '[CW] New CA cert and private key written to: {}'
    print(msg.format(output_path))

    ca_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)

    with open(output_path, 'w') as fd:
        fd.write(private_key_pem.decode('utf-8'))
        fd.write(ca_cert_pem.decode('utf-8'))

    return output_path

def set_subject(cert,
                cn,
                country=None,
                state_province=None,
                city=None,
                organization=None,
                org_unit=None,
                email_address=None):

    if country is not None:
        cert.get_subject().C = country
    if state_province is not None:
        cert.get_subject().ST = state_province
    if city is not None:
        cert.get_subject().L = city
    if organization is not None:
        cert.get_subject().O = organization
    if org_unit is not None:
        cert.get_subject().OU = org_unit
    if email_address is not None:
        cert.get_subject().emailAddress = email_address
    cert.get_subject().CN = cn

    return cert

def create_ca_cert(cn,
                country=None,
                state_province=None,
                city=None,
                organization=None,
                org_unit=None,
                email_address=None,
                not_before=0,
                key_length=DEFAULT_KEY_LEN,
                not_after=DEFAULT_EXP,
                algorithm=DEFAULT_ALGORITHM):

    key_pair = create_key_pair(key_length)
    serial_number = random.getrandbits(64)
    
    server_cert = crypto.X509()

    server_cert.set_version(0x2)

    cert = set_subject(server_cert,
                       cn,
                       country,
                       state_province,
                       city,
                       organization,
                       org_unit,
                       email_address)

    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(not_before)
    cert.gmtime_adj_notAfter(not_after)

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, algorithm)

    return cert, key_pair

def create_csr(key_pair,
            cn,
            country=None,
            state_province=None,    
            city=None,
            organization=None,
            org_unit=None,
            email_address=None,
            not_before=0,
            not_after=DEFAULT_EXP,
            algorithm=DEFAULT_ALGORITHM):

    req = crypto.X509Req()
    req.set_pubkey(key_pair)

    req = set_subject(req,
                       cn,
                       country,
                       state_province,
                       city,
                       organization,
                       org_unit,
                       email_address)

    req.set_pubkey(key_pair)
    req.sign(key_pair, algorithm)

    return req

def create_server_cert(req,
                ca_cert,
                ca_key_pair,
                not_before=0,
                not_after=DEFAULT_EXP,
                algorithm=DEFAULT_ALGORITHM):

    cert = crypto.X509()

    cert.set_version(2)
    serial_number = random.getrandbits(64)
    cert.gmtime_adj_notBefore(not_before)
    cert.gmtime_adj_notAfter(not_after)

    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(ca_key_pair, algorithm)

    return cert


