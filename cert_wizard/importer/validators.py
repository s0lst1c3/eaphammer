from cert_wizard import cert_utils
import sys

def validation_error(message, abort=True):
        print('[CW] Error: {}'.format(message))
        if abort:
            print('[CW] Aborting.')
            sys.exit(1)

def combined_ca_and_server_separate_key(server_cert_path, private_key_path):

    # server cert should have at least one cert in it
    cert_count = cert_utils.count_certs_in_file(server_cert_path)
    if cert_count == 0:
        validation_error('no certs detected in server cert file')

    # server cert should not have any private keys in it
    key_count = cert_utils.count_keys_in_file(server_cert_path)
    if key_count > 0:
        validation_error(('server cert file should not contain '
                        'any private keys if a separate private '
                        'key file is provided'))

    # the private key file should have a single key in it and 
    # no certs of any kind
    key_count = cert_utils.count_keys_in_file(private_key_path)
    if key_count == 0:
        validation_error('no private keys found in private key file.')
    if key_count > 1:
        validation_error('multiple private keys found in private key file.')
    if cert_utils.count_certs_in_file(private_key_path) > 0:
        validation_error('certificates found in private key file.')


def combined_ca_and_server_integrated_key(server_cert_path):

    # the server cert should have exactly one private key in it
    key_count = cert_utils.count_keys_in_file(server_cert_path)
    if key_count == 0:
        validation_error(('no keys found in server cert file, '
                          'but no private key file specified'))
    if key_count > 1:
        validation_error('too many keys found in server cert file')

    # the server cert should have at least one cert in it
    cert_count = cert_utils.count_certs_in_file(server_cert_path)
    if cert_count == 0:
        validation_error('no certs detected in server cert file')

def separate_ca_and_server_integrated_key(server_cert_path, ca_cert_path):

    # server cert should contain a single private key
    key_count = cert_utils.count_keys_in_file(server_cert_path)
    if key_count == 0:
        validation_error(('no keys found in server cert file, '
                          'but no private key file specified'))
    if key_count > 1:
        validation_error('too many keys found in server cert file')
    
    # the server cert file should have a single cert in it if a separate
    # CA file was provided by the user
    cert_count = cert_utils.count_certs_in_file(server_cert_path)
    if cert_count > 1:
        validation_error(('certificate chain detected in server cert file, '
                          'yet separate CA cert file was provided'))
    if cert_count == 0:
        validation_error('no certs detected in server cert file')

    # the ca cert file should not have any private keys in it
    if cert_utils.count_keys_in_file(ca_cert_path) > 0:
        validation_error('private keys found in CA cert file.')

    # the ca cert file should have at least one certificate in it
    if cert_utils.count_certs_in_file(ca_cert_path) == 0:
        validation_error('no certs found in CA cert file.')

def all_separate(server_cert_path, private_key_path, ca_cert_path):

    print(server_cert_path)
    print(private_key_path)
    print(ca_cert_path)

    # there should be no extra private keys lingering
    # in the server cert file if a private key was provided by the user.
    if cert_utils.count_keys_in_file(server_cert_path) > 0:
        validation_error(('server cert file should not contain any private '
                          'keys if a separate private key file is provided'))

    # the server cert file should have a single PEM in it if a separate
    # CA file was provided by the user
    cert_count = cert_utils.count_certs_in_file(server_cert_path)
    if cert_count > 1:
        validation_error(('certificate chain detected in server cert file, '
                          'yet separate CA cert file was provided'))
    if cert_count == 0:
        validation_error('no certs detected in server cert file')

    # the private key file should have a single key in it and 
    # no certs of any kind
    key_count = cert_utils.count_keys_in_file(private_key_path)
    if key_count == 0:
        validation_error('no private keys found in private key file.')
    if key_count > 1:
        validation_error('multiple private keys found in private key file.')
    if cert_utils.count_certs_in_file(private_key_path) > 0:
        validation_error('certificates found in private key file.')

    # the ca cert file should not have any private keys in it
    if cert_utils.count_keys_in_file(ca_cert_path) > 0:
        validation_error('private keys found in CA cert file.')

    # the ca cert file should have at least one certificate in it
    if cert_utils.count_certs_in_file(ca_cert_path) == 0:
        validation_error('no certs found in CA cert file.')
