#!/usr/bin/env python3

# Abandon all hope ye who enter here.

import sys
import json

from argparse import ArgumentParser
from settings import settings

def _parse_eap_user_line(line):

    line = line.strip()
    
    # skip lines that have been commented out
    if line.startswith('#'):
        return None
    
    # skip blank lines
    if line.split() == []:
        return None
    
    # if the username is a wildcard, we handle this separately. this has
    # to go at the top of the file for the WPE functionality to work as
    # intended. it's easier if we just rewrite this manually
    if line[0] == '*':
        return None
    
    # locate quotes within line
    quotes = []
    for index,l in enumerate(line):
        if l == '"':
            quotes.append(index)
    
    # odd number of quotes means unmatched quotes in line
    if len(quotes) % 2 != 0:
        print('[!] Unmatched quote found on line %d. Skipping.' % line_number)
        return None
    
    quotes_len = len(quotes)
    
    # if 4 quotes, then quotes are being used around the
    # eap identity and the password
    if quotes_len == 4:
    
        # if it's a phase 1 user, the last character of the
        # line will be a double quote
        if line[-1] == '"':
            identity_start = quotes[0]+1
            identity_end = quotes[1]
            password_start = quotes[2]+1
            password_end = quotes[3]
            identity = line[identity_start: identity_end]
            methods = line[identity_end+1: password_start-1].strip()
            password = line[password_start: password_end]
            password = line[password_start: password_end]
            nt_hash = None
            phase = 1
    
        # if it's not a phase 1 user, it's a phase 2 user
        else:
            identity_start = quotes[0]+1
            identity_end = quotes[1]
            password_start = quotes[2]+1
            password_end = quotes[3]
            identity = line[identity_start: identity_end]
            methods = line[identity_end+1: password_start-1].strip()
            password = line[password_start: password_end]
            nt_hash = None
            phase = 2 
    
    # elif 2 quotes, the quotes are being used to surround
    # the identity but not the nt password hash
    elif quotes_len == 2:
    
        # the only way a line will ever end with ] is if it's a phase 2 user
        if line[-1] == ']':
    
            line = line.replace('[2]', '')
            identity_start = quotes[0]+1
            identity_end = quotes[1]
            identity = line[identity_start: identity_end]
            remaining = line[identity_end+1:].split()
            # phase 1 user with identity,methods,nt hash
            if len(remaining) == 2:
                methods = remaining[0].strip()
                nt_hash = remaining[1].strip()
                password = None
            # phase 1 user with identity,methods
            else:
                methods = remaining[0].strip()
                password = None
                nt_hash = None
            phase = 2
    
        else:
    
            identity_start = quotes[0]+1
            identity_end = quotes[1]
            identity = line[identity_start: identity_end]
            remaining = line[identity_end+1:].split()
            # phase 1 user with identity,methods,nt hash
            if len(remaining) == 2:
                methods = remaining[0].strip()
                nt_hash = remaining[1].strip()
                password = None
            # phase 1 user with identity,methods
            else:
                methods = remaining[0].strip()
                password = None
                nt_hash = None
            phase = 1
    
    # hostapd's syntax rules dictate that at least 
    # the identity should be  surrounded by quotes. 
    # therefore this should never happen since we've
    # already skipped comments, wildcards, and blank lines.
    else:
    
        # this should never happen
        sys.exit('[!] 2. Invalid eap_user file.')
    
    eap_user = {
    
        'identity' : identity,
        'methods' : methods,
        'password' : password,
        'nt_hash' : nt_hash,
        'phase' : phase,
    }

    return eap_user


def parse_eap_user_file():

    master_set = set([])

    phase1_users = []
    phase2_users = []
    with open(settings.dict['paths']['hostapd']['phase1_accounts']) as phase1_handle:
        for line_number,line in enumerate(phase1_handle):

            eap_user = _parse_eap_user_line(line)

            if eap_user is None:
                continue
                
            if eap_user['identity'] in master_set:
                print('[!] Duplicate entry detected... pruning from eap_user file.')
            else:
                master_set.add(eap_user['identity'])

                # don't trust that the user account is in the correct file
                if eap_user['phase'] == 1:
                    phase1_users.append(eap_user)
                else:
                    phase2_users.append(eap_user)

    with open(settings.dict['paths']['hostapd']['phase2_accounts']) as phase2_handle:

        for line_number,line in enumerate(phase2_handle):

            eap_user = _parse_eap_user_line(line)

            if eap_user is None:
                continue
                
            if eap_user['identity'] in master_set:
                print('[!] Duplicate entry detected... pruning from eap_user file.')
            else:
                master_set.add(eap_user['identity'])

                # don't trust that the user account is in the correct file
                if eap_user['phase'] == 1:
                    phase1_users.append(eap_user)
                else:
                    phase2_users.append(eap_user)

    return {
    
        'phase1' : phase1_users,
        'phase2' : phase2_users,
        'master_set' : master_set,
    }

def filter_users(users,
            filtered=True,
            phase=None,
            identity_is=None,
            in_identity=None,
            methods_any=None,
            methods_all=None,
            has_password=False,
            has_nt_hash=False,
            invert=False):

    matching_users = { 'phase1' : [], 'phase2' : [], 'master_set' : set([]) }
    if not filtered or (phase is None) or phase == 1: 

        for user in users['phase1']:

            identity_is_match = not filtered or (identity_is is None) or identity_is == user['identity']
            in_identity_match = not filtered or (in_identity is None) or in_identity in user['identity']
            method_match = not filtered or do_methods_match(user, methods_any, methods_all)
            has_password_match = not filtered or (has_password == False) or (user['password'] is not None)
            has_nt_hash_match = not filtered or (has_nt_hash == False) or (user['nt_hash'] is not None)

            full_match = identity_is_match and in_identity_match and method_match and has_password_match and has_nt_hash_match

            if full_match and invert:
                continue
            elif full_match and (not invert):
                matching_users['phase1'].append(user)
                matching_users['master_set'].add(user['identity'])
            elif (not full_match) and invert:
                matching_users['phase1'].append(user)
                matching_users['master_set'].add(user['identity'])
            elif (not full_match) and (not invert):
                continue

    if not filtered or (phase is None) or phase == 2: 

        for user in users['phase2']:

            identity_is_match = not filtered or (identity_is is None) or identity_is == user['identity']
            in_identity_match = not filtered or (in_identity is None) or in_identity in user['identity']
            method_match = not filtered or do_methods_match(user, methods_any, methods_all)
            has_password_match = not filtered or (has_password == False) or (user['password'] is not None)
            has_nt_hash_match = not filtered or (has_nt_hash == False) or (user['nt_hash'] is not None)

            full_match = identity_is_match and in_identity_match and method_match and has_password_match and has_nt_hash_match

            if full_match and invert:
                continue
            elif full_match and (not invert):
                matching_users['phase2'].append(user)
                matching_users['master_set'].add(user['identity'])
            elif (not full_match) and invert:
                matching_users['phase2'].append(user)
                matching_users['master_set'].add(user['identity'])
            elif (not full_match) and (not invert):
                continue

    return matching_users

def do_methods_match(user, methods_any, methods_all):

    user_methods = set(user['methods'].split(','))
    if methods_any is None:
        matches_any = True
    else:
        methods_any = set(methods_any.split(','))
        intersection = user_methods.intersection(methods_any)
        if len(intersection) > 0:
            matches_any = True
        else:
            matches_any = False

    if methods_all is None:
        matches_all = True
    else:

        methods_all = set(methods_all.split(','))
        if methods_all.issubset(user_methods):
            matches_all = True
        else:
            matches_all = False
    return matches_any and matches_all

def create_user_string(user):

    user_string = [
        '"%s"' % user['identity'],
        user['methods'],
    ]

    if user['password'] is not None:
        user_string.append('"%s"' % user['password'])
    elif user['nt_hash'] is not None:
        user_string.append(user['nt_hash'])

    if user['phase'] == 2:
        user_string.append('[2]')

    return '\t'.join(user_string)

def list_users(users,
            filtered=True,
            phase=None,
            identity_is=None,
            in_identity=None,
            methods_any=None,
            methods_all=None,
            has_password=False,
            has_nt_hash=False,
            invert=False):

    filtered_users = filter_users(
        users,
        filtered=filtered,
        phase=phase,
        identity_is=identity_is,
        in_identity=in_identity,
        methods_any=methods_any,
        methods_all=methods_all,
        has_password=has_password,
        has_nt_hash=has_nt_hash,
        invert=invert
    )

    print('Phase 1 users')
    for user in filtered_users['phase1']:
        print(create_user_string(user))
    print()

    print('Phase 2 users')
    for user in filtered_users['phase2']:
        print(create_user_string(user))
    print()


def delete_users(users,
                filtered=True,
                phase=None,
                identity_is=None,
                in_identity=None,
                methods_any=None,
                methods_all=None,
                has_password=False,
                has_nt_hash=False,
                invert=False):

    return filter_users(
        users,
        filtered=filtered,
        phase=phase,
        identity_is=identity_is,
        in_identity=in_identity,
        methods_any=methods_any,
        methods_all=methods_all,
        has_password=has_password,
        has_nt_hash=has_nt_hash,
        invert=(not invert),
    )


def add_user(users, identity, methods, phase, password=None, nt_hash=None):

    eap_user = {
    
        'identity' : identity,
        'methods' : methods,
        'password' : password,
        'nt_hash' : nt_hash,
        'phase' : phase,
    }

    if identity == 't':
        print('[*] Updating existing entry.')
        return users
    
    if identity in users['master_set']:

        print('[*] Updating existing entry.')
        old_phase = 0

        # get old phase and index
        for index, user in enumerate(users['phase1']):
            if identity == user['identity']:
                old_phase = 1
                old_phase_key = 'phase1'
                new_phase_key = 'phase2'
                break
        if old_phase == 0:
            for index, user in enumerate(users['phase2']):
                if identity == user['identity']:
                    old_phase = 2
                    old_phase_key = 'phase2'
                    new_phase_key = 'phase1'
                    break

        if users[old_phase_key][index]['identity'] != identity:
            users[old_phase_key][index]['identity'] = identity

        if users[old_phase_key][index]['methods'] != methods:
            users[old_phase_key][index]['methods'] = methods

        if users[old_phase_key][index]['password'] != password:
            users[old_phase_key][index]['password'] = password

        if users[old_phase_key][index]['nt_hash'] != nt_hash:
            users[old_phase_key][index]['nt_hash'] = nt_hash

        if old_phase != phase:
            new_user = users[old_phase_key].pop(index)
            new_user['phase'] = phase
            users[new_phase_key].append(new_user)

        return users

    if phase == 1:

        users['phase1'].append(eap_user)
        users['master_set'].add(identity)

    else:

        users['phase2'].append(eap_user)
        users['master_set'].add(identity)

    return users

def write_users(users):

    with open(settings.dict['paths']['hostapd']['phase1_accounts'], 'w') as output_handle:

        output_handle.write('\n\n# Phase 1 users\n')
        for user in users['phase1']:
            output_handle.write('%s\n' % create_user_string(user))

    with open(settings.dict['paths']['hostapd']['phase2_accounts'], 'w') as output_handle:

        output_handle.write('\n\n# Phase 2 users\n')
        for user in users['phase2']:
    
            user_string = create_user_string(user)
            output_handle.write('%s\n' % user_string)

def set_options():

    parser = ArgumentParser()

    # delete
        # filter
    
    add_user_group = parser.add_argument_group(
                'add_user',
                'Options for adding a user to eaphammer_db',
    )
    add_user_group.add_argument(
            '--identity',
            dest='identity',
            type=str,
            help='The username for the user you wish to add.',
    )
    add_user_group.add_argument(
            '--methods',
            dest='methods',
            default=None,
            required=False,
            type=str,
            help='Leave this as the default unless you really know what you are doing. '
                 'A comma seperated list of the authentication methods that should be used '
                 'when the user attempts to connect. EAPHammer will attempt to use each of '
                 'these methods one by one until the victim accepts one.',
    )
    add_user_group.add_argument(
            '--phase',
            dest='phase',
            default=2,
            required=False,
            choices=[1, 2],
            type=int,
            help='You should probably leave this as the default.',
    )
    add_user_group.add_argument(
            '--password',
            dest='password',
            required=False,
            type=str,
            help='Specify the user\'s password. You should probably specify a password for '
                 'your user unless you are specifying an nt password hash.',
    )
    add_user_group.add_argument(
            '--nt-hash',
            dest='nt_hash',
            required=False,
            type=str,
            help='Specify the nt hash of the user\'s password. You should probably specify '
                 'the nt hash for your user unless you are specifying a password instead.',
    )

    filter_group = parser.add_argument_group(
            'filters',
            'Filter options for --list and --delete',
    )
    


    filter_group.add_argument(
            '--by-phase',
            dest='by_phase',
            type=int,
            choices=[1,2],
            help='Filter by phase.',
    )
    filter_group.add_argument(
            '--identity-is',
            dest='identity_is',
            type=str,
            help='Filter by identity (exact match)',
    )
    filter_group.add_argument(
            '--in-identity',
            dest='in_identity',
            type=str,
            help='Filter for any identities containing a specified keyword',
    )
    filter_group.add_argument(
            '--methods-any',
            dest='methods_any',
            type=str,
            help='Filter for users that can authenticate using any of the '
                 'provided methods (comma separated list).',
    )
    filter_group.add_argument(
            '--methods-all',
            dest='methods_all',
            type=str,
            help='Filter for users that can authenticate using all of the '
                 'provided methods (comma separated list).',
    )
    filter_group.add_argument(
            '--has-password',
            dest='has_password',
            action='store_true',
            help='Filter for users that have a password in the database.',
    )
    filter_group.add_argument(
            '--has-nt-hash',
            dest='has_nt_hash',
            action='store_true',
            help='Filter for users that have a nt hash in the database.',
    )
    filter_group.add_argument(
            '--invert',
            dest='invert',
            action='store_true',
            help='Invert the results of the search.',
    )

    filter_group = parser.add_argument_group(
            'delete',
            'Options for --delete.',
    )
    filter_group.add_argument(
            '--delete-all',
            dest='delete_all',
            action='store_true',
            help='Delete everything in the database. Only works when '
                 'combined with --delete.',
    )

    modes_group = parser.add_mutually_exclusive_group()

    modes_group.add_argument(
            '--add',
            dest='add_user',
            action='store_true',
            help='Add a user to the database.',
    )
    modes_group.add_argument(
            '--delete',
            dest='delete_user',
            action='store_true',
            help='Delete a user from the database.',
    )
    modes_group.add_argument(
            '--list',
            dest='list_users',
            action='store_true',
            help='List user from the database.',
    )
    
    args = parser.parse_args()

    filtered = any([
        args.by_phase is not None,
        args.identity_is is not None,
        args.in_identity is not None,
        args.methods_any is not None,
        args.methods_all is not None,
        args.has_password == True,
        args.has_nt_hash == True,
        args.invert == True,
    ])
    args = args.__dict__
    args['filtered'] = filtered

    if args['methods'] is None:
        
        if args['phase'] == 1:
            args['methods'] = 'PEAP,TTLS,TLS,FAST'
        elif args['phase'] == 2:
            args['methods'] = 'MSCHAPV2,TTLS-MSCHAPV2,TTLS,TTLS-CHAP,GTC,TTLS-PAP,TTLS-MSCHAP,MD5'
        else:
            raise Exception('error: wtf is this')

    if args['add_user']:
        if args['identity'] is None:
            print('[!] Please specify an identity using the --identity flag.')
            sys.exit()
    elif args['delete_user']:
        if args['filtered'] == False and args['delete_all'] == False:

            print('[!] Cowardly refusing to delete everything in the '\
                  'database without additional confirmation')
            print('[!] If this is really what you want to do, please use the following syntax:')
            print('[!] root@localhost:~# ./ehdb --delete --delete-all')
            sys.exit()
    elif args['list_users']:
        pass
    else:
        parser.print_help()
        sys.exit()
    return args
    
if __name__ == '__main__':

    options = set_options()

    users = parse_eap_user_file()
    if options['add_user']:

        users = add_user(
            users,
            options['identity'],
            options['methods'],
            options['phase'],
            password=options['password'],
            nt_hash=options['nt_hash'],
        )

    elif options['list_users']:

        list_users(
            users,
            filtered=options['filtered'], 
            phase=options['by_phase'],
            identity_is=options['identity_is'],
            in_identity=options['in_identity'],
            methods_any=options['methods_any'],
            methods_all=options['methods_all'],
            has_password=options['has_password'],
            has_nt_hash=options['has_nt_hash'],
            invert=options['invert'],
        )

    elif options['delete_user']:

        users = delete_users(
            users,
            filtered=options['filtered'], 
            phase=options['by_phase'],
            identity_is=options['identity_is'],
            in_identity=options['in_identity'],
            methods_any=options['methods_any'],
            methods_all=options['methods_all'],
            has_password=options['has_password'],
            has_nt_hash=options['has_nt_hash'],
            invert=options['invert'],
        )

    write_users(users)
