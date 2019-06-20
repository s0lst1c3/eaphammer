'''

Heavily inspired by Sensepost's crackapd. Go check them out, they did it first:

    github.com/sensepost/hostapd-mana

'''

import os
import errno
import time
import subprocess
import select
import json
import core.utils

from multiprocessing import Process
from settings import settings

remote_rig = False

ASLEAP_CMD = 'asleap -C %s -R %s -W %s | grep -v asleap | grep password'
EAP_USERS_ENTRY =  '"%s"\tTTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2\t"%s"\t[2]'

def crack_locally(username, challenge, response, wordlist):

    cmd = ASLEAP_CMD % (challenge, response, wordlist)
    output = subprocess.check_output(cmd, shell=True).decode('utf-8')
    try:
        password = output.split('password:')[1].strip()
        append2eap_users(username, password)
    except IndexError:
        print('\n\n[autocrack] {}\n'.format(output.strip()))


def append2eap_users(username, password):

    # create new entry for eap_users file
    line = EAP_USERS_ENTRY % (username, password)

    # append the entry to the file
    with open(settings.dict['paths']['hostapd']['eap_user'], 'a') as fd:
        fd.write('%s\n' % line)

def run_autocrack(wordlist):


    try:
        os.mkfifo(settings.dict['paths']['hostapd']['fifo'])
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # this is basically a primative event loop
    while True:

        print(settings.dict['paths']['hostapd']['fifo'])
        with open(settings.dict['paths']['hostapd']['fifo']) as fifo:

            print('[fifo reader] FIFO opened')
            while True:

                data = fifo.read()
                if len(data) == 0:
                    print('[fifo reader] writer closed')
                    break

                print('[fifo reader] received data from writer:', data)

                data = data.strip().split('|')
                username = data[0]
                challenge = data[1]
                response = data[2]

                if remote_rig:
                    pass
                else:

                    crack_locally(username,
                            challenge,
                            response,
                            wordlist)


class Autocrack(object):

    instance = None

    @staticmethod
    def get_instance():

        if Autocrack.instance is None:
            instance = Autocrack()
        return instance

    def configure(self, wordlist=None):

        assert wordlist is not None


        self.wordlist = wordlist
        self.fifo_path = settings.dict['paths']['hostapd']['fifo']

        print('[8] Using wordlist:', self.wordlist)

    @staticmethod
    def _start(args):

        run_autocrack(args['wordlist'])

    def start(self):

        args = {

            'wordlist' : self.wordlist,
        }
        self.proc = Process(target=self._start, args=(args,))
        self.proc.daemon = True
        self.proc.start()
        time.sleep(1)

    def stop(self):

        self.proc.terminate()
        self.proc.join()
