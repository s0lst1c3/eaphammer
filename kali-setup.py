import os
import config

def read_deps_file(deps_file):
    with open(deps_file) as fd:
        return ' '.join([ line.strip() for line in fd ])

if __name__ == '__main__':

    print '[*] Installing Kali dependencies...'
    os.system('apt-get install %s' % read_deps_file('kali-dependencies.txt'))
    print '[*] complete!'

    print '[*] Installing Python dependencies...'
    os.system('pip install -r pip.req')
    print '[*] complete!'

    print '[*] Compiling hostapd...'
    os.system("cd %s && make" % config.hostapd_dir)
    print '[*] complete!'
