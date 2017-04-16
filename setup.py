''' Commands borrowed from the original easy hostapd-wpe build script:
http://blog.gojhonny.com/2015/08/pwning-wpa-enterprise-with-hostapd-on.html
'''

import os
import config

print '[*] Downloading hostapd-%s...' % config.hostapd_version
os.system('wget https://w1.fi/releases/hostapd-%s.tar.gz' % config.hostapd_version)
print '[*] complete!'

print '[*] Extracting hostapd from tar archive...'
os.system('tar xzf hostapd-%s.tar.gz' % config.hostapd_version)
print '[*] complete!'

print '[*] Removing tar archive...'
os.system('rm -f hostapd-%s.tar.gz' % config.hostapd_version)
print '[*] complete!'

print '[*] Patching hostapd...'
os.system('cd %s && pwd && patch -p1 < .%s' % (config.hostapd_submodule_dir, config.hostapd_wpe_patch))
print '[*] complete!'

print '[*] Modifying build config...'
os.system("sed -i 's/#CONFIG_LIBNL32=y/CONFIG_LIBNL32=y/g' %s/.config" % (config.hostapd_dir))
print '[*] complete!'

print '[*] Compiling hostapd...'
os.system("cd %s && make" % config.hostapd_dir)
print '[*] complete!'

print "[*] Setup complete"
