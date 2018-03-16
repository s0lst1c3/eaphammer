#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import optparse
import ssl
import json
import os, time
import sys
import socket

from multiprocessing import Process
from SocketServer import TCPServer, UDPServer, ThreadingMixIn
from threading import Thread
from core.responder import utils
from core.responder import responder_settings


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		if utils.OsInterfaceIsSupported():
			print 'Bind to:',responder_settings.Config.Bind_To 
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, responder_settings.Config.Bind_To+'\0')
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
	def server_bind(self):
		if utils.OsInterfaceIsSupported():
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, responder_settings.Config.Bind_To+'\0')
			except:
				pass
		TCPServer.server_bind(self)

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR = "224.0.0.251"
		
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + responder_settings.Config.IP_aton)

		if utils.OsInterfaceIsSupported():
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, responder_settings.Config.Bind_To+'\0')
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		MADDR = "224.0.0.252"

		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + responder_settings.Config.IP_aton)
		
		if utils.OsInterfaceIsSupported():
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, responder_settings.Config.Bind_To+'\0')
			except:
				pass
		UDPServer.server_bind(self)

ThreadingUDPServer.allow_reuse_address = 1
ThreadingTCPServer.allow_reuse_address = 1
ThreadingUDPMDNSServer.allow_reuse_address = 1
ThreadingUDPLLMNRServer.allow_reuse_address = 1

def serve_thread_udp_broadcast(host, port, handler):
	try:
		server = ThreadingUDPServer(('', port), handler)
		server.serve_forever()
	except:
		print utils.color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running."

def serve_NBTNS_poisoner(host, port, handler):
	serve_thread_udp_broadcast(host, port, handler)

def serve_MDNS_poisoner(host, port, handler):
	try:
		server = ThreadingUDPMDNSServer((host, port), handler)
		server.serve_forever()
	except:
		print utils.color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running."

def serve_LLMNR_poisoner(host, port, handler):
	try:
		server = ThreadingUDPLLMNRServer((host, port), handler)
		server.serve_forever()
	except:
		print utils.color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running."

def serve_thread_udp(host, port, handler):
	try:
		if utils.OsInterfaceIsSupported():
			server = ThreadingUDPServer((responder_settings.Config.Bind_To, port), handler)
			server.serve_forever()
		else:
			server = ThreadingUDPServer((host, port), handler)
			server.serve_forever()
	except:
		print utils.color("[!] ", 1, 1) + "Error starting UDP server on port " + str(port) + ", check permissions or other servers running."

def serve_thread_tcp(host, port, handler):
	try:
		if utils.OsInterfaceIsSupported():
			server = ThreadingTCPServer((responder_settings.Config.Bind_To, port), handler)
			server.serve_forever()
		else:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
	except:
		print utils.color("[!] ", 1, 1) + "Error starting TCP server on port " + str(port) + ", check permissions or other servers running."

def serve_thread_SSL(host, port, handler):
	try:

		cert = os.path.join(responder_settings.Config.ResponderPATH, responder_settings.Config.SSLCert)
		key =  os.path.join(responder_settings.Config.ResponderPATH, responder_settings.Config.SSLKey)

		if utils.OsInterfaceIsSupported():
			server = ThreadingTCPServer((responder_settings.Config.Bind_To, port), handler)
			server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
			server.serve_forever()
		else:
			server = ThreadingTCPServer((host, port), handler)
			server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
			server.serve_forever()
	except:
		print utils.color("[!] ", 1, 1) + "Error starting SSL server on port " + str(port) + ", check permissions or other servers running."

def run_responder():
	try:
		threads = []

		# Load (M)DNS, NBNS and LLMNR Poisoners
		from core.poisoners.LLMNR import LLMNR
		from core.poisoners.NBTNS import NBTNS
		from core.poisoners.MDNS import MDNS

		threads.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR,)))
		threads.append(Thread(target=serve_MDNS_poisoner,  args=('', 5353, MDNS,)))
		threads.append(Thread(target=serve_NBTNS_poisoner, args=('', 137,  NBTNS,)))

		# Load Browser Listener
		from core.servers.Browser import Browser
		threads.append(Thread(target=serve_thread_udp_broadcast, args=('', 138,  Browser,)))

		if responder_settings.Config.HTTP_On_Off:
			from core.servers.HTTP import HTTP
			threads.append(Thread(target=serve_thread_tcp, args=('', 80, HTTP,)))

		if responder_settings.Config.SSL_On_Off:
			from core.servers.HTTP import HTTPS
			threads.append(Thread(target=serve_thread_SSL, args=('', 443, HTTPS,)))

		if responder_settings.Config.WPAD_On_Off:
			from core.servers.HTTP_Proxy import HTTP_Proxy
			threads.append(Thread(target=serve_thread_tcp, args=('', 3141, HTTP_Proxy,)))

		if responder_settings.Config.SMB_On_Off:
			if responder_settings.Config.LM_On_Off:
				from core.servers.SMB import SMB1LM
				threads.append(Thread(target=serve_thread_tcp, args=('', 445, SMB1LM,)))
				threads.append(Thread(target=serve_thread_tcp, args=('', 139, SMB1LM,)))
			else:
				from core.servers.SMB import SMB1
				threads.append(Thread(target=serve_thread_tcp, args=('', 445, SMB1,)))
				threads.append(Thread(target=serve_thread_tcp, args=('', 139, SMB1,)))

		if responder_settings.Config.Krb_On_Off:
			from core.servers.Kerberos import KerbTCP, KerbUDP
			threads.append(Thread(target=serve_thread_udp, args=('', 88, KerbUDP,)))
			threads.append(Thread(target=serve_thread_tcp, args=('', 88, KerbTCP,)))

		if responder_settings.Config.SQL_On_Off:
			from core.servers.MSSQL import MSSQL
			threads.append(Thread(target=serve_thread_tcp, args=('', 1433, MSSQL,)))

		if responder_settings.Config.FTP_On_Off:
			from core.servers.FTP import FTP
			threads.append(Thread(target=serve_thread_tcp, args=('', 21, FTP,)))

		if responder_settings.Config.POP_On_Off:
			from core.servers.POP3 import POP3
			threads.append(Thread(target=serve_thread_tcp, args=('', 110, POP3,)))

		if responder_settings.Config.LDAP_On_Off:
			from core.servers.LDAP import LDAP
			threads.append(Thread(target=serve_thread_tcp, args=('', 389, LDAP,)))

		if responder_settings.Config.SMTP_On_Off:
			from core.servers.SMTP import ESMTP
			threads.append(Thread(target=serve_thread_tcp, args=('', 25,  ESMTP,)))
			threads.append(Thread(target=serve_thread_tcp, args=('', 587, ESMTP,)))

		if responder_settings.Config.IMAP_On_Off:
			from core.servers.IMAP import IMAP
			threads.append(Thread(target=serve_thread_tcp, args=('', 143, IMAP,)))

		if responder_settings.Config.DNS_On_Off:
			from core.servers.DNS import DNS, DNSTCP
			threads.append(Thread(target=serve_thread_udp, args=('', 53, DNS,)))
			threads.append(Thread(target=serve_thread_tcp, args=('', 53, DNSTCP,)))

		for thread in threads:
			thread.setDaemon(True)
			thread.start()

		print utils.color('[+]', 2, 1) + " Listening for events..."

		while True:
			time.sleep(1)

	except KeyboardInterrupt:
		sys.exit("\r%s Exiting..." % utils.color('[+]', 2, 1))

class Responder(object):

    instance = None

    @staticmethod
    def get_instance():
        if Responder.instance is None:
            instance = Responder()
        return instance
    
    def configure(self, interface=None):

        assert interface is not None

        responder_configs = {}
        responder_configs['interface'] = interface
        responder_configs['responder'] = {}
        responder_configs['responder']['lm_downgrade'] = True
        responder_configs['responder']['wpad'] = True
        responder_configs['responder']['w_redirect'] = True
        responder_configs['responder']['nbtns_domain'] = False
        responder_configs['responder']['basic_auth'] = False
        responder_configs['responder']['fingerprint'] = False
        responder_configs['responder']['ourip'] = None
        responder_configs['responder']['force_wpad_auth'] = False
        responder_configs['responder']['upstream_proxy'] = None
        responder_configs['responder']['analyze'] = False
        responder_configs['responder']['verbose'] = False
    

        if not os.geteuid() == 0:
            print utils.color("[!] Responder must be run as root.")
            sys.exit(-1)
        elif responder_configs['responder']['ourip'] is None and utils.IsOsX() is True:
            print "\n\033[1m\033[31mOSX detected, -i mandatory option is missing\033[0m\n"
            parser.print_help()
            exit(-1)
        
        responder_settings.init()
        responder_settings.Config.populate(responder_configs)
        
        utils.StartupMessage()
        
        responder_settings.Config.ExpandIPRanges()
        
        if responder_settings.Config.AnalyzeMode:
            	print utils.color('[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.', 3, 1)

    @staticmethod
    def _start(configs):
        run_responder()
        

    def start(self):
    
        self.proc = Process(target=self._start, args=({},))
        self.proc.daemon = True
        self.proc.start()
        time.sleep(8)

    def stop(self):

        self.proc.terminate()
        self.proc.join()

if __name__ == '__main__':

    responder = Responder.get_instance()
    responder.configure()
    responder.start()

    raw_input('responder started.')

    responder.stop()
