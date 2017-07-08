from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from multiprocessing import Process
import time
import sys
import random
import string

# lol, i mean it works...
bind_addr = None
bind_port = None
upper_alnum = string.ascii_uppercase + string.digits

class RedirectHandler(BaseHTTPRequestHandler):

    def do_HEAD(s):

        s.send_response(302)
        share_path = ''.join(random.choice(upper_alnum) for _ in range(8))
        new_location = 'file://%s/%s' % (bind_addr, share_path)
        s.send_header('Location', new_location)
        s.end_headers()

    def do_GET(s):
        s.do_HEAD()

    def do_POST(s):
        s.do_HEAD()

    def do_OPTIONS(s):
        s.do_HEAD()

    def do_PUT(s):
        s.do_HEAD()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    ''' yay '''

def run_redirect_server(bind_addr, bind_port):

    server_class = ThreadedHTTPServer
    httpd = server_class((bind_addr, bind_port), RedirectHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

class RedirectServer(object):

    instance = None

    @staticmethod
    def get_instance():
        if RedirectServer.instance is None:
            instance = RedirectServer()
        return instance
    
    def configure(self, b_addr, b_port=80):
        
        global bind_addr
        global bind_port

        # idfk
        bind_addr = b_addr
        bind_port = b_port

    @staticmethod
    def _start(args):

        run_redirect_server(args['bind_addr'], args['bind_port'])

    def start(self):
    
        args = {
            'bind_addr' : bind_addr,
            'bind_port' : bind_port,
        }
        self.proc = Process(target=self._start, args=(args,))
        self.proc.daemon = True
        self.proc.start()
        time.sleep(4)

    def stop(self):

        self.proc.terminate()
        self.proc.join()

