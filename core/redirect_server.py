import time
import sys
import random
import string

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from multiprocessing import Process

upper_alnum = string.ascii_uppercase + string.digits
bind_addr = None
bind_port = None

class RedirectHandler(BaseHTTPRequestHandler):

    def do_HEAD(s):

        s.send_response(302)
        share_path = ''.join(random.choice(upper_alnum) for _ in range(8))
        new_location = 'file://%s:%s/%s' % (bind_addr, bind_port, share_path)
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

class RedirectServer(object):

    instance = None

    @staticmethod
    def get_instance():
        if RedirectServer.instance is None:
            instance = RedirectServer()
        return instance

    def configure(self, lbind_addr, lbind_port=80):

        global bind_addr
        global bind_port

        self.bind_addr = lbind_addr
        self.bind_port = lbind_port

        bind_addr = lbind_addr
        bind_port = lbind_port
        

    @staticmethod
    def _start(bind_addr, bind_port):

        server_class = ThreadedHTTPServer
        httpd = server_class((bind_addr, bind_port), RedirectHandler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

    def start(self):

        args = (self.bind_addr, self.bind_port,)
        self.proc = Process(target=self._start, args=args)
        self.proc.daemon = True
        self.proc.start()
        time.sleep(4)

    def stop(self):

        self.proc.terminate()
        self.proc.join()
