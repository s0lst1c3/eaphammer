import os
import time

from multiprocessing import Process
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

class WebDeliveryHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try: 
            with open(config.payload_path) as fd:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(fd.read())
            return
        except IOError:
            self.send_error(404, 'Content not available.')

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    ''' yay '''

class WebDeliveryServer(object):

    instance = None

    @staticmethod
    def get_instance():
        if WebDeliveryServer.instance is None:
            instance = WebDeliveryServer()
        return instance
    
    def configure(self, bind_addr, bind_port=7777):
        
        self.bind_addr = bind_addr
        self.bind_port = bind_port

    @staticmethod
    def _start(bind_addr, bind_port):

        httpd = ThreadedHTTPServer((bind_addr, bind_port), WebDeliveryHandler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

    def start(self):
    
        args = (self.bind_addr,self.bind_port,)
        self.proc = Process(target=self._start, args=args)
        self.proc.daemon = True
        self.proc.start()
        time.sleep(4)

    def stop(self):

        self.proc.terminate()
        self.proc.join()

