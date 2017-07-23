
import os
import time
#import config

from multiprocessing import Process
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

# lol, i mean it works...
bind_addr = None
bind_port = None

# todo: make this system suck less lol
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

def run_web_delivery_server(bind_addr, bind_port):

    httpd = ThreadedHTTPServer((bind_addr, bind_port), WebDeliveryHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

class WebDeliveryServer(object):

    instance = None

    @staticmethod
    def get_instance():
        if WebDeliveryServer.instance is None:
            instance = WebDeliveryServer()
        return instance
    
    def configure(self, b_addr, b_port=7777):
        
        global bind_addr
        global bind_port

        # idfk
        bind_addr = b_addr
        bind_port = b_port

    @staticmethod
    def _start(args):

        run_web_delivery_server(args['bind_addr'], args['bind_port'])

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

if __name__ == '__main__':        
    
    wd = WebDeliveryServer()
    wd.configure('0.0.0.0')
    wd.start()

    raw_input()

    wd.stop()
