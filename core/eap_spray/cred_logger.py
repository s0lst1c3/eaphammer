from threading import Thread

class Cred_Logger(object):

    def __init__(self, output_file, input_queue):

        args = (
            output_file,
            input_queue,
        )
        self.thread = Thread(target=self._start, args=args)
        self.input_queue = input_queue

    @staticmethod
    def _start(output_file, input_queue):

        with open(output_file, 'a') as fd:
            creds = input_queue.get()
            if creds is None:
                return
            fd.write('%s\n' % creds)

    def start(self):
        self.thread.start()

    def join(self):
        self.input_queue.put(None)
        self.thread.join()
