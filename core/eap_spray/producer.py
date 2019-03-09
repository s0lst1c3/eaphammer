from core.lazy_file_reader import LazyFileReader

class Producer(object):

    def __init__(self, input_file, output_queue, num_consumers):
        self.lfr = LazyFileReader(input_file)
        self.output_queue = output_queue
        self.num_consumers = num_consumers

    def run(self):
        for identity in self.lfr.read_one():
            self.output_queue.put(identity, block=True)
        for i in range(self.num_consumers):
            self.output_queue.put(None)
