class LazyFileReader(object):

    def __init__(self, input_file):
        self.input_file = input_file

    def read_one(self):
        with open(self.input_file) as fd:
            for line in fd:
                yield line.strip()
