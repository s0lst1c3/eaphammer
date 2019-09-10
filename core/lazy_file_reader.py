class LazyFileReader(object):

    def __init__(self, input_file):
        self.input_file = input_file

    def read_one(self):
        with open(self.input_file) as fd:
            for line in fd:
                yield line.strip()

    def _read(self):
        with open(self.input_file) as fd:
            yield fd.read()

    def read(self):
        return next(self._read())

    def path(self, path=None):
        if path is not None:
            self.input_file = path
        return self.input_file
