class ModuleStore():

    def __init__(self, modules=[]):
        
        self.modules = {}

        for m in modules:
            self.modules[m.name] = m

        self.index = 0

    def __iter__(self):

        
        yield from (v for k,v in self.modules.items())

    def __getitem__(self, key):

        
        for k,v in self.modules.items():

            if k.lower() == key.lower():
                return v

    def __setitem__(self, key, value):

        for k,v in self.modules.items():

            if k.lower() == key.lower():

                self.modules[k] = value
