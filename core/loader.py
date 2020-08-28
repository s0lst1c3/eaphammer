import os

from importlib import util
from core.module_store import ModuleStore

class Loader:

    def __init__(self, mtype=None, paths=[]):

        assert mtype is not None
    
        self.type = mtype
        self.paths = paths
        self.loaded = [ ]

        self.get_loadables()

    def load(self, path):


        spec = util.spec_from_file_location(self.type, path)
        module = util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def get_loadables(self):

        self.loaded = [ ]
        
        for path in self.paths:

            for module in os.listdir(path):
                try:

                    m = self.load(os.path.join(path, module + '/meta.py'))
                    
                    if self.type == 'MPortalTemplate':

                        module = m.MPortalTemplate()
                        module.validate()
                        self.loaded.append(module)

                except Exception as e:
                    print(e)

        return ModuleStore(modules=self.loaded)
