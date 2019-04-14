import json
import os
import glob

import settings.paths
import configparser

CONF_SUBDIRS = [
    'core',
]


class EaphammerSettings(object):

    def __init__(self):

        self.dict = { 

            'paths' : settings.paths.paths,
        }
        self.parse_configs()

    def parse_configs(self):

        conf_dir = self.dict['paths']['directories']['conf'] 
        config_dirs = [os.path.join(conf_dir, subdir) for subdir in CONF_SUBDIRS]

        for config_dir in config_dirs:

            category = os.path.basename(os.path.normpath(config_dir))
            self.dict[category] = {}

            for filename in glob.glob('%s/*.ini' % config_dir):

                parser = configparser.ConfigParser()
                parser.read(filename)
                module = os.path.basename(os.path.normpath(filename))

                module = module.lower()[:-4]

                self.dict[category][module] = {}

                for section in parser.sections():

                    self.dict[category][module][section] = {}
                    
                    for key,val in parser.items(section):
                        self.dict[category][module][section][key] = val

settings = EaphammerSettings()
