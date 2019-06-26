import os
import json
import shutil
import configparser

class ResponderConfig(object):

    def __init__(self, settings, options):

        self.conf_path = settings.dict['paths']['responder']['conf']
        self.paths = settings.dict['paths']['responder']
        self.dict = settings.dict['core']['responder']

        self.set_paths()

        config = configparser.ConfigParser()
        for section_title in self.dict:
            config.add_section(section_title)
            for key,value in self.dict[section_title].items():
                config.set(section_title, key, value)

        self.config = config

    def write(self):

        with open(self.conf_path, 'w') as output_handle:
            self.config.write(output_handle)

    def remove(self):
        try:
            os.remove(self.path)
        except OSError:
            print('[*] Can\'t remove non-existant config file.')
            pass


    def set_paths(self):

        self.dict['Responder Core']['Database'] = self.paths['db']
        self.dict['Responder Core']['SessionLog'] = self.paths['session_log']
        self.dict['Responder Core']['PoisonersLog'] = self.paths['poisoners_log']
        self.dict['Responder Core']['AnalyzeLog'] = self.paths['analyzer_log']
        self.dict['Responder Core']['ResponderConfigDump'] = self.paths['config_log']
        self.dict['HTTP Server']['HtmlFilename'] = self.paths['html']
        self.dict['HTTP Server']['ExeFilename'] = self.paths['exe']
        self.dict['HTTPS Server']['SSLCert'] = self.paths['cert']
        self.dict['HTTPS Server']['SSLKey'] = self.paths['key']
