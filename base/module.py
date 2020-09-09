import sys

class Module(object):

    def __init__(self):

        self.required_attrs([

            'name',
            'mtype',
            'author',
            'description',
        ])

    def required_attrs(self, attrs):

        if hasattr(self, '_required_attrs'):

            self._required_attrs += attrs

        else:

            self._required_attrs = attrs

        

    def validate(self):

        for ra in self._required_attrs:
            if not hasattr(self, ra):
                sys.exit('Missing attribute' + ra)

    def __str__(self):

        return f'{self.name:<16} - {self.description}'

    def __getitem__(self, key):

        for k,v in self.options.items():

            if k.lower() == key.lower():
                return self.options[k]['Value']

    def __setitem__(self, key, value):

        for k,v in self.options.items():

            if k.lower() == key.lower():

                self.options[k]['Value'] = value

