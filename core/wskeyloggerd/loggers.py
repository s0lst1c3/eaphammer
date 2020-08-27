import logging

class Logger(object):

    def __init__(self, name, output_file, formatter, level=logging.INFO):

        self.output_file = output_file
        self.handler = logging.FileHandler(self.output_file)
        self.handler.setFormatter(formatter)
        self.formatter = formatter

        self.level = level

        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.level)
        self.logger.addHandler(self.handler)


class EventLogger(Logger):

    def __init__(self):

        formatter = logging.Formatter('%(asctime)s,%(levelname)s,%(message)s')
        Logger.__init__(self, 'events', 'events.log', formatter)

    def log(self, message):

        self.logger.info(message)

class UserLogger(Logger):

    def __init__(self):

        formatter = logging.Formatter('%(asctime)s,%(levelname)s,%(message)s')
        Logger.__init__(self, 'user', 'user.log', formatter)

    def log(self,
        view_state='',
        session_id='',
        page_view='',
        username='',
        password='',
        file_download='',
        file_upload='',
        method=''):

        message = ','.join([view_state, session_id, page_view, username, password, file_download, file_upload])
        self.logger.info(message)

class KeystrokeLogger(Logger):

    def __init__(self):

        formatter = logging.Formatter('%(asctime)s,%(levelname)s,%(message)s')
        Logger.__init__(self, 'keystroke', 'keystroke.log', formatter)

    def log(self, view_state='', entry=''):

        message = ','.join([view_state, entry])
        self.logger.info(message)

if __name__ == '__main__':

    el = EventLogger()
    ul = UserLogger()
    kl = KeystrokeLogger()

    el.log('test1')
    el.log('test2')

    ul.log(view_state='asdf', session_id='asdf')

    kl.log(view_state='asdf', username_field='username fieldlllasdfa', password_field='asdfasdfsapassword')
