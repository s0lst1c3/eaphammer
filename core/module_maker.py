import sys
import os
import glob
import shutil

from pywebcopy import save_webpage
from settings import settings
from core.loader import Loader
from pathlib import Path
from bs4 import BeautifulSoup

g_tmp_dir = settings.dict['paths']['directories']['tmp']
g_wk_paths = settings.dict['paths']['wskeyloggerd']
g_template_dir = g_wk_paths['usr_templates']


class Cloaner(object):

    def __init__(self, url, project_name=None):

        self.url = url

        self.target_host = url.replace('https://', '').replace('http://', '').split('/')[0]

        self.project_name = project_name

        self.project_folder = g_tmp_dir

        self.full_project_path = os.path.join(g_tmp_dir, project_name, self.target_host)

    def run(self):

        kwargs = {
            'bypass_robots' : True,
            'project_name' : self.project_name,
        }
        
        save_webpage(
        
            url=self.url,
            project_folder=g_tmp_dir,
            **kwargs
        )
    
        return 


class ModuleMaker(object):

    def __init__(self,
                 url=None,
                 name=None,
                 author='',
                 description='',
                 dl_form_message='',
                 add_downloader=False):

        assert url is not None
        assert name is not None



        loader = Loader(paths=[settings.dict['paths']['wskeyloggerd']['usr_templates']],
                        mtype='MPortalTemplate')
        
        
        templates = loader.get_loadables()

        for t in templates:

            if t.name == name:

                sys.exit(f'[*] Module {name} already exists. Choose a different name or delete the preexisting module.')
            print(t.name)

        print(f'[*] Setting module name to {name}')

        self.name = name
        self.url = url
        self.author = author
        self.description = description
        self.add_downloader = add_downloader
        self.target_host = url.replace('https://', '').replace('http://', '').split('/')[0]

        self.full_project_path = os.path.join(g_tmp_dir, name, self.target_host)
        self.proj_parent_path = os.path.join(g_tmp_dir, name)


        self.target_dir = os.path.join(g_template_dir, name)

        self.dl_form_message = dl_form_message

    def clone_website(self):

        cloaner = Cloaner(url=self.url, project_name=self.name)

        cloaner.run()

    def get_html_file_path(self):

        proj_path = self.full_project_path.rstrip('/')
    
        html_files = [html_file for html_file in glob.glob(f'{proj_path}/*.html')]

        if len(html_files) > 1:

            sys.exit('[*] Fatal error: please contact the dev team')
    
        elif len(html_files) == 0:

            sys.exit('[*] Website cloaning did not work.')

        self.html_file_path = html_files[0]

        return html_files[0]

    def create_mod_dir(self):

        target_path = Path(self.target_dir)
        target_path.mkdir(parents=True, exist_ok=True)

    def move_index_to_target(self):


        with open(self.html_file_path) as input_handle:
            text = input_handle.read()

        soup = BeautifulSoup(text, features="lxml")
    
        # link href
        for link in soup.findAll('link'):

            link['href'] = "{{ url_for('static', filename='%s') }}" % link['href']

        # img src
        for img in soup.findAll('img'):

            img['src'] = "{{ url_for('static', filename='%s') }}" % img['src']

        # script src
        for script in soup.findAll('script'):

            script['src'] = "{{ url_for('static', filename='%s') }}" % script['src']

        body = soup.body.extract()
        head = soup.head.extract()

        head_path = os.path.join(self.target_dir, 'head.html')
        body_path = os.path.join(self.target_dir, 'body.html')

        with open(head_path, 'w') as output_handle:
            output_handle.write('''{%% block head %%}

%s

{%% endblock %%}
''' % str(head).replace('<head>', '').replace('</head>', ''))


        if self.add_downloader:

            with open(body_path, 'w') as output_handle:
                output_handle.write('''{%% block body %%}

%s










	<p>%s</p><br/>
	<a href='{{ serve_route }}'>Download</a><br/>
	
	<br/>


{%% endblock %%}
''' % (str(body).replace('<body>', '').replace('</body>', ''), self.dl_form_message))

        else:

            with open(body_path, 'w') as output_handle:
                output_handle.write('''{%% block body %%}

%s

{%% endblock %%}
''' % str(body).replace('<body>', '').replace('</body>', ''))

        Path(self.html_file_path).unlink()

        static_dir = os.path.join(self.target_dir, 'static')

        shutil.move(self.full_project_path, static_dir)


    def delete_dl_dir(self):

        shutil.rmtree(self.proj_parent_path)

    def create_meta_file(self):

        meta_path = os.path.join(self.target_dir, 'meta.py')

        with open(meta_path, 'w') as output_handle:

            output_handle.write('''from base.module import Module

class MPortalTemplate(Module):
    
    def __init__(self):

        self.author = '%s'
        self.name = '%s'
        self.mtype = 'MPortalTemplate'
        self.description = '%s'

        super().__init__()

''' % (self.author, self.name, self.description))

    def run(self):

        self.clone_website()

        self.get_html_file_path()

        self.create_mod_dir()

        self.move_index_to_target()

        self.delete_dl_dir()

        self.create_meta_file()
        
