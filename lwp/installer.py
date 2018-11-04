#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function

import os, sys, socket
import subprocess
import string, random
def id_generator(size=24, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

from flask import Flask, request, session, g, redirect, url_for, abort, render_template
from lwp.utils import ConfigParser
#~ from lwp.utils import connect_db, check_session_limit, config
#~ import lwp.lxclite as lxc

DEBUG = False
ADDRESS = 'localhost'
PORT = 5000
PREFIX = '/install'

# Flask app
app = Flask('lwp', static_url_path="{0}/static".format(PREFIX))
app.config.from_object(__name__)

def create(path):
    if os.path.exists(path) == False:
        os.makedirs(path)
    return path

def get_parent_path(path):
    sp = path.split('/')
    parent = os.path.join('/'.join(sp[0:-1]))
    return parent

def is_already_installed():
    try:
        from lwp.config import read_config_file
        config = read_config_file()
        config.get('database', 'file')
        return True
    except: pass
    return False

@app.route('/', methods=['POST', 'GET'], defaults={'path': ''})
@app.route('/<path:path>', methods=['POST', 'GET'])
def install(path):
    """
    Installer
    """ 
    exec_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    if len(path) > 0:
        return redirect('/')
    test_file = os.path.join('/etc',id_generator())
    can_we_install = False
    already_installed = is_already_installed()
    #~ print(already_installed)
    context = {
        'can_we_install': can_we_install,
        'already_installed': already_installed,
    }
    

    try:
        open(test_file, 'w').close()
    except:
        pass
    if os.path.exists(test_file):
        context['can_we_install'] = True
        os.remove(test_file)
    else:
        return render_template('installer.html', **context)
    context['checks'] = lxc.checkconfig()
    if request.method == 'POST':
        from lwp.utils import hash_passwd
        f = request.form
        datadir = f.get('datadir','/var/lwp')
        create(datadir)
        conffile = f.get('conffile','/etc/lwp/lwp.conf')
        create(get_parent_path(conffile))
        config = ConfigParser()
        config['global'] = {}
        config['global']['address'] = f.get('address','127.0.0.1')
        config['global']['debug'] = f.get('debug','False')
        config['global']['port'] = f.get('port','5000')
        config['global']['auth'] = f.get('auth','database')
        config['global']['prefix'] = f.get('prefix','')
        config['storage_repository'] = {}
        config['storage_repository']['local'] = f.get('local_storage_repository','backups')
        create(os.path.join(datadir,config['storage_repository']['local']))
        config['database'] = {}
        config['database']['file'] = f.get('database_uri','sqlite:////var/lwp/lwp.db')
        config['session'] = {}
        config['session']['time'] = f.get('time','10')
        config['api'] = {}
        internal_token = hash_passwd('lwp')
        config['api']['username'] = f.get('api_username','admin')
        config['api']['token'] = f.get('api_token',internal_token)
        with open(conffile, 'w') as configfile:
            config.write(configfile)
        
        from lwp.database.models import get_database,Users,ApiTokens,Projects,Hosts,Containers,ContainerTag,Tags

        database = get_database()
        database.create_tables([Users,ApiTokens,Projects,Hosts,Containers,ContainerTag,Tags])
        admin = Users.create(name='Admin',username='admin',su='Yes',password=hash_passwd('admin'))
        ApiTokens.create(username='admin',description='internal',token=internal_token)
        host = Hosts.create(hostname=socket.gethostname(), admin=admin, api_token=config['api']['token'], api_user=config['api']['username'])
        default_project = Projects.create(title='Default',description='Default project to start with',admin=admin)
        subprocess.check_call('touch {}'.format(exec_path), shell=True)
        context['already_installed'] = is_already_installed()
    return render_template('installer.html', **context)
