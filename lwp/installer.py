#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function

import os
import sys
import string, random
def id_generator(size=24, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

from flask import Flask, request, session, g, redirect, url_for, abort, render_template
from lwp.utils import ConfigParser
#~ from lwp.utils import connect_db, check_session_limit, config
import lwp.lxclite as lxc
#~ from lwp import SESSION_SECRET_FILE
#~ from lwp.views import main, auth, api

#~ try:
    #~ SECRET_KEY = open(SESSION_SECRET_FILE, 'br').read()
#~ except IOError:
    #~ print(' * Missing session_secret file, your session will not survive server reboot. Run with --generate-session-secret to generate permanent file.')
    #~ SECRET_KEY = os.urandom(24)

DEBUG = True
#~ DEBUG = config.getboolean('global', 'debug')
#~ DATABASE = config.get('database', 'file')
#~ ADDRESS = config.get('global', 'address')
#~ PORT = int(config.get('global', 'port'))
#~ PREFIX = config.get('global', 'prefix')
ADDRESS = 'localhost'
PORT = 5000
PREFIX = '/install'

# Flask app
app = Flask('lwp', static_url_path="{0}/static".format(PREFIX))
app.config.from_object(__name__)
#~ app.register_blueprint(main.mod, url_prefix=PREFIX)
#~ app.register_blueprint(auth.mod, url_prefix=PREFIX)
#~ app.register_blueprint(api.mod, url_prefix=PREFIX)
def create(path):
    if os.path.exists(path) == False:
        os.makedirs(path)
    return path

def get_parent_path(path):
    sp = path.split('/')
    parent = os.path.join('/'.join(sp[0:-1]))
    return parent

@app.route('/', methods=['POST', 'GET'], defaults={'path': ''})
@app.route('/<path:path>', methods=['POST', 'GET'])
def install(path):
    """
    Installer
    """ 
    print(path)
    if len(path) > 0:
        return redirect('/')
    test_file = os.path.join('/etc',id_generator())
    can_we_install = False
    print(test_file)
    context = {
        'hie': 'yea',
        'can_we_install': can_we_install,
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
        f = request.form
        datadir = f.get('datadir','/var/lwp')
        create(datadir)
        conffile = f.get('conffile','/etc/lwp/lwp.conf')
        create(get_parent_path(conffile))
        config = ConfigParser()
        config['global'] = {}
        config['global']['address'] = f.get('address','127.0.0.1')
        config['global']['debug'] = f.get('debug','False')
        config['global']['port'] = f.get('port',5000)
        config['global']['auth'] = f.get('auth','database')
        config['global']['prefix'] = f.get('prefix','')
        config['storage_repository'] = {}
        config['storage_repository']['local'] = f.get('local_storage_repository','local_storage_repository')
        config['database'] = {}
        config['database']['file'] = f.get('database_uri','sqlite:///var/lwp/lwp.db')
        config['session'] = {}
        config['session']['time'] = f.get('time',10)
        
        
        with open(conffile, 'w') as configfile:
            config.write(configfile)
    return render_template('installer.html', **context)
