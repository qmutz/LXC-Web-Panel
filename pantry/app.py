#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function

import os
import sys
import jinja2
from peewee import *
from flask import Flask, g
from pantry.config import config
#~ from lwp import SESSION_SECRET_FILE
from pantry.views import main, auth, api
from pantry.dashboard.views import mod as dashboard
from pantry.api.views import mod as api
from pantry.containers.views import mod as containers
from pantry.projects.views import mod as projects

SESSION_SECRET_FILE = '/etc/pantry/session_secret'
try:
    SECRET_KEY = open(SESSION_SECRET_FILE, 'br').read()
except IOError:
    print(' * Missing session_secret file, your session will not survive server reboot. Run with --generate-session-secret to generate permanent file.')
    SECRET_KEY = os.urandom(24)

DEBUG = config.getboolean('global', 'debug')
DATABASE = config.get('database', 'file')
ADDRESS = config.get('global', 'address')
PORT = int(config.get('global', 'port'))
PREFIX = config.get('global', 'prefix')

#~ from pantry.database.models import db
# Flask app
#~ from playhouse.flask_utils import FlaskDB

#~ database = FlaskDB()

app = Flask('pantry', static_url_path="{0}/static".format(PREFIX))
app.config.from_object(__name__)
app.register_blueprint(dashboard, url_prefix=PREFIX)
app.register_blueprint(main.mod, url_prefix=PREFIX)
app.register_blueprint(containers, url_prefix=PREFIX)
app.register_blueprint(projects, url_prefix=PREFIX)
app.register_blueprint(auth.mod, url_prefix=PREFIX)
app.register_blueprint(api, url_prefix=PREFIX)

template_paths = [  ]
for blueprint in app.blueprints.keys():
    template_paths.append((os.path.join(os.path.dirname(__file__),blueprint,'templates',blueprint)))
app.jinja_loader = jinja2.ChoiceLoader([app.jinja_loader,jinja2.FileSystemLoader(template_paths)])


if '--profiling' in sys.argv[1:]:
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.config['PROFILE'] = True
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
    app.debug = True  # also enable debug


@app.before_request
def before_request():
    """
    executes functions before all requests
    """
    from pantry.utils import check_session_limit
    from pantry.api.client import GantryClient
    from pantry.config import read_config_file

    check_session_limit()
    g.api = GantryClient(read_config_file())
    #~ g.api.hydrate()
    #~ g.db = connect_db(app.config['DATABASE'])


#~ @app.teardown_request
#~ def teardown_request(exception):
    #~ """
    #~ executes functions after all requests
    #~ """
    #~ if hasattr(g, 'db'):
        #~ g.db.close()
