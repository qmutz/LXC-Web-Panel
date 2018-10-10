from flask import Blueprint, g, render_template
#~ from lwp.config import read_config_file
from lwp.decorators import if_logged_in

#~ config = read_config_file()

mod = Blueprint('dashboard', __name__)


@mod.route('/')
@mod.route('/dashboard')
@if_logged_in()
def home():
    """
    Home page function, list containers
    """
    #~ gantry = GantryClient(config)
    host = g.api.get_host()
    containers = g.api.get_containers()
    clonable_containers = []
    for container in containers:
        if container['state'] == 'STOPPED':
            clonable_containers.append(container['name'])
    context = {
        'containers': containers,
        'clonable_containers': clonable_containers,
        'host': host,
        #~ 'templates': lwp.get_templates_list(),
        #~ 'storage_repos': storage_repos,
        #~ 'auth': AUTH,
    }
    return render_template('index.html', **context)
