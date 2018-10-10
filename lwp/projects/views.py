from flask import Blueprint, g, render_template, request
from lwp.decorators import if_logged_in

mod = Blueprint('projects', __name__)

@mod.route('/projects')
@if_logged_in()
def index():
    """
    List containers
    """
    projects = g.api.get_projects()
    
    print(projects)
    #~ clonable_containers = []
    #~ for container in containers:
        #~ if container['state'] == 'STOPPED':
            #~ clonable_containers.append(container['name'])
    context = {
        'projects': projects,
        #~ 'clonable_containers': clonable_containers,
        #~ 'host': g.api.get_host(),
        #~ 'templates': lwp.get_templates_list(),
        #~ 'storage_repos': storage_repos,
        #~ 'auth': AUTH,
    }
    return render_template('list.html', **context)
    
@mod.route('/projects/<project_name>')
@if_logged_in()
def edit(project_name):
    return render_template('list.html', **context)
