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
    context = {
        'projects': projects,
    }
    return render_template('list.html', **context)
    
@mod.route('/projects/<id>')
@mod.route('/projects/<id>/<add_container>')
@if_logged_in()
def edit(id, add_container=False):
    projects = g.api.get_projects()
    project = g.api.get_project(id)
    context = {
        'projects': projects,
        'project': project,
        'add_container': False,
    }
    if add_container and add_container == 'add_container':
        context['add_container'] = True
        context['containers'] = g.api.get_containers()
        #~ return render_template('add_container.html', **context)
    return render_template('project.html', **context)
