from flask import Blueprint, g, render_template, request
from pantry.decorators import if_logged_in

mod = Blueprint('projects', __name__)

@mod.route('/projects')
@if_logged_in()
def index():
    """
    List containers
    """
    projects = g.api.get_projects()['objects']
    context = {
        'projects': projects,
    }
    return render_template('list.html', **context)
    
@mod.route('/projects/<id>')
@if_logged_in()
def details(id, assign_container=False):
    #~ projects = g.api.get_projects()['objects']
    project = g.api.get_project(id)['objects']
    #~ print(project['containers'])
    context = {
        #~ 'projects': projects,
        'project': project,
    }
    #~ return render_template('add_container.html', **context)
    return render_template('project.html', **context)

@mod.route('/projects/edit/<id>')
@mod.route('/projects/edit/<id>/<assign_container>', methods=['GET','POST'])
@if_logged_in()
def edit(id, assign_container=False):
    #~ projects = g.api.get_projects()['objects']
    project = g.api.get_project(id)['objects']
    #~ print(project['containers'])
    context = {
        #~ 'projects': projects,
        'project': project,
        'add_container': False,
    }
    if assign_container and assign_container == 'assign_container':
        context['assign_container'] = True
        context['containers'] = g.api.get_containers()
        if request.method == 'POST':
            form = request.form
            containers = []
            for key, value in request.form.items():
                if key.startswith('container-'):
                    containers.append(value)
                
            if len(containers) >= 0:
                g.api.deassign_project(id)
            for container in containers:
                g.api.assign_project(id, container)
            project = g.api.get_project(id)['objects']
            context['containers'] = g.api.get_containers()
            context['project'] = project
        #~ return render_template('add_container.html', **context)
    return render_template('project.html', **context)
