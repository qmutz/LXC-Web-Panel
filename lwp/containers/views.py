from flask import Blueprint, g, render_template, request, jsonify
from lwp.decorators import if_logged_in

mod = Blueprint('containers', __name__)


@mod.route('/containers')
@if_logged_in()
def index():
    """
    List containers
    """
    containers = g.api.get_containers()
    clonable_containers = []
    for container in containers:
        if container['state'] == 'STOPPED':
            clonable_containers.append(container['name'])
    context = {
        'containers': containers,
        'clonable_containers': clonable_containers,
        'host': g.api.get_host(),
        #~ 'templates': lwp.get_templates_list(),
        #~ 'storage_repos': storage_repos,
        #~ 'auth': AUTH,
    }
    return render_template('containers.html', **context)

@mod.route('/<container_name>/edit', methods=['POST', 'GET'])
@if_logged_in()
def edit(container_name):
    """
    Edit containers page and actions if form post request
    """
    container = g.api.get_container(container_name)
    host = g.api.get_host()
    #~ host['memory'] = lwp.host['memory']_usage()
    #~ info = lxc.info(container)
    #~ cfg = lwp.get_container_settings(container, info['state'])
    if request.method == 'POST':
        form = request.form.copy()
        # convert boolean in correct value for lxc, if checkbox is inset value is not submitted inside POST
        form['network.flags'] = 'up' if 'flags' in form else 'down'
        form['start.auto'] = '1' if 'start.auto' in form else '0'

        # if memlimits/memswlimit is at max values unset form values
        if 'memlimit' in form and int(form['memlimit']) == host['memory']['total']:
            form['memlimit'] = ''
        if 'swlimit' in form and int(form['swlimit']) == host['memory']['total'] * 2:
            form['swlimit'] = ''
        data = {}
        del form['submit']
        for option in form.keys():
            if option.startswith('ic-') is False and option.startswith('_') is False:
                data[option] = form[option]
        #~ print("main wtf")
        container = g.api.set_config(container_name, data)
        #~ print("after request main wtf")
        #~ for option in form.keys():
            # if the key is supported AND is different
            #~ if option in cfg.keys() and form[option] != cfg[option]:
                # validate value with regex
            
            
            #~ if re.match(cgroup_ext[option][1], form[option]):
                #~ lwp.push_config_value(cgroup_ext[option][0], form[option], container=container)
                #~ flash(cgroup_ext[option][2], 'success')
            #~ else:
                #~ flash('Cannot validate value for option {}. Unsaved!'.format(option), 'error')
            
        # we should re-read container configuration now to be coherent with the newly saved values
        #~ cfg = lwp.get_container_settings(container)

        #~ info = lxc.info(container)
    #~ infos = {'status': container['state'], 'pid': info['pid'], 'memusg': lwp.memory_usage(container)}
    #~ infos = {'status': container['state'], 'memusg': lwp.memory_usage(container['name'])}
    # prepare a regex dict from cgroups_ext definition
    regex = {}
    #~ for k, v in cgroup_ext.items():
        #~ regex[k] = v[1]

    context = {
        'container': container,
        'storage_repository': g.api.storage_repository,
        'regex': regex,
        'host': host,
    }
    return render_template('edit.html', **context)

@mod.route('/action', methods=['GET'])
@if_logged_in()
def action():
    """
    Manage all actions related to containers
    lxc-start, lxc-stop, etc...
    """
    action = request.args['action']
    act = action
    name = request.args['name']
    #~ gantry =  GantryClient(config)
    if act == 'start':
        response = g.api.set_state(name,action)
        if response['state'] == 'RUNNING':
            flash(u'Container %s started successfully!' % name, 'success')
        else:
            flash(u'Unable to start %s!' % name, 'danger')
    elif act == 'stop':
        response = g.api.set_state(name,action)
        if response['state'] == 'STOPPED':
            flash(u'Container %s stopped successfully!' % name, 'success')
        else:
            flash(u'Unable to stop %s!' % name, 'danger')
    elif action == 'freeze':
        response = g.api.set_state(name,action)
        if response['state'] == 'FROZEN':
            flash(u'Container %s frozen successfully!' % name, 'success')
        else:
            flash(u'Unable to freeze %s!' % name, 'danger')
    elif action == 'unfreeze':
        response = g.api.set_state(name,action)
        if response['state'] != 'FROZEN':
            flash(u'Container %s unfrozen successfully!' % name, 'success')
        else:
            flash(u'Unable to unfreeze %s!' % name, 'danger')
    elif action == 'destroy':
        if session['su'] != 'Yes':
            return abort(403)
        g.api.make_operation(name,action)
    elif action == 'snapshot_create':
        g.api.make_operation(name, action)
    elif action == 'snapshot_destroy' and 'snapshot_name' in request.args:
        g.api.make_operation(name, action, snapshot_name=request.args['snapshot_name'])
        
    elif action == 'copy' and 'new_name' in request.args:
        g.api.make_operation(name, action, new_name=request.args['new_name'])
    elif act == 'reboot' and name == 'host':
        if session['su'] != 'Yes':
            return abort(403)
        msg = '\v*** LXC Web Panel *** \
                \nReboot from web panel'
        try:
            subprocess.check_call('/sbin/shutdown -r now \'%s\'' % msg, shell=True)
            flash(u'System will now restart!', 'success')
        except subprocess.CalledProcessError:
            flash(u'System error!', 'error')
    if 'next' in request.args:
        return redirect(request.args['next'])
    try:
        if request.args['from'] == 'edit':
            return redirect(url_for('containers.edit', container_name=name))
        else:
            return redirect(url_for('main.home'))
    except KeyError:
        return redirect(url_for('main.home'))

@mod.route('/action/create-container', methods=['GET', 'POST'])
@if_logged_in()
def create():
    """
    verify all forms to create a container
    """
    if session['su'] != 'Yes':
        return abort(403)
    if request.method == 'POST':
        name = request.form['name']
        template = request.form['template']
        command = request.form['command']
        if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
            storage_method = request.form['backingstore']

            if storage_method == 'default':
                try:
                    if lxc.create(name, template=template, xargs=command) == 0:
                        flash(u'Container %s created successfully!' % name, 'success')
                    else:
                        flash(u'Failed to create %s!' % name, 'error')
                except lxc.ContainerAlreadyExists:
                    flash(u'The Container %s is already created!' % name, 'error')
                except subprocess.CalledProcessError:
                    flash(u'Error! %s' % name, 'error')

            elif storage_method == 'directory':
                directory = request.form['dir']

                if re.match('^/[a-zA-Z0-9_/-]+$', directory) and directory != '':
                    try:
                        if lxc.create(name, template=template, storage='dir --dir %s' % directory, xargs=command) == 0:
                            flash(u'Container %s created successfully!' % name, 'success')
                        else:
                            flash(u'Failed to create %s!' % name, 'error')
                    except lxc.ContainerAlreadyExists:
                        flash(u'The Container %s is already created!' % name, 'error')
                    except subprocess.CalledProcessError:
                        flash(u'Error! %s' % name, 'error')

            elif storage_method == 'btrfs':
                try:
                    if lxc.create(name, template=template, storage='btrfs', xargs=command) == 0:
                        flash(u'Container %s created successfully!' % name, 'success')
                    else:
                        flash(u'Failed to create %s!' % name, 'error')
                except lxc.ContainerAlreadyExists:
                    flash(u'The Container %s is already created!' % name, 'error')
                except subprocess.CalledProcessError:
                    flash(u'Error! %s' % name, 'error')

            elif storage_method == 'zfs':
                zfs = request.form['zpoolname']

                if re.match('^[a-zA-Z0-9_-]+$', zfs) and zfs != '':
                    try:
                        if lxc.create(name, template=template, storage='zfs --zfsroot %s' % zfs, xargs=command) == 0:
                            flash(u'Container %s created successfully!' % name, 'success')
                        else:
                            flash(u'Failed to create %s!' % name, 'error')
                    except lxc.ContainerAlreadyExists:
                        flash(u'The Container %s is already created!' % name, 'error')
                    except subprocess.CalledProcessError:
                        flash(u'Error! %s' % name, 'error')

            elif storage_method == 'lvm':
                lvname = request.form['lvname']
                vgname = request.form['vgname']
                fstype = request.form['fstype']
                fssize = request.form['fssize']
                storage_options = 'lvm'

                if re.match('^[a-zA-Z0-9_-]+$', lvname) and lvname != '':
                    storage_options += ' --lvname %s' % lvname
                if re.match('^[a-zA-Z0-9_-]+$', vgname) and vgname != '':
                    storage_options += ' --vgname %s' % vgname
                if re.match('^[a-z0-9]+$', fstype) and fstype != '':
                    storage_options += ' --fstype %s' % fstype
                if re.match('^[0-9]+[G|M]$', fssize) and fssize != '':
                    storage_options += ' --fssize %s' % fssize

                try:
                    if lxc.create(name, template=template, storage=storage_options, xargs=command) == 0:
                        flash(u'Container %s created successfully!' % name, 'success')
                    else:
                        flash(u'Failed to create %s!' % name, 'error')
                except lxc.ContainerAlreadyExists:
                    flash(u'The container/logical volume %s is already created!' % name, 'error')
                except subprocess.CalledProcessError:
                    flash(u'Error! %s' % name, 'error')

            else:
                flash(u'Missing parameters to create container!', 'error')

        else:
            if name == '':
                flash(u'Please enter a container name!', 'error')
            else:
                flash(u'Invalid name for \"%s\"!' % name, 'error')

    return redirect(url_for('main.home'))

@mod.route('/_refresh_memory_<name>')
@if_logged_in()
def refresh_memory(name=None):
    #~ gantry = GantryClient(config)
    host = g.api.get_host()
    if name == 'containers':
        all_containers = g.api.get_containers()
        #~ containers_running = lxc.running()
        containers = []
        for container in all_containers:
            if container['state'] == 'RUNNING':
            #~ container = container.replace(' (auto)', '')
                containers.append({'name': container['name'],
                                'runtime': container['runtime']['memory.usage_in_bytes'],
                               'settings': container['settings']
                               })
        return jsonify(data=containers)
    elif name == 'host':
        #~ return jsonify(lwp.host['memory']_usage())
        return jsonify(host['memory'])
    return jsonify({'memusg': lwp.memory_usage(name)})
