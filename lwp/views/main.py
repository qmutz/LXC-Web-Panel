# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function
import os
import re
import time
import socket
import subprocess
import requests
from flask import Blueprint, request, session, g, redirect, url_for, abort, render_template, flash, jsonify
from flask import current_app as app
import lwp
import lwp.lxclite as lxc
from lwp.utils import hash_passwd, cgroup_ext
from lwp.config import read_config_file, ConfigParser
from lwp.decorators import if_logged_in
from lwp.views.auth import AUTH

config = read_config_file()

if 'setup_mode' in config['global'] and config['global']['setup_mode'] == 'True':
    config = None
    private_token = None
    storage_repos = []
else:
    private_token = config['api']['token']
    storage_repos = config.items('storage_repository')

# Flask module
mod = Blueprint('main', __name__)

api_prefix = '/api/v1'

payload = {'private_token':private_token}


class GantryClient():
    api_prefix = '/api/v1'
    
    def __init__(self, config):
        self.address = app.config['ADDRESS']
        self.port = app.config['PORT']
        self.token = config['api']['token']
        self.default_url = 'http://{}:{}{}'.format(self.address, self.port, self.api_prefix)
        self.payload = {'private_token':self.token}
        
    def get_payload(self):
        return self.payload.copy()
        
    def build_url(self, endpoint):
        return '{}/{}/'.format(self.default_url, endpoint)
        
    def get_host(self):
        r = requests.get(self.build_url('host'), params=self.get_payload())
        return r.json()
        
    def get_checks(self):
        r = requests.get(self.build_url('host/checks'), params=self.get_payload())
        return r.json()
        
    def get_users(self, su=False):
        payload = self.get_payload()
        if su:
            payload['su'] = True
        r = requests.get(self.build_url('user'), params=payload)
        return r.json()['data']
        
    def create_user(self, username, password, name=False, su=False):
        data = {'username':username,'password':password}
        if name:
            data['name'] = name
        if su:
            data['su'] = su
        r = requests.put(self.build_url('user'), params=self.get_payload(), json=data)
        return r.json()
        
    def update_user(self, user_id, attribs):
        data = attribs
        r = requests.put(self.build_url('user/{}'.format(user_id)), params=self.get_payload(), json=data)
        return r.status_code
        
    def delete_user(self, user_id):
        r = requests.delete(self.build_url('user/{}'.format(user_id)), params=self.get_payload())
        return r.status_code
        
    def get_tokens(self):
        r = requests.get(self.build_url('token'),params=self.get_payload())
        return r.json()['data']
    
    def delete_token(self, token):
        data = {'token':token}
        r = requests.delete(self.build_url('token'),params=self.get_payload(),json=data)
        return r.status_code
        
    def add_token(self, token, description, username):
        data = {'token':token,'description':description,'username':username}
        r = requests.put(self.build_url('token'),params=self.get_payload(),json=data)
        return r.status_code
        
    def get_containers(self):
        r = requests.get(self.build_url('container'),params=self.get_payload())
        return r.json()
        
    def get_container(self,container_name):
        r = requests.get(self.build_url('container/{}'.format(container_name)),params=self.get_payload())
        return r.json()
        
def plain_containers(_list):
    container_list = []
    for container in _list:
        container_list.append(container)
    return container_list 


    
    #~ STATUSES = ('RUNNING', 'FROZEN', 'STOPPED')
    #~ if plain:
        #~ return plain_containers(container_list)
    #~ if by_status:
        #~ containers_status = []
        #~ for status in STATUSES:
            #~ containers_by_status = []
            #~ for container in container_list:
                #~ if container['state'] == status.lower():
                    #~ container_info = {
                        #~ 'name': container['container'],
                        #~ 'settings': lwp.get_container_settings(container['container'], status),
                        #~ 'memusg': 0,
                    #~ }
                    #~ containers_by_status.append(container_info)
            #~ containers_status.append({
                #~ 'status': status.lower(),
                #~ 'containers': containers_by_status
            #~ })
        #~ return container_list, containers_status
    #~ return container_list

@mod.route('/')
@mod.route('/home')
@if_logged_in()
def home():
    """
    Home page function, list containers
    """
    gantry = GantryClient(config)
    host_info = gantry.get_host()
    containers = gantry.get_containers()
    clonable_containers = []
    for container in containers:
        if container['state'] == 'stopped':
            clonable_containers.append(container['container'])
    context = {
        'containers': containers,
        'clonable_containers': clonable_containers,
        'dist': host_info['distribution'],
        'host': host_info['hostname'],
        'templates': lwp.get_templates_list(),
        'storage_repos': storage_repos,
        'auth': AUTH,
    }
    return render_template('index.html', **context)


@mod.route('/about')
@if_logged_in()
def about():
    """
    About page
    """
    gantry = GantryClient(config)
    host_info = gantry.get_host()
    context = {
        'version':host_info['version'],
        'dist':host_info['distribution'],
        'host':host_info['hostname'],
    }
    return render_template('about.html', **context)


@mod.route('/<container_name>/edit', methods=['POST', 'GET'])
@if_logged_in()
def edit(container_name):
    """
    Edit containers page and actions if form post request
    """
    host_memory = lwp.host_memory_usage()
    gantry = GantryClient(config)
    container = gantry.get_container(container_name)
    #~ info = lxc.info(container)
    #~ cfg = lwp.get_container_settings(container, info['state'])
    if request.method == 'POST':
        form = request.form.copy()
        # convert boolean in correct value for lxc, if checkbox is inset value is not submitted inside POST
        form['flags'] = 'up' if 'flags' in form else 'down'
        form['start_auto'] = '1' if 'start_auto' in form else '0'

        # if memlimits/memswlimit is at max values unset form values
        if 'memlimit' in form and int(form['memlimit']) == host_memory['total']:
            form['memlimit'] = ''
        if 'swlimit' in form and int(form['swlimit']) == host_memory['total'] * 2:
            form['swlimit'] = ''

        for option in form.keys():
            # if the key is supported AND is different
            if option in cfg.keys() and form[option] != cfg[option]:
                # validate value with regex
                if re.match(cgroup_ext[option][1], form[option]):
                    lwp.push_config_value(cgroup_ext[option][0], form[option], container=container)
                    flash(cgroup_ext[option][2], 'success')
                else:
                    flash('Cannot validate value for option {}. Unsaved!'.format(option), 'error')

        # we should re-read container configuration now to be coherent with the newly saved values
        cfg = lwp.get_container_settings(container)

        info = lxc.info(container)
    infos = {'status': info['state'], 'pid': info['pid'], 'memusg': lwp.memory_usage(container)}
    # prepare a regex dict from cgroups_ext definition
    regex = {}
    for k, v in cgroup_ext.items():
        regex[k] = v[1]

    snapshots = lxc.snapshots(container)
    context = {
        'all_info': info,
        'snapshots': snapshots,
        'containers': lxc.ls(),
        'container': container,
        'infos': infos,
        'settings': cfg,
        'host_memory': host_memory,
        'storage_repos': storage_repos,
        'regex': regex,
        'clonable_containers': lxc.listx()['STOPPED'],
        'dist': lwp.name_distro(),
        'host': socket.gethostname(),
    }
    return render_template('edit.html', **context)


@mod.route('/settings/lxc-net', methods=['POST', 'GET'])
@if_logged_in()
def lxc_net():
    """
    lxc-net (/etc/default/lxc) settings page and actions if form post request
    """
    if session['su'] != 'Yes':
        return abort(403)

    if request.method == 'POST':
        if lxc.running() == []:
            cfg = lwp.get_net_settings()
            ip_regex = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

            form = {}
            for key in ['bridge', 'address', 'netmask', 'network', 'range', 'max']:
                form[key] = request.form.get(key, None)
            form['use'] = request.form.get('use', None)

            if form['use'] != cfg['use']:
                lwp.push_net_value('USE_LXC_BRIDGE', 'true' if form['use'] else 'false')

            if form['bridge'] and form['bridge'] != cfg['bridge'] and \
                    re.match('^[a-zA-Z0-9_-]+$', form['bridge']):
                lwp.push_net_value('LXC_BRIDGE', form['bridge'])

            if form['address'] and form['address'] != cfg['address'] and \
                    re.match('^%s$' % ip_regex, form['address']):
                lwp.push_net_value('LXC_ADDR', form['address'])

            if form['netmask'] and form['netmask'] != cfg['netmask'] and \
                    re.match('^%s$' % ip_regex, form['netmask']):
                lwp.push_net_value('LXC_NETMASK', form['netmask'])

            if form['network'] and form['network'] != cfg['network'] and \
                    re.match('^%s(?:/\d{1,2}|)$' % ip_regex, form['network']):
                lwp.push_net_value('LXC_NETWORK', form['network'])

            if form['range'] and form['range'] != cfg['range'] and \
                    re.match('^%s,%s$' % (ip_regex, ip_regex), form['range']):
                lwp.push_net_value('LXC_DHCP_RANGE', form['range'])

            if form['max'] and form['max'] != cfg['max'] and \
                    re.match('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', form['max']):
                lwp.push_net_value('LXC_DHCP_MAX', form['max'])

            if lwp.net_restart() == 0:
                flash(u'LXC Network settings applied successfully!', 'success')
            else:
                flash(u'Failed to restart LXC networking.', 'error')
        else:
            flash(u'Stop all containers before restart lxc-net.', 'warning')
    return render_template('lxc-net.html', containers=lxc.ls(), cfg=lwp.get_net_settings(), running=lxc.running(), dist=lwp.name_distro(), host=socket.gethostname())


@mod.route('/lwp/users', methods=['POST', 'GET'])
@if_logged_in()
def lwp_users():
    """
    Returns users and get posts request : can edit or add user in page.
    this funtction uses sqlite3
    """
    if session['su'] != 'Yes':
        return abort(403)

    if AUTH != 'database':
        return abort(403, 'You are using an auth method other that database.')

    try:
        trash = request.args.get('trash')
    except KeyError:
        trash = 0
    gantry = GantryClient(config)
    users = gantry.get_users()
    su_users = []
    for u in users:
        if u['su'] == 'Yes':
            su_users.append(u)
    if request.args.get('token') == session.get('token') and int(trash) == 1 and request.args.get('userid') and \
            request.args.get('username'):
        if len(users) > 1:
            if len(su_users) == 1:
                if su_users[0]['username'] == request.args.get('username'):
                    flash(u'Can\'t delete the last admin user : %s' % request.args.get('username'), 'error')
                    return redirect(url_for('main.lwp_users'))
            gantry.delete_user(user_id=request.args.get('userid'))
            flash(u'Deleted %s' % request.args.get('username'), 'success')
            return redirect(url_for('main.lwp_users'))

        flash(u'Can\'t delete the last user!', 'error')
        return redirect(url_for('main.lwp_users'))

    if request.method == 'POST':
        if request.form['newUser'] == 'True':
            if not request.form['username'] in [user['username'] for user in users]:
                if re.match('^\w+$', request.form['username']) and request.form['password1']:
                    if request.form['password1'] == request.form['password2']:
                        if request.form['name']:
                            if re.match('[a-z A-Z0-9]{3,32}', request.form['name']):
                                gantry.create_user(
                                    name=request.form['name'],
                                    username=request.form['username'],
                                    password=hash_passwd(request.form['password1'])
                                )
                            else:
                                flash(u'Invalid name!', 'error')
                        else:
                            gantry.create_user(
                                username=request.form['username'],
                                password=hash_passwd(request.form['password1'])
                            )
                        users = gantry.get_users()
                        su_users = []
                        for u in users:
                            if u['su'] == Yes:
                                su_users.append(u)
                        flash(u'Created %s' % request.form['username'], 'success')
                    else:
                        flash(u'No password match', 'error')
                else:
                    flash(u'Invalid username or password!', 'error')
            else:
                flash(u'Username already exist!', 'error')

        elif request.form['newUser'] == 'False':
            if re.match('[a-z A-Z0-9]{3,32}', request.form['name']):
                if len(su_users) <= 1:
                    su = 'Yes'
                else:
                    try:
                        su = request.form['su']
                    except KeyError:
                        su = 'No'
                update_user = {
                    'user_id':request.form['id'],
                    'username':request.form['username'],
                    'name':request.form.get('name',request.form['username']),
                    'su': su,
                }
                if request.form['password1'] and request.form['password2'] and request.form['password1'] == request.form['password2']:
                    update_user['password'] = hash_passwd(request.form['password1'])
                elif request.form['password1'] and request.form['password2'] and request.form['password1'] != request.form['password2']:
                    flash(u'No password match. Not changed', 'error')
                print(update_user)
                gantry.update_user(request.form['id'],update_user)
                users = gantry.get_users()
                su_users = []
                for u in users:
                    if u['su'] == Yes:
                        su_users.append(u)
                flash(u'Updated', 'success')
            else:
                flash(u'Invalid name!', 'error')
            
        else:
            flash(u'Unknown error!', 'error')
    context = {
        'users': users,
        'su_users': su_users,
    }
    return render_template('users.html', **context)


@mod.route('/lwp/tokens', methods=['POST', 'GET'])
@if_logged_in()
def lwp_tokens():
    """
    Returns api tokens info and get posts request: can show/delete or add token in page.
    this function uses sqlite3, require admin privilege
    """
    if session['su'] != 'Yes':
        return abort(403)
    gantry = GantryClient(config)
    tokens = gantry.get_tokens()
    if request.method == 'POST':
        if request.form['action'] == 'add':
            # we want to add a new token
            token = request.form['token']
            description = request.form['description']
            username = session['username']  # we should save the username due to ldap option
            #~ ApiTokens.create(username=username,description=description,token=token)
            gantry.add_token(token,description,username)
            #~ g.db.execute("INSERT INTO api_tokens (username, token, description) VALUES(?, ?, ?)", [username, token,
                                                                                                   #~ description])
            #~ g.db.commit()
            tokens = gantry.get_tokens()
            flash(u'Token %s successfully added!' % token, 'success')

    if request.args.get('action') == 'del':
        token = request.args['token']
        gantry.delete_token(token)
        #~ g.db.execute("DELETE FROM api_tokens WHERE token=?", [token])
        #~ g.db.commit()
        tokens = gantry.get_tokens()
        flash(u'Token %s successfully deleted!' % token, 'success')
        return redirect(url_for('main.lwp_tokens'))
    #~ tokens = query_db("SELECT description, token, username FROM api_tokens ORDER BY token DESC")
    #~ tokens = get_tokens()
    context = {
        'tokens': tokens,
        
    }
    return render_template('tokens.html', **context)
    #~ return render_template('tokens.html', containers=lxc.ls(), tokens=tokens, dist=lwp.name_distro(), host=socket.gethostname())


@mod.route('/checkconfig')
@if_logged_in()
def checkconfig():
    """
    Returns the display of lxc-checkconfig command
    """
    if session['su'] != 'Yes':
        return abort(403)
    gantry = GantryClient(config)
    host = gantry.get_host()
    checks = gantry.get_checks()
    print(checks)
    context = {
        'host': host,
        'checks': checks['checks'],
        #~ 'containers': lxc.ls(),
        #~ 'cfg': lxc.checkconfig(),
        #~ 'dist': lwp.name_distro(),
        #~ 'host': socket.gethostname(),
    }
    return render_template('checkconfig.html', **context)


@mod.route('/action', methods=['GET'])
@if_logged_in()
def action():
    """
    Manage all actions related to containers
    lxc-start, lxc-stop, etc...
    """
    act = request.args['action']
    name = request.args['name']
    
    # TODO: refactor this method, it's horrible to read
    if act == 'start':
        try:
            
            if lxc.start(name) == 0:
                time.sleep(1)  # Fix bug : "the container is randomly not displayed in overview list after a boot"
                flash(u'Container %s started successfully!' % name, 'success')
            else:
                flash(u'Unable to start %s!' % name, 'error')
        except lxc.ContainerAlreadyRunning:
            flash(u'Container %s is already running!' % name, 'error')
    elif act == 'stop':
        try:
            if lxc.stop(name) == 0:
                flash(u'Container %s stopped successfully!' % name, 'success')
            else:
                flash(u'Unable to stop %s!' % name, 'error')
        except lxc.ContainerNotRunning:
            flash(u'Container %s is already stopped!' % name, 'error')
    elif act == 'freeze':
        try:
            if lxc.freeze(name) == 0:
                flash(u'Container %s frozen successfully!' % name, 'success')
            else:
                flash(u'Unable to freeze %s!' % name, 'error')
        except lxc.ContainerNotRunning:
            flash(u'Container %s not running!' % name, 'error')
    elif act == 'unfreeze':
        try:
            if lxc.unfreeze(name) == 0:
                flash(u'Container %s unfrozen successfully!' % name, 'success')
            else:
                flash(u'Unable to unfeeze %s!' % name, 'error')
        except lxc.ContainerNotRunning:
            flash(u'Container %s not frozen!' % name, 'error')
    elif act == 'destroy':
        if session['su'] != 'Yes':
            return abort(403)
        try:
            if lxc.destroy(name) == 0:
                flash(u'Container %s destroyed successfully!' % name, 'success')
            else:
                flash(u'Unable to destroy %s!' % name, 'error')
        except lxc.ContainerDoesntExists:
            flash(u'The Container %s does not exists!' % name, 'error')
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
    elif act == 'push':
        # TODO: implement push action
        pass
    try:
        if request.args['from'] == 'edit':
            return redirect(url_for('main.edit', container=name))
        else:
            return redirect(url_for('main.home'))
    except KeyError:
        return redirect(url_for('main.home'))


@mod.route('/action/create-container', methods=['GET', 'POST'])
@if_logged_in()
def create_container():
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


@mod.route('/action/snapshot-container', methods=['GET', 'POST'])
@if_logged_in()
def snapshot_container():
    """
    Operations on snapshots, create, delete, restore
    """
    operation_message = False
    if session['su'] != 'Yes':
        return abort(403)
    if request.method == 'POST':
        name = request.form['name']
        delete_snapshot = request.form.get('delete_snapshot', False)
        restore_snapshot = request.form.get('restore_snapshot', False)
        if delete_snapshot:
            restore_snapshot = False
        if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
            out = None

            try:
                out = lxc.snapshot(name,delete_snapshot=delete_snapshot,restore_snapshot=restore_snapshot)
            except lxc.SnapshotError:
                operation_message = u'Error with snapshot for {}!'.format(name)
                flash(operation_message, 'error')
                
            if out and out == 0:
                operation_message = u'Operation on snapshot for container {}'.format(name)
                flash(operation_message, 'success')
            elif out and out != 0:
                operation_message = u'Failed operation snapshot for {}!'.format(name)
                flash(operation_message, 'error')

        else:
            if name == '':
                flash(u'Please enter a container name!', 'error')
            else:
                flash(u'Invalid name for \"%s\"!' % name, 'error')    
    snapshots = lxc.snapshots(name)
    return render_template('snapshots.html', container=name, snapshots=snapshots, operation_message=operation_message)

    
@mod.route('/action/copy-container', methods=['GET', 'POST'])
@if_logged_in()
def copy_container():
    """
    Verify all forms to copy a container
    """
    if session['su'] != 'Yes':
        return abort(403)
    if request.method == 'POST':
        orig = request.form['orig']
        name = request.form['name']
        if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
            out = None

            try:
                out = lxc.copy(orig=orig, new=name)
            except lxc.ContainerAlreadyExists:
                flash(u'The Container %s already exists!' % name, 'error')
            except subprocess.CalledProcessError:
                flash(u'Can\'t copy a directory', 'error')

            if out and out == 0:
                flash(u'Container %s copy into %s successfully!' % (orig, name), 'success')
            elif out and out != 0:
                flash(u'Failed to copy %s into %s!' % (orig, name), 'error')

        else:
            if name == '':
                flash(u'Please enter a container name!', 'error')
            else:
                flash(u'Invalid name for \"%s\"!' % name, 'error')

    return redirect(url_for('main.home'))


@mod.route('/action/backup-container', methods=['GET', 'POST'])
@if_logged_in()
def backup_container():
    """
    Verify the form to backup a container
    """
    if request.method == 'POST':
        container = request.form['orig']
        sr_type = request.form['dest']

        sr_path = None
        for sr in storage_repos:
            if sr_type in sr:
                sr_path = sr[1]
                break
                
        backup_failed = True
        
        try:
            backup_file = lxc.backup(container=container, sr_type=sr_type, destination=sr_path)
            backup_failed = False
        except lxc.ContainerDoesntExists:
            flash(u'The Container %s does not exist !' % container, 'error')
        except lxc.DirectoryDoesntExists:
            flash(u'Local backup directory "%s" does not exist !' % sr_path, 'error')
        except lxc.NFSDirectoryNotMounted:
            flash(u'NFS repository "%s" not mounted !' % sr_path, 'error')
        except subprocess.CalledProcessError:
            flash(u'Error during transfert !', 'error')
        except:
            flash(u'Error during transfert !', 'error')

        if backup_failed is not True:
            flash(u'Container %s backed up successfully' % container, 'success')
        else:
            flash(u'Failed to backup %s container' % container, 'error')

    return redirect(url_for('main.home'))


@mod.route('/_refresh_info')
@if_logged_in()
def refresh_info():
    context = {
        'cpu': lwp.host_cpu_percent(),
        'uptime': lwp.host_uptime(),
        'disk': lwp.host_disk_usage()
    }
    return jsonify(**context)


@mod.route('/_refresh_memory_<name>')
@if_logged_in()
def refresh_memory_containers(name=None):
    if name == 'containers':
        containers_running = lxc.running()
        containers = []
        for container in containers_running:
            container = container.replace(' (auto)', '')
            containers.append({'name': container, 'memusg': lwp.memory_usage(container),
                               'settings': lwp.get_container_settings(container)})
        return jsonify(data=containers)
    elif name == 'host':
        return jsonify(lwp.host_memory_usage())
    return jsonify({'memusg': lwp.memory_usage(name)})


@mod.route('/_check_version')
@if_logged_in()
def check_version():
    print(lwp.check_version())
    return jsonify(lwp.check_version())
