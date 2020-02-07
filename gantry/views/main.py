# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function
import os
import re
import time
import socket
import subprocess
#~ import requests
from flask import Blueprint, request, session, g, redirect, url_for, abort, render_template, flash, jsonify
from flask import current_app as app
import lwp
#~ import pantry.lxclite as lxc
from pantry.utils import hash_passwd, cgroup_ext
from pantry.config import read_config_file
from pantry.decorators import if_logged_in
from pantry.views.auth import AUTH
from pantry.api.client import GantryClient

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

#~ api_prefix = '/api/v1'

#~ payload = {'private_token':private_token}



def plain_containers(_list):
    container_list = []
    for container in _list:
        container_list.append(container)
    return container_list


@mod.route('/about')
@if_logged_in()
def about():
    """ About page
    """
    gantry = GantryClient(config)
    host_info = g.api.get_host()
    context = {
        'version':host_info['version'],
        'dist':host_info['distribution'],
        'host':host_info['hostname'],
    }
    return render_template('about.html', **context)





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
            cfg = pantry.get_net_settings()
            ip_regex = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

            form = {}
            for key in ['bridge', 'address', 'netmask', 'network', 'range', 'max']:
                form[key] = request.form.get(key, None)
            form['use'] = request.form.get('use', None)

            if form['use'] != cfg['use']:
                pantry.push_net_value('USE_LXC_BRIDGE', 'true' if form['use'] else 'false')

            if form['bridge'] and form['bridge'] != cfg['bridge'] and \
                    re.match('^[a-zA-Z0-9_-]+$', form['bridge']):
                pantry.push_net_value('LXC_BRIDGE', form['bridge'])

            if form['address'] and form['address'] != cfg['address'] and \
                    re.match('^%s$' % ip_regex, form['address']):
                pantry.push_net_value('LXC_ADDR', form['address'])

            if form['netmask'] and form['netmask'] != cfg['netmask'] and \
                    re.match('^%s$' % ip_regex, form['netmask']):
                pantry.push_net_value('LXC_NETMASK', form['netmask'])

            if form['network'] and form['network'] != cfg['network'] and \
                    re.match('^%s(?:/\d{1,2}|)$' % ip_regex, form['network']):
                pantry.push_net_value('LXC_NETWORK', form['network'])

            if form['range'] and form['range'] != cfg['range'] and \
                    re.match('^%s,%s$' % (ip_regex, ip_regex), form['range']):
                pantry.push_net_value('LXC_DHCP_RANGE', form['range'])

            if form['max'] and form['max'] != cfg['max'] and \
                    re.match('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', form['max']):
                pantry.push_net_value('LXC_DHCP_MAX', form['max'])

            if pantry.net_restart() == 0:
                flash(u'LXC Network settings applied successfully!', 'success')
            else:
                flash(u'Failed to restart LXC networking.', 'error')
        else:
            flash(u'Stop all containers before restart lxc-net.', 'warning')
    return render_template('lxc-net.html', containers=lxc.ls(), cfg=pantry.get_net_settings(), running=lxc.running(), dist=pantry.name_distro(), host=socket.gethostname())


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
    users = g.api.get_users()
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
            g.api.delete_user(user_id=request.args.get('userid'))
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
                                g.api.create_user(
                                    name=request.form['name'],
                                    username=request.form['username'],
                                    password=hash_passwd(request.form['password1'])
                                )
                            else:
                                flash(u'Invalid name!', 'error')
                        else:
                            g.api.create_user(
                                username=request.form['username'],
                                password=hash_passwd(request.form['password1'])
                            )
                        users = g.api.get_users()
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
                g.api.update_user(request.form['id'],update_user)
                users = g.api.get_users()
                su_users = []
                for u in users:
                    if u['su'] == 'Yes':
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
    tokens = g.api.get_tokens()
    if request.method == 'POST':
        if request.form['action'] == 'add':
            token = request.form['token']
            description = request.form['description']
            username = session['username']  # we should save the username due to ldap option
            g.api.add_token(token,description,username)
            tokens = g.api.get_tokens()
            flash(u'Token %s successfully added!' % token, 'success')

    if request.args.get('action') == 'del':
        token = request.args['token']
        g.api.delete_token(token)
        tokens = g.api.get_tokens()
        flash(u'Token %s successfully deleted!' % token, 'success')
        return redirect(url_for('main.lwp_tokens'))
    context = {
        'tokens': tokens,

    }
    return render_template('tokens.html', **context)


@mod.route('/checkconfig')
@if_logged_in()
def checkconfig():
    """
    Returns the display of lxc-checkconfig command
    """
    if session['su'] != 'Yes':
        return abort(403)
    gantry = GantryClient(config)
    host = g.api.get_host()
    checks = g.api.get_checks()
    print(checks)
    context = {
        'host': host,
        'checks': checks['checks'],
    }
    return render_template('checkconfig.html', **context)








#~ @mod.route('/action/snapshot-container', methods=['GET', 'POST'])
#~ @if_logged_in()
#~ def candeletesnapshot_container():
    #~ """
    #~ Operations on snapshots, create, delete, restore
    #~ """
    #~ operation_message = False
    #~ if session['su'] != 'Yes':
        #~ return abort(403)
    #~ if request.method == 'POST':
        #~ name = request.form['name']
        #~ delete_snapshot = request.form.get('delete_snapshot', False)
        #~ restore_snapshot = request.form.get('restore_snapshot', False)
        #~ if delete_snapshot:
            #~ restore_snapshot = False
        #~ if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
            #~ out = None
            #~ try:
                #~ out = lxc.snapshot(name,delete_snapshot=delete_snapshot,restore_snapshot=restore_snapshot)
            #~ except lxc.SnapshotError:
                #~ operation_message = u'Error with snapshot for {}!'.format(name)
                #~ flash(operation_message, 'error')

            #~ if out and out == 0:
                #~ operation_message = u'Operation on snapshot for container {}'.format(name)
                #~ flash(operation_message, 'success')
            #~ elif out and out != 0:
                #~ operation_message = u'Failed operation snapshot for {}!'.format(name)
                #~ flash(operation_message, 'error')

        #~ else:
            #~ if name == '':
                #~ flash(u'Please enter a container name!', 'error')
            #~ else:
                #~ flash(u'Invalid name for \"%s\"!' % name, 'error')
    #~ snapshots = lxc.snapshots(name)
    #~ return render_template('snapshots.html', container=name, snapshots=snapshots, operation_message=operation_message)


#~ @mod.route('/action/copy-container', methods=['GET', 'POST'])
#~ @if_logged_in()
#~ def copy_container():
    #~ """
    #~ Verify all forms to copy a container
    #~ """
    #~ if session['su'] != 'Yes':
        #~ return abort(403)
    #~ if request.method == 'POST':
        #~ orig = request.form['orig']
        #~ name = request.form['name']
        #~ if re.match('^(?!^containers$)|[a-zA-Z0-9_-]+$', name):
            #~ out = None

            #~ try:
                #~ out = lxc.copy(orig=orig, new=name)
            #~ except lxc.ContainerAlreadyExists:
                #~ flash(u'The Container %s already exists!' % name, 'error')
            #~ except subprocess.CalledProcessError:
                #~ flash(u'Can\'t copy a directory', 'error')

            #~ if out and out == 0:
                #~ flash(u'Container %s copy into %s successfully!' % (orig, name), 'success')
            #~ elif out and out != 0:
                #~ flash(u'Failed to copy %s into %s!' % (orig, name), 'error')

        #~ else:
            #~ if name == '':
                #~ flash(u'Please enter a container name!', 'error')
            #~ else:
                #~ flash(u'Invalid name for \"%s\"!' % name, 'error')

    #~ return redirect(url_for('main.home'))


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
            flash(u'The Container %s does not exist !' % container, 'danger')
        except lxc.DirectoryDoesntExists:
            flash(u'Local backup directory "%s" does not exist !' % sr_path, 'danger')
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

    return redirect(url_for('dashboard.home'))


@mod.route('/_refresh_info')
@if_logged_in()
def refresh_info():
    context = {
        'cpu': pantry.host_cpu_percent(),
        'uptime': pantry.host_uptime(),
        'disk': pantry.host_disk_usage()
    }
    return jsonify(**context)


@mod.route('/_check_version')
@if_logged_in()
def check_version():
    #~ gantry = GantryClient(config)
    host = g.api.get_host()
    return jsonify(host['version'])
