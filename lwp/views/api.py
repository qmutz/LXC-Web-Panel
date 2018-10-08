# -*- coding: utf-8 -*-
#~ from __future__ import absolute_import, print_function
import socket
import json

from flask import Blueprint, request, g, jsonify
import lwp
import lwp.lxclite as lxc
from lwp.decorators import api_auth
from playhouse.shortcuts import model_to_dict, dict_to_model
from lwp.database.models import ApiTokens, Users

# Flask module
mod = Blueprint('api', __name__)


@mod.route('/api/v1/host/')
@api_auth()
def get_host_info():
    """
    Returns lxc containers on the current machine and brief status information.
    """
    info = {
        'hostname': socket.gethostname(),
        'distribution': lwp.name_distro(),
        'version': lwp.check_version(),
        'network': lwp.get_net_settings(),
    }
    return jsonify(info)


@mod.route('/api/v1/host/checks/')
@api_auth()
def get_host_checks():
    """
    Returns lxc configuration checks.
    """
    info = {
        'checks': lxc.checkconfig(),
    }
    return jsonify(info)

import subprocess   
from marshmallow import Schema, fields, pprint
class ContainerSchema(Schema):
    name = fields.Str()
    state = fields.Str()
    init_pid = fields.Str()
    config_file_name = fields.Str()
    #~ interfaces = fields.List(fields.String)
    interfaces = fields.Function(lambda obj: obj.get_interfaces())
    snapshots = fields.Function(lambda obj: obj.snapshots_list())
    ips = fields.Function(lambda obj: obj.get_ips())
    #~ max_mem = fields.Function(lambda obj: obj.get_cgroup_item("memory.limit_in_bytes"))
    runtime = fields.Method('get_runtime_values')
    settings = fields.Method('get_settings')
    os_release = fields.Method('get_os_release')
    
    def get_os_release(self, obj):
        release_files = ('os-release','lsb-release','fedora-release','redhat-release','centos-release','plamo-release')
        output = False
        for release_file in release_files:
            cmd = "cat {}/etc/{}".format(obj.get_config_item('lxc.rootfs'),release_file)
            try:
                output = subprocess.check_output(cmd, shell=True)
            except: pass
            if output:
                return format_release(output)
                
    def get_runtime_values(self, obj):
        cgroups = ['memory.limit_in_bytes','memory.usage_in_bytes']
        to_int = ['memory.limit_in_bytes','memory.usage_in_bytes']
        values = {
            'memory.usage_in_bytes':0,
        }
        for cgroup in cgroups:
            try:
                values[cgroup] = obj.get_cgroup_item(cgroup)
            except: pass
        #~ print(values)
        for to_int_key in to_int:
            if to_int_key in values:
                values[to_int_key] = int(values[to_int_key])
        return values
        
    def get_settings(self, obj):
        network_settings = ['lxc.network.type','lxc.network.link','lxc.network.flags','lxc.network.hwaddr','lxc.network.ipv4']
        settings = ['lxc.rootfs','lxc.rootfs.backend','lxc.tty','lxc.utsname','lxc.arch','lxc.loglevel','lxc.start.auto']
        values = {}
        for setting in settings:
            #~ print(obj.name, setting)
            values[setting.replace('lxc.','')] = obj.get_config_item(setting)
        values['networks'] = {}
        count = 0
        networks = set(obj.get_config_item('lxc.network'))
        for network in networks:
            values['networks'][network] = {}
            for nk in network_settings:
                new_key = nk.replace('lxc.network.','lxc.network.{}.'.format(count))        
                values['networks'][network][nk.replace('lxc.network.','')] = obj.get_config_item(new_key)
            count +=1
        return values

def format_release(output):
    if 'NAME' in output.decode():
        release = {}
        for line in output.decode().split('\n'):
            if '=' in line:
                splitted = line.split('=')
                release[splitted[0]] = splitted[1].replace('"','')
            #~ print(line)
    
    else:
        release = {'PRETTY_NAME':output.decode().strip()}
    return release
    
@mod.route('/api/v1/container/')
@api_auth()
def get_containers():
    """
    Returns lxc containers on the current machine and brief status information.
    """
    import lxc

    #~ list_container = []
    _list = []
    for c in lxc.list_containers():
        container = lxc.Container(c)
        schema = ContainerSchema()
        result = schema.dump(container)
        #~ pprint(result)
        #~ print(result.data['settings'])

        #~ if container.running:
            #~ osrelease = container.attach_wait(lxc.attach_run_command, ["cat", "/etc/os-release"])
            #~ print(osrelease)
        _list.append(result[0])
    return jsonify(_list)
    
@mod.route('/api/v1/container/<name>/')
@api_auth()
def get_container(name):
    import lxc
    container = lxc.Container(name)
    schema = ContainerSchema()
    result = schema.dump(container)
    return jsonify(result[0])

#~ @mod.route('/api/v1/container/<name>/')
#~ @api_auth()
#~ def get_container(name):
    #~ return jsonify(lxc.info(name))


@mod.route('/api/v1/container/<name>/', methods=['POST'])
@api_auth()
def post_container(name):
    data = request.get_json(force=True)
    if data is None:
        return jsonify(status="error", error="Bad request"), 400

    status = data['action']
    try:
        if status == "stop":
            lxc.stop(name)
            return jsonify(status="ok"), 200
        elif status == "start":
            lxc.start(name)
            return jsonify(status="ok"), 200
        elif status == "freeze":
            lxc.freeze(name)
            return jsonify(status="ok"), 200

        return jsonify(status="error", error="Bad request"), 400
    except lxc.ContainerDoesntExists:
        return jsonify(status="error", error="Container doesn' t exists"), 409


@mod.route('/api/v1/container/', methods=['PUT'])
@api_auth()
def add_container():
    data = request.get_json(force=True)
    if data is None:
        return jsonify(status="error", error="Bad request"), 400

    if (not(('template' in data) or ('clone' in data)) or ('name' not in data)):
        return jsonify(status="error", error="Bad request"), 402

    if 'template' in data:
        # we want a new container
        if 'store' not in data:
            data['store'] = ""
        if 'xargs' not in data:
            data['xargs'] = ""

        try:
            lxc.create(data['name'], data['template'], data['store'], data['xargs'])
        except lxc.ContainerAlreadyExists:
            return jsonify(status="error", error="Container yet exists"), 409
    else:
        # we want to clone a container
        try:
            lxc.clone(data['clone'], data['name'])
        except lxc.ContainerAlreadyExists:
            return jsonify(status="error", error="Container yet exists"), 409
    return jsonify(status="ok"), 200


@mod.route('/api/v1/container/<name>/', methods=['DELETE'])
@api_auth()
def delete_container(name):
    try:
        lxc.destroy(name)
        return jsonify(status="ok"), 200
    except lxc.ContainerDoesntExists:
        return jsonify(status="error", error="Container doesn' t exists"), 400


@mod.route('/api/v1/token/', methods=['GET'])
@api_auth()
def list_tokens():
    results = ApiTokens.select()
    _list = []
    for obj in results:
        _list.append(model_to_dict(obj))
    return jsonify(status="ok", data=_list), 200


@mod.route('/api/v1/token/', methods=['POST','PUT'])
@api_auth()
def add_token():
    data = request.get_json(force=True)
    if data is None or 'token' not in data:
        return jsonify(status="error", error="Bad request"), 400
    if 'description' not in data:
        data.update(description="no description")
    ApiTokens.create(description=data['description'],token=data['token'],username=data['username'])
    return jsonify(status="ok"), 200


@mod.route('/api/v1/token/', methods=['DELETE'])
@api_auth()
def delete_token():
    data = request.get_json(force=True)
    if data is None or 'token' not in data:
        return jsonify(status="error", error="Bad request"), 400
    results = ApiTokens.delete().where(ApiTokens.token == data['token']).limit(1)
    if len(results) > 0:
        results.execute()
    return jsonify(status="ok"), 200


@mod.route('/api/v1/user/', methods=['GET'])
@api_auth()
def list_users():
    su = request.args.get('su',False)
    _list = []
    if su:
        results = Users.select().where(Users.su == 'Yes')
    else:
        results = Users.select()
    for obj in results:
        _list.append(model_to_dict(obj))
    return jsonify(status="ok", data=_list), 200


@mod.route('/api/v1/user/', methods=['POST','PUT'])
@api_auth()
def create_user():
    data = request.get_json(force=True)
    if data is None or 'username' not in data:
        return jsonify(status="error", error="Bad request"), 400
    if 'name' not in data:
        data.update(name=data['username'])
    if 'su' not in data:
        data['su'] = False
    q = Users.create(name=data['name'],username=data['username'],password=data['password'],su=data['su'])
    return jsonify(status="ok"), 200

@mod.route('/api/v1/user/<user_id>/', methods=['POST','PUT'])
@api_auth()
def update_user(user_id):
    data = request.get_json(force=True)
    user = Users.get(Users.id ==user_id)
    if user:
        user.name = data['name']
        user.su = data['su']
        if 'password' in data:
            user.password = data['password']
        user.save()
    return jsonify(status="ok"), 200

@mod.route('/api/v1/user/<user_id>/', methods=['DELETE'])
@api_auth()
def delete_user(user_id):
    results = Users.delete().where(Users.id ==user_id).limit(1)
    if len(results) > 0:
        results.execute()
    return jsonify(status="ok"), 200
