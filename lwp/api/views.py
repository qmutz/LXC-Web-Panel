# -*- coding: utf-8 -*-
#~ from __future__ import absolute_import, print_function
import socket
import json
import subprocess   
import lxc
from configobj import ConfigObj
from playhouse.shortcuts import model_to_dict, dict_to_model
from flask import Blueprint, request, g, jsonify
import lwp
from lwp.decorators import api_auth
from lwp.utils import ContainerSchema
from lwp.database.models import ApiTokens, Users, Projects, Containers, Hosts
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
        'memory': lwp.host_memory_usage(),
        'cpu': lwp.host_cpu_percent(),
        'disk': lwp.host_disk_usage(),
        'uptime': lwp.host_uptime(),
    }
    return jsonify(info)


@mod.route('/api/v1/host/checks/')
@api_auth()
def get_host_checks():
    """
    Returns lxc configuration checks.
    """
    import lxc
    out = subprocess.check_output('lxc-checkconfig', shell=True)
    response = []
    if out:
        for line in out.splitlines():
            response.append(line.decode('utf-8'))    
    info = {
        'checks': response,
    }
    return jsonify(info)

@mod.route('/api/v1/project/')
@api_auth()
def get_projects():
    """
    Returns projects on the current machine and brief status information.
        title = CharField()
    description = TextField(null=True)
    admin = ForeignKeyField(Users)
    created_date = DateTimeField(default=datetime.datetime.now)
    active = BooleanField(default=True)
    """
    _list = []
    results = Projects.select()
    if len(results) == 0:
        admin = Users.get(Users.name=='admin')
        Projects.create(title='Default',description='Default project to start with',admin=admin)
    for obj in results:
        _list.append(model_to_dict(obj))
    return jsonify(status="ok", data=_list), 200
    #~ for c in lxc.list_containers():
        #~ container = lxc.Container(c)
        #~ schema = ContainerSchema()
        #~ result = schema.dump(container)
        #~ _list.append(result[0])
    #~ return jsonify(_list)
    
@mod.route('/api/v1/container/')
@api_auth()
def get_containers():
    """
    Returns lxc containers on the current machine and brief status information.
    """
    _list = []
    for c in lxc.list_containers():
        container = lxc.Container(c)
        schema = ContainerSchema()
        result = schema.dump(container)
        _list.append(result[0])
    return jsonify(_list)



@mod.route('/api/v1/container/<name>/')
@api_auth()
def get_container(name):
    container = lxc.Container(name)
    schema = ContainerSchema()
    result = schema.dump(container)
    return jsonify(result[0])


@mod.route('/api/v1/container/config/<name>/', methods=['POST'])
@api_auth()
def configure_container(name):
    container = lxc.Container(name)
    data = request.get_json(force=True)
    if data is None:
        return jsonify({'status':"error", 'error':"Bad request"}), 400
    container_config = ConfigObj(container.config_file_name)
    for option, value in data.items():
        if len(value) > 0:
            if option.startswith('lxc.') is False:
                option = 'lxc.{}'.format(option)
            container_config[option] = value
            container_config.write()
    result = ContainerSchema().dump(lxc.Container(name))
    return jsonify(result[0])


@mod.route('/api/v1/container/state/<name>/', methods=['POST'])
@api_auth()
def container_state(name):
    data = request.get_json(force=True)
    if data is None:
        return jsonify(status="error", error="Bad request"), 400
    container = lxc.Container(name)
    action = data['action']
    if action == "stop" and container.running:
        container.stop()
        container.wait("STOPPED", 3)
    elif action == "start" and not container.running:
        container.start()
        container.wait("RUNNING", 3)
    elif action == "freeze" and container.running:
        container.freeze()
        container.wait("FREEZE", 3)
    elif action == "unfreeze" and container.state == 'FROZEN':
        container.unfreeze()
        container.wait("UNFREEZE", 3)
    return jsonify(state=container.state), 200
    

@mod.route('/api/v1/container/operation/<name>/', methods=['POST'])
@api_auth()
def container_operation(name):
    data = request.get_json(force=True)
    if data is None:
        return jsonify(status="error", error="Bad request"), 400
    container = lxc.Container(name)
    operation = data['operation']
    if operation == "destroy":
        container.destroy()
    elif operation == "copy" and 'new_name' in data:
        clone = container.clone(data['new_name'])
    elif operation == "snapshot_create":
        container.snapshot()
    elif operation == "snapshot_restore" and 'snapshot_name' in data:
        container.snapshot_restore(data['snapshot_name'])
    elif operation == "snapshot_destroy" and 'snapshot_name' in data:
        container.snapshot_destroy(data['snapshot_name'])
    return jsonify(state=container.state), 200


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
