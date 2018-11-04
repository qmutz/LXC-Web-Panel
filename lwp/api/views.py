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

def mix_container(obj, container):
    _dict = model_to_dict(obj)
    schema = ContainerSchema()
    dumped = schema.dump(container)
    for key, value in dumped.items():
        _dict[key] = value
    return _dict
    
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
    
@mod.route('/api/v1/host/hydrate/')
@api_auth()
def hydrate_system():
    """
    Checks for unmanaged hosts and containers in db.
    """
    #~ print("hydrating...")
    hosts = Hosts.select()
    admin = Users.get(Users.username=='admin')
    containers_in_db = Containers.select()
    containers_in_host = lxc.list_containers()
    print(len(containers_in_db),len(containers_in_host))
    if len(containers_in_host) > len(containers_in_db):
        for cih in containers_in_host:
            #~ print(cih)
            search = Containers.select().where(Containers.name==cih)
            if len(search) == 0:
                container = Containers.create(name=cih,host=host,admin=admin)
    
    return jsonify({})

"""
class Hosts(BaseModel):
    hostname = CharField()
    api_user = CharField(null=True)
    api_token = CharField(null=True)
    admin = ForeignKeyField(Users)
    active = BooleanField(default=True)
    is_available = BooleanField(default=True)
        

    name = CharField()
    host = ForeignKeyField(Hosts)
    admin = ForeignKeyField(Users)
    locked = BooleanField(default=False)
    project = ForeignKeyField(Projects, null=True)
    created_date = DateTimeField(default=datetime.datetime.now)
"""
@mod.route('/api/v1/project/')
@api_auth()
def get_projects():
    """
    Returns projects.
        title = CharField()
    description = TextField(null=True)
    admin = ForeignKeyField(Users)
    created_date = DateTimeField(default=datetime.datetime.now)
    active = BooleanField(default=True)
    """
    _list = []
    results = Projects.select()
    if len(results) == 0:
        admin = Users.get(Users.username=='admin')
        Projects.create(title='Default',description='Default project to start with',admin=admin)
        results = Projects.select()
    for obj in results:
        _list.append(model_to_dict(obj))
    return jsonify(status="ok", objects=_list), 200


@mod.route('/api/v1/project/<id>/')
@api_auth()
def get_project(id):
    """
    Returns project and attached containers.
    """
    project = Projects.get(Projects.id ==id)
    if not project:
        return jsonify({'status':"error", 'error':"Not found"}), 404
    objects = model_to_dict(project)
    objects['containers'] = []
    for c in project.get_containers():
        _dict = mix_container(c, lxc.Container(c.name))
        objects['containers'].append(_dict)
    return jsonify(status="ok", objects=objects), 200

@mod.route('/api/v1/project/<id>/assign/', methods=['POST'])
@api_auth()
def assign_project(id):
    """
    Assigns to project a container.
    """
    project = Projects.get(Projects.id ==id)
    if not project:
        return jsonify({'status':"error", 'error':"Not found"}), 404
    data = request.get_json(force=True)
    container = Containers.get(Containers.name == data['container'])
    container.project = project
    container.save()
    return jsonify(status="ok", data=model_to_dict(container)), 200
    
@mod.route('/api/v1/project/<id>/deassign/', methods=['DELETE'])
@api_auth()
def deassign_project(id):
    """
    Deassigns all containers from project.
    """
    project = Projects.get(Projects.id ==id)
    if not project:
        return jsonify({'status':"error", 'error':"Not found"}), 404
    #~ data = request.get_json(force=True)
    #~ containers = Containers.select().where(Containers.project == project)
    for container in Containers.select().where(Containers.project == project):
        container.project = False
        container.save()
    return jsonify(status="ok", data=model_to_dict(project)), 200



@mod.route('/api/v1/container/')
@api_auth()
def get_containers():
    """
    Returns lxc containers on the current machine and brief status information.
    """
    _list = []
    containers = Containers.select()
    for c in Containers.select():
    #~ for c in lxc.list_containers():
        #~ dict_obj = model_to_dict(c)
        #~ container = 
        _dict = mix_container(c,lxc.Container(c.name))
        #~ schema = ContainerSchema()
        #~ result = schema.dump(container)
        #~ for key, value in result.items():
            #~ dict_obj[key] = value
        _list.append(_dict)
    return jsonify(_list)


@mod.route('/api/v1/container/<name>/')
@api_auth()
def get_container(name):
    container = lxc.Container(name)
    schema = ContainerSchema()
    result = schema.dump(container)
    return jsonify(result)
    

@mod.route('/api/v1/container/config/<name>/', methods=['POST'])
@api_auth()
def configure_container(name):
    container = lxc.Container(name)
    data = request.get_json(force=True)
    if data is None:
        return jsonify({'status':"error", 'error':"Bad request"}), 400
    container_config = ConfigObj(container.config_file_name, stringify=True, list_values=False)
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
def create_container():
    data = request.get_json(force=True)
    if data is None:
        return jsonify(status="error", error="Bad request"), 400

    if (not('template' in data) or ('name' not in data)):
        return jsonify(status="error", error="Bad request"), 402

    if 'template' in data:
        final_data = {}
        final_storage = {}
        container = lxc.Container(data['name'])
        template = data['template']
        storage = data['storage']
        del data['template']
        del data['storage']
        for key,value in data.items():
            if value != False:
                if len(value) > 0:
                    final_data[key] = value
        for key,value in storage.items():
            if value != False or len(value) > 0:
                final_storage[key] = value
        container.create(template,0,final_data)
        #~ try:
            #~ lxc.create(data['name'], data['template'], data['store'], data['xargs'])
        #~ except lxc.ContainerAlreadyExists:
            #~ return jsonify(status="error", error="Container yet exists"), 409
    #~ else:
        # we want to clone a container
        #~ try:
            #~ lxc.clone(data['clone'], data['name'])
        #~ except lxc.ContainerAlreadyExists:
            #~ return jsonify(status="error", error="Container yet exists"), 409
    return jsonify(status="ok"), 200

@mod.route('/api/v1/container/', methods=['PUT'])
@api_auth()
def naget_container():
    data = request.get_json(force=True)
    if data is None:
        return jsonify({'status':"error", 'error':"Bad request"}), 400
    container = lxc.Container(name)
    return jsonify(result[0])
    
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
