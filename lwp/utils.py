import os, sys
import time
import subprocess
import hashlib

from flask import session, flash, request, jsonify
from lwp.config import ConfigParser, read_config_file
from marshmallow import Schema, fields, pprint

def format_release(output):
    if 'NAME' in output.decode():
        release = {}
        for line in output.decode().split('\n'):
            if '=' in line:
                splitted = line.split('=')
                release[splitted[0]] = splitted[1].replace('"','')
    else:
        release = {'PRETTY_NAME':output.decode().strip()}
    return release

"""
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__',

'add_device_net', 'add_device_node', 'append_config_item', 'attach', 'attach_interface', 'attach_wait', 'clear_config', 'clear_config_item', 'clone', 'config_file_name', 'console', 'console_getfd', 'controllable', 'create', 'defined', 'destroy', 'detach_interface', 'freeze', 'get_cgroup_item', 'get_config_item', 'get_config_path', 'get_interfaces', 'get_ips', 'get_keys', 'get_running_config_item', 'init_pid', 'load_config', 'name', 'network', 'reboot', 'remove_device_node', 'rename', 'running', 'save_config', 'set_cgroup_item', 'set_config_item', 'set_config_path', 'shutdown', 'snapshot', 'snapshot_destroy', 'snapshot_list', 'snapshot_restore', 'start', 'state', 'stop', 'unfreeze', 'wait']

"""

class ContainerSchema(Schema):
    name = fields.Str()
    state = fields.Str()
    init_pid = fields.Str()
    config_file_name = fields.Str()
    running = fields.Bool()
    stopped = fields.Bool()
    frozen = fields.Bool()
    #~ interfaces = fields.List(fields.String)
    interfaces = fields.Function(lambda obj: obj.get_interfaces())

    # ~ snapshots = fields.Function(lambda obj: obj.snapshot_list())

    ips = fields.Function(lambda obj: obj.get_ips())
    #~ max_mem = fields.Function(lambda obj: obj.get_cgroup_item("memory.limit_in_bytes"))
    runtime = fields.Method('get_runtime_values')
    settings = fields.Method('get_settings')
    os_release = fields.Method('get_os_release')

    def get_os_release(self, obj):
        print(dir(obj), obj.name)
        release_files = ('os-release','lsb-release','fedora-release','redhat-release','centos-release','plamo-release')
        output = 'Unknown'.encode()
        for release_file in release_files:
            cmd = "cat {}/etc/{}".format(obj.get_config_item('lxc.rootfs.path'),release_file)
            try:
                output = subprocess.check_output(cmd, shell=True)
            except: pass
            if output:
                return format_release(output)
        return output

    def get_runtime_values(self, obj):
        cgroups = [
            'memory.usage_in_bytes',
            'memory.limit_in_bytes',
            #~ 'lxc.cgroup.memory.memsw.limit_in_bytes'
        ]
        to_int = ['memory.limit_in_bytes','memory.usage_in_bytes',]
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
        print(dir(obj), obj.name)
        network_settings = [
            'lxc.network.type',
            'lxc.network.script_up',
            'lxc.network.script_down',
            'lxc.network.link',
            'lxc.network.flags',
            'lxc.network.hwaddr',
            'lxc.network.ipv4',
            'lxc.network.ipv4gw',
            'lxc.network.ipv6',
            'lxc.network.ipv6gw',
        ]
        settings = [
            'lxc.rootfs.path',
            # ~ 'lxc.storage.backend',
            'lxc.tty.max',
            'lxc.uts.name',
            'lxc.arch',
            'lxc.log.level',
            'lxc.log.file',
            'lxc.start.auto',
            'lxc.start.delay',
            'lxc.start.order',
            'lxc.cgroup.cpuset.cpus',
            'lxc.cgroup.cpuset.shares',
            'lxc.cgroup.memory.limit_in_bytes'
        ]
        values = {}
        for setting in settings:
            setting_name = setting.replace('lxc.','')
            print(obj, setting_name, setting)
            values[setting_name] = obj.get_config_item(setting)
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

"""
cgroup_ext is a data structure where for each input of edit.html we have an array with:
    position 0: the lxc container option to be saved on file
    position 1: the regex to validate the field
    position 2: the flash message to display on success.
"""
ip_regex = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
cidr_regex = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))*$'
file_match = '^\/\w[\w.\/-]+$'

cgroup_ext = {
    'arch': ['lxc.arch', '^(x86|i686|x86_64|amd64)$', ''],
    'utsname': ['lxc.utsname', '^\w[\w.-]+$', 'Hostname updated'],
    'type': ['lxc.network.type', '^(none|empty|veth|vlan|macvlan|phys)$', 'Link network type updated'],
    'link': ['lxc.network.link', '^[\w.-/]+$', 'Link name updated'],
    'flags': ['lxc.network.flags', '^(up|down)$', 'Network flag updated'],
    'hwaddr': ['lxc.network.hwaddr', '^[0-9a-fA-F:]+$', 'Hardware address updated'],
    'ipv4': ['lxc.network.ipv4', cidr_regex, 'IPv4 address updated'],
    'ipv4gw': ['lxc.network.ipv4.gateway', ip_regex, 'IPv4 gateway address updated'],
    'ipv6': ['lxc.network.ipv6', '^([0-9a-fA-F:/]+)+$', 'IPv6 address updated'],  # weak ipv6 regex check
    'ipv6gw': ['lxc.network.ipv6.gateway', '^([0-9a-fA-F:]+)+$', 'IPv6 gateway address updated'],
    'script_up': ['lxc.network.script.up', file_match, 'Network script down updated'],
    'script_down': ['lxc.network.script.down', file_match, 'Network script down updated'],
    'rootfs': ['lxc.rootfs', '^(\/|loop:\/|overlayfs:\/)[\w.\/:-]+$', 'Rootfs updated'],
    'memlimit': ['lxc.cgroup.memory.limit_in_bytes', '^([0-9]+|)$', 'Memory limit updated'],
    'swlimit': ['lxc.cgroup.memory.memsw.limit_in_bytes', '^([0-9]+|)$', 'Swap limit updated'],
    'cpus': ['lxc.cgroup.cpuset.cpus', '^[0-9,-]+$', 'CPUs updated'],
    'shares': ['lxc.cgroup.cpu.shares', '^[0-9]+$', 'CPU shares updated'],
    'deny': ['lxc.cgroup.devices.deny', '^$', '???'],
    'allow': ['lxc.cgroup.devices.allow', '^$', '???'],
    'loglevel': ['lxc.loglevel', '^[0-9]$', 'Log level updated'],
    'logfile': ['lxc.logfile', file_match, 'Log file updated'],
    'id_map': ['lxc.id_map', '^[ug0-9 ]+$', 'UID Mapping updated'],
    'hook_pre_start': ['lxc.hook.pre-start', file_match, 'Pre hook start updated'],
    'hook_pre_mount': ['lxc.hook.pre-mount', file_match, 'Pre mount hook updated'],
    'hook_mount': ['lxc.hook.mount', file_match, 'Mount hook updated'],
    'hook_start': ['lxc.hook.start', file_match, 'Container start hook updated'],
    'hook_post_stop': ['lxc.hook.post-stop', file_match, 'Container post hook updated'],
    'hook_clone': ['lxc.hook.clone', file_match, 'Container clone hook updated'],
    'start.auto': ['lxc.start.auto', '^(0|1)$', 'Autostart saved'],
    'start.delay': ['lxc.start.delay', '^[0-9]*$', 'Autostart delay option updated'],
    'start.order': ['lxc.start.order', '^[0-9]*$', 'Autostart order option updated']
}


def hash_passwd(passwd):
    return hashlib.sha512(passwd.encode('utf-8')).hexdigest()


def get_token():
    return hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()


def check_session_limit():
    config = read_config_file()
    if 'logged_in' in session and session.get('last_activity') is not None:
        now = int(time.time())
        limit = 3600
        try:
            limit = now - 60 * int(config.get('session', 'time'))
        except: pass
        last_activity = session.get('last_activity')
        if last_activity < limit:
            flash(u'Session timed out !', 'info')
            session.pop('logged_in', None)
            session.pop('token', None)
            session.pop('last_activity', None)
            session.pop('username', None)
            session.pop('name', None)
            session.pop('su', None)
            flash(u'You are logged out!', 'success')
        else:
            session['last_activity'] = now
