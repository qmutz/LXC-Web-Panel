import os, sys
import time
import hashlib

from flask import session, flash, request, jsonify
from lwp.config import ConfigParser, read_config_file

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
    'start_auto': ['lxc.start.auto', '^(0|1)$', 'Autostart saved'],
    'start_delay': ['lxc.start.delay', '^[0-9]*$', 'Autostart delay option updated'],
    'start_order': ['lxc.start.order', '^[0-9]*$', 'Autostart order option updated']
}


def hash_passwd(passwd):
    return hashlib.sha512(passwd.encode('utf-8')).hexdigest()


def get_token():
    return hashlib.md5(str(time.time()).encode('utf-8')).hexdigest()


def check_session_limit():
    config = read_config_file()
    if 'logged_in' in session and session.get('last_activity') is not None:
        now = int(time.time())
        limit = now - 60 * int(config.get('session', 'time'))
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

from lwp.database.models import ApiTokens

def api_auth():
    """
    api decorator to verify if a token is valid
    """
    def decorator(handler):
        def new_handler(*args, **kwargs):
            token = request.args.get('private_token')
            if token is None:
                token = request.headers.get('Private-Token')
            if token:
                results = ApiTokens.select().where(ApiTokens.token == token).limit(1)
                result = results[0] if len(results) > 0 else None
                if result:
                    # token exists, access granted
                    return handler(*args, **kwargs)
                else:
                    return jsonify(status="error", error="Unauthorized"), 401
            else:
                return jsonify(status="error", error="Unauthorized"), 401
        new_handler.__name__ = handler.__name__
        return new_handler
    return decorator
