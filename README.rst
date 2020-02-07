Gantry: LXC-Web-Panel reloaded
==========================

.. image:: https://travis-ci.org/EstudioNexos/LXC-Web-Panel.svg?branch=master
    :target: https://travis-ci.org/EstudioNexos/LXC-Web-Panel

Gantry is an easy to use Linux Containers manager.

- NEW Installer to make it even easier to start running.
- Display some host and container information: IP, CPU, Mem and Disk usage.
- List, create, delete containers and change container settings.
- Start, stop and freeze containers
- Create container backup to a tar.gz
- List, create and delete snapshots
- Show system compatibility
- Manage panel users
- Expose container operations through a REST API and Manage API authoritation tokens

.. image:: https://github.com/EstudioNexos/LXC-Web-Panel/raw/master/screenshots/dashboard.png
  :width: 400
  :alt: Revamped dashboard


This is a fork of the original LXC-Web-Panel from https://github.com/lxc-webpanel/LXC-Web-Panel and https://github.com/claudyus/LXC-Web-Panel/ looking for LXC 2.x compatibility, Python 3, UI updating, New features like snapshots and backup restore management, and Fabric (fabfile) integration to be able to manage remote hosts.

The code was tested on Debian 10 Buster and Python 3.8.

We are working on this heavily so expect frequent changes in code, installation docs outdated, ...

All contributions are welcomed.

.. image:: screenshots/container_details.png
  :width: 300
  :alt: Container snapshots

.. image:: screenshots/create_user.png
  :width: 300
  :alt: Container snapshots

.. image:: screenshots/container_snapshots.png
  :width: 300
  :alt: Container snapshots

Installation from source code
----------------------------------------------

Easiest way to run it is using Pyenv:

::
  curl https://pyenv.run | bash

Add following to your .bashrc or .zshrc

::
  export PATH="$HOME/.pyenv/bin:$PATH"
  eval "$(pyenv init -)"
  eval "$(pyenv virtualenv-init -)"

After that continue Pyenv setup:

::
  exec $SHELL
  pyenv update
  pyenv install 3.8.1
  pyenv rehash
  pyenv global 3.8.1 OR pyenv local 3.8.1



::
  git clone https://github.com/EstudioNexos/LXC-Web-Panel.git pantry
  cd pantry
  pip install -r requirements.txt
  python setup.py install
  ./bin/gtr        # run lwp wth debug support

We recomend using /var/gantry/backups or /var/backups/gantry path.

First run we will get an installer page, most of defaults are OK and just click INSTALL.

Then stop gtr with CTRL+C and start it again.

Default login is admin/admin but soon it will be configurable through the installer.

Your lwp panel is now at http://localhost:5000/.

htpasswd
++++++++

To enable authentication against htpasswd file you should set ``auth`` type to ``htpasswd`` and ``file`` variable in ``htpasswd`` section to point to the htpasswd file.

This backend use the crypt function, here an example where ``-d`` force the use of crypt encryption when generating the htpasswd file::

  htpasswd -d -b -c /etc/lwp/httpasswd admin admin

PAM
+++

To enable authentication against PAM you should set ``auth`` type to ``pam`` and ``service`` variable in ``pam`` section.
Python PAM module needs to be installed::

  apt-get install python-pam

or

::

  pip install pam

or

::

  yum install python-pam

With default ``login`` service all valid linux users can login to lwp.
Many more options are available via PAM Configuration, see PAM docs.

HTTP
+++++

This auth method is used to authenticate the users using an external http server through a POST request. To enable this method  ``auth`` type to ``http`` and configure the option under ``http`` section.


LICENSE
-------
This work is released under MIT License, see LICENSE file.
