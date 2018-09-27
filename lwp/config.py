import os
from configparser import ConfigParser

config = ConfigParser()
CONFIG_FILE = '/etc/lwp/lwp.conf'
class Mode():
    def __init__(self,setup=False):
        self.setup = setup

def read_config_file():
    if os.path.exists(CONFIG_FILE):
        try:
            # TODO: should really use with statement here rather than rely on cpython reference counting
            config.readfp(open(CONFIG_FILE))
        except:
            # TODO: another blind exception
            print(' * missed {} file'.format(CONFIG_FILE))
    else:
        print('Setup mode')
        mode = Mode(setup=True)
        return mode
            #~ try:
                # fallback on local config file
                #~ config.readfp(open('lwp.conf'))
            #~ except:
                #~ print(' * cannot read config files. Exit!')
                #~ sys.exit(1)
    return config
