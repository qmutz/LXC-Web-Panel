import os
from configparser import ConfigParser, RawConfigParser

CONFIG_FILE = '/etc/lwp/lwp.conf'
config = ConfigParser()


#~ class Mode():
    #~ def __init__(self,setup=False):
        #~ self.setup = setup

def read_config_file():
    if os.path.exists(CONFIG_FILE):
        try:
            config.readfp(open(CONFIG_FILE))
        except:
            print(' * missed {} file'.format(CONFIG_FILE))
    else:
        config['global'] = {}
        config['global']['setup_mode'] = 'True'
        print('Setup mode')
        #~ mode = Mode(setup=True)
        #~ return mode
            #~ try:
                # fallback on local config file
                #~ config.readfp(open('lwp.conf'))
            #~ except:
                #~ print(' * cannot read config files. Exit!')
                #~ sys.exit(1)
    return config
