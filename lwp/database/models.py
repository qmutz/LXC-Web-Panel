import datetime
#~ from flask import current_app as app
from peewee import *
from playhouse.db_url import connect
from lwp.config import read_config_file


def get_database(fresh_config=False):
    config = read_config_file()
    DATABASE = config.get('database', 'file')

    if DATABASE.startswith('/'):
        DATABASE = 'sqlite:///{}'.format(DATABASE)
    return connect(DATABASE)
        

#~ class UnknownField(object):
    #~ def __init__(self, *_, **__): pass

class BaseModel(Model):
    class Meta:
        database = get_database()

class Users(BaseModel):
    name = CharField(null=True)  # string
    password = CharField()  # string
    su = CharField(null=True)  # string
    username = CharField()  # string

    class Meta:
        table_name = 'users'

class ApiTokens(BaseModel):
    description = CharField(null=True)
    token = CharField()
    username = CharField(null=True)

    class Meta:
        table_name = 'api_tokens'
        primary_key = False

#~ class Machine(BaseModel):
    #~ bucket_token = CharField(null=True)
    #~ machine_name = CharField(null=True)

    #~ class Meta:
        #~ table_name = 'machine'
        #~ primary_key = False

#~ class SqliteSequence(BaseModel):
    #~ name = CharField(null=True)  # 
    #~ seq = IntegerField(null=True)  # 

    #~ class Meta:
        #~ table_name = 'sqlite_sequence'
        #~ primary_key = False
