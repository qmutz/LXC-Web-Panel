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


class BaseModel(Model):
    class Meta:
        database = get_database()

class Users(BaseModel):
    name = CharField(null=True)
    password = CharField()
    su = CharField(null=True)
    username = CharField()
    email = CharField(null=True)
    active = BooleanField(default=True)
    
    def __str__(self):
        return '%s %s' % (self.username, self.name)
        
    class Meta:
        table_name = 'users'
        
class Projects(BaseModel):
    title = CharField()
    description = TextField(null=True)
    admin = ForeignKeyField(Users)
    created_date = DateTimeField(default=datetime.datetime.now)
    active = BooleanField(default=True)
    
    def __str__(self):
        return self.title
        
    class Meta:
        table_name = 'projects'


class Hosts(BaseModel):
    hostname = CharField()
    api_user = CharField()
    api_token = CharField()
    admin = ForeignKeyField(Users)
    active = BooleanField(default=True)
    is_available = BooleanField(default=True)
        
    def __str__(self):
        return self.hostname
        
    class Meta:
        table_name = 'hosts'


class Containers(BaseModel):
    name = CharField()
    host = ForeignKeyField(Hosts)
    admin = ForeignKeyField(Users)
    locked = BooleanField(default=False)
    created_date = DateTimeField(default=datetime.datetime.now)
    
    def __str__(self):
        return self.name
        
    class Meta:
        table_name = 'containers'
        indexes = (
            # Specify a unique multi-column index on from/to-user.
            (('name', 'host'), True),
        )


class Tags(BaseModel):
    name = CharField()
    color = CharField(null=True)
    
    def __str__(self):
        return self.name
        
    class Meta:
        table_name = 'tags'


class ContainerTag(BaseModel):
    container = ForeignKeyField(Containers)
    tag = ForeignKeyField(Tags)


class ApiTokens(BaseModel):
    description = CharField(null=True)
    token = CharField()
    username = CharField(null=True)
    
    def __str__(self):
        return '%s: %s' % (self.description, self.token)
        
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
