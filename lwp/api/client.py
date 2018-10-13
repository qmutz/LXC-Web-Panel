import requests



class GantryClient():
    api_prefix = '/api/v1'
    
    def __init__(self, config):
        #~ self.address = app.config['ADDRESS']
        #~ self.port = app.config['PORT']
        self.address = config['global']['address']
        self.port = config['global']['port']
        self.token = config['api']['token']
        self.default_url = 'http://{}:{}{}'.format(self.address, self.port, self.api_prefix)
        self.payload = {'private_token':self.token}
        self.storage_repository = config['storage_repository']
        
    def get_payload(self):
        return self.payload.copy()
        
    def build_url(self, endpoint):
        return '{}/{}/'.format(self.default_url, endpoint)
        
    def set_state(self, name, state):
        data = {'action':state}
        r = requests.post(self.build_url('container/state/{}'.format(name)), params=self.get_payload(),json=data)
        return r.json()
        
    def make_operation(self, name, operation, **kwargs):
        data = {'operation':operation}
        for key, value in kwargs.items():
            data[key] = value
        r = requests.post(self.build_url('container/operation/{}'.format(name)), params=self.get_payload(),json=data)
        return r.status_code
        
    def set_config(self, name, data):
        r = requests.post(self.build_url('container/config/{}'.format(name)), params=self.get_payload(),json=data)
        return r.json()
        
    def get_host(self):
        r = requests.get(self.build_url('host'), params=self.get_payload())
        return r.json()
        
    def get_checks(self):
        r = requests.get(self.build_url('host/checks'), params=self.get_payload())
        return r.json()
        
    def get_users(self, su=False):
        payload = self.get_payload()
        if su:
            payload['su'] = True
        r = requests.get(self.build_url('user'), params=payload)
        return r.json()['data']
        
    def get_projects(self, su=False):
        payload = self.get_payload()
        r = requests.get(self.build_url('project'), params=payload)
        return r.json()['data']
        
    def get_project(self, id):
        payload = self.get_payload()
        r = requests.get(self.build_url('project/{}'.format(id)), params=payload)
        return r.json()['data']
        
    def create_user(self, username, password, name=False, su=False):
        data = {'username':username,'password':password}
        if name:
            data['name'] = name
        if su:
            data['su'] = su
        r = requests.put(self.build_url('user'), params=self.get_payload(), json=data)
        return r.json()
        
    def update_user(self, user_id, attribs):
        data = attribs
        r = requests.put(self.build_url('user/{}'.format(user_id)), params=self.get_payload(), json=data)
        return r.status_code
        
    def delete_user(self, user_id):
        r = requests.delete(self.build_url('user/{}'.format(user_id)), params=self.get_payload())
        return r.status_code
        
    def get_tokens(self):
        r = requests.get(self.build_url('token'),params=self.get_payload())
        return r.json()['data']
    
    def delete_token(self, token):
        data = {'token':token}
        r = requests.delete(self.build_url('token'),params=self.get_payload(),json=data)
        return r.status_code
        
    def add_token(self, token, description, username):
        data = {'token':token,'description':description,'username':username}
        r = requests.put(self.build_url('token'),params=self.get_payload(),json=data)
        return r.status_code
        
    def get_containers(self):
        r = requests.get(self.build_url('container'),params=self.get_payload())
        return r.json()
        
    def get_container(self,container_name):
        r = requests.get(self.build_url('container/{}'.format(container_name)),params=self.get_payload())
        return r.json()
        
    def create_container(self, name, template, release, storage):
        data = {'name':name,'template':template,'release':release,'storage': storage}
        r = requests.put(self.build_url('container'),params=self.get_payload(), json=data)
        return r.json()
