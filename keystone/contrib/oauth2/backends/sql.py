# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import sql
from keystone.contrib import oauth2
from keystone import exception
from keystone.i18n import _
import uuid

VALID_RESPONSE_TYPES = sql.Enum('code')
VALID_CLIENT_TYPES = sql.Enum('confidential')
VALID_GRANT_TYPES = sql.Enum('authorization_code')

class Consumer(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'consumer'
    attributes = ['id', 'description','secret','client_type', 'redirect_uris',
                    'grant_type','response_type','scopes']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    description = sql.Column(sql.String(64), nullable=True)
    secret = sql.Column(sql.String(64), nullable=False)
    client_type = sql.Column(VALID_CLIENT_TYPES,nullable=False) 
    redirect_uris = sql.Column(sql.JsonBlob(), nullable=False)
    grant_type = sql.Column(VALID_GRANT_TYPES,nullable=False) 
    response_type = sql.Column(VALID_RESPONSE_TYPES,nullable=False) 
    scopes = sql.Column(sql.JsonBlob(),nullable=True)#TODO better naming to reflect they are the allowed scopes for the client

class AuthorizationCode(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'authorization_code'

    attributes = ['code', 'consumer_id','authorizing_user_id','expires_at','scopes',
                'state','redirect_uri']

    code = sql.Column(sql.String(64),primary_key=True,nullable=False)
    consumer_id = sql.Column(sql.String(64), sql.ForeignKey('consumer.id'),
                             nullable=False, index=True)
    authorizing_user_id = sql.Column(sql.String(64), nullable=False)#TODO shouldnt it be a Foreign Key??
    expires_at = sql.Column(sql.String(64), nullable=False)#TODO datetime type or similar?
    scopes = sql.Column(sql.JsonBlob(),nullable=True)
    state = sql.Column(sql.String(64), nullable=True)
    redirect_uri = sql.Column(sql.String(64), nullable=False)

class ConsumerCredentials(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'consumer_credentials'
    attributes = ['id', 'client_id','redirect_uri','response_type','state']

    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    client_id = sql.Column(sql.String(64), sql.ForeignKey('consumer.id'),
                             nullable=False, index=True)
    redirect_uri = sql.Column(sql.String(64), nullable=False)
    response_type = sql.Column(VALID_RESPONSE_TYPES,nullable=False)
    state = sql.Column(sql.String(64), nullable=True)

class OAuth2(oauth2.Driver):
    """ CRUD driver for the SQL backend """
    def _get_consumer(self, session, consumer_id):
        consumer_ref = session.query(Consumer).get(consumer_id)
        if consumer_ref is None:
            raise exception.NotFound(_('Consumer not found'))
        return consumer_ref
    def list_consumers(self):
        session = sql.get_session()
        cons = session.query(Consumer)
        return [consumer.to_dict() for consumer in cons]

    def create_consumer(self,consumer):
        consumer['secret'] = uuid.uuid4().hex
        if not consumer.get('description'):
            consumer['description'] = None
        session = sql.get_session()
        #set the response_type based on the grant_type
        if consumer['grant_type'] == 'authorization_code':
            consumer['response_type'] = 'code'
        with session.begin():
            consumer_ref = Consumer.from_dict(consumer)
            session.add(consumer_ref)
        return consumer_ref.to_dict()

    def get_consumer(self,consumer_id):
        session = sql.get_session()
        with session.begin():
            consumer_ref = self._get_consumer(session,consumer_id)
        return consumer_ref.to_dict()

    def update_consumer(self,consumer_id,consumer):
        session = sql.get_session()
        with session.begin():
            consumer_ref = self._get_consumer(session, consumer_id)
            for k in consumer:
                setattr(consumer_ref,k,consumer[k])
        return consumer_ref.to_dict()

    def delete_consumer(self, consumer_id):
        session = sql.get_session()
        with session.begin():
            self._delete_consumer(session, consumer_id)

    def _delete_consumer(self, session, consumer_id):
        consumer_ref = self._get_consumer(session, consumer_id)
        session.delete(consumer_ref)

    def list_authorization_codes(self):
        session = sql.get_session()
        cons = session.query(AuthorizationCode)
        return [authorization_code.to_dict() for authorization_code in cons]

    def store_consumer_credentials(self, credentials):
        if not credentials.get('state'):
            credentials['state'] = None
        session = sql.get_session()
        with session.begin():
            credentials_ref = ConsumerCredentials.from_dict(credentials)
            session.add(credentials_ref)
        return credentials_ref.to_dict()

    def get_consumer_credentials(self, client_id):
        session = sql.get_session()
        with session.begin():
            credentials_ref =  session.query(ConsumerCredentials).filter_by(client_id=client_id).first() #TODO see interface definition in core to decide what to do
        if credentials_ref is None:
            raise exception.NotFound(_('Credentials not found'))
        return credentials_ref.to_dict()

    def store_authorization_code(self,authorization_code):
        session = sql.get_session()
        with session.begin():
            authorization_code_ref = AuthorizationCode.from_dict(authorization_code)
            session.add(authorization_code_ref)
        return authorization_code_ref.to_dict()

    def get_authorization_code(self, code):
        session = sql.get_session()
        with session.begin():
            authorization_code_ref =  session.query(AuthorizationCode).get(code)
        if authorization_code_ref is None:
            raise exception.NotFound(_('Authorization Code not found'))
        return authorization_code_ref.to_dict()