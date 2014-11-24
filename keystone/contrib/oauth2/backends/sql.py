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

import uuid

from keystone.common import sql
from keystone.contrib import oauth2
from keystone import exception
from keystone.i18n import _
from oslo.utils import timeutils


VALID_RESPONSE_TYPES = sql.Enum('code')
VALID_CLIENT_TYPES = sql.Enum('confidential')
VALID_GRANT_TYPES = sql.Enum('authorization_code')

class Consumer(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'consumer_oauth2'
    attributes = ['id', 'name', 'description', 'secret', 'client_type', 'redirect_uris',
                    'grant_type', 'response_type', 'scopes',]
    __table_args__ = {'extend_existing': True}                
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    description = sql.Column(sql.String(64), nullable=True)
    secret = sql.Column(sql.String(64), nullable=False)
    client_type = sql.Column(VALID_CLIENT_TYPES, nullable=False) 
    redirect_uris = sql.Column(sql.JsonBlob(), nullable=False)
    grant_type = sql.Column(VALID_GRANT_TYPES, nullable=False) 
    response_type = sql.Column(VALID_RESPONSE_TYPES, nullable=False)
    # TODO(garcianavalon) better naming to reflect they are the allowed scopes for the client
    scopes = sql.Column(sql.JsonBlob(), nullable=True)

class AuthorizationCode(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'authorization_code_oauth2'

    attributes = ['code', 'consumer_id', 'authorizing_user_id', 'expires_at', 'scopes',
                'state', 'redirect_uri', 'valid']

    code = sql.Column(sql.String(64), primary_key=True, nullable=False)
    consumer_id = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True)
    # TODO(garcianavalon) shouldnt it be a Foreign Key??
    authorizing_user_id = sql.Column(sql.String(64), nullable=False)
    # TODO(garcianavalon) datetime type or similar?
    expires_at = sql.Column(sql.String(64), nullable=False)
    scopes = sql.Column(sql.JsonBlob(), nullable=True)
    state = sql.Column(sql.String(64), nullable=True)
    redirect_uri = sql.Column(sql.String(64), nullable=False)
    valid = sql.Column(sql.Boolean(), default=True, nullable=False)

class ConsumerCredentials(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'consumer_credentials_oauth2'
    attributes = ['id', 'user_id', 'client_id', 'redirect_uri',
                'response_type', 'state', 'created_at']
    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    # TODO(garcianavalon) shouldnt it be a Foreign Key??
    user_id = sql.Column(sql.String(64), index=True, nullable=False)
    client_id = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True)
    redirect_uri = sql.Column(sql.String(64), nullable=False)
    response_type = sql.Column(VALID_RESPONSE_TYPES, nullable=False)
    state = sql.Column(sql.String(64), nullable=True)
    created_at = sql.Column(sql.DateTime(), default=None, nullable=False)
    

class AccessToken(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'access_token_oauth2'

    attributes = ['id', 'consumer_id', 'authorizing_user_id', 'expires_at',
                'scopes', 'valid']

    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    consumer_id = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True)
    # TODO(garcianavalon) shouldnt it be a Foreign Key??
    authorizing_user_id = sql.Column(sql.String(64), nullable=False)
    # TODO(garcianavalon) datetime type or similar?
    expires_at = sql.Column(sql.String(64), nullable=False)
    scopes = sql.Column(sql.JsonBlob(), nullable=True)
    refresh_token = sql.Column(sql.String(64), nullable=True)
    valid = sql.Column(sql.Boolean(), default=True, nullable=False)

class OAuth2(oauth2.Driver):
    """ CRUD driver for the SQL backend """
    # CONSUMERS
    def _get_consumer(self, session, consumer_id):
        consumer_ref = session.query(Consumer).get(consumer_id)
        if consumer_ref is None:
            raise exception.NotFound(_('No Consumer found with id: %s' %consumer_id))
        return consumer_ref

    def list_consumers(self):
        session = sql.get_session()
        cons = session.query(Consumer)
        return [consumer.to_dict() for consumer in cons]

    def create_consumer(self, consumer):
        consumer['secret'] = uuid.uuid4().hex
        if not consumer.get('description'):
            consumer['description'] = None
        session = sql.get_session()
        # set the response_type based on the grant_type
        if consumer['grant_type'] == 'authorization_code':
            consumer['response_type'] = 'code'
        with session.begin():
            consumer_ref = Consumer.from_dict(consumer)
            session.add(consumer_ref)
        return consumer_ref.to_dict()

    def get_consumer(self, consumer_id):
        session = sql.get_session()
        with session.begin():
            consumer_ref = self._get_consumer(session, consumer_id) 
        return consumer_ref.to_dict()

    def update_consumer(self, consumer_id, consumer):
        session = sql.get_session()
        with session.begin():
            consumer_ref = self._get_consumer(session, consumer_id)
            for k in consumer:
                setattr(consumer_ref, k, consumer[k])
        return consumer_ref.to_dict()

    def delete_consumer(self, consumer_id):
        session = sql.get_session()
        with session.begin():
            self._delete_consumer(session, consumer_id)

    def _delete_consumer(self, session, consumer_id):
        consumer_ref = self._get_consumer(session, consumer_id)
        session.delete(consumer_ref)

    # AUTHORIZATION CODES
    def list_authorization_codes(self):
        session = sql.get_session()
        cons = session.query(AuthorizationCode)
        return [authorization_code.to_dict() for authorization_code in cons]

    def store_authorization_code(self, authorization_code):
        session = sql.get_session()
        with session.begin():
            authorization_code_ref = AuthorizationCode.from_dict(authorization_code)
            session.add(authorization_code_ref)
        return authorization_code_ref.to_dict()

    def _get_authorization_code(self, session, code):
        authorization_code_ref = session.query(AuthorizationCode).get(code)

        if authorization_code_ref is None:
            msg = _('Authorization Code %s not found') %code
            raise exception.NotFound(message=msg)
        return authorization_code_ref
        
    def get_authorization_code(self, code):
        session = sql.get_session()
        with session.begin():
            authorization_code_ref = self._get_authorization_code(session, code)
        return authorization_code_ref.to_dict()

    def invalidate_authorization_code(self, code):
        session = sql.get_session()
        with session.begin():
            authorization_code_ref = self._get_authorization_code(session, code)
            setattr(authorization_code_ref, 'valid', False)

    # CONSUMER CREDENTIALS
    def store_consumer_credentials(self, credentials):
        if not credentials.get('state'):
            credentials['state'] = None
            
        if not credentials.get('created_at'):
            credentials['created_at'] = timeutils.utcnow()

        session = sql.get_session()
        with session.begin():
            credentials_ref = ConsumerCredentials.from_dict(credentials)
            session.add(credentials_ref)
        return credentials_ref.to_dict()

    def get_consumer_credentials(self, client_id, user_id):
        session = sql.get_session()
        with session.begin():
            # NOTE(garcianavalon) I have decided to keep the credentials stored
            # after the client grants the authorization, so the client can POST
            # again to get a new authorization code with out needing the redirect
            # with the query string before. Therefore, this query retrieves the 
            #last row for that user-client tuple
            query = (
                session.query(ConsumerCredentials)
                    .filter_by(user_id=user_id, 
                            client_id=client_id)
                    .order_by(sql.sql.desc(ConsumerCredentials.created_at))
            )
            credentials_ref = query.first()
        if credentials_ref is None:
            raise exception.NotFound(_('Credentials not found'))
        return credentials_ref.to_dict()

    # ACCESS TOKENS
    def get_access_token(self, access_token_id):
        session = sql.get_session()
        with session.begin():
            access_token_ref = session.query(AccessToken).get(access_token_id)

        if access_token_ref is None:
            msg = _('Access Token %s not found') %access_token_id
            raise exception.NotFound(message=msg)

        return access_token_ref.to_dict()

    def store_access_token(self, access_token):
        session = sql.get_session()
        with session.begin():
            access_token_ref = AccessToken.from_dict(access_token)
            session.add(access_token_ref)
        return access_token_ref.to_dict()