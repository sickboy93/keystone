# Copyright 2014 OpenStack Foundation
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

"""OAuthlib request validator."""

import six
import datetime

from keystone import exception
from keystone.common import dependency
from keystone.contrib.oauth2 import core as oauth2_api
from keystone.i18n import _
from keystone.openstack.common import log
from oauthlib.oauth2 import RequestValidator

from oslo.utils import timeutils

METHOD_NAME = 'oauth2_validator'
LOG = log.getLogger(__name__)

@dependency.requires('oauth2_api')
class OAuth2Validator(RequestValidator):

    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.
    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        client_dict = self.oauth2_api.get_consumer(client_id)
        if client_dict:
            return True
        return False #Currently the sql driver raises an exception if the consumer doesnt exist

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        client_dict = self.oauth2_api.get_consumer(client_id)
        registered_uris = client_dict['redirect_uris']  
        return redirect_uri in registered_uris

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        #TODO implement
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        if not scopes:
            return True #the client is not requesting any scope

        client_dict = self.oauth2_api.get_consumer(client_id)

        if not client_dict['scopes']:
            return False #the client isnt allowed any scopes

        for scope in scopes:
            if not scope in client_dict['scopes']:
                return False
        return True      

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        #TODO implement
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        client_dict = self.oauth2_api.get_consumer(client_id)
        allowed_response_type = client_dict['response_type']
        return allowed_response_type == response_type

    # Post-authorization
    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        #TODO write it cleaner
        authorization_code = {}
        authorization_code['code'] = code['code']#code is a dict with state and the code
        authorization_code['consumer_id'] = client_id
        #TODO authorization_code['redirect_uri'] = request.redirect_uri
        authorization_code['scopes'] = request.scopes
        authorization_code['authorizing_user_id'] = request.user_id#populated through the credentials
        authorization_code['state'] = request.state
        authorization_code['redirect_uri'] = request.redirect_uri
        token_duration=28800#TODO extract as configuration option
        #TODO find a better place to do this
        now = timeutils.utcnow()
        future = now + datetime.timedelta(seconds=token_duration)
        expiry_date = timeutils.isotime(future, subsecond=True)
        authorization_code['expires_at'] = expiry_date
        self.oauth2_api.store_authorization_code(authorization_code)

    # Token request
    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work 
        #TODO(garcianavalon) write it cleaner
        authmethod, auth = request.headers['Authorization'].split(' ', 1)
        auth = auth.decode('unicode_escape')
        if authmethod.lower() == 'basic':
            auth = auth.decode('base64')
            client_id, secret = auth.split(':', 1)
            client_dict = self.oauth2_api.get_consumer(client_id)
            if client_dict['secret'] == secret:
                # TODO(garcianavalon) this can be done in a cleaner way if we change the consumer model attribute to client_id
                request.client = type('obj', (object,), {'client_id' : client_id})
                return True
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False
    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes, request.state and request.user.
        authorization_code = self.oauth2_api.get_authorization_code(code)
        if not authorization_code['consumer_id'] == request.client.client_id:
            return False
        request.scopes = authorization_code['scopes']
        request.state = authorization_code['state']
        request.user = authorization_code['authorizing_user_id']
        return True
        
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        authorization_code = self.oauth2_api.get_authorization_code(code)
        return authorization_code['redirect_uri'] == redirect_uri

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"

        # TODO(garcianavalon) support for refresh tokens
        # client_id comes as None, we use the one in request
        client_dict = self.oauth2_api.get_consumer(request.client.client_id)
        return grant_type==client_dict['grant_type']

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
 

        # token is a dictionary with the following elements:
        # { 
        #     u'access_token': u'iC1DQuu7zOgNIjquPXPmXE5hKnTwgu', 
        #     u'expires_in': 3600, 
        #     u'token_type': u'Bearer', 
        #     u'state': u'yKxWeujbz9VUBncQNrkWvVcx8EXl1w', 
        #     u'scope': u'basic_scope', 
        #     u'refresh_token': u'02DTsL6oWgAibU7xenvXttwG80trJC'
        # }

        # TODO(garcinanavalon) create a custom TokenCreator instead of
        # hacking the dictionary
        access_token = {
            'id':token['access_token'],
            'consumer_id':request.client.client_id,
            'authorizing_user_id':request.user,
            'scopes': request.scopes,
            'expires_at':token['expires_in'],
            'refresh_token': token['refresh_token']
        }
        self.oauth2_api.store_access_token(access_token)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        pass
        
    # Protected resource request
    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership

        try:
            access_token = self.oauth2_api.get_access_token(token)
        except exception.NotFound:
            return False

        # TODO(garcianavalon) check expiration date
        if access_token['scopes'] != scopes:
            return False
        # NOTE(garcianavalon) we set some attributes in request for later use. There
        # is no documentation about this so I follow the comments found in the example
        # at https://oauthlib.readthedocs.org/en/latest/oauth2/endpoints/resource.html
        # which are:
        # oauthlib_request has a few convenient attributes set such as
        # oauthlib_request.client = the client associated with the token
        # oauthlib_request.user = the user associated with the token
        # oauthlib_request.scopes = the scopes bound to this token
        # request.scopes is set by oauthlib already
        request.user = access_token['authorizing_user_id']
        request.client = access_token['consumer_id']
        return True

    # Token refresh request
    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        pass