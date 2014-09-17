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

from keystone.common import dependency
from keystone import exception
from keystone.openstack.common import log
from oauthlib.oauth2 import RequestValidator

METHOD_NAME = 'oauth2_validator'
LOG = log.getLogger(__name__)

@dependency.requires('oauth2_api')
class OAuth2Validator(RequestValidator):

    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.
    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        # client_dict = self.oauth2_api.get_consumer(client_id)
        # if client_dict:
        #     return True
        # return False #Currently the sql driver raises an exception if the consumer doesnt exist
        return True #TODO dev

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
        pass

    # Token request
    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        pass
    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False
    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes, request.state and request.user.
        pass
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        pass
    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        pass
    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        pass
    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        pass
        
    # Protected resource request
    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        pass
    # Token refresh request
    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        pass