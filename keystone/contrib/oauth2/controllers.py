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

from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _
from oauthlib.oauth2 import WebApplicationServer, FatalClientError, OAuth2Error
from keystone.contrib.oauth2 import validator

@dependency.requires('oauth2_api')	
class ConsumerCrudV3(controller.V3Controller):

    collection_name = 'consumers'
    member_name = 'consumer'

    @controller.protected()
    def list_consumers(self, context):
        """Description of the controller logic."""
        ref = self.oauth2_api.list_consumers()
        return ConsumerCrudV3.wrap_collection(context, ref)

    @controller.protected()
    def create_consumer(self, context,consumer):
        ref = self._assign_unique_id(self._normalize_dict(consumer))
        consumer_ref = self.oauth2_api.create_consumer(ref)
        return ConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected()
    def get_consumer(self, context,consumer_id):
        consumer_ref = self.oauth2_api.get_consumer(consumer_id)
        return ConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected() 
    def update_consumer(self, context,consumer_id,consumer):
        self._require_matching_id(consumer_id, consumer)
        ref = self._normalize_dict(consumer)
        self._validate_consumer_ref(ref)
        ref = self.oauth2_api.update_consumer(consumer_id, ref)
        return ConsumerCrudV3.wrap_member(context, ref)

    def _validate_consumer_ref(self, consumer):
        if 'secret' in consumer:
            msg = _('Cannot change consumer secret')
            raise exception.ValidationError(message=msg)

    @controller.protected()
    def delete_consumer(self, context,consumer_id):
        #TODO revoke and delete consumer tokens
        self.oauth2_api.delete_consumer(consumer_id)

@dependency.requires('oauth2_api')  
class AuthorizationCodeCrudV3(controller.V3Controller):

    collection_name = 'authorization_codes'
    member_name = 'authorization_code'

    @controller.protected()
    def list_authorization_codes(self, context):
        """Description of the controller logic."""
        ref = self.oauth2_api.list_authorization_codes()
        return AuthorizationCodeCrudV3.wrap_collection(context, ref)

@dependency.requires('oauth2_api')  
class OAuth2ControllerV3(controller.V3Controller):

    collection_name = 'consumers'
    member_name = 'consumer'
    request_validator = validator.OAuth2Validator
    server = WebApplicationServer(request_validator)

    @controller.protected()
    def request_authorization_code(self, context):
   
        # Validate request
        headers = context['headers']
        body = context['body']
        uri = self.base_url(context, context['path'])

        try:
            scopes, credentials = self.server.validate_authorization_request(
                uri, body, headers)
            # scopes will hold default scopes for client, i.e.
            #['https://example.com/userProfile', 'https://example.com/pictures']

            # credentials is a dictionary of
            # {
            #     'client_id': 'foo',
            #     'redirect_uri': 'https://foo.com/welcome_back',
            #     'response_type': 'code',
            #     'state': 'randomstring',
            # }
            # these credentials will be needed in the post authorization view and
            # should be persisted between. None of them are secret but take care
            # to ensure their integrity if embedding them in the form or cookies.


            self.oauth2_api.store_consumer_credentials(credentials)

            # Present user with a nice form where client (id foo) request access to
            # his default scopes (omitted from request), after which you will
            # redirect to his default redirect uri (omitted from request).

        except FatalClientError as e:
            # this is your custom error page
            raise exception.ValidationError(message=e.description)


    @controller.protected()
    def create_authorization_code(self, context):
        # # Validate request
        # uri = 'https://example.com/post_authorize?client_id=foo'
        # headers, body, http_method = {}, '', 'GET'

        # # Fetch the credentials saved in the pre authorization phase
        # credentials = fetch_credentials()

        # # Fetch authorized scopes from the request
        # from your_framework import request
        # scopes = request.POST.get('scopes')

        # http_response(body, status=status, headers=headers)
        # try:
        #     headers, body, status = server.create_authorization_response(
        #         uri, http_method, body, headers, scopes, credentials)
        #     # headers = {'Location': 'https://foo.com/welcome_back?code=somerandomstring&state=xyz'}, this might change to include suggested headers related
        #     # to cache best practices etc.
        #     # body = '', this might be set in future custom grant types
        #     # status = 302, suggested HTTP status code

        #     return http_response(body, status=status, headers=headers)

        # except FatalClientError as e:
        #     # this is your custom error page
        #     from your_view_helpers import error_to_response
        #     return error_to_response(e)

        # except OAuth2Error as e:
        #     # Less grave errors will be reported back to client
        #     client_redirect_uri = credentials.get('redirect_uri')
        #     redirect(e.in_uri(client_redirect_uri))
        pass