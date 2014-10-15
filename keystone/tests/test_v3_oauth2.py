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

import copy
import json
import urlparse
import uuid
import mock

from keystone import auth
from keystone import config
from keystone import exception
from keystone import tests
from keystone.contrib.oauth2 import core
from keystone.tests import test_v3
# TODO(garcianavalon) remove the request_oauthlib dependency
from  requests_oauthlib import OAuth2Session

CONF = config.CONF

class OAuth2Tests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'oauth2'
    EXTENSION_TO_ADD = 'oauth2_extension'

    CONSUMER_URL = '/OS-OAUTH2/consumers'

    DEFAULT_REDIRECT_URIS = ['https://uri.com']
    DEFAULT_SCOPES = ['all_info']

    def setUp(self):
        super(OAuth2Tests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        # TODO(garcianavalon) I've put this line for dependency injection to work, but I don't know if its the right way to do it...
        self.manager = core.Manager()

    def _create_consumer(self,description=None,
                         client_type='confidential',
                         redirect_uris=DEFAULT_REDIRECT_URIS,
                         grant_type='authorization_code',
                         scopes=DEFAULT_SCOPES):
        data = {
            'description': description,
            'client_type': client_type,
            'redirect_uris': redirect_uris,
            'grant_type': grant_type,
            'scopes': scopes
        }
        response = self.post(self.CONSUMER_URL,body={'consumer': data})

        return response.result['consumer'],data

    def _create_user_and_tenant(self):
        pass

class ConsumerCRUDTests(OAuth2Tests):

    def _consumer_assertions(self, consumer,data):
        self.assertEqual(consumer['description'], data['description'])
        self.assertIsNotNone(consumer['id'])
        self.assertIsNotNone(consumer['secret'])

        return consumer

    def _test_create_consumer(self,consumer_data=None):
        consumer,data = self._create_consumer(consumer_data)
        self._consumer_assertions(consumer,data)

    def test_create_consumer_no_data(self):
        self._test_create_consumer()

    def test_consumer_delete(self):
        consumer,data = self._create_consumer()
        consumer_id = consumer['id']
        response = self.delete(self.CONSUMER_URL + '/%s' % consumer_id)
        self.assertResponseStatus(response, 204)

    def test_consumer_get(self):
        consumer,data = self._create_consumer()
        consumer_id = consumer['id']
        response = self.get(self.CONSUMER_URL + '/%s' % consumer_id)
        self_url = ['http://localhost/v3', self.CONSUMER_URL,
                    '/', consumer_id]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['consumer']['links']['self'], self_url)
        self.assertEqual(response.result['consumer']['id'], consumer_id)

    def test_consumer_list(self):
        self._create_consumer()
        response = self.get(self.CONSUMER_URL)
        entities = response.result['consumers']
        self.assertIsNotNone(entities)
        self_url = ['http://localhost/v3', self.CONSUMER_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])

    def test_consumer_update(self):
        consumer,data = self._create_consumer()
        original_id = consumer['id']
        original_description = consumer['description'] or ''
        update_description = original_description + '_new'

        update_ref = {'description': update_description}
        update_response = self.patch(self.CONSUMER_URL + '/%s' % original_id,
                                 body={'consumer': update_ref})
        consumer = update_response.result['consumer']
        self.assertEqual(consumer['description'], update_description)
        self.assertEqual(consumer['id'], original_id)

    def test_consumer_update_bad_secret(self):
        consumer,data = self._create_consumer()
        original_id = consumer['id']
        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = uuid.uuid4().hex
        update_ref['secret'] = uuid.uuid4().hex
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_bad_id(self):
        consumer,data = self._create_consumer()
        original_id = consumer['id']
        original_description = consumer['description'] or ''
        update_description = original_description + "_new"

        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = update_description
        update_ref['id'] = update_description
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_get_bad_id(self):
        self.get(self.CONSUMER_URL + '/%(consumer_id)s'
                 % {'consumer_id': uuid.uuid4().hex},
                 expected_status=404)

class OAuth2FlowTests(OAuth2Tests):
    
    def _create_authorization_url(self,consumer):

        
        oauth = OAuth2Session(consumer['id'], 
                              redirect_uri=consumer['redirect_uris'][0],
                              scope=consumer['scopes'][0])
        authorization_url, state = oauth.authorization_url('https://remove.this/OS-OAUTH2/authorize')
        # NOTE(garcianavalon)hack to work around the need for https in request_oauthilb authorization_url 
        # and the fact that RestfulTestCase prepends the base_url when calling get
        authorization_url = authorization_url.replace('https://remove.this','')
        return authorization_url

    def _request_authorization(self):
        self.consumer, data = self._create_consumer()
        authorization_url = self._create_authorization_url(self.consumer)
        # GET authorization_url to request the authorization
        return self.get(authorization_url)

    def test_request_authorization(self):
        response = self._request_authorization()

        self.assertIsNotNone(response.result['data'])

        data = response.result['data']
        self.assertIsNotNone(data['redirect_uri'])
        self.assertIsNotNone(data['requested_scopes'])
        self.assertIsNotNone(data['consumer'])
        self.assertIsNotNone(data['consumer']['id'])

        consumer_id = data['consumer']['id']
        self.assertEqual(consumer_id,self.consumer['id'])

        requested_scopes = data['requested_scopes']
        self.assertEqual(requested_scopes,self.DEFAULT_SCOPES)

        redirect_uri = data['redirect_uri']
        self.assertEqual(redirect_uri,self.DEFAULT_REDIRECT_URIS[0])

    def _authorization_data(self,consumer_id):
        data = {
            "user_auth": {
                "client_id":consumer_id,
                "user_id":self.user_id,
                "scopes":self.DEFAULT_SCOPES
            }
        }
        return data

    def _grant_authorization(self):
        get_response = self._request_authorization()
        # POST authorization url to simulate ResourceOwner granting authorization
        consumer_id = get_response.result['data']['consumer']['id']
        data = self._authorization_data(consumer_id)
        return self.post('/OS-OAUTH2/authorize',body=data,expected_status=302)

    def test_grant_authorization(self):
        response = self._grant_authorization()

        self.assertIsNotNone(response.headers['Location'])
        ###
        # TODO(garcianavalon) extract method
        redirect_uri = response.headers['Location']
        query_params = urlparse.parse_qs(urlparse.urlparse(redirect_uri).query)
        ###
        self.assertIsNotNone(query_params['code'][0])
        self.assertIsNotNone(query_params['state'][0])

    def _http_basic(self,consumer_id,consumer_secret):
        auth_string = consumer_id + ':' + consumer_secret
        return 'Basic ' + auth_string.encode('base64')

    def _generate_urlencoded_request(self,authorization_code,consumer_id,consumer_secret):
        # NOTE(garcianavalon) No use for now, keystone only accepts JSON bodies
        body = 'grant_type=authorization_code&code=%s&redirect_uri=%s' %authorization_code,self.DEFAULT_REDIRECT_URIS[0]
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': self._http_basic(consumer_id,consumer_secret)
        }
        return headers,body

    def _generate_json_request(self,authorization_code,consumer_id,consumer_secret):
        body = {
            'token_request' : {
                'grant_type':'authorization_code',
                'code': authorization_code,
                'redirect_uri':self.DEFAULT_REDIRECT_URIS[0]
            }
        }    
        headers = {
            'Authorization': self._http_basic(consumer_id,consumer_secret)
        }
        return headers,body

    def _obtain_access_token(self):
        response = self._grant_authorization()
        ###
        # TODO(garcianavalon) extract method
        redirect_uri = response.headers['Location']
        query_params = urlparse.parse_qs(urlparse.urlparse(redirect_uri).query)
        authorization_code = query_params['code'][0]
        ###
        consumer_id = self.consumer['id']
        consumer_secret = self.consumer['secret']

        headers,body = self._generate_json_request(authorization_code,
                                                   consumer_id,consumer_secret)
        #POST to the token url
        return self.post('/OS-OAUTH2/access_token',body=body,
                        headers=headers,expected_status=200)

    def test_obtain_access_token(self):
        # TODO(garcianavalon) test all the stuff
        response = self._obtain_access_token()
        json_response = json.loads(response.result)
        self.assertIsNotNone(json_response['access_token'])
        self.assertIsNotNone(json_response['token_type'])
        self.assertIsNotNone(json_response['expires_in'])
        self.assertIsNotNone(json_response['scope'])

        scope = json_response['scope']
        self.assertEqual(scope,self.DEFAULT_SCOPES[0])

    def _exchange_access_token_for_keystone_token(self):
        token_data = json.loads(self._obtain_access_token().result)
        body = {
            "auth": {
                "identity": {  
                    "methods": [
                        "oauth2"
                    ],
                    "oauth2": {
                        'access_token_id':token_data['access_token']
                    },
                },
                "scope": {
                    "project": {
                        "id": self.project_id
                    }
                }
            }
        }
        # POST to the auth url to get a keystone token
        return self.post('/auth/tokens',body=body)

    def test_exchange_access_token_for_keystone_token(self):
        response = self._exchange_access_token_for_keystone_token()
        token = json.loads(response.body)['token']
        #self.assertEqual(token['project']['id'],self.project_id)
        self.assertEqual(token['user']['id'],self.user_id)
        self.assertEqual(token['methods'],["oauth2"])
        self.assertIsNotNone(token['expires_at'])