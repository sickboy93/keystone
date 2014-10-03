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

import copy
import urlparse
import uuid

from keystone import config
from keystone.contrib.oauth2 import core
from keystone.tests import test_v3

from  requests_oauthlib import OAuth2Session

CONF = config.CONF

class OAuth2Tests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'oauth2'
    EXTENSION_TO_ADD = 'oauth2_extension'

    CONSUMER_URL = '/OS-OAUTH2/consumers'

    def setUp(self):
        super(OAuth2Tests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        #TODO(garcianavalon) I've put this line for dependency injection to work, but I don't know if its the right way to do it...
        self.manager = core.Manager()

    def _create_consumer(self,description=None,client_type='confidential',
                         redirect_uris=[],grant_type='authorization_code',scopes=[]):
        data = {
            'description': description,
            'client_type': client_type,
            'redirect_uris': redirect_uris,
            'grant_type': grant_type,
            'scopes': scopes
        }
        response = self.post(self.CONSUMER_URL,body={'consumer': data})

        return response.result['consumer'],data

# class ConsumerCRUDTests(OAuth2Tests):

#     def _consumer_assertions(self, consumer,data):
#         self.assertEqual(consumer['description'], data['description'])
#         self.assertIsNotNone(consumer['id'])
#         self.assertIsNotNone(consumer['secret'])

#         return consumer

#     def _test_create_consumer(self,consumer_data=None):
#         consumer,data = self._create_consumer(consumer_data)
#         self._consumer_assertions(consumer,data)

#     def test_create_consumer_no_data(self):
#         self._test_create_consumer()

#     def test_consumer_delete(self):
#         consumer,data = self._create_consumer()
#         consumer_id = consumer['id']
#         response = self.delete(self.CONSUMER_URL + '/%s' % consumer_id)
#         self.assertResponseStatus(response, 204)

#     def test_consumer_get(self):
#         consumer,data = self._create_consumer()
#         consumer_id = consumer['id']
#         response = self.get(self.CONSUMER_URL + '/%s' % consumer_id)
#         self_url = ['http://localhost/v3', self.CONSUMER_URL,
#                     '/', consumer_id]
#         self_url = ''.join(self_url)
#         self.assertEqual(response.result['consumer']['links']['self'], self_url)
#         self.assertEqual(response.result['consumer']['id'], consumer_id)

#     def test_consumer_list(self):
#         self._create_consumer()
#         response = self.get(self.CONSUMER_URL)
#         entities = response.result['consumers']
#         self.assertIsNotNone(entities)
#         self_url = ['http://localhost/v3', self.CONSUMER_URL]
#         self_url = ''.join(self_url)
#         self.assertEqual(response.result['links']['self'], self_url)
#         self.assertValidListLinks(response.result['links'])

#     def test_consumer_update(self):
#         consumer,data = self._create_consumer()
#         original_id = consumer['id']
#         original_description = consumer['description'] or ''
#         update_description = original_description + '_new'

#         update_ref = {'description': update_description}
#         update_response = self.patch(self.CONSUMER_URL + '/%s' % original_id,
#                                  body={'consumer': update_ref})
#         consumer = update_response.result['consumer']
#         self.assertEqual(consumer['description'], update_description)
#         self.assertEqual(consumer['id'], original_id)

#     def test_consumer_update_bad_secret(self):
#         consumer,data = self._create_consumer()
#         original_id = consumer['id']
#         update_ref = copy.deepcopy(consumer)
#         update_ref['description'] = uuid.uuid4().hex
#         update_ref['secret'] = uuid.uuid4().hex
#         self.patch(self.CONSUMER_URL + '/%s' % original_id,
#                    body={'consumer': update_ref},
#                    expected_status=400)

#     def test_consumer_update_bad_id(self):
#         consumer,data = self._create_consumer()
#         original_id = consumer['id']
#         original_description = consumer['description'] or ''
#         update_description = original_description + "_new"

#         update_ref = copy.deepcopy(consumer)
#         update_ref['description'] = update_description
#         update_ref['id'] = update_description
#         self.patch(self.CONSUMER_URL + '/%s' % original_id,
#                    body={'consumer': update_ref},
#                    expected_status=400)

#     def test_consumer_get_bad_id(self):
#         self.get(self.CONSUMER_URL + '/%(consumer_id)s'
#                  % {'consumer_id': uuid.uuid4().hex},
#                  expected_status=404)

class OAuth2FlowTests(OAuth2Tests):
    DEFAULT_REDIRECT_URIS = ['https://uri.com']
    DEFAULT_SCOPES = ['basic_scope']

    def _generate_consumer(self):
        #TODO(garcianavalon) refractor this
        self.consumer, self.data = self._create_consumer(redirect_uris=self.DEFAULT_REDIRECT_URIS,
                                     scopes=self.DEFAULT_SCOPES)
        return self.consumer, self.data

    def _create_authorization_url(self):

        consumer,data = self._generate_consumer()
        oauth = OAuth2Session(consumer['id'], 
                              redirect_uri=consumer['redirect_uris'][0],
                              scope=consumer['scopes'][0])
        authorization_url, state = oauth.authorization_url('https://remove.this/OS-OAUTH2/authorize')
        #hack to work around the need for https in request_oauthilb authorization_url 
        #and the fact that RestfulTestCase prepends the base_url when calling get
        authorization_url = authorization_url.replace('https://remove.this','')
        return authorization_url

    # def test_authorization_url(self):
    #     #TODO(garcianavalon) is this encesary? are we testing our test methods here?
    #     #TODO(garcianavalon) check more stuff in the url
    #     authorization_url = self._create_authorization_url()
    #     self.assertIsNotNone(authorization_url)    

    def _request_authorization(self):
        authorization_url = self._create_authorization_url()
        #GET authorization_url to request the authorization
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

    def _authorization_data(self,consumer_id,user_id=1):
        #TODO(garcianavalon) fix user_id, now there is no Foreign Key constrain so we can put any value
        data = {
            "user_auth": {
                "client_id":consumer_id,
                "user_id":user_id,
                "scopes":self.DEFAULT_SCOPES
            }
        }
        return data

    def _grant_authorization(self):
        get_response = self._request_authorization()
        #POST authorization url to simulate ResourceOwner granting authorization
        consumer_id = get_response.result['data']['consumer']['id']
        data = self._authorization_data(consumer_id)
        return self.post('/OS-OAUTH2/authorize',body=data,expected_status=302)

    def test_grant_authorization(self):
        response = self._grant_authorization()

        self.assertIsNotNone(response.headers['Location'])
        ###
        #TODO(garcianavalon) extract method
        redirect_uri = response.headers['Location']
        query_params = urlparse.parse_qs(urlparse.urlparse(redirect_uri).query)
        ###
        self.assertIsNotNone(query_params['code'][0])
        self.assertIsNotNone(query_params['state'][0])

    def _http_basic(self,consumer_id,consumer_secret):
        auth_string = consumer_id + ':' + consumer_secret
        return 'Basic ' + auth_string.encode('base64')

    def _generate_urlencoded_request(self,authorization_code,consumer_id,consumer_secret):
        #No use for now, keystone only accepts JSON bodys
        body = 'grant_type=authorization_code&code=%s&' %authorization_code
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': self._http_basic(consumer_id,consumer_secret)
        }
        return headers,body

    def _generate_json_request(self,authorization_code,consumer_id,consumer_secret):
        #TODO(garcianavalon) implement this stub correctly
        body = {
            'token_request' : {
                'grant_type':'authorization_code',
                'code': authorization_code
            }
        }    
        headers = {
            'Authorization': self._http_basic(consumer_id,consumer_secret)
        }
        return headers,body

    def _obtain_access_token(self):
        response = self._grant_authorization()
        ###
        #TODO(garcianavalon) extract method
        redirect_uri = response.headers['Location']
        query_params = urlparse.parse_qs(urlparse.urlparse(redirect_uri).query)
        authorization_code = query_params['code'][0]
        ###
        consumer_id = self.consumer['id']
        consumer_secret = self.consumer['secret']

        headers,body = self._generate_json_request(authorization_code,
                                                   consumer_id,consumer_secret)
        #POST to the token url
        return self.post('/OS-OAUTH2/access_token',body=body,headers=headers)

    def test_obtain_access_token(self):
        #TODO(garcianavalon) test all the stuff
        response = self._obtain_access_token()
        self.assertIsNotNone(response)