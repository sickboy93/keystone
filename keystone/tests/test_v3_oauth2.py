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

    def _create_consumer(self, data=None):

        if data is None:
            data = self._consumer_data()
        response = self.post(self.CONSUMER_URL,body={'consumer': data})

        return response.result['consumer'],data

    def _consumer_data(self,description=None,client_type='confidential',
                         redirect_uris=[],grant_type='authorization_code',scopes=[]):
        data = {
            'description': description,
            'client_type': client_type,
            'redirect_uris': redirect_uris,
            'grant_type': grant_type,
            'scopes': scopes
        }
        return data

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


    def test_request_authorization(self):
        data = self._consumer_data(redirect_uris=['https://uri.com'],
                                  scopes=['basic_scope'])
        consumer,data = self._create_consumer(data)

        #self.assertIsNotNone(consumer['secret'])

        oauth = OAuth2Session(consumer['id'], 
                              redirect_uri=consumer['redirect_uris'][0],
                              scope=consumer['scopes'][0])

        authorization_url, state = oauth.authorization_url('https://remove.this/OS-OAUTH2/authorize')
        #hack to work around the need for https in request_oauthilb authorization_url 
        #and the fact that RestfulTestCase prepends the base_url when calling get
        authorization_url = authorization_url.replace('https://remove.this','')
        self.assertIsNotNone(authorization_url)
        #GET authorization_url to request the authorization
        response = self.get(authorization_url)

        