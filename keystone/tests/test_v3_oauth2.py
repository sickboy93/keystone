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

from six.moves import urllib

from keystone import config
from keystone.contrib import oauth2
from keystone.contrib.oauth2 import controllers
from keystone.contrib.oauth2 import core
from keystone import exception
from keystone.openstack.common import jsonutils
from keystone.tests.ksfixtures import temporaryfile
from keystone.tests import test_v3


CONF = config.CONF


class OAuth2Tests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'oauth2'
    EXTENSION_TO_ADD = 'oauth2_extension'

    CONSUMER_URL = '/OS-OAUTH2/consumers'

    def setUp(self):
        super(OAuth2Tests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        self.controller = controllers.OAuthControllerV3()

    def _create_consumer(self, description=None,client_type='confidential',
                         redirect_uris=[],grant_type='authorization_code',scopes=[]):
        data = {
            'description': description,
            'client_type': client_type,
            'redirect_uris': redirect_uris,
            'grant_type': grant_type,
            'scopes': scopes
        }
        resp = self.post(self.CONSUMER_URL,body={'consumer': data})

        return resp.result['consumer']


class ConsumerCRUDTests(OAuth2Tests):


    def _create_consumer_assertions(self, consumer):
        
        self.assertEqual(consumer['description'], description)
        self.assertIsNotNone(consumer['id'])
        self.assertIsNotNone(consumer['secret'])
        return consumer

    def test_create_consumer(self):
        self._create_consumer_assertions(description='a description',
                            redirect_uris=['http://a.uri.com'],
                            scopes=['some scopes'])

    def test_create_consumer_no_data(self):
        self._create_consumer_assertions()

    def test_consumer_delete(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        resp = self.delete(self.CONSUMER_URL + '/%s' % consumer_id)
        self.assertResponseStatus(resp, 204)

    def test_consumer_get(self):
        consumer = self._create_single_consumer()
        consumer_id = consumer['id']
        resp = self.get(self.CONSUMER_URL + '/%s' % consumer_id)
        self_url = ['http://localhost/v3', self.CONSUMER_URL,
                    '/', consumer_id]
        self_url = ''.join(self_url)
        self.assertEqual(resp.result['consumer']['links']['self'], self_url)
        self.assertEqual(resp.result['consumer']['id'], consumer_id)

    def test_consumer_list(self):
        self._create_consumer()
        resp = self.get(self.CONSUMER_URL)
        entities = resp.result['consumers']
        self.assertIsNotNone(entities)
        self_url = ['http://localhost/v3', self.CONSUMER_URL]
        self_url = ''.join(self_url)
        self.assertEqual(resp.result['links']['self'], self_url)
        self.assertValidListLinks(resp.result['links'])

    def test_consumer_update(self):
        consumer = self._create_single_consumer()
        original_id = consumer['id']
        original_description = consumer['description']
        update_description = original_description + '_new'

        update_ref = {'description': update_description}
        update_resp = self.patch(self.CONSUMER_URL + '/%s' % original_id,
                                 body={'consumer': update_ref})
        consumer = update_resp.result['consumer']
        self.assertEqual(consumer['description'], update_description)
        self.assertEqual(consumer['id'], original_id)

    def test_consumer_update_bad_secret(self):
        consumer = self._create_single_consumer()
        original_id = consumer['id']
        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = uuid.uuid4().hex
        update_ref['secret'] = uuid.uuid4().hex
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_bad_id(self):
        consumer = self._create_single_consumer()
        original_id = consumer['id']
        original_description = consumer['description']
        update_description = original_description + "_new"

        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = update_description
        update_ref['id'] = update_description
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_normalize_field(self):
        # If update a consumer with a field with : or - in the name,
        # the name is normalized by converting those chars to _.
        field1_name = 'some:weird-field'
        field1_orig_value = uuid.uuid4().hex

        extra_fields = {field1_name: field1_orig_value}
        consumer = self._create_consumer(**extra_fields)
        consumer_id = consumer['id']

        field1_new_value = uuid.uuid4().hex

        field2_name = 'weird:some-field'
        field2_value = uuid.uuid4().hex

        update_ref = {field1_name: field1_new_value,
                      field2_name: field2_value}

        update_resp = self.patch(self.CONSUMER_URL + '/%s' % consumer_id,
                                 body={'consumer': update_ref})
        consumer = update_resp.result['consumer']

        normalized_field1_name = 'some_weird_field'
        self.assertEqual(field1_new_value, consumer[normalized_field1_name])

        normalized_field2_name = 'weird_some_field'
        self.assertEqual(field2_value, consumer[normalized_field2_name])

    def test_create_consumer_no_description(self):
        resp = self.post(self.CONSUMER_URL, body={'consumer': {}})
        consumer = resp.result['consumer']
        consumer_id = consumer['id']
        self.assertIsNone(consumer['description'])
        self.assertIsNotNone(consumer_id)
        self.assertIsNotNone(consumer['secret'])

    def test_consumer_get_bad_id(self):
        self.get(self.CONSUMER_URL + '/%(consumer_id)s'
                 % {'consumer_id': uuid.uuid4().hex},
                 expected_status=404)
