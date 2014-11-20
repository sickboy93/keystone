# Copyright (C) 2014 Universidad Politecnica de Madrid
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

from keystone import config
from keystone.tests import rest

CONF = config.CONF

class FiwareLegacyApiTests(rest.RestfulTestCase):

    def setUp(self):
        super(FiwareLegacyApiTests, self).setUp()

    def test_validate_token_redirection(self):
        token_id = uuid.uuid4().hex
        endpoint = '/access-tokens/%s' %token_id
        path = '/v2.0%s' %endpoint
        response = self.public_request(path=path, 
                                    expected_status=301)
        self.assertIsNotNone(response.headers['Location'])
        redirect_url = response.headers['Location']

        self.assertEqual(u'http://localhost/v3%s' %endpoint, redirect_url)