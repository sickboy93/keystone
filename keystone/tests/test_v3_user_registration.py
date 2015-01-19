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

import base64
import copy
import json
import urllib
import urlparse
import uuid

from keystone import config
from keystone.common import dependency
from keystone.contrib.user_registration import core
from keystone.tests import test_v3

CONF = config.CONF

class RegistrationBaseTests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'user_registration'
    EXTENSION_TO_ADD = 'user_registration_extension'

    BASE_URL = '/OS-REGISTRATION/users'
    REGISTER_URL = BASE_URL
    REQUEST_NEW_ACTIVATION_KEY_URL = BASE_URL + '/{user_id}/activate'
    PERFORM_ACTIVATION_URL = BASE_URL + '/{user_id}/activate/{activation_key}'
    REQUEST_RESET_URL = BASE_URL + '/{user_id}/reset_password'
    PERFORM_RESET_URL = BASE_URL + '/{user_id}/reset_password/{token_id}'

    PROJECTS_URL = '/projects/{project_id}'
    ROLES_URL = '/projects/{project_id}/users/{user_id}/roles'

    def setUp(self):
        super(RegistrationBaseTests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        # TODO(garcianavalon) I've put this line for dependency injection to work, 
        # but I don't know if its the right way to do it...
        self.manager = core.Manager()

    def _register_new_user(self, user_ref=None):
        user_ref = user_ref if user_ref else self.new_user_ref(
                                                    domain_id=self.domain_id)

        response = self.post(self.REGISTER_URL, body={'user': user_ref})
        return response.result['user']
        
    def _activate_user(self, user_id, activation_key):
        response = self.patch(self.PERFORM_ACTIVATION_URL.format(user_id=user_id,
                                                    activation_key=activation_key))
        return response.result['user']

    def _get_default_project(self, new_user):
        response = self.get(self.PROJECTS_URL.format(
                                        project_id=new_user['default_project_id']))
        return response.result['project']

    def _get_project_user_roles(self, user_id, project_id):
        response = self.get(self.ROLES_URL.format(user_id=user_id,
                                                project_id=project_id))
        return response.result['roles']


class RegistrationUseCaseTests(RegistrationBaseTests):


    def test_registered_user(self):
        new_user_ref = self.new_user_ref(domain_id=self.domain_id)
        new_user = self._register_new_user(new_user_ref)

        # Check the user is not enabled
        self.assertEqual(False, new_user['enabled'])

        # Check the user comes with activation_key
        self.assertIsNotNone(new_user['activation_key'])

        # and that it has a project
        self.assertIsNotNone(new_user['default_project_id'])

    def test_default_project(self):
        new_user_ref = self.new_user_ref(domain_id=self.domain_id)
        new_user = self._register_new_user(new_user_ref)

        # Check a project with same name as user exists
        new_project = self._get_default_project(new_user)
        self.assertIsNotNone(new_project)
        self.assertEqual(new_user['name'], new_project['name'])
        # and is not enabled
        self.assertEqual(False, new_project['enabled'])

    def test_user_belongs_to_project(self):
        new_user_ref = self.new_user_ref(domain_id=self.domain_id)
        new_user = self._register_new_user(new_user_ref)

        # Check the user belongs and has a role in his default project
        new_project = self._get_default_project(new_user)
        roles = self._get_project_user_roles(new_user['id'], 
                                            new_project['id'])
        self.assertIsNotNone(roles)
        self.assertEqual(1, len(roles))

        # check that it actually is the default role
        role = roles[0]
        self.assertEqual(core.DEFAULT_ROLE_ID, role['id'])
        self.assertEqual(core.DEFAULT_ROLE_NAME, role['name'])


class ActivationUseCaseTest(RegistrationBaseTests):


    def test_activate_user(self):
        new_user = self._register_new_user()
        active_user = self._activate_user(user_id=new_user['id'],
                                activation_key=new_user['activation_key'])

        # Check the user is active
        self.assertEqual(True, active_user['enabled'])

        # Check id to be sure
        self.assertEqual(new_user['id'], active_user['id'])

    def test_default_project_active(self):
        new_user = self._register_new_user()
        new_project = self._get_default_project(new_user)
        active_user = self._activate_user(user_id=new_user['id'],
                                activation_key=new_user['activation_key'])
        active_project = self._get_default_project(new_user)

        # Check the project is active
        self.assertEqual(True, active_project['enabled'])

        # Check id to be sure
        self.assertEqual(new_project['id'], active_project['id'])

