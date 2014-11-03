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
from keystone.contrib.roles import core
from keystone.tests import test_v3

CONF = config.CONF

class RolesBaseTests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'roles'
    EXTENSION_TO_ADD = 'roles_extension'

    ROLES_URL = '/OS-ROLES/roles'
    PERMISSIONS_URL = '/OS-ROLES/permissions'

    def setUp(self):
        super(RolesBaseTests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        # NOTE(garcianavalon) I've put this line for dependency injection to work, 
        # but I don't know if its the right way to do it...
        self.manager = core.RolesManager()

    def _create_role(self, name, is_editable=True):
        data = {
            'name': name,   
        }
        if not is_editable:
            data['is_editable'] = False

        response = self.post(self.ROLES_URL, body={'role': data})

        return response.result['role']

    def _create_permission(self, name, is_editable=True):
        data = {
            'name': name,   
        }
        if not is_editable:
            data['is_editable'] = False

        response = self.post(self.PERMISSIONS_URL, body={'permission': data})

        return response.result['permission']


class RoleCrudTests(RolesBaseTests):

    def test_role_create_default(self):
        name = uuid.uuid4().hex
        role = self._create_role(name)

        self.assertIsNotNone(role)

        self.assertEqual(name, role['name'])
        self.assertEqual(True, role['is_editable'])

    def test_role_create_explicit(self):
        name = uuid.uuid4().hex
        role = self._create_role(name, is_editable=True)

        self.assertIsNotNone(role)

        self.assertEqual(name, role['name'])
        self.assertEqual(True, role['is_editable'])

    def test_role_create_not_editable(self):
        name = uuid.uuid4().hex
        role = self._create_role(name, is_editable=False)

        self.assertIsNotNone(role)

        self.assertEqual(name, role['name'])
        self.assertEqual(False, role['is_editable'])

    def test_role_to_application(self):
        # TODO(garcianavalon)
        pass

    def test_roles_list(self):
        role1 = self._create_role(uuid.uuid4().hex)
        role2 = self._create_role(uuid.uuid4().hex)
        response = self.get(self.ROLES_URL)
        entities = response.result['roles']
        self.assertIsNotNone(entities)

        self_url = ['http://localhost/v3', self.ROLES_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])

        self.assertEqual(2, len(entities))

class PermissionCrudTests(RolesBaseTests):

    def test_permission_create_default(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name)

        self.assertIsNotNone(permission)

        self.assertEqual(name, permission['name'])
        self.assertEqual(True, permission['is_editable'])

    def test_permission_create_explicit(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name, is_editable=True)

        self.assertIsNotNone(permission)

        self.assertEqual(name, permission['name'])
        self.assertEqual(True, permission['is_editable'])

    def test_permission_create_not_editable(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name, is_editable=False)

        self.assertIsNotNone(permission)

        self.assertEqual(name, permission['name'])
        self.assertEqual(False, permission['is_editable'])

    def test_permission_to_application(self):
        # TODO(garcianavalon)
        pass

    def test_permissions_list(self):
        permission1 = self._create_permission(uuid.uuid4().hex)
        permission2 = self._create_permission(uuid.uuid4().hex)
        response = self.get(self.PERMISSIONS_URL)
        entities = response.result['permissions']
        self.assertIsNotNone(entities)

        self_url = ['http://localhost/v3', self.PERMISSIONS_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])

        self.assertEqual(2, len(entities))

