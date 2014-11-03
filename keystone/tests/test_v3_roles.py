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

    def _assert_role(self, role, expected_name, expected_is_editable):
        self.assertIsNotNone(role)
        self.assertIsNotNone(role['id'])
        self.assertEqual(expected_name, role['name'])
        self.assertEqual(expected_is_editable, role['is_editable'])

    def test_role_create_default(self):
        name = uuid.uuid4().hex
        role = self._create_role(name)

        self._assert_role(role, name, True)

    def test_role_create_explicit(self):
        name = uuid.uuid4().hex
        role = self._create_role(name, is_editable=True)

        self._assert_role(role, name, True)

    def test_role_create_not_editable(self):
        name = uuid.uuid4().hex
        role = self._create_role(name, is_editable=False)

        self._assert_role(role, name, False)

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

    def test_get_role(self):
        name = uuid.uuid4().hex
        role = self._create_role(name)
        role_id = role['id']
        response = self.get(self.ROLES_URL + '/%s' %role_id)
        get_role = response.result['role']

        self._assert_role(role, name, True)
        self_url = ['http://localhost/v3', self.ROLES_URL, '/', role_id]
        self_url = ''.join(self_url)
        self.assertEqual(self_url, get_role['links']['self'])
        self.assertEqual(role_id, get_role['id'])

    def test_update_role(self):
        name = uuid.uuid4().hex
        role = self._create_role(name)
        original_id = role['id']
        original_name = role['name']
        update_name = original_name + '_new'
       
        body = {
            'role': {
                'name': update_name,
            }
        }
        response = self.patch(self.ROLES_URL + '/%s' %original_id,
                                 body=body)
        update_role = response.result['role']

        self._assert_role(update_role, update_name, True)
        self.assertEqual(original_id, update_role['id'])

    def test_delete_role(self):
        name = uuid.uuid4().hex
        role = self._create_role(name)
        role_id = role['id']
        response = self.delete(self.ROLES_URL + '/%s' %role_id,
                                expected_status=204)

    def test_add_permissions_to_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        role_id = role['id']
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)

        body = {
            'role': {
                'permissions': [permission['id']],
            }
        }
        response = self.patch(self.ROLES_URL + '/%s' %role_id,
                                 body=body)
        update_role = response.result['role']

        self._assert_role(update_role, role_name, True)
        self.assertIsNotNone(role['permissions'])
        self.assertEqual(1, len(role['permissions']))
        self.assertEqual(permission_name, role['permissions'][0]['name'])

class PermissionCrudTests(RolesBaseTests):

    def _assert_permission(self, permission, expected_name, expected_is_editable):
        self.assertIsNotNone(permission)
        self.assertIsNotNone(permission['id'])
        self.assertEqual(expected_name, permission['name'])
        self.assertEqual(expected_is_editable, permission['is_editable'])

    def test_permission_create_default(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name)

        self._assert_permission(permission, name, True)

    def test_permission_create_explicit(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name, is_editable=True)

        self._assert_permission(permission, name, True)

    def test_permission_create_not_editable(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name, is_editable=False)

        self._assert_permission(permission, name, False)

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

    def test_get_permission(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name)
        permission_id = permission['id']
        response = self.get(self.PERMISSIONS_URL + '/%s' %permission_id)
        get_permission = response.result['permission']

        self._assert_permission(permission, name, True)
        self_url = ['http://localhost/v3', self.PERMISSIONS_URL, '/', permission_id]
        self_url = ''.join(self_url)
        self.assertEqual(self_url, get_permission['links']['self'])
        self.assertEqual(permission_id, get_permission['id'])

    def test_update_permission(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name)
        original_id = permission['id']
        original_name = permission['name']
        update_name = original_name + '_new'
       
        body = {
            'permission': {
                'name': update_name,
            }
        }
        response = self.patch(self.PERMISSIONS_URL + '/%s' %original_id,
                                 body=body)
        update_permission = response.result['permission']

        self._assert_permission(update_permission, update_name, True)
        self.assertEqual(original_id, update_permission['id'])

    def test_delete_permission(self):
        name = uuid.uuid4().hex
        permission = self._create_permission(name)
        permission_id = permission['id']
        response = self.delete(self.PERMISSIONS_URL + '/%s' %permission_id,
                                expected_status=204)