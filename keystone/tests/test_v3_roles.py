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
    USERS_URL = '/OS-ROLES/users'


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

    def _create_user(self):
        user_ref = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        user = self.identity_api.create_user(user_ref)
        user['password'] = user_ref['password']
        return user

    def _create_organization(self):
        # create a keystone project/fiware organization
        project_ref = self.new_project_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        project_ref['id'] = uuid.uuid4().hex
        project = self.assignment_api.create_project(project_ref['id'], project_ref)
        return project

    def _create_keystone_role(self):
        keystone_role_ref = self.new_role_ref()
        keystone_role_ref['id'] = uuid.uuid4().hex
        keystone_role_ref['name'] = 'keystone_role_%s' % keystone_role_ref['id']
        keystone_role = self.assignment_api.create_role(keystone_role_ref['id'], 
                                                        keystone_role_ref)
        return keystone_role

    def _add_permission_to_role(self, role_id, permission_id, 
                                expected_status=204):
        
        ulr_args = {
            'role_id':role_id,
            'permission_id':permission_id
        }
        url = self.ROLES_URL + '/%(role_id)s/permissions/%(permission_id)s' \
                                %ulr_args
        return self.put(url, expected_status=expected_status)

    def _add_user_to_role(self, role_id, user_id,
                        organization_id, expected_status=204):
        
        ulr_args = {
            'role_id':role_id,
            'user_id':user_id
        }  
        body = {
            'organization': {
                'id': organization_id,
            } 
        }
        url = self.ROLES_URL + '/%(role_id)s/users/%(user_id)s' \
                                %ulr_args
        return self.put(url, expected_status=expected_status, body=body)

    def _add_user_to_organization(self, project_id, user_id, keystone_role_id, 
                                expected_status=204):
        
        self.assignment_api.add_role_to_user_and_project(
            user_id, project_id, keystone_role_id)

    def _delete_role(self, role_id, expected_status=204):

        ulr_args = {
            'role_id': role_id,
        }
        url = self.ROLES_URL + '/%(role_id)s' \
                %ulr_args
        return self.delete(url, expected_status=expected_status)

    def _delete_permission(self, permission_id, expected_status=204):

        ulr_args = {
            'permission_id': permission_id,
        }
        url = self.PERMISSIONS_URL + '/%(permission_id)s' \
                    %ulr_args
        return self.delete(url, expected_status=expected_status)

    def _remove_permission_from_role(self, role_id, permission_id, expected_status=204):
        ulr_args = {
            'role_id':role_id,
            'permission_id':permission_id
        } 
        url = self.ROLES_URL + '/%(role_id)s/permissions/%(permission_id)s' \
                                %ulr_args
        return self.delete(url, expected_status=expected_status)

    def _remove_user_from_role(self, role_id, user_id, 
                            organization_id, expected_status=204):
        ulr_args = {
            'role_id':role_id,
            'user_id':user_id
        }
        body = {
            'organization': {
                'id': organization_id,
            } 
        }  
        url = self.ROLES_URL + '/%(role_id)s/users/%(user_id)s' \
                                %ulr_args
        return self.delete(url, expected_status=expected_status, body=body)

    def _list_roles_for_permission(self, permission_id, expected_status=200):
        ulr_args = {
            'permission_id': permission_id
        }   
        url = self.PERMISSIONS_URL + '/%(permission_id)s/roles/' \
                                %ulr_args
        return self.get(url, expected_status=expected_status)

    def _list_roles_for_user(self, user_id, expected_status=200):
        ulr_args = {
            'user_id': user_id
        }   
        url = self.USERS_URL + '/%(user_id)s/roles/' \
                                %ulr_args
        return self.get(url, expected_status=expected_status)

    def _assert_role(self, role, expected_name, expected_is_editable):
        self.assertIsNotNone(role)
        self.assertIsNotNone(role['id'])
        self.assertEqual(expected_name, role['name'])
        self.assertEqual(expected_is_editable, role['is_editable'])

    def _assert_permission(self, permission, expected_name, expected_is_editable):
        self.assertIsNotNone(permission)
        self.assertIsNotNone(permission['id'])
        self.assertEqual(expected_name, permission['name'])
        self.assertEqual(expected_is_editable, permission['is_editable'])

class RoleCrudTests(RolesBaseTests):

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
        response = self._delete_role(role_id)

    def test_add_permission_to_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

    def test_add_permission_to_role_non_existent(self):
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        response = self._add_permission_to_role(role_id=uuid.uuid4().hex, 
                                                permission_id=permission['id'],
                                                expected_status=404)

    def test_add_non_existent_permission_to_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=uuid.uuid4().hex,
                                                expected_status=404)

    def test_add_permission_to_role_repeated(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

    def test_remove_permission_from_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)

        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])

    def test_remove_permission_from_role_non_associated(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        
        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])

    def test_remove_permission_from_non_existent_role(self):
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)

        response = self._remove_permission_from_role(role_id=uuid.uuid4().hex, 
                                                     permission_id=permission['id'],
                                                     expected_status=404)

    def test_remove_non_existent_permission_from_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)

        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=uuid.uuid4().hex,
                                                     expected_status=404)

    def test_remove_permision_from_role_repeated(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)

        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])
        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])

    def test_add_user_to_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        organization = self._create_organization()
        user = self._create_user()
        response = self._add_user_to_role(role_id=role['id'],
                                          user_id=user['id'],
                                          organization_id=organization['id'])

    def test_add_user_to_role_non_existent(self):
        user = self._create_user()
        organization = self._create_organization()
        response = self._add_user_to_role(role_id=uuid.uuid4().hex, 
                                          user_id=user['id'],
                                          organization_id=organization['id'],
                                          expected_status=404)

    def test_add_non_existent_user_to_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        organization = self._create_organization()
        response = self._add_user_to_role(role_id=role['id'], 
                                          user_id=uuid.uuid4().hex,
                                          organization_id=organization['id'],
                                          expected_status=404)

    def test_add_user_to_role_repeated(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user = self._create_user()
        organization = self._create_organization()
        response = self._add_user_to_role(role_id=role['id'],
                                          user_id=user['id'],
                                          organization_id=organization['id'])
        response = self._add_user_to_role(role_id=role['id'],
                                          user_id=user['id'],
                                          organization_id=organization['id'])

    def test_remove_user_from_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user = self._create_user()
        organization = self._create_organization()
        response = self._add_user_to_role(role_id=role['id'], 
                                          user_id=user['id'],
                                          organization_id=organization['id'])
        response = self._remove_user_from_role(role_id=role['id'], 
                                               user_id=user['id'],
                                               organization_id=organization['id'])

    def test_remove_user_from_non_existent_role(self):
        user = self._create_user()
        organization = self._create_organization()
        response = self._remove_user_from_role(role_id=uuid.uuid4().hex, 
                                               user_id=user['id'],
                                               organization_id=organization['id'],
                                               expected_status=404)

    def test_remove_non_existent_user_from_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        organization = self._create_organization()
        response = self._remove_user_from_role(role_id=role['id'], 
                                               user_id=uuid.uuid4().hex,
                                               organization_id=organization['id'],
                                               expected_status=404)

    def test_remove_user_from_role_repeated(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user = self._create_user()
        organization = self._create_organization()
        response = self._add_user_to_role(role_id=role['id'], 
                                          user_id=user['id'],
                                          organization_id=organization['id'])
        response = self._remove_user_from_role(role_id=role['id'], 
                                               user_id=user['id'],
                                               organization_id=organization['id'])
        response = self._remove_user_from_role(role_id=role['id'], 
                                               user_id=user['id'],
                                               organization_id=organization['id'])

    def test_list_roles_for_permission(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        role_name2 = uuid.uuid4().hex
        role2 = self._create_role(role_name2)

        self._add_permission_to_role(role_id=role['id'], 
                                     permission_id=permission['id'])
        self._add_permission_to_role(role_id=role2['id'], 
                                     permission_id=permission['id'])

        response = self._list_roles_for_permission(permission_id=permission['id'])

        entities = response.result['roles']

        self.assertIsNotNone(entities)

        self.assertEqual(2, len(entities))

    def test_dont_list_deleted_roles_for_permission(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        role_name2 = uuid.uuid4().hex
        role2 = self._create_role(role_name2)

        self._add_permission_to_role(role_id=role['id'], 
                                     permission_id=permission['id'])
        self._add_permission_to_role(role_id=role2['id'], 
                                     permission_id=permission['id']) 
        self._delete_role(role2['id'])

        response = self._list_roles_for_permission(permission_id=permission['id'])

        entities = response.result['roles']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))
        
    def test_list_roles_for_user(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user = self._create_user()
        organization = self._create_organization()
        self._add_user_to_role(role_id=role['id'], 
                                user_id=user['id'],
                                organization_id=organization['id'])

        response = self._list_roles_for_user(user_id=user['id'])
        entities = response.result['roles']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))

    def test_dont_list_deleted_roles_for_user(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user = self._create_user()
        role_name2 = uuid.uuid4().hex
        role2 = self._create_role(role_name2)
        organization = self._create_organization()
        self._add_user_to_role(role_id=role['id'], 
                                user_id=user['id'],
                                organization_id=organization['id'])
        self._add_user_to_role(role_id=role2['id'], 
                                user_id=user['id'],
                                organization_id=organization['id'])
        self._delete_role(role2['id'])

        response = self._list_roles_for_user(user_id=user['id'])

        entities = response.result['roles']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))


class PermissionCrudTests(RolesBaseTests):

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
        response = self._delete_permission(permission_id)

    def test_list_permissions_for_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)

        self._add_permission_to_role(role_id=role['id'], 
                                     permission_id=permission['id'])

        ulr_args = {
            'role_id':role['id']
        }   
        url = self.ROLES_URL + '/%(role_id)s/permissions/' \
                                %ulr_args

        response = self.get(url)
        entities = response.result['permissions']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))

    def test_dont_list_deleted_permissions_for_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        permission_name = uuid.uuid4().hex
        permission = self._create_permission(permission_name)
        permission_name2 = uuid.uuid4().hex
        permission2 = self._create_permission(permission_name2)


        self._add_permission_to_role(role_id=role['id'], 
                                     permission_id=permission['id'])
        self._add_permission_to_role(role_id=role['id'], 
                                     permission_id=permission2['id'])

        permission_id = permission2['id']

        response = self._delete_permission(permission_id)

        ulr_args = {
            'role_id':role['id']
        }   
        url = self.ROLES_URL + '/%(role_id)s/permissions/' \
                                %ulr_args

        response = self.get(url)
        entities = response.result['permissions']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))

class UserControllerTests(RolesBaseTests):

    def test_list_users_for_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user = self._create_user() 

        self._add_user_to_role(role_id=role['id'], 
                                user_id=user['id'])

        ulr_args = {
            'role_id':role['id']
        }   
        url = self.ROLES_URL + '/%(role_id)s/users/' \
                                %ulr_args

        response = self.get(url)
        entities = response.result['users']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))

    def test_dont_list_deleted_users_for_role(self):
        role_name = uuid.uuid4().hex
        role = self._create_role(role_name)
        user1 = self._create_user() 
        user2 = self._create_user() 


        self._add_user_to_role(role_id=role['id'], 
                                     user_id=user1['id'])
        self._add_user_to_role(role_id=role['id'], 
                                     user_id=user2['id'])

        response = self.delete('/users/%(user_id)s' % {
            'user_id': user2['id']})

        ulr_args = {
            'role_id':role['id']
        }   
        url = self.ROLES_URL + '/%(role_id)s/users/' \
                                %ulr_args

        response = self.get(url)
        entities = response.result['users']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))

class FiwareApiTests(RolesBaseTests):

    # FIWARE API tests
    def test_validate_token_unscoped(self):
        # create user
        user = self._create_user()
        # create a keysrtone role
        keystone_role = self._create_keystone_role()

        # create some projects/organizations
        number_of_organizations = 2
        organizations = []
        for i in range(number_of_organizations):
            organizations.append(self._create_organization())
            self._add_user_to_organization(
                        project_id=organizations[i]['id'], 
                        user_id=user['id'],
                        keystone_role_id=keystone_role['id'])

        # assign some user-scoped roles
        number_of_user_roles = 2
        user_roles = []
        for i in range(number_of_user_roles):
            user_roles.append(self._create_role(uuid.uuid4().hex))
            self._add_user_to_role(role_id=user_roles[i]['id'], 
                                    user_id=user['id'])
        # assign some organization-scoped roles
        number_of_organization_roles = 1
        organization_roles = {}
        for organization in organizations:
            for i in range(number_of_organization_roles):
                organization_roles[organization['name']] = (
                    self._create_role(uuid.uuid4().hex))
            self._add_user_to_role(role_id=user_roles[i]['id'], 
                                    user_id=user['id'])
        # get a token for the user
        auth_data = self.build_authentication_request(
            username=user['name'],
            user_domain_id=test_v3.DEFAULT_DOMAIN_ID,
            password=user['password'])
        auth_response = self.post('/auth/tokens', body=auth_data)
        token_id = auth_response.headers.get('X-Subject-Token')

        # acces the resource
        url = '/access-tokens/%s' %token_id
        #import pdb; pdb.set_trace()
        response = self.get(url)

        # check stuff
        # from https://github.com/ging/fi-ware-idm/wiki/\
        # Using-the-FI-LAB-instance#get-user-information-and-roles
        # {
        #   schemas: ["urn:scim:schemas:core:2.0:User"],
        #   id: 1,
        #   actorId: 1,
        #   nickName: "demo",
        #   displayName: "Demo user",
        #   email: "demo@fi-ware.org",
        #   roles: [
        #     {
        #       id: 1,
        #       name: "Manager"
        #     },
        #     {
        #       id: 7
        #       name: "Ticket manager"
        #     }
        #   ],
        #   organizations: [
        #     {
        #        id: 1,
        #        actorId: 2,
        #        displayName: "Universidad Politecnica de Madrid",
        #        roles: [
        #          {
        #            id: 14,
        #            name: "Admin"
        #          }
        #       ]
        #     }
        #   ]
        # }
        self.assertIsNotNone(response.result['id'])
        self.assertIsNotNone(response.result['email'])
        self.assertIsNotNone(response.result['nickName'])

        response_roles = response.result['roles']
        self.assertIsNotNone(response_roles)
        self.assertEqual(number_of_roles, len(response_roles))
        for role in response_roles:
            i = response_roles.index(role)
            self.assertIsNotNone(role['id'])
            self.assertIsNotNone(role['name'])

        response_organizations = response.result['organizations']
        self.assertIsNotNone(response_organizations)
        self.assertEqual(number_of_organizations, len(response_organizations))
        for organization in response_organizations:
            i = response_organizations.index(organization)
            self.assertIsNotNone(organization['id'])
            self.assertIsNotNone(organization['name'])
