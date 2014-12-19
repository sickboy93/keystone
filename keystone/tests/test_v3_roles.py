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
from keystone.common import dependency
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

    def new_fiware_role_ref(self, name, application=False, is_internal=False):
        role_ref = {
            'name': name,
            'application': application if application else uuid.uuid4().hex,
        }
        if is_internal:
            role_ref['is_internal'] = True
        return role_ref

    def _create_role(self, role_ref=None):
        if not role_ref:
            role_ref = self.new_fiware_role_ref(uuid.uuid4().hex)
        response = self.post(self.ROLES_URL, body={'role': role_ref})

        return response.result['role']

    def new_fiware_permission_ref(self, name, application=False, is_internal=False):
        permission_ref = {
            'name': name,
            'application': application if application else uuid.uuid4().hex,  
        }
        if is_internal:
            permission_ref['is_internal'] = True
        return permission_ref

    def _create_permission(self, permission_ref=None):
        if not permission_ref:
            permission_ref = self.new_fiware_permission_ref(uuid.uuid4().hex)        
        response = self.post(self.PERMISSIONS_URL, body={'permission': permission_ref})

        return response.result['permission']

    def _create_user(self):
        user_ref = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        user = self.identity_api.create_user(user_ref)
        user['password'] = user_ref['password']
        # To simulate the IdM's registration we also create a project with 
        # the same name as the user and give it membership status
        keystone_role = self._create_keystone_role()
        project = self._create_organization(name=user['name'])
        self._add_user_to_organization(
                        project_id=project['id'], 
                        user_id=user['id'],
                        keystone_role_id=keystone_role['id'])
        return user, project

    def _create_organization(self, name=None):
        # create a keystone project/fiware organization
        project_ref = self.new_project_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        project_ref['id'] = uuid.uuid4().hex
        if name:
            project_ref['name'] = name
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


    def _add_user_to_organization(self, project_id, user_id, keystone_role_id):
        self.assignment_api.add_role_to_user_and_project(
            user_id, project_id, keystone_role_id)

    def _add_role_to_user(self, role_id, user_id, 
                        organization_id, expected_status=204):
        ulr_args = {
            'role_id': role_id,
            'user_id': user_id,
            'organization_id': organization_id,
        }
        url = self.USERS_URL + '/%(user_id)s/organizations/%(organization_id)s/roles/%(role_id)s' \
                                %ulr_args
        return self.put(url, expected_status=expected_status)

    def _add_multiple_roles_to_user(self, number_of_roles, user_id, 
                        organization_id):
        user_roles = []
        for i in range(number_of_roles):
            user_roles.append(self._create_role())
            self._add_role_to_user(role_id=user_roles[i]['id'], 
                                    user_id=user_id,
                                    organization_id=organization_id)

        return user_roles

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

    def _remove_role_from_user(self, role_id, user_id, 
                            organization_id, expected_status=204):
        ulr_args = {
            'role_id':role_id,
            'user_id':user_id,
            'organization_id': organization_id,
        }
        url = self.USERS_URL + '/%(user_id)s/organizations/%(organization_id)s/roles/%(role_id)s' \
                                %ulr_args
        return self.delete(url, expected_status=expected_status)

    def _list_roles_for_user(self, user_id, organization_id, expected_status=200):
        ulr_args = {
            'user_id': user_id,
            'organization_id': organization_id
        }   
        url = self.USERS_URL + '/%(user_id)s/organizations/%(organization_id)s/roles/' \
                                %ulr_args
        return self.get(url, expected_status=expected_status)

    def _list_roles_allowed_to_assign(self, user_id, organization_id, 
                                                    expected_status=200):
        ulr_args = {
            'user_id': user_id,
            'organization_id': organization_id
        }   
        url = self.USERS_URL + '/%(user_id)s/organizations/%(organization_id)s/roles/allowed' \
                                %ulr_args
        return self.get(url, expected_status=expected_status)

    def _assert_role(self, test_role, reference_role):
        self.assertIsNotNone(test_role)
        self.assertIsNotNone(test_role['id'])
        self.assertEqual(reference_role['name'], test_role['name'])
        if hasattr(reference_role, 'is_internal'):
            self.assertEqual(reference_role['is_internal'], test_role['is_internal'])

    def _assert_permission(self, test_permission, reference_permission):
        self.assertIsNotNone(test_permission)
        self.assertIsNotNone(test_permission['id'])
        self.assertEqual(reference_permission['name'], test_permission['name'])
        if hasattr(reference_permission, 'is_internal'):
            self.assertEqual(reference_permission['is_internal'], test_permission['is_internal'])

    def _assert_list(self, entities, entity_type, reference_list):
        """ Utility method to check lists."""
        self.assertIsNotNone(entities)
        self.assertEqual(len(reference_list), len(entities))
        for entity in entities:
            reference_entity = [item for item in reference_list if item['id'] == entity['id']]
            self.assertEqual(len(reference_entity), 1)
            # FIXME(garcianavalon) not ready yet! dont use this method!
            entity_assert_method = getattr(RolesBaseTests, 'assert_%s' %entity_type)
            entity_assert_method(entity, reference_entity)

class RoleCrudTests(RolesBaseTests):

    def test_role_create_default(self):
        role_ref = self.new_fiware_role_ref(uuid.uuid4().hex)
        role = self._create_role(role_ref)

        self._assert_role(role, role_ref)

    def test_role_create_explicit(self):
        role_ref = self.new_fiware_role_ref(uuid.uuid4().hex, is_internal=True)
        role = self._create_role(role_ref)

        self._assert_role(role, role_ref)

    def test_role_create_not_editable(self):
        role_ref = self.new_fiware_role_ref(uuid.uuid4().hex, is_internal=False)
        role = self._create_role(role_ref)

        self._assert_role(role, role_ref)

    def test_roles_list(self):
        role1 = self._create_role()
        role2 = self._create_role()
        response = self.get(self.ROLES_URL)
        entities = response.result['roles']
        self.assertIsNotNone(entities)

        self_url = ['http://localhost/v3', self.ROLES_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])

        self.assertEqual(2, len(entities))

    def test_get_role(self):
        role_ref = self.new_fiware_role_ref(uuid.uuid4().hex)
        role = self._create_role(role_ref)
        role_id = role['id']
        response = self.get(self.ROLES_URL + '/%s' %role_id)
        get_role = response.result['role']

        self._assert_role(role, role_ref)
        self_url = ['http://localhost/v3', self.ROLES_URL, '/', role_id]
        self_url = ''.join(self_url)
        self.assertEqual(self_url, get_role['links']['self'])
        self.assertEqual(role_id, get_role['id'])

    def test_update_role(self):
        role_ref = self.new_fiware_role_ref(uuid.uuid4().hex)
        role = self._create_role(role_ref)
        original_id = role['id']
        update_name = role['name'] + '_new'
        role_ref['name'] = update_name
        body = {
            'role': {
                'name': update_name,
            }
        }
        response = self.patch(self.ROLES_URL + '/%s' %original_id,
                                 body=body)
        update_role = response.result['role']

        self._assert_role(update_role, role_ref)
        self.assertEqual(original_id, update_role['id'])

    def test_delete_role(self):
        role_ref = self.new_fiware_role_ref(uuid.uuid4().hex)
        role = self._create_role(role_ref)
        role_id = role['id']
        response = self._delete_role(role_id)

        
    def test_list_roles_for_user(self):
        user, organization = self._create_user()
        number_of_roles = 2
        user_roles = self._add_multiple_roles_to_user(number_of_roles, 
                                                user['id'], organization['id'])

        response = self._list_roles_for_user(user_id=user['id'],
                                          organization_id=organization['id'])
        entities = response.result['roles']

        #self._assert_list(entities, 'role', user_roles)
        self.assertIsNotNone(entities)
        self.assertEqual(len(user_roles), len(entities))
        for role in entities:
            reference_role = [r for r in user_roles if r['id'] == role['id']]
            self.assertEqual(len(reference_role), 1)
            self._assert_role(role, reference_role[0])
            self.assertIsNotNone(role['organization_id'])
            self.assertEqual(organization['id'], role['organization_id'])

    def test_add_role_to_user(self):
        role = self._create_role()
        user, organization = self._create_user()
        response = self._add_role_to_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])

    def test_add_non_existent_role_to_user(self):
        user, organization = self._create_user()
        response = self._add_role_to_user(role_id=uuid.uuid4().hex,
                                        user_id=user['id'],
                                        organization_id=organization['id'],
                                        expected_status=404)

    def test_add_role_to_non_existent_user(self):
        role = self._create_role()
        response = self._add_role_to_user(role_id=role['id'],
                                        user_id=uuid.uuid4().hex,
                                        organization_id=uuid.uuid4().hex,
                                        expected_status=404)

    def test_add_role_to_user_repeated(self):
        role = self._create_role()
        user, organization = self._create_user()
        response = self._add_role_to_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])
        response = self._add_role_to_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])

    def test_remove_role_from_user(self):
        role = self._create_role()
        user, organization = self._create_user()
        response = self._add_role_to_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])
        response = self._remove_role_from_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])

    def test_remove_non_existent_role_from_user(self):
        user, organization = self._create_user()
        response = self._remove_role_from_user(role_id=uuid.uuid4().hex,
                                            user_id=user['id'],
                                            organization_id=organization['id'],
                                            expected_status=404)

    def test_remove_role_from_non_existent_user(self):
        role = self._create_role()
        response = self._remove_role_from_user(role_id=role['id'],
                                            user_id=uuid.uuid4().hex,
                                            organization_id=uuid.uuid4().hex,
                                            expected_status=404)

    def test_remove_user_from_role_repeated(self):
        role = self._create_role()
        user, organization = self._create_user()
        response = self._add_role_to_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])
        response = self._remove_role_from_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])
        response = self._remove_role_from_user(role_id=role['id'],
                                        user_id=user['id'],
                                        organization_id=organization['id'])

    def test_list_roles_allowed_to_assign_all(self):
        user, organization = self._create_user()
        applications = [
            uuid.uuid4().hex,
        ]
        for app in applications:
            permissions = []
            # create the internal permissions
            perm_ref = self.new_fiware_permission_ref(
                                    core.ASSIGN_ALL_ROLES_PERMISSION, 
                                    application=app, 
                                    is_internal=True)
            permissions.append(self._create_permission(perm_ref))

            # create the internal role
            role_ref = self.new_fiware_permission_ref(
                                    uuid.uuid4().hex, 
                                    application=app, 
                                    is_internal=True)
            role = self._create_role(role_ref)
            # assign the permissions to the role
            for permission in permissions:
                self._add_permission_to_role(role['id'], permission['id'])

            # grant the role to the user
            self._add_role_to_user(role['id'], user['id'], organization['id'])

        response = self._list_roles_allowed_to_assign(user_id=user['id'],
                                          organization_id=organization['id'])
        # check the correct roles are displayed

class PermissionCrudTests(RolesBaseTests):

    def test_create_permission_default(self):
        permission_ref = self.new_fiware_permission_ref(uuid.uuid4().hex)
        permission = self._create_permission(permission_ref)

        self._assert_permission(permission, permission_ref)

    def test_create_permission_explicit(self):
        permission_ref = self.new_fiware_permission_ref(uuid.uuid4().hex, is_internal=True)
        permission = self._create_permission(permission_ref)

        self._assert_permission(permission, permission_ref)

    def test_create_permission_not_editable(self):
        permission_ref = self.new_fiware_permission_ref(uuid.uuid4().hex, is_internal=False)
        permission = self._create_permission(permission_ref)

        self._assert_permission(permission, permission_ref)

    def test_list_permissions(self):
        permission1 = self._create_permission()
        permission2 = self._create_permission()

        response = self.get(self.PERMISSIONS_URL)
        entities = response.result['permissions']

        self.assertIsNotNone(entities)

        self_url = ['http://localhost/v3', self.PERMISSIONS_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])

        self.assertEqual(2, len(entities))

    def test_get_permission(self):
        permission_ref = self.new_fiware_permission_ref(uuid.uuid4().hex)
        permission = self._create_permission(permission_ref)
        permission_id = permission['id']
        response = self.get(self.PERMISSIONS_URL + '/%s' %permission_id)
        get_permission = response.result['permission']

        self._assert_permission(permission, permission_ref)
        self_url = ['http://localhost/v3', self.PERMISSIONS_URL, '/', permission_id]
        self_url = ''.join(self_url)
        self.assertEqual(self_url, get_permission['links']['self'])
        self.assertEqual(permission_id, get_permission['id'])

    def test_update_permission(self):
        permission_ref = self.new_fiware_permission_ref(uuid.uuid4().hex)
        permission = self._create_permission(permission_ref)
        original_id = permission['id']
        original_name = permission['name']
        update_name = original_name + '_new'
        permission_ref['name'] = update_name
        body = {
            'permission': {
                'name': update_name,
            }
        }
        response = self.patch(self.PERMISSIONS_URL + '/%s' %original_id,
                                 body=body)
        update_permission = response.result['permission']

        self._assert_permission(update_permission, permission_ref)
        self.assertEqual(original_id, update_permission['id'])

    def test_delete_permission(self):
        permission = self._create_permission()
        permission_id = permission['id']
        response = self._delete_permission(permission_id)

    def test_list_permissions_for_role(self):
        role = self._create_role()
        permission = self._create_permission()

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

    def test_add_permission_to_role(self):
        role = self._create_role()
        permission = self._create_permission()
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

    def test_add_permission_to_role_non_existent(self):
        permission = self._create_permission()
        response = self._add_permission_to_role(role_id=uuid.uuid4().hex, 
                                                permission_id=permission['id'],
                                                expected_status=404)

    def test_add_non_existent_permission_to_role(self):
        role = self._create_role()
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=uuid.uuid4().hex,
                                                expected_status=404)

    def test_add_permission_to_role_repeated(self):
        role = self._create_role()
        permission = self._create_permission()
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])
        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

    def test_remove_permission_from_role(self):
        role = self._create_role()
        permission = self._create_permission()

        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])

    def test_remove_permission_from_role_non_associated(self):
        role = self._create_role()
        permission = self._create_permission()
        
        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])

    def test_remove_permission_from_non_existent_role(self):
        permission = self._create_permission()

        response = self._remove_permission_from_role(role_id=uuid.uuid4().hex, 
                                                     permission_id=permission['id'],
                                                     expected_status=404)

    def test_remove_non_existent_permission_from_role(self):
        role = self._create_role()

        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=uuid.uuid4().hex,
                                                     expected_status=404)

    def test_remove_permision_from_role_repeated(self):
        role = self._create_role()
        permission = self._create_permission()

        response = self._add_permission_to_role(role_id=role['id'], 
                                                permission_id=permission['id'])

        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])
        response = self._remove_permission_from_role(role_id=role['id'], 
                                                     permission_id=permission['id'])

@dependency.requires('oauth2_api')
class FiwareApiTests(RolesBaseTests):

    def _create_organizations_with_user_and_keystone_role(self, 
                    user, keystone_role, number):
        organizations = []
        for i in range(number):
            organizations.append(self._create_organization())
            self._add_user_to_organization(
                        project_id=organizations[i]['id'], 
                        user_id=user['id'],
                        keystone_role_id=keystone_role['id'])
        return organizations

    def _assign_user_scoped_roles(self, user, user_organization, number):
        user_roles = []
        for i in range(number):
            user_roles.append(self._create_role())
            self._add_role_to_user(role_id=user_roles[i]['id'], 
                                    user_id=user['id'],
                                    organization_id=user_organization['id'])
        return user_roles

    def _assign_organization_scoped_roles(self, user, organizations, number):
        organization_roles = {}
        for organization in organizations:
            organization_roles[organization['name']] = []
            for i in range(number):
                organization_roles[organization['name']].append(
                    self._create_role())
                role = organization_roles[organization['name']][i]
                self._add_role_to_user(role_id=role['id'], 
                                    user_id=user['id'],
                                    organization_id=organization['id'])
        return organization_roles

    def _create_oauth2_token(self, user):
        token_dict = {
            'id':uuid.uuid4().hex,
            'consumer_id':uuid.uuid4().hex,
            'authorizing_user_id':user['id'],
            'scopes': [uuid.uuid4().hex],
            'expires_at':uuid.uuid4().hex,
        }
        # TODO(garcianavalon) the correct thing to do here is mock up the
        # get_access_token call inside our method
        oauth2_access_token = self.oauth2_api.store_access_token(token_dict)
        return oauth2_access_token['id']

    def _validate_token(self, token_id):
        url = '/access-tokens/%s' %token_id
        return self.get(url)

    def _assert_user_info(self, response):
        self.assertIsNotNone(response.result['id'])
        self.assertIsNotNone(response.result['email'])
        self.assertIsNotNone(response.result['nickName'])

    def _assert_user_scoped_roles(self, response, reference):
        response_user_roles = response.result['roles']
        self.assertIsNotNone(response_user_roles)
        for role in response_user_roles:
            self.assertIsNotNone(role['id'])
            self.assertIsNotNone(role['name'])
        actual_user_roles = set([role['id'] for role in response_user_roles])
        expected_user_roles = set([role['id'] for role in reference])
        self.assertEqual(actual_user_roles, expected_user_roles)
    
    def _assert_organization_scoped_roles(self, response, reference, number_of_organizations):
        response_organizations = response.result['organizations']
        self.assertIsNotNone(response_organizations)
        self.assertEqual(number_of_organizations, len(response_organizations))
        for organization in response_organizations:
            self.assertIsNotNone(organization['id'])
            self.assertIsNotNone(organization['name'])
            self.assertIsNotNone(organization['roles'])
            for role in organization['roles']:
                self.assertIsNotNone(role['id'])
                self.assertIsNotNone(role['name'])
            actual_org_roles = set([role['id'] for role in organization['roles']])
            expected_org_roles = set([role['id'] for role 
                                    in reference[organization['name']]])
            self.assertEqual(expected_org_roles, actual_org_roles)

    # FIWARE API tests
    def _test_validate_token(self, number_of_organizations=0, number_of_user_roles=0,
                            number_of_organization_roles=0):
        # create user
        user, user_organization = self._create_user()
        # create a keysrtone role
        keystone_role = self._create_keystone_role()

        # create some projects/organizations
        if number_of_organizations:
            organizations = self._create_organizations_with_user_and_keystone_role(
                                            user=user,
                                            keystone_role=keystone_role,
                                            number=number_of_organizations)
        # assign some user-scoped roles
        if number_of_user_roles:
            user_roles = self._assign_user_scoped_roles(user=user,
                                                    user_organization=user_organization,
                                                    number=number_of_user_roles)

        # assign some organization-scoped roles
        if number_of_organization_roles and number_of_organizations:
            organization_roles = self._assign_organization_scoped_roles(user=user,
                                                            organizations=organizations,
                                                            number=number_of_organization_roles)
        # get a token for the user
        token_id = self._create_oauth2_token(user)
        # acces the resource
        response = self._validate_token(token_id)

        # assertions
        self._assert_user_info(response)
        if number_of_user_roles:
            self._assert_user_scoped_roles(response, reference=user_roles)
        else:
            self.assertEquals([], response.result['roles'])
        if number_of_organization_roles and number_of_organizations:
            self._assert_organization_scoped_roles(response, 
                                            reference=organization_roles, 
                                            number_of_organizations=number_of_organizations)
        else:
            self.assertEquals([], response.result['organizations'])

    def test_validate_token(self):
        self._test_validate_token(number_of_organizations=2, 
                                number_of_user_roles=2,
                                number_of_organization_roles=1)

    def test_validate_token_no_organizations(self):
        self._test_validate_token(number_of_user_roles=2)
        
    def test_validate_token_no_user_scoped_roles(self):
        self._test_validate_token(number_of_organizations=2, 
                                number_of_organization_roles=1)

    def test_validate_token_no_organization_scoped_roles(self):
        self._test_validate_token(number_of_organizations=2, 
                                number_of_user_roles=2)

    def test_validate_token_no_roles(self):
        self._test_validate_token(number_of_organizations=2)

    def test_validate_token_empty_user(self):
        self._test_validate_token()