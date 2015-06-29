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

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib.roles import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-ROLES', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-ROLES', extension_version='1.0')

class RolesExtension(wsgi.V3ExtensionRouter):
    """The API looks like:

    # ROLES
    GET /OS-ROLES/roles list all roles
    POST /OS-ROLES/roles create a role
    
    GET /OS-ROLES/roles/{role_id} get role
    PATCH /OS-ROLES/roles/{role_id} 
    DELETE /OS-ROLES/roles/{role_id}


    """
    PATH_PREFIX = '/OS-ROLES'

    def add_routes(self, mapper):
        roles_controller = controllers.RoleCrudV3()
        permissions_controller = controllers.PermissionCrudV3()
        fiware_api_controller = controllers.FiwareApiControllerV3()
        user_assignment_controller = controllers.RoleUserAssignmentV3()
        organization_assignment_controller = controllers.RoleOrganizationAssignmentV3()
        allowed_controller = controllers.AllowedActionsControllerV3()
        consumer_controller = controllers.ExtendedPermissionsConsumerCrudV3()
        
        # ROLES
        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/roles',
            get_action='list_roles',
            post_action='create_role',
            rel=build_resource_relation(resource_name='roles'))

        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/roles/{role_id}',
            get_action='get_role',
            patch_action='update_role',
            delete_action='delete_role',
            rel=build_resource_relation(resource_name='role'),
            path_vars={
                'role_id':
                build_parameter_relation(parameter_name='role_id'),
            })

        # ROLES-USERS
        self._add_resource(
            mapper, user_assignment_controller,
            path=self.PATH_PREFIX + '/users/role_assignments',
            get_action='list_role_user_assignments',
            rel=build_resource_relation(resource_name='role_assignments'))

        self._add_resource(
            mapper, user_assignment_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/organizations/{organization_id}/applications/{application_id}/roles/{role_id}',
            put_action='add_role_to_user',
            delete_action='remove_role_from_user',
            rel=build_resource_relation(resource_name='role_user'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
                'user_id':build_parameter_relation(parameter_name='user_id'),
                'organization_id':
                    build_parameter_relation(parameter_name='organization_id'),
                'application_id':
                    build_parameter_relation(parameter_name='application_id'),
            })

        self._add_resource(
            mapper, user_assignment_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/applications/{application_id}/roles/{role_id}',
            put_action='add_role_to_user_default_org',
            delete_action='remove_role_from_user_default_org',
            rel=build_resource_relation(resource_name='role_user'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
                'user_id':build_parameter_relation(parameter_name='user_id'),
                'application_id':
                    build_parameter_relation(parameter_name='application_id'),
            })

        # ROLES_ORGANIZATIONS
        self._add_resource(
            mapper, organization_assignment_controller,
            path=self.PATH_PREFIX + '/organizations/role_assignments',
            get_action='list_role_organization_assignments',
            rel=build_resource_relation(resource_name='role_assignments'))

        self._add_resource(
            mapper, organization_assignment_controller,
            path=self.PATH_PREFIX + '/organizations/{organization_id}/applications/{application_id}/roles/{role_id}',
            put_action='add_role_to_organization',
            delete_action='remove_role_from_organization',
            rel=build_resource_relation(resource_name='role_organization'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
                'organization_id':
                    build_parameter_relation(parameter_name='organization_id'),
                'application_id':
                    build_parameter_relation(parameter_name='application_id'),
            })

        # ALLOWED ACTIONS
        self._add_resource(
            mapper, allowed_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/organizations/{organization_id}/roles/allowed',
            get_action='list_roles_user_allowed_to_assign',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'user_id':build_parameter_relation(parameter_name='user_id'),
                'organization_id':build_parameter_relation(parameter_name='organization_id'),
            })

        self._add_resource(
            mapper, allowed_controller,
            path=self.PATH_PREFIX + '/organizations/{organization_id}/roles/allowed',
            get_action='list_roles_organization_allowed_to_assign',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'organization_id':build_parameter_relation(parameter_name='organization_id'),
            })

        self._add_resource(
            mapper, allowed_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/organizations/{organization_id}/applications/allowed',
            get_action='list_applications_user_allowed_to_manage',
            rel=build_resource_relation(resource_name='applications'),
            path_vars={
                'user_id':build_parameter_relation(parameter_name='user_id'),
                'organization_id':build_parameter_relation(parameter_name='organization_id'),
            })

        self._add_resource(
            mapper, allowed_controller,
            path=self.PATH_PREFIX + '/organizations/{organization_id}/applications/allowed',
            get_action='list_applications_organization_allowed_to_manage',
            rel=build_resource_relation(resource_name='applications'),
            path_vars={
                'organization_id':build_parameter_relation(parameter_name='organization_id'),
            })

        self._add_resource(
            mapper, allowed_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/organizations/{organization_id}/applications/allowed_roles',
            get_action='list_applications_user_allowed_to_manage_roles',
            rel=build_resource_relation(resource_name='applications'),
            path_vars={
                'user_id':build_parameter_relation(parameter_name='user_id'),
                'organization_id':build_parameter_relation(parameter_name='organization_id'),
            })

        self._add_resource(
            mapper, allowed_controller,
            path=self.PATH_PREFIX + '/organizations/{organization_id}/applications/allowed_roles',
            get_action='list_applications_organization_allowed_to_manage_roles',
            rel=build_resource_relation(resource_name='applications'),
            path_vars={
                'organization_id':build_parameter_relation(parameter_name='organization_id'),
            })

        # PERMISSIONS
        self._add_resource(
            mapper, permissions_controller,
            path=self.PATH_PREFIX + '/permissions',
            get_action='list_permissions',
            post_action='create_permission',
            rel=build_resource_relation(resource_name='permissions'))

        self._add_resource(
            mapper, permissions_controller,
            path=self.PATH_PREFIX + '/permissions/{permission_id}',
            get_action='get_permission',
            patch_action='update_permission',
            delete_action='delete_permission',
            rel=build_resource_relation(resource_name='permission'),
            path_vars={
                'permission_id':
                build_parameter_relation(parameter_name='permission_id'),
            })

        self._add_resource(
            mapper, permissions_controller,
            path=self.PATH_PREFIX + '/roles/{role_id}/permissions',
            get_action='list_permissions_for_role',
            rel=build_resource_relation(resource_name='permissions'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
            })

        self._add_resource(
            mapper, permissions_controller,
            path=self.PATH_PREFIX + '/roles/{role_id}/permissions/{permission_id}',
            put_action='add_permission_to_role',
            delete_action='remove_permission_from_role',
            rel=build_resource_relation(resource_name='role_permission'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
                'permission_id':build_parameter_relation(parameter_name='permission_id'),
            })

        # FIWARE specific endpoints
        self._add_resource(
            mapper, fiware_api_controller,
            path='/access-tokens/{token_id}',
            get_action='validate_oauth2_token',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'token_id':build_parameter_relation(parameter_name='token_id'),
            })
        
        self._add_resource(
            mapper, fiware_api_controller,
            path='/authorized_organizations/{token_id}',
            get_action='authorized_organizations',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'token_id':build_parameter_relation(parameter_name='token_id'),
            })
        
        # OAUTH2 consumer CRUD
        self._add_resource(
            mapper, consumer_controller,
            path=self.PATH_PREFIX + '/consumers',
            get_action='list_consumers',
            post_action='create_consumer',
            rel=build_resource_relation(resource_name='consumers'))

        self._add_resource(
            mapper, consumer_controller,
            path=self.PATH_PREFIX + '/consumers/{consumer_id}',
            get_action='get_consumer',
            patch_action='update_consumer',
            delete_action='delete_consumer',
            rel=build_resource_relation(resource_name='consumer'),
            path_vars={
                'consumer_id':
                build_parameter_relation(parameter_name='consumer_id'),
            })
