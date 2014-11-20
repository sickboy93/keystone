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

    PATH_PREFIX = '/OS-ROLES'

    def add_routes(self, mapper):
        roles_controller = controllers.RoleCrudV3()
        permissions_controller = controllers.PermissionCrudV3()
        user_controller = controllers.UserV3()
        
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

        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/roles/{role_id}/permissions/{permission_id}',
            put_action='add_permission_to_role',
            delete_action='remove_permission_from_role',
            rel=build_resource_relation(resource_name='role_permission'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
                'permission_id':build_parameter_relation(parameter_name='permission_id'),
            })

        

        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/roles/{role_id}/users/{user_id}',
            put_action='add_user_to_role',
            delete_action='remove_user_from_role',
            rel=build_resource_relation(resource_name='role_user'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
                'user_id':build_parameter_relation(parameter_name='user_id'),
            })

        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/permissions/{permission_id}/roles',
            get_action='list_roles_for_permission',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'permission_id':build_parameter_relation(parameter_name='permission_id'),
            })

        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/roles',
            get_action='list_roles_for_user',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'user_id':build_parameter_relation(parameter_name='user_id'),
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
            mapper, user_controller,
            path=self.PATH_PREFIX + '/roles/{role_id}/users',
            get_action='list_users_for_role',
            rel=build_resource_relation(resource_name='users'),
            path_vars={
                'role_id':build_parameter_relation(parameter_name='role_id'),
            })

        # FIWARE specific endpoints
        self._add_resource(
            mapper, roles_controller,
            path='/access-tokens/{token_id}',
            get_action='validate_token',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'token_id':build_parameter_relation(parameter_name='token_id'),
            })
