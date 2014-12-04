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

from keystone.common import controller
from keystone.common import dependency
from keystone.models import token_model


@dependency.requires('roles_api')
class BaseControllerV3(controller.V3Controller):

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""
        path = '/OS-ROLES/' + cls.collection_name
        return super(BaseControllerV3, cls).base_url(context, path=path)


class RoleCrudV3(BaseControllerV3):

    collection_name = 'roles'
    member_name = 'role'

    @controller.protected()
    def list_roles(self, context):
        """Description of the controller logic."""
        ref = self.roles_api.list_roles()
        return RoleCrudV3.wrap_collection(context, ref)

    @controller.protected()
    def create_role(self, context, role):
        ref = self._assign_unique_id(self._normalize_dict(role))
        role_ref = self.roles_api.create_role(ref)
        return RoleCrudV3.wrap_member(context, role_ref)

    @controller.protected()
    def get_role(self, context, role_id):
        role_ref = self.roles_api.get_role(role_id)
        return RoleCrudV3.wrap_member(context, role_ref)

    @controller.protected() 
    def update_role(self, context, role_id, role):
        self._require_matching_id(role_id, role)
        ref = self.roles_api.update_role(role_id, self._normalize_dict(role))
        return RoleCrudV3.wrap_member(context, ref)

    @controller.protected()
    def delete_role(self, context, role_id):
        self.roles_api.delete_role(role_id)

    @controller.protected()
    def add_role_to_user(self, context, role_id, user_id, organization_id):
        self.roles_api.add_role_to_user(role_id, user_id, organization_id)

    @controller.protected()
    def remove_role_from_user(self, context, role_id, user_id, organization_id):
        self.roles_api.remove_role_from_user(role_id, user_id, organization_id)  

    @controller.protected()
    def list_roles_for_user(self, context, user_id):
        ref = self.roles_api.list_roles_for_user(user_id)
        return RoleCrudV3.wrap_collection(context, ref)


class PermissionCrudV3(BaseControllerV3):

    collection_name = 'permissions'
    member_name = 'permission'

    @controller.protected()
    def list_permissions(self, context):
        """Description of the controller logic."""
        ref = self.roles_api.list_permissions()
        return PermissionCrudV3.wrap_collection(context, ref)

    @controller.protected()
    def create_permission(self, context, permission):
        ref = self._assign_unique_id(self._normalize_dict(permission))
        permission_ref = self.roles_api.create_permission(ref)
        return PermissionCrudV3.wrap_member(context, permission_ref)

    @controller.protected()
    def get_permission(self, context, permission_id):
        permission_ref = self.roles_api.get_permission(permission_id)
        return PermissionCrudV3.wrap_member(context, permission_ref)

    @controller.protected() 
    def update_permission(self, context, permission_id, permission):
        self._require_matching_id(permission_id, permission)
        ref = self.roles_api.update_permission(permission_id, 
                                self._normalize_dict(permission))
        return PermissionCrudV3.wrap_member(context, ref)

    @controller.protected()
    def delete_permission(self, context, permission_id):
        self.roles_api.delete_permission(permission_id)  

    @controller.protected()
    def list_permissions_for_role(self, context, role_id):
        ref = self.roles_api.list_permissions_for_role(role_id)
        return PermissionCrudV3.wrap_collection(context, ref)  

    @controller.protected()
    def add_permission_to_role(self, context, role_id, permission_id):
        self.roles_api.add_permission_to_role(role_id, permission_id)

    @controller.protected()
    def remove_permission_from_role(self, context, role_id, permission_id):
        self.roles_api.remove_permission_from_role(role_id, permission_id)


@dependency.requires('assignment_api', 'identity_api', 'oauth2_api')
class FiwareApiControllerV3(BaseControllerV3):

    #@controller.protected()
    def validate_token(self, context, token_id):
        """ Return a list of the roles and permissions of the user associated 
        with this token.

            See https://github.com/ging/fi-ware-idm/wiki/Using-the-FI-LAB-instance\
            #get-user-information-and-roles
        """
        # TODO(garcianavalon) check if token is valid, use user_id to filter in get
        token = self.oauth2_api.get_access_token(token_id)
        user_id = token['authorizing_user_id']
        # get the user_id
        user = self.identity_api.get_user(user_id)
        # roles associated with this user
        roles = self.roles_api.list_roles_for_user(user_id)
        # organizations the user is in
        organizations = self.assignment_api.list_projects_for_user(user_id)
        # filter to only organizations with roles
        organizations = [org for org in organizations 
                    if org['id'] in [role['organization_id'] for role in roles]]
        for organization in organizations:
            organization['roles'] = [role for role in roles 
                                if role['organization_id'] == organization['id']]
        # remove the user-default organization from the organizations list
        user_organization = [org for org in organizations 
                            if org['name'] == user['name']]
        user_roles = []
        if user_organization:
            user_organization = user_organization[0]
            organizations.remove(user_organization) #there is only one!
            # extract the user-scoped roles
            user_roles = user_organization['roles'] 

        response_body = {
            'id':user_id,
            'email': user['email'],
            'nickName': user['name'],
            'roles': user_roles,
            'organizations': organizations
        }
        return response_body