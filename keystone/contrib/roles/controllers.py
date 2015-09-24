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

import itertools

from keystone import exception
from keystone.common import controller
from keystone.common import dependency
from keystone.i18n import _

@dependency.requires('roles_api')
class BaseControllerV3(controller.V3Controller):

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""
        path = '/OS-ROLES/' + cls.collection_name
        return super(BaseControllerV3, cls).base_url(context, path=path)

# CUSTOM API CHECKS
def _check_allowed_to_manage_roles(self, context, protection, role=None, role_id=None):
    """Add a flag for the policy engine if the user is allowed to manage
    the requested application.

    """
    ref = {}
    application_id = None
    if role_id or (role and not 'application_id' in role):
        role = self.roles_api.get_role(role_id)

    if role:
        application_id = role['application_id']

    if 'application_id' in context['query_string']:
        # List filtering
        application_id = context['query_string']['application_id']

    user_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['user_id']
    allowed_applications = self.roles_api.list_applications_user_allowed_to_manage_roles(
        user_id=user_id, organization_id=None)
    ref['is_allowed_to_manage_roles'] = application_id in allowed_applications

    self.check_protection(context, protection, ref)

def _check_allowed_to_get_and_assign(self, context, protection, user_id=None,
                                     role_id=None, organization_id=None,
                                     application_id=None):
    """Add a flag for the policy engine if the user is allowed to asign and
    remove roles from a user or list application assignments.

    """
    ref = {}
    if application_id:
        req_user = self.identity_api.get_user(
            context['environment']['KEYSTONE_AUTH_CONTEXT']['user_id'])
        req_project_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['project_id']
        if req_project_id == req_user.get('default_project_id'):
            # user acting as user
            allowed_roles = self.roles_api.list_roles_user_allowed_to_assign(
                user_id=req_user['id'], organization_id=None)
        else:
            # user logged as org
            allowed_roles = self.roles_api.list_roles_organization_allowed_to_assign(
                organization_id=req_project_id)

        if role_id:
            # Role must be allowed
            ref['is_allowed_to_get_and_assign'] = role_id in list(
                itertools.chain(*allowed_roles.values()))
        else:
            # application must be allowed
            ref['is_allowed_to_get_and_assign'] = application_id in allowed_roles.keys()

    self.check_protection(context, protection, ref)

def _check_allowed_to_manage_permissions(self, context, protection, permission=None,
                                         permission_id=None, role_id=None):
    """Add a flag for the policy engine if the user is allowed to manage
    the requested application.

    """
    ref = {}
    application_id = None

    if permission_id or (permission and not 'application_id' in permission):
        permission = self.roles_api.get_permission(permission_id)

    if permission:
        application_id = permission['application_id']

    if role_id:
        role = self.roles_api.get_role(role_id)
        application_id = role['application_id']

    if 'application_id' in context['query_string']:
        # List filtering
        application_id = context['query_string']['application_id']

    user_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['user_id']
    allowed_applications = self.roles_api.list_applications_user_allowed_to_manage_roles(
        user_id=user_id, organization_id=None)
    ref['is_allowed_to_manage_roles'] = application_id in allowed_applications

    self.check_protection(context, protection, ref)

def _check_allowed_to_manage_consumer(self, context, protection, consumer_id=None,
                                      consumer=None):
    """Add a flag for the policy engine if the user is allowed to manage
    the requested application.

    """
    ref = {}

    user_id = context['environment']['KEYSTONE_AUTH_CONTEXT']['user_id']
    allowed_applications = self.roles_api.list_applications_user_allowed_to_manage(
        user_id=user_id, organization_id=None)
    ref['is_allowed_to_manage'] = consumer_id in allowed_applications

    self.check_protection(context, protection, ref)

# CONTROLLERS

class RoleCrudV3(BaseControllerV3):

    collection_name = 'roles'
    member_name = 'role'

    @controller.protected(callback=_check_allowed_to_manage_roles)
    def list_roles(self, context):
        """Description of the controller logic."""
        filters = context['query_string']
        ref = self.roles_api.list_roles(**filters)
        return RoleCrudV3.wrap_collection(context, ref)

    @controller.protected(callback=_check_allowed_to_manage_roles)
    def create_role(self, context, role):
        ref = self._assign_unique_id(self._normalize_dict(role))
        role_ref = self.roles_api.create_role(ref)
        return RoleCrudV3.wrap_member(context, role_ref)

    @controller.protected(callback=_check_allowed_to_manage_roles)
    def get_role(self, context, role_id):
        role_ref = self.roles_api.get_role(role_id)
        return RoleCrudV3.wrap_member(context, role_ref)

    @controller.protected(callback=_check_allowed_to_manage_roles) 
    def update_role(self, context, role_id, role):
        self._require_matching_id(role_id, role)
        ref = self.roles_api.update_role(role_id, self._normalize_dict(role))
        return RoleCrudV3.wrap_member(context, ref)

    @controller.protected(callback=_check_allowed_to_manage_roles)
    def delete_role(self, context, role_id):
        self.roles_api.delete_role(role_id)

@dependency.requires('identity_api')
class RoleUserAssignmentV3(BaseControllerV3):
    collection_name = 'role_assignments'
    member_name = 'role_assignment'

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        pass

    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def list_role_user_assignments(self, context):
        filters = context['query_string']

        use_default_org = filters.pop('default_organization', False)
        user_id = filters.get('user_id', False)
        
        if use_default_org and user_id:
            user = self.identity_api.get_user(user_id)
            organization_id = user.get('default_project_id', None)

            if not organization_id:
                raise exception.ProjectNotFound(
                    message='This user has no default organization')

            filters['organization_id'] = organization_id

        ref = self.roles_api.list_role_user_assignments(**filters)
        return RoleUserAssignmentV3.wrap_collection(context, ref)

    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def add_role_to_user(self, context, role_id, user_id, 
                         organization_id, application_id):
        self.roles_api.add_role_to_user(role_id, user_id, 
                                        organization_id, application_id)

    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def remove_role_from_user(self, context, role_id, user_id, 
                            organization_id, application_id):
        self.roles_api.remove_role_from_user(role_id, user_id, 
                                             organization_id, application_id)


    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def add_role_to_user_default_org(self, context, role_id, user_id, 
                                     application_id):
        user = self.identity_api.get_user(user_id)
        organization_id = user.get('default_project_id', None)
        if organization_id:
            self.roles_api.add_role_to_user(role_id, user_id, 
                organization_id, application_id)
        else:
            raise exception.ProjectNotFound(
                message='This user has no default organization')

    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def remove_role_from_user_default_org(self, context, role_id, user_id, 
                                          application_id):
        user = self.identity_api.get_user(user_id)
        organization_id = user.get('default_project_id', None)
        if organization_id:
            self.roles_api.remove_role_from_user(role_id, user_id, 
                organization_id, application_id)
        else:
            raise exception.ProjectNotFound(
                message='This user has no default organization')


class RoleOrganizationAssignmentV3(BaseControllerV3):
    collection_name = 'role_assignments'
    member_name = 'role_assignment'

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        pass

    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def list_role_organization_assignments(self, context):
        filters = context['query_string']
        ref = self.roles_api.list_role_organization_assignments(**filters)
        return RoleOrganizationAssignmentV3.wrap_collection(context, ref)

    @controller.protected(callback=_check_allowed_to_get_and_assign)
    def add_role_to_organization(self, context, role_id,
                                 organization_id, application_id):
        self.roles_api.add_role_to_organization(role_id,
                                                organization_id, 
                                                application_id)

    #@controller.protected(callback=_check_allowed_to_get_and_assign)
    def remove_role_from_organization(self, context, role_id, 
                                      organization_id, application_id):
        self.roles_api.remove_role_from_organization(role_id,
                                                     organization_id,
                                                     application_id)


class AllowedActionsControllerV3(BaseControllerV3):

    @controller.protected()
    def list_roles_user_allowed_to_assign(self, context, user_id, 
                                          organization_id):
        ref = self.roles_api.list_roles_user_allowed_to_assign(
            user_id, organization_id)
        response = {
            'allowed_roles': ref
        }
        return response

    @controller.protected()
    def list_roles_organization_allowed_to_assign(self, context, 
                                                  organization_id):
        ref = self.roles_api.list_roles_organization_allowed_to_assign(
            organization_id)
        response = {
            'allowed_roles': ref
        }
        return response

    @controller.protected()
    def list_applications_user_allowed_to_manage(self, context, user_id, 
                                                 organization_id):
        ref = self.roles_api.list_applications_user_allowed_to_manage(
            user_id, organization_id)
        response = {
            'allowed_applications': ref
        }
        return response

    @controller.protected()
    def list_applications_organization_allowed_to_manage(self, context, 
                                                         organization_id):
        ref = self.roles_api.list_applications_organization_allowed_to_manage(
            organization_id)
        response = {
            'allowed_applications': ref
        }
        return response

    @controller.protected()
    def list_applications_user_allowed_to_manage_roles(self, context, user_id, 
                                                       organization_id):
        ref = self.roles_api.list_applications_user_allowed_to_manage_roles(
            user_id, organization_id)
        response = {
            'allowed_applications': ref
        }
        return response

    @controller.protected()
    def list_applications_organization_allowed_to_manage_roles(self, context, 
                                                               organization_id):
        ref = self.roles_api.list_applications_organization_allowed_to_manage_roles(
            organization_id)
        response = {
            'allowed_applications': ref
        }
        return response


class PermissionCrudV3(BaseControllerV3):

    collection_name = 'permissions'
    member_name = 'permission'

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def list_permissions(self, context):
        """Description of the controller logic."""
        filters = context['query_string']
        ref = self.roles_api.list_permissions(**filters)
        return PermissionCrudV3.wrap_collection(context, ref)

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def create_permission(self, context, permission):
        ref = self._assign_unique_id(self._normalize_dict(permission))
        permission_ref = self.roles_api.create_permission(ref)
        return PermissionCrudV3.wrap_member(context, permission_ref)

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def get_permission(self, context, permission_id):
        permission_ref = self.roles_api.get_permission(permission_id)
        return PermissionCrudV3.wrap_member(context, permission_ref)

    @controller.protected(callback=_check_allowed_to_manage_permissions) 
    def update_permission(self, context, permission_id, permission):
        self._require_matching_id(permission_id, permission)
        ref = self.roles_api.update_permission(
            permission_id, self._normalize_dict(permission))
        return PermissionCrudV3.wrap_member(context, ref)

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def delete_permission(self, context, permission_id):
        self.roles_api.delete_permission(permission_id)  

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def list_permissions_for_role(self, context, role_id):
        ref = self.roles_api.list_permissions_for_role(role_id)
        return PermissionCrudV3.wrap_collection(context, ref)  

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def add_permission_to_role(self, context, role_id, permission_id):
        self.roles_api.add_permission_to_role(role_id, permission_id)

    @controller.protected(callback=_check_allowed_to_manage_permissions)
    def remove_permission_from_role(self, context, role_id, permission_id):
        self.roles_api.remove_permission_from_role(role_id, permission_id)


@dependency.requires('identity_api', 'oauth2_api')
class FiwareApiControllerV3(BaseControllerV3):

    #@controller.protected()
    def authorized_organizations(self, context, token_id):
        """ Returns all the organizations in which the user has a role
        from the application that got the OAuth2.0 token.
        """
        # TODO(garcianavalon) check if token is valid, use user_id to filter in get
        token = self.oauth2_api.get_access_token(token_id)
        user = self.identity_api.get_user(token['authorizing_user_id'])
        application_id = token['consumer_id']

        organizations = self.roles_api.get_authorized_organizations(
            user, application_id, remove_default_organization=True)

        return {
            'organizations': organizations
        }
    
    # @controller.protected()
    def validate_oauth2_token(self, context, token_id):
        """ Return a list of the roles and permissions of the user associated 
        with this token.

            See https://github.com/ging/fi-ware-idm/wiki/Using-the-FI-LAB-instance\
            #get-user-information-and-roles
        """
        # TODO(garcianavalon) check if token is valid, use user_id to filter in get
        token = self.oauth2_api.get_access_token(token_id)
        user = self.identity_api.get_user(token['authorizing_user_id'])
        application_id = token['consumer_id']
        
        organizations = self.roles_api.get_authorized_organizations(
            user, application_id)

        # remove the default organization and extract its roles
        user_roles = []
        user_organization = next((org for org in organizations 
            if org['id'] == user['default_project_id']), None)

        if user_organization:
            organizations.remove(user_organization)
            # extract the user-scoped roles
            user_roles = user_organization.pop('roles') 

        def _get_name(user):
            name = user.get('username')
            if not name:
                name = user['name']
            return name

        response_body = {
            'id':user['id'],
            'email': user['name'],
            'displayName': _get_name(user),
            'roles': user_roles,
            'organizations': organizations,
            'app_id': application_id
        }
        return response_body

@dependency.requires('oauth2_api')
class ExtendedPermissionsConsumerCrudV3(BaseControllerV3):
    """This class is ment to extend the basic consumer with callbacks that use
    the internal permission from this extensions.
    """

    collection_name = 'consumers'
    member_name = 'consumer'

    @controller.protected()
    def list_consumers(self, context):
        ref = self.oauth2_api.list_consumers()
        return ExtendedPermissionsConsumerCrudV3.wrap_collection(context, ref)

    @controller.protected()
    def create_consumer(self, context, consumer):
        ref = self._assign_unique_id(self._normalize_dict(consumer))
        consumer_ref = self.oauth2_api.create_consumer(ref)
        return ExtendedPermissionsConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected(callback=_check_allowed_to_manage_consumer)
    def get_consumer(self, context, consumer_id):
        consumer_ref = self.oauth2_api.get_consumer_with_secret(consumer_id)
        return ExtendedPermissionsConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected(callback=_check_allowed_to_manage_consumer) 
    def update_consumer(self, context, consumer_id, consumer):
        self._require_matching_id(consumer_id, consumer)
        ref = self._normalize_dict(consumer)
        self._validate_consumer_ref(ref)
        ref = self.oauth2_api.update_consumer(consumer_id, ref)
        return ExtendedPermissionsConsumerCrudV3.wrap_member(context, ref)

    def _validate_consumer_ref(self, consumer):
        if 'secret' in consumer:
            msg = _('Cannot change consumer secret')
            raise exception.ValidationError(message=msg)

    @controller.protected(callback=_check_allowed_to_manage_consumer)
    def delete_consumer(self, context, consumer_id):
        self.oauth2_api.delete_consumer(consumer_id)
