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

import abc
import six

from keystone import exception
from keystone import notifications
from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone.openstack.common import log


LOG = log.getLogger(__name__)

EXTENSION_DATA = {
    'name': 'UPM-FIWARE Roles API',
    'namespace': 'https://github.com/ging/keystone/'
                 'OS-ROLES/v1.0',
    'alias': 'OS-ROLES',
    'updated': '2014-11-3T12:00:0-00:00',
    'description': 'UPM\'s Roles provider for applications in the FIWARE GE \
                    Identity Manager implementation',
    'links': [
        {
            'rel': 'describedby',
            # TODO(garcianavalon): needs a description
            'type': 'text/html',
            'href': 'https://github.com/ging/keystone/wiki',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)

ASSIGN_ALL_PUBLIC_ROLES_PERMISSION = 'Get and assign all public application roles'
ASSIGN_OWNED_PUBLIC_ROLES_PERMISSION = 'Get and assign only public owned roles'
ASSIGN_INTERNAL_ROLES_PERMISSION = 'Get and assign all internal application roles'
MANAGE_APPLICATION_PERMISSION = 'Manage the application'
MANAGE_ROLES_PERMISSION = 'Manage roles'

@dependency.requires('assignment_api')
@dependency.provider('roles_api')
class RolesManager(manager.Manager):
    """Roles and Permissions Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    def __init__(self):

        self.event_callbacks = {
            notifications.ACTIONS.deleted: {
                'user': [self.delete_user_assignments],
                'project': [self.delete_organization_assignments],
                'consumer_oauth2':[self.delete_application_resources]
            },
        }

        super(RolesManager, self).__init__(
            'keystone.contrib.roles.backends.sql.Roles')

    def remove_role_from_organization(self, role_id,  
                                      organization_id, application_id,
                                      check_ids=True):

        response = self.driver.remove_role_from_organization(
            role_id, organization_id, application_id, check_ids=check_ids)

        # get all roles allowed to assign
        application_roles = self.list_roles_organization_allowed_to_assign(
            organization_id)

        # delete all assignments if the role is not allowed anymore
        user_assignments = self.driver.list_role_user_assignments(
            organization_id=organization_id)

        delete_assignments = [
            a for a in user_assignments
            if a['application_id'] not in application_roles
            or a['role_id'] not in application_roles[a['application_id']]
        ]

        self._delete_user_assignments(delete_assignments)
        
        return response

    def delete_application_resources(self, service, resource_type, 
                                     operation, payload):
        app_id = payload['resource_info']
        # Delete all assignments
        user_assignments = self.driver.list_role_user_assignments(
            application_id=app_id)
        self._delete_user_assignments(user_assignments)
        org_assignments = self.driver.list_role_organization_assignments(
            application_id=app_id)
        self._delete_organization_assignments(org_assignments)

        # Delete all roles and permissions
        roles = self.driver.list_roles(application_id=app_id)
        for role in roles:
            self.driver.delete_role(role['id'])

        permissions = self.driver.list_roles(application_id=app_id)
        for permission in permissions:
            self.driver.delete_permission(permission['id'])


    def delete_user_assignments(self, service, resource_type, operation,
                                payload):
        user_id = payload['resource_info']
        assignments = self.driver.list_role_user_assignments(
            user_id=user_id)
        self._delete_user_assignments(assignments)


    def delete_organization_assignments(self, service, resource_type, 
                                        operation, payload):
        org_id = payload['resource_info']
        org_assignments = self.driver.list_role_organization_assignments(
            organization_id=org_id)
        self._delete_organization_assignments(org_assignments)

        # Delete all user assignments in this org
        user_assignments = self.driver.list_role_user_assignments(
            organization_id=org_id)
        self._delete_user_assignments(user_assignments)

    def _delete_user_assignments(self, assignments):
        for assignment in assignments:
            self.driver.remove_role_from_user(
                role_id=assignment['role_id'], 
                user_id=assignment['user_id'],
                organization_id=assignment['organization_id'],
                application_id=assignment['application_id'],
                check_ids=False)


    def _delete_organization_assignments(self, assignments):
        for assignment in assignments:
            self.driver.remove_role_from_organization(
                role_id=assignment['role_id'], 
                organization_id=assignment['organization_id'],
                application_id=assignment['application_id'],
                check_ids=False)


    def get_authorized_organizations(self, user, 
                                    application_id,
                                    remove_default_organization=False):
        # roles associated with this user in the application
        assignments = self.driver.list_role_user_assignments(
            user_id=user['id'], application_id=application_id)

        # organizations the user is in
        organizations = self.assignment_api.list_projects_for_user(user['id'])

        # filter to only organizations with roles
        organizations = [org for org in organizations 
            if org['id'] in [a['organization_id'] for a in assignments]]

        for organization in organizations:
            role_ids = [a['role_id'] for a in assignments 
                        if a['organization_id'] == organization['id']]            
            # Load roles' names
            organization['roles'] = [dict(id=r['id'], name=r['name']) for r
                    in [self.driver.get_role(id) for id in role_ids]]

        if remove_default_organization:
            # always remove the default org
            organizations = [org for org in organizations 
                if not org['id'] == user['default_project_id']]

        return organizations


    def list_applications_user_allowed_to_manage_roles(self, user_id, 
                                                       organization_id):
        """List all the applications in which the user has at least 
        one role with the permission 'Manage the application' permission.
        """
        assignments = self.driver.list_role_user_assignments(
            user_id, organization_id)
        return self._get_allowed_applications_manage_roles(assignments)
       
    def list_applications_organization_allowed_to_manage_roles(self, 
                                                               organization_id):
        """List all the applications in which the organization has at least 
        one role with the permission 'Manage the application' permission.
        """
        assignments = self.driver.list_role_organization_assignments(
            organization_id)
        return self._get_allowed_applications_manage_roles(assignments)

    def list_applications_user_allowed_to_manage(self, user_id, 
                                                 organization_id):
        """List all the applications in which the user has at least 
        one role with the permission 'Manage the application' permission.
        """
        assignments = self.driver.list_role_user_assignments(
            user_id, organization_id)
        return self._get_allowed_applications(assignments)
       
    def list_applications_organization_allowed_to_manage(self, 
                                                         organization_id):
        """List all the applications in which the organization has at least 
        one role with the permission 'Manage the application' permission.
        """
        assignments = self.driver.list_role_organization_assignments(
            organization_id)
        return self._get_allowed_applications(assignments)

    def list_roles_user_allowed_to_assign(self, user_id, organization_id):
        """List the roles that a given user can assign. To be able to assign roles
        a user needs a certain permission. It can be the 'get and assign all
        application's roles' or the 'get and assign owned roles'

        :param user_id: user with roles
        :type user_id: string
        :param organization_id: organization-scope
        :type organization_id: string
        :returns: dictionary with application ids as keys and list 
            of role ids as values
        """
        assignments = self.driver.list_role_user_assignments(
            user_id, organization_id)
        return self._get_allowed_roles(assignments)


    def list_roles_organization_allowed_to_assign(self, organization_id):
        """List the roles that a given organization can assign. To be able to assign roles
        a organization needs a certain permission. It can be the 'get and assign all
        application's roles' or the 'get and assign owned roles'

        :param organization_id: organization with roles
        :type organization_id: string
        :returns: dictionary with application ids as keys and list 
            of role ids as values
        """
        assignments = self.driver.list_role_organization_assignments(
            organization_id)
        return self._get_allowed_roles(assignments)
        
    def _get_all_internal_permissions(self, current_assignments):
        applications = set([a['application_id'] for a in current_assignments])
        permissions = {}
        for application_id in applications:
            owned_roles = [a['role_id'] for a in current_assignments
                           if a['application_id'] == application_id]
            permissions[application_id] = []
            for role_id in owned_roles:
                permissions[application_id] += \
                    [p['name'] for p in 
                     self.driver.list_permissions_for_role(role_id)
                     if p['is_internal'] == True]
        return permissions

    def _get_allowed_applications_manage_roles(self, current_assignments):
        application_permissions = self._get_all_internal_permissions(
            current_assignments)
        allowed_applications = []
        for application in application_permissions:
            permissions = application_permissions[application]

            # Check if the manage internal permission is present
            if MANAGE_ROLES_PERMISSION in permissions:
                allowed_applications.append(application)

        return allowed_applications

    def _get_allowed_applications(self, current_assignments):
        application_permissions = self._get_all_internal_permissions(
            current_assignments)
        allowed_applications = []
        for application in application_permissions:
            permissions = application_permissions[application]

            # Check if the manage internal permission is present
            if MANAGE_APPLICATION_PERMISSION in permissions:
                allowed_applications.append(application)

        return allowed_applications

    def _get_allowed_roles(self, current_assignments):
        application_permissions = self._get_all_internal_permissions(
            current_assignments)
        allowed_roles = {}
        for application in application_permissions:
            permissions = application_permissions[application]
            roles_to_add = []
            # Now check if the internal permissions are present
            if ASSIGN_ALL_PUBLIC_ROLES_PERMISSION in permissions:
                # add all public roles in the application
                roles_to_add += set([r['id'] for r 
                    in self.driver.list_roles(application_id=application)])

            elif ASSIGN_OWNED_PUBLIC_ROLES_PERMISSION in permissions:
                # add only the public roles the user has in the application
                roles_to_add += [a['role_id'] for a 
                    in current_assignments 
                    if a['application_id'] == application]

            # Add the internal permissions if necesary
            if ASSIGN_INTERNAL_ROLES_PERMISSION in permissions:
                roles_to_add += [r['id'] for r 
                    in self.driver.list_roles(is_internal=True)]

            if roles_to_add:
                allowed_roles[application] = roles_to_add

        return allowed_roles


@dependency.requires('assignment_api', 'identity_api', 'oauth2_api')
@six.add_metaclass(abc.ABCMeta)
class RolesDriver(object):
    """Interface description for Roles and Permissions driver."""

    # ROLES
    @abc.abstractmethod
    def list_roles(self, **kwargs):
        """List all created roles

        :returns: roles list as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_role(self, role):
        """Create a new role

        :param role: role data
        :type role: dict
        :returns: role as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_role(self, role_id):
        """Get role details
        
        :param role_id: role id
        :type role_id: string
        :returns: role

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_role(self, role_id, role):
        """Update role details
        
        :param role_id: id of role to update
        :type role_id: string
        :param role: new role data
        :type role: dict
        :returns: role

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_role(self, role_id):
        """Delete role.

        :param role_id: id of role to delete
        :type role_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    # ROLE-USER
    @abc.abstractmethod
    def list_role_user_assignments(self, user_id=None, organization_id=None, 
                              application_id=None):
        """List all role to user assignments. Filtering by user, organization and/or 
        application

        :param user_id: user to filter by. Optional parameter
        :type user_id: string
        :param organization_id: organization-scope in which we want to list the
            roles of the user. If we want user-scoped roles it should be the id of
            the user default organization (the project created with same name as user
            when user registration). Optional parameter
        :type organization_id: string
        :param application_id: application to filter by. Optional parameter
        :type application_id: string
        :returns: list of assignments
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def add_role_to_user(self, role_id, user_id, organization_id, application_id):
        """Grant role to a user.

        :param role_id: id of role to add user to
        :type role_id: string
        :param user_id: user to add to role
        :type user_id: string
        :param organization_id: organization-scope in which we are giving the
            role to the user. If is a user-scoped role it should be the id of
            the user default organization (the project created with same name as user
            when user registration)
        :type organization_id: string
        :param application_id: application in which assign the role
        :type application_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_role_from_user(self, role_id, user_id, 
                              organization_id, application_id,
                              check_ids=True):
        """Revoke an user's role.

        :param role_id: id of role to remove user from
        :type role_id: string
        :param user_id: user to remove from role
        :type user_id: string
        :param organization_id: organization-scope in which the role was given to the user. 
            If is a user-scoped role it should be the id of the user default organization 
            (the project created with same name as user when user registration)
        :type organization_id: string
        :param application_id: application in which the role was assigned
        :type application_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    # ROLE-ORGANIZATION
    @abc.abstractmethod
    def list_role_organization_assignments(self, organization_id=None, 
                                           application_id=None):
        """List all role to organization assignments. Filtering by organization and/or 
        application.

        :param organization_id: organization to filter by. Optional parameter
        :type organization_id: string
        :param application_id: application to filter by. Optional parameter
        :type application_id: string
        :returns: list of assignments
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def add_role_to_organization(self, role_id, organization_id, application_id):
        """Grant role to a organization.

        :param role_id: id of role to add organization to
        :type role_id: string
        :param organization_id: organization to add to role
        :type organization_id: string
        :param application_id: application in which assign the role
        :type application_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_role_from_organization(self, role_id,  
                                      organization_id, application_id,
                                      check_ids=True):
        """Revoke an organization's role.

        :param role_id: id of role to remove organization from
        :type role_id: string
        :param organization_id: organization to remove from role
        :type organization_id: string
        :param application_id: application in which the role was assigned
        :type application_id: string
        :returns: None.

        """
        raise exception.NotImplemented() 
    
    # PERMISSIONS
    @abc.abstractmethod
    def list_permissions(self, **kwargs):
        """List all created permissions

        :returns: permissions list as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_permission(self, permission):
        """Create a new permission

        :param permission: permission data
        :type permission: dict
        :returns: permission as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_permission(self, permission_id):
        """Get permission details
        
        :param permission_id: permission id
        :type permission_id: string
        :returns: permission

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_permission(self, permission_id, permission):
        """Update permission details
        
        :param permission_id: id of permission to update
        :type permission_id: string
        :param permission: new permission data
        :type permission: dict
        :returns: permission

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_permission(self, permission_id):
        """Delete permission.

        :param permission_id: id of permission to delete
        :type permission_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_permissions_for_role(self, role_id):
        """List permissions for role.

        :param role_id: id of role to remove permission from
        :type role_id: string
        :param permission_id: permission to remove from role
        :type permission_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def add_permission_to_role(self, role_id, permission_id):
        """Delete role.

        :param role_id: id of role to add permission to
        :type role_id: string
        :param permission_id: permission to add to role
        :type permission_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_permission_from_role(self, role_id, permission_id):
        """Remove Permission from role.

        :param role_id: id of role to remove permission from
        :type role_id: string
        :param permission_id: permission to remove from role
        :type permission_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

