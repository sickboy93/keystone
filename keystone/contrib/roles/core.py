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

from keystone.common import dependency
from keystone import exception
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

@dependency.provider('roles_api')
class RolesManager(manager.Manager):
    """Roles and Permissions Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    def __init__(self):
        super(RolesManager, self).__init__(
            'keystone.contrib.roles.backends.sql.Roles')


@dependency.requires('assignment_api', 'identity_api')
@six.add_metaclass(abc.ABCMeta)
class RolesDriver(object):
    """Interface description for Roles and Permissions driver."""

    # ROLES
    @abc.abstractmethod
    def list_roles(self):
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

    @abc.abstractmethod
    def add_user_to_role(self, role_id, user_id, organization_id):
        """Add user to role.

        :param role_id: id of role to add user to
        :type role_id: string
        :param user_id: user to add to role
        :type user_id: string
        :param organization_id: organization-scope in which we are giving the
            role to the user. If is a user-scoped role it should be the id of
            the user default organization (the project created with same name as user
            when user registration)
        :type organization_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def remove_user_from_role(self, role_id, user_id, organization_id):
        """Remove user from role.

        :param role_id: id of role to remove user from
        :type role_id: string
        :param user_id: user to remove from role
        :type user_id: string
        :param organization_id: organization-scope in which the role was given to the user. 
            If is a user-scoped role it should be the id of the user default organization 
            (the project created with same name as user when user registration)
        :type organization_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_roles_for_permission(self, permission_id):
        """List roles for permission.

        :param permission_id: permission with roles
        :type permission_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_roles_for_user(self, user_id):
        """List roles for a user_id

        :param user_id: user with roles
        :type user_id: string
        ;returns: None.
        """
        raise exception.NotImplemented()
    
    # PERMISSIONS
    @abc.abstractmethod
    def list_permissions(self):
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

    #USERS
    @abc.abstractmethod
    def list_users_for_role(self, role_id):
        """List users for role.

        :param role_id: id of role to remove permission from
        :type role_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

