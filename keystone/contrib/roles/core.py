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
