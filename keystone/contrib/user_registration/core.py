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

from __future__ import absolute_import

import six
import abc

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import exception
from keystone.openstack.common import log


LOG = log.getLogger(__name__)

EXTENSION_DATA = {
    'name': 'Keystone User Registration API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-REGISTRATION/v1.0',
    'alias': 'OS-REGISTRATION',
    'description': 'Handles creating users with activation through a key',
    'links': [
        {
            'rel': 'describedby',
            # TODO(garcianavalon): needs a description
            'type': 'text/html',
            'href': 'https://github.com/ging/keystone',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)

@dependency.provider('registration_api')
class Manager(manager.Manager):
    """Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(
            'keystone.contrib.user_registration.backends.sql.Registration')
        # TODO(garcianavalon) set as configuration option in keystone.conf
        
@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for drivers"""

    @abc.abstractmethod
    def create_activation_profile(self, activation_profile):
        """Create an activation_profile for a newly registered user

        :param activation_profile: activation_profile data
        :type activation_profile: dict
        :returns: activation_profile

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_activation_profile(self, user_id, activation_key):
        """Get activation_profile details for a user, if the key is valid
        
        :param user_id: id of user that wants to activate
        :type user_id: string
        param activation_key: provided in the registration process
        :type activation_key: string
        :returns: activation_profile

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_reset_profile(self, reset_profile):
        """Register a user reset password request

        :param reset_profile: reset_profile data
        :type reset_profile: dict
        :returns: reset_profile

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_reset_profile(self, user_id, reset_token):
        """Get reset_profile details, if the token is valid
        
        :param user_id: id of user that wants to activate
        :type user_id: string
        param reset_token: provided in the registration process
        :type reset_token: string
        :returns: reset_profile

        """
        raise exception.NotImplemented()