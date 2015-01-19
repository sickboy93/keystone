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

import abc
import datetime
import six
import uuid

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import exception
from keystone.openstack.common import log

from oslo.utils import timeutils

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


# TODO(garcianavalon) extract as configuration options in keystone.conf
ACTIVATION_KEY_DURATION = 28800
RESET_TOKEN_DURATION = 28800
DEFAULT_ROLE_ID = '1g5603db1083441e8e63152afd49a1ac'
DEFAULT_ROLE_NAME = 'default_member'

@dependency.requires('assignment_api')
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

    def request_password_reset(self, user_id):
        """ Prepares a reset profile for the user."""
        profile_ref = {
            'user_id': user_id,
            'expires_at': self._calculate_expiry_date(RESET_TOKEN_DURATION),
            'id': uuid.uuid4().hex,
            'reset_token': uuid.uuid4().hex,
        }
        return self.driver.create_reset_profile(profile_ref)

    def register_user(self, user_ref):
        """ Translates the user_ref to an activation profile."""
        profile_ref = {
            'user_id': user_ref['id'],
            'project_id': user_ref['default_project_id'],
            'expires_at': self._calculate_expiry_date(ACTIVATION_KEY_DURATION),
            'id': uuid.uuid4().hex,
            'activation_key': uuid.uuid4().hex,
        }
        return self.driver.create_activation_profile(profile_ref)
        
    def _calculate_expiry_date(self, duration_in_seconds):
        now = timeutils.utcnow()
        future = now + datetime.timedelta(seconds=duration_in_seconds)
        return timeutils.isotime(future, subsecond=True)

    def get_default_role(self):
        """ Obtains the default role to give the user in his default organization. If
        the role doesn't exists creates a new one.
        """
        # NOTE(garcianavalon) mimick v2 Identity API behaviour where both
        # name and id are defined in keystone.conf. But it doesn't look like the
        # perfect solution, are there other better options to handle this?
        try:
            default_role = self.assignment_api.get_role(DEFAULT_ROLE_ID)
        except exception.RoleNotFound:
            LOG.info(("Creating the default role {0} because it does not \
                        exist.").format(DEFAULT_ROLE_ID))
            role = {'id': DEFAULT_ROLE_ID,
                    'name': DEFAULT_ROLE_NAME}
            default_role = self.assignment_api.create_role(DEFAULT_ROLE_ID, role)

        return default_role

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

    # @abc.abstractmethod
    # def new_activation_key(self, user_id):
    #     """Generates a new activation key for the user
        
    #     :param user_id: id of user
    #     :type user_id: string
    #     :returns: activation_profile

    #     """
    #     raise exception.NotImplemented()
        