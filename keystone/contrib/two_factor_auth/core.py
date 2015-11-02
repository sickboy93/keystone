# Copyright (C) 2015 Universidad Politecnica de Madrid
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


from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone.i18n import _
from keystone import notifications
from keystone.openstack.common import log

import pyotp
import six
import abc


LOG = log.getLogger(__name__)

@dependency.requires('identity_api')
@dependency.provider('two_factor_auth_api')
class TwoFactorAuthManager(manager.Manager):
    """Two Factor Authentication Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    def __init__(self):

        self.event_callbacks = {
            'deleted': {
                'user': [self.delete_two_factor_key_callback],
            }
        }
        super(TwoFactorAuthManager, self).__init__(
            'keystone.contrib.two_factor_auth.backends.sql.TwoFactorAuth')

    def delete_two_factor_key_callback(self, service, resource_type, operation,
                                 payload):
        user_id = payload['resource_info']
        self.driver.delete_two_factor_key(user_id)

    def create_two_factor_key(self, user_id):
        user = self.identity_api.get_user(user_id) # check if user exists
        LOG.info("Creating a new two factor key.")
        key = pyotp.random_base32()
        return self.driver.create_two_factor_key(user_id, key)

@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for Two Factor Auth driver."""
    
    @abc.abstractmethod
    def create_two_factor_key(self, user_id, two_factor_key):
        """Do something

        :param data: example data
        :type data: string
        :raises: keystone.exception,
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_two_factor_enabled(self, user_id):
        """Do something

        :param data: example data
        :type data: string
        :raises: keystone.exception,
        :returns: None.

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_two_factor_key(self, user_id):
        """Do something

        :param data: example data
        :type data: string
        :raises: keystone.exception,
        :returns: None.

        """
        raise exception.NotImplemented()