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

ISSUER_NAME = 'FIWARE Lab Accounts'

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
        """"Deletes user two factor info when user is deleted."""
        
        user_id = payload['resource_info']
        if self.driver.is_two_factor_enabled(user_id):
            self.driver.delete_two_factor_key(user_id)

    def create_two_factor_key(self, user_id, two_factor_auth):
        """Enables two factor auth for a certain user."""

        user = self.identity_api.get_user(user_id) # check if user exists

        # create dictionary if requesting a new key
        if not two_factor_auth and self.driver.is_two_factor_enabled(user_id):
            two_factor_auth = {}

        two_factor_auth['key'] = pyotp.random_base32()
        key_object = self.driver.create_two_factor_key(user_id, two_factor_auth)

        totp = pyotp.TOTP(two_factor_auth['key'])
        # TODO(@federicofdez) Save issuer_name in settings
        key_object['uri'] = totp.provisioning_uri(user['name'], issuer_name=ISSUER_NAME)
        
        return key_object

    def is_two_factor_enabled(self, user_id):
        """Checks whether two factor auth is enabled."""

        if not self.driver.is_two_factor_enabled(user_id):
            raise exception.NotFound(_('Two Factor Authentication is not enabled for user %s.' %user_id))

    def check_security_question(self, user_id, two_factor_auth):
        """Checks if the provided security answer is correct"""

        user = self.identity_api.get_user(user_id) # check if user exists
        return self.driver.check_security_question(user_id, two_factor_auth)

    def verify_code(self, user_id, verification_code):
        """Verifies a given time based code"""

        twofactor = self.driver.get_two_factor_info(user_id)
        totp = pyotp.TOTP(twofactor.two_factor_key)
        return totp.verify(verification_code)

@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for Two Factor Auth driver."""
    
    @abc.abstractmethod
    def create_two_factor_key(self, user_id, two_factor_auth):
        """Saves both the two factor key and the security question.

        :param user_id: user ID
        :param two_factor_auth: dict containing the data to be saved
        :raises: keystone.exception,
        :returns: dict with the saved data

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_two_factor_enabled(self, user_id):
        """Checks whether two factor authentication is enabled.

        :param user_id: user ID
        :returns: True or False

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_two_factor_key(self, user_id):
        """Deletes two factor data.

        :param user_id: user ID
        :raises: keystone.exception,
        :returns: None.

        """
        raise exception.NotImplemented()

    def get_two_factor_info(self, user_id):
        """Provides two factor info.

        :param user_id: user ID
        :raises: keystone.exception
        :returns: the two factor data, if available
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def check_security_question(self, user_id, two_factor_auth):
        """Checks whether the provided answer is correct.

        :param user_id: user ID
        :param sec_answer: answer to the security question
        :returns: None.
        """
        raise exception.NotImplemented()