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

from keystone.openstack.common import log

from keystone.common import dependency
from keystone.auth.plugins.password import UserAuthInfo,Password
from keystone import exception
from keystone.i18n import _


LOG = log.getLogger(__name__)

METHOD_NAME = 'two_factor'

@dependency.requires('identity_api')
class UserTwoFactorAuthInfo(UserAuthInfo):
    @staticmethod
    def create(auth_payload):
        user_auth_info = UserTwoFactorAuthInfo()
        user_auth_info._validate_and_normalize_auth_data(auth_payload)
        return user_auth_info

    def __init__(self):
        self.user_id = None
        self.password = None
        self.user_ref = None
        self.time_based_code = None

    def _validate_and_normalize_auth_data(self, auth_payload):
        if 'time_based_code' not in auth_payload:
            raise exception.ValidationError(attribute='user', target=METHOD_NAME)
        self.time_based_code = auth_payload['time_based_code']
        #super(UserTwoFactorAuthInfo, self)._validate_and_normalize_auth_data(auth_payload=auth_payload)

@dependency.requires('two_factor_auth_api')
class TwoFactor(Password):

    method = METHOD_NAME

    def authenticate(self, context, auth_payload, auth_context):
        """Two factor authentication"""

        LOG.info("Authenticating with twofactor")

        if not self.two_factor_auth_api:
            raise exception.Unauthorized(_('%s not supported') % self.method)

        user_id = auth_payload['user']['id']

        LOG.info("User is "+str(user_id))

        try:
            self.two_factor_auth_api.is_two_factor_enabled(user_id)
        except exception.NotFound:
            LOG.info("twofactor is not enabled.")
            return super(TwoFactor, self).authenticate(context, auth_payload, auth_context)

        LOG.info("User has twofactor enabled")
        user_info = UserTwoFactorAuthInfo.create(auth_payload)

        LOG.info("Code to try is "+str(user_info.time_based_code))

        if not self.two_factor_auth_api.verify_code(user_id, user_info.time_based_code):
            raise exception.Unauthorized(_('Invalid time based code'))
        
        return super(TwoFactor, self).authenticate(context, auth_payload, auth_context)
            