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

import sys

import six

from keystone.auth.plugins.password import UserAuthInfo,Password
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _
from keystone.openstack.common import log


LOG = log.getLogger(__name__)

METHOD_NAME = 'two_factor'
      
@dependency.requires('assignment_api', 'identity_api')
class UserTwoFactorAuthInfo(object):
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

    def _assert_domain_is_enabled(self, domain_ref):
        try:
            self.assignment_api.assert_domain_enabled(
                domain_id=domain_ref['id'],
                domain=domain_ref)
        except AssertionError as e:
            LOG.warning(e)
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _assert_user_is_enabled(self, user_ref):
        try:
            self.identity_api.assert_user_enabled(
                user_id=user_ref['id'],
                user=user_ref)
        except AssertionError as e:
            LOG.warning(e)
            six.reraise(exception.Unauthorized, exception.Unauthorized(e),
                        sys.exc_info()[2])

    def _lookup_domain(self, domain_info):
        domain_id = domain_info.get('id')
        domain_name = domain_info.get('name')
        domain_ref = None
        if not domain_id and not domain_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='domain')
        try:
            if domain_name:
                domain_ref = self.assignment_api.get_domain_by_name(
                    domain_name)
            else:
                domain_ref = self.assignment_api.get_domain(domain_id)
        except exception.DomainNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_domain_is_enabled(domain_ref)
        return domain_ref

    def _validate_and_normalize_auth_data(self, auth_payload):
        if 'user' not in auth_payload:
            raise exception.ValidationError(attribute='user',
                                            target=METHOD_NAME)
        user_info = auth_payload['user']
        user_id = user_info.get('id')
        user_name = user_info.get('name')
        user_ref = None
        if not user_id and not user_name:
            raise exception.ValidationError(attribute='id or name',
                                            target='user')
        self.password = user_info.get('password')
        try:
            if user_name:
                if 'domain' not in user_info:
                    raise exception.ValidationError(attribute='domain',
                                                    target='user')
                domain_ref = self._lookup_domain(user_info['domain'])
                user_ref = self.identity_api.get_user_by_name(
                    user_name, domain_ref['id'])
            else:
                user_ref = self.identity_api.get_user(user_id)
                domain_ref = self.assignment_api.get_domain(
                    user_ref['domain_id'])
                self._assert_domain_is_enabled(domain_ref)
        except exception.UserNotFound as e:
            LOG.exception(e)
            raise exception.Unauthorized(e)
        self._assert_user_is_enabled(user_ref)
        self.user_ref = user_ref
        self.user_id = user_ref['id']
        self.domain_id = domain_ref['id']
        if 'time_based_code' not in auth_payload:
            raise exception.ValidationError(attribute='user', target=METHOD_NAME)
        self.time_based_code = auth_payload['time_based_code']


@dependency.requires('two_factor_auth_api')
class TwoFactor(Password):

    method = METHOD_NAME

    def authenticate(self, context, auth_payload, auth_context):
        """Two factor authentication"""

        if not self.two_factor_auth_api:
            raise exception.Unauthorized(_('%s not supported') % self.method)

        user_info = UserAuthInfo.create(auth_payload)
        user_id = user_info.user_id

        try:
            self.two_factor_auth_api.is_two_factor_enabled(user_id)
        except exception.NotFound:
            return super(TwoFactor, self).authenticate(context, auth_payload, auth_context)

        user_info = UserTwoFactorAuthInfo.create(auth_payload)

        if not self.two_factor_auth_api.verify_code(user_id, user_info.time_based_code):
            raise exception.Unauthorized(_('Invalid time based code'))
        
        return super(TwoFactor, self).authenticate(context, auth_payload, auth_context)
            