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

from keystone import exception
from keystone.common import controller
from keystone.common import dependency

from keystone.openstack.common import log
LOG = log.getLogger(__name__)


@dependency.requires('two_factor_auth_api', 'identity_api')
class TwoFactorV3Controller(controller.V3Controller):
    collection_name = 'two_factor_auth'
    member_name = ''

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""
        path = '/OS-TWOFACTOR/' + cls.collection_name
        return super(TwoFactorV3Controller, cls).base_url(context, path=path)

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        ref.setdefault('links', {})
        ref['links']['self'] = cls.base_url(context) + '/' + ref['user_id']

    #@controller.protected()
    def is_two_factor_auth_enabled(self, context):
        """Checks if a certain user has enabled two factor auth"""
        user_id = context['query_string'].get('user_id')
        
        if not user_id:
            user_name = context['query_string'].get('user_name')
            domain_id = context['query_string'].get('domain_id')

            if not user_name and not domain_id:
                # 400 bad request -> need id or name + domain
                raise exception.ValidationError(
                    attribute='user_id or user_name and domain_id',
                    target='query string')

            if bool(user_name) != bool(domain_id):
                # 400 bad request -> need both domain and name
                raise exception.ValidationError(
                    attribute='user_name and domain_id',
                    target='query string')

            user = self.identity_api.get_user_by_name(user_name, domain_id)
            user_id = user['id']

        self.two_factor_auth_api.is_two_factor_enabled(user_id)

    @controller.protected()
    def enable_two_factor_auth(self, context, user_id, two_factor_auth):
        """Enables two factor auth for a certain user"""
        twofactor = self.two_factor_auth_api.create_two_factor_key(user_id, two_factor_auth)
        return TwoFactorV3Controller.wrap_member(context, twofactor)

    @controller.protected()
    def disable_two_factor_auth(self, context, user_id):
        """Disables two factor auth for a certain user"""

        return self.two_factor_auth_api.delete_two_factor_key(user_id)

    @controller.protected()
    def check_security_question(self, context, user_id, two_factor_auth):
        """Checks whether the provided answer is correct"""

        return self.two_factor_auth_api.check_security_question(user_id, two_factor_auth)

        

