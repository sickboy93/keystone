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

import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib.two_factor_auth import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-TWOFACTOR', extension_version='1.0')


class TwoFactorExtension(wsgi.V3ExtensionRouter):
    """API Endpoints for the two factor authentication extension.

    The API looks like::

      # two factor enabling and disabling endpoint
      POST /users/{user_id}/OS-TWOFACTOR/two_factor_auth #enable and create question/answer
      HEAD /users/{user_id}/OS-TWOFACTOR/two_factor_auth #is enabled?
      DELETE /users/{user_id}/OS-TWOFACTOR/two_factor_auth #disable 
      GET /users/{user_id}/OS-TWOFACTOR/sec_question #check security question
      
    """

    PATH_PREFIX = '/users'

    def add_routes(self, mapper):
        two_factor_controller = controllers.TwoFactorV3Controller()

        self._add_resource(
            mapper, two_factor_controller,
            path=self.PATH_PREFIX + '/{user_id}/OS-TWOFACTOR/two_factor_auth',
            get_head_action='is_two_factor_auth_enabled',
            post_action='enable_two_factor_auth',
            delete_action='disable_two_factor_auth',
            rel=build_resource_relation(resource_name='two_factor_auth')
            )

        self._add_resource(
            mapper, two_factor_controller,
            path=self.PATH_PREFIX + '/{user_id}/OS-TWOFACTOR/sec_question',
            get_action='check_security_question',
            rel=build_resource_relation(resource_name='two_factor_auth')
            )
