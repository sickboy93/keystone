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
    extension_name='OS-TWO-FACTOR', extension_version='1.0')


class TwoFactorExtension(wsgi.V3ExtensionRouter):
    """API Endpoints for the two factor authentication extension.

    The API looks like::

      # check if two factor is enabled for a certain user
      HEAD /OS-TWO-FACTOR/two_factor_auth?user_id={user_id}&user_name={user_name}&domain_id={domain_id}

      # two factor enabling and disabling endpoint
      POST /users/{user_id}/OS-TWO-FACTOR/two_factor_auth #enable and create question/answer
      DELETE /users/{user_id}/OS-TWO-FACTOR/two_factor_auth #disable

      # get non-sensitive data and check security question
      GET /users/{user_id}/OS-TWO-FACTOR/two_factor_data
      HEAD /users/{user_id}/OS-TWO-FACTOR/sec_question #check security question

      # remember device functionality
      POST /OS-TWO-FACTOR/devices?user_id={user_id}&user_name={user_name}&domain_name={domain_name}
      GET /OS-TWO-FACTOR/devices?device_id={device_id}&device_token={device_token}&user_id={user_id}
      DELETE /users/{user_id}/OS-TWO-FACTOR/devices
      
    """

    PATH_PREFIX = '/OS-TWO-FACTOR'

    def add_routes(self, mapper):
        two_factor_controller = controllers.TwoFactorV3Controller()

        self._add_resource(
            mapper,
            two_factor_controller,
            path=self.PATH_PREFIX + '/two_factor_auth',
            get_head_action='is_two_factor_auth_enabled',
            rel=build_resource_relation(resource_name='two_factor_auth')
        )

        self._add_resource(
            mapper,
            two_factor_controller,
            path='/users/{user_id}' + self.PATH_PREFIX + '/two_factor_auth',
            post_action='enable_two_factor_auth',
            delete_action='disable_two_factor_auth',
            rel=build_resource_relation(resource_name='two_factor_auth')
        )

        self._add_resource(
            mapper,
            two_factor_controller,
            path='/users/{user_id}' + self.PATH_PREFIX + '/sec_question',
            get_head_action='check_security_question',
            rel=build_resource_relation(resource_name='two_factor_auth')
        )

        self._add_resource(
            mapper,
            two_factor_controller,
            path='/users/{user_id}' + self.PATH_PREFIX +'/two_factor_data',
            get_action='get_two_factor_data',
            rel=build_resource_relation(resource_name='two_factor_auth')
        )

        self._add_resource(
            mapper,
            two_factor_controller,
            path='/users/{user_id}' + self.PATH_PREFIX + '/devices',
            delete_action='forget_devices',
            rel=build_resource_relation(resource_name='two_factor_auth')
        )

        self._add_resource(
            mapper,
            two_factor_controller,
            path=self.PATH_PREFIX + '/devices',
            get_action='check_for_device',
            post_action='remember_device',
            rel=build_resource_relation(resource_name='two_factor_auth')
        )
