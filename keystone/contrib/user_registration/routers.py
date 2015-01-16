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
import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib.user_registration import controllers

build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-REGISTRATION', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-REGISTRATION', extension_version='1.0')

class Registration(wsgi.V3ExtensionRouter):
    """API Endpoints for the user registration extension.

    The API looks like::

      # user creation and activation endpoint
      POST /OS-REGISTRATION/users
      GET /OS-REGISTRATION/users/$user_id/activate # get a new activation key
      PATCH /OS-REGISTRATION/users/$user_id/activate/$activation_key
      GET /OS-REGISTRATION/users/$user_id/password_reset #gets a token
      PATCH /OS-REGISTRATION/users/$user_id/password_reset/$token_id
      
    """

    PATH_PREFIX = '/OS-REGISTRATION'

    def add_routes(self, mapper):
        user_controller = controllers.UserRegistrationV3()

        self._add_resource(
            mapper, user_controller,
            path=self.PATH_PREFIX + '/users',
            post_action='register_user',
            rel=build_resource_relation(resource_name='users'))
        
        self._add_resource(
            mapper, user_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/activate',
            get_action='get_activation_key',
            rel=build_resource_relation(resource_name='activation_key'),
            path_vars={
                'user_id':
                build_parameter_relation(parameter_name='user_id'),
            })

        self._add_resource(
            mapper, user_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/activate/{activation_key}',
            patch_action='activate_user',
            rel=build_resource_relation(resource_name='user'),
            path_vars={
                'user_id':
                build_parameter_relation(parameter_name='user_id'),
                'activation_key':
                build_parameter_relation(parameter_name='activation_key'),
            })

        self._add_resource(
            mapper, user_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/password_reset',
            get_action='get_reset_token',
            rel=build_resource_relation(resource_name='reset_token'),
            path_vars={
                'user_id':
                build_parameter_relation(parameter_name='user_id'),
            })

        self._add_resource(
            mapper, user_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/password_reset/{token_id}',
            patch_action='password_reset',
            rel=build_resource_relation(resource_name='user'),
            path_vars={
                'user_id':
                build_parameter_relation(parameter_name='user_id'),
                'token_id':
                build_parameter_relation(parameter_name='token_id'),
            })