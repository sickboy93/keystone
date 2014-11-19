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
from keystone.contrib.fiware_legacy_api import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='FIWARE-LEGACY-API', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='FIWARE-LEGACY-API', extension_version='1.0')

class FiwareExtension(wsgi.V3ExtensionRouter):

    PATH_PREFIX = ''
    def add_routes(self, mapper):
        fiware_controller = controllers.FiwareControllerV3()
        # FIWARE specific endpoints
        # Needed for backwards compatibility of the API
        self._add_resource(
            mapper, fiware_controller,
            path='/access-tokens/{token_id}',
            get_action='validate_token',
            rel=build_resource_relation(resource_name='roles'),
            path_vars={
                'token_id':build_parameter_relation(parameter_name='token_id'),
            })