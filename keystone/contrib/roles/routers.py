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
from keystone.contrib.roles import controllers


build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-ROLES', extension_version='1.0')


class RolesExtension(wsgi.V3ExtensionRouter):

    PATH_PREFIX = '/OS-ROLES'

    def add_routes(self, mapper):
        roles_controller = controllers.RoleCrudV3()

        self._add_resource(
            mapper, roles_controller,
            path=self.PATH_PREFIX + '/roles',
            get_action='list_roles',
            post_action='create_role',
            rel=build_resource_relation(resource_name='roles'))
