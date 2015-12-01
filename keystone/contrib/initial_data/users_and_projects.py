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

from keystone import config
from keystone.contrib.initial_data import core
from keystone.contrib.initial_data import data


CONF = config.CONF

DEFAULT_DOMAIN = CONF.default_domain_id

PROJECTS = [
    {
        'id': 'idm_project',
        'name': 'idm',
        'description':'',
        'domain': DEFAULT_DOMAIN,
        'extra': {
            'is_default': True,
        }
    },
]

USERS = [
    {
        'id': 'idm_user',
        'name': 'idm',
        'username': 'idm',
        'password': 'idm', #TODO(garcianavalon)
        'default_project': PROJECTS[0],
        'domain': DEFAULT_DOMAIN,
    },
]


RELATIONSHIPS = [
    {
        'role': core.find_element_by(data.KEYSTONE_ROLES, 'name', 'admin'),
        'user': USERS[0]['id'],
        'project': PROJECTS[0]['id'],
    },
    {
        'role': core.find_element_by(data.KEYSTONE_ROLES, 'name', 'owner'),
        'user': USERS[0]['id'],
        'project': PROJECTS[0]['id'],
    },
]
