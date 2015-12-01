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

import json
import uuid

from keystone import config
from keystone.assignment.backends.sql import AssignmentType
from keystone.common import utils


CONF = config.CONF
DEFAULT_DOMAIN = CONF.identity.default_domain_id

# Utils
def find_id(elements, attr='name', value=None):
    return next(r for r in elements if r[attr] == value)['id']

# Catalog, endpoints and services
KEYSTONE_PUBLIC_ADDRESS = '127.0.0.1'
KEYSTONE_ADMIN_ADDRESS = '127.0.0.1'
KEYSTONE_INTERNAL_ADDRESS = '127.0.0.1'

REGIONS = [
  'Spain2', 
]

SERVICE_CATALOG = [
  {
    'endpoints': [
      {
        'region': REGIONS[0],
        'adminURL': 'http://{url}:{port}/v3/'.format(
          url=KEYSTONE_ADMIN_ADDRESS,
          port=CONF.admin_port),
        'internalURL': 'http://{url}:{port}/v3/'.format(
          url=KEYSTONE_INTERNAL_ADDRESS,
          port=CONF.admin_port),
        'publicURL': 'http://{url}:{port}/v3/'.format(
          url=KEYSTONE_PUBLIC_ADDRESS,
          port=CONF.public_port)
      }
    ],
    'type': 'identity',
    'name': 'keystone'
  }
]

# Keystone Roles
KEYSTONE_ROLES = [
    {
        'id': uuid.uuid4().hex,
        'name': 'member'
    },
    {
        'id': uuid.uuid4().hex,
        'name': 'owner'
    },
    {
        'id': uuid.uuid4().hex,
        'name': 'trial',
        'extra': json.dumps({
            'is_default': True
        })
    },
    {
        'id': uuid.uuid4().hex,
        'name': 'basic',
        'extra': json.dumps({
            'is_default': True
        })
    },
    {
        'id': uuid.uuid4().hex,
        'name': 'community',
        'extra': json.dumps({
            'is_default': True
        })
    },
    {
        'id': uuid.uuid4().hex,
        'name': 'admin',
        'extra': json.dumps({
            'is_default': True
        })
    },
]

# Projects
PROJECTS = [
    {
        'id': 'idm_project',
        'name': 'idm',
        'description':'',
        'domain_id': DEFAULT_DOMAIN,
        'extra': json.dumps({
            'is_default': True,
        })
    },
]

# Users
_USERS = [
    {
        'id': 'idm_user',
        'name': 'idm',
        'username': 'idm',
        'default_project_id': find_id(PROJECTS, value='idm'),
        'domain_id': DEFAULT_DOMAIN,
        'password': 'idm', #TODO(garcianavalon)
    },
]

USERS = []
for user in _USERS:
    USERS.append(utils.hash_user_password(user))

# Keystone role assignments
ASSIGNMENTS = [
    {
        'role_id': find_id(KEYSTONE_ROLES, value='admin'),
        'actor_id': find_id(USERS, value='idm'),
        'target_id': find_id(PROJECTS, value='idm'),
        'type': AssignmentType.USER_PROJECT,
        'inherited': False,
    },
    {
        'role_id': find_id(KEYSTONE_ROLES, value='owner'),
        'actor_id': find_id(USERS, value='idm'),
        'target_id': find_id(PROJECTS, value='idm'),
        'type': AssignmentType.USER_PROJECT,
        'inherited': False,
    },
]
