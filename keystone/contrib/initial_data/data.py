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

_REGIONS = [
    'Spain2',
]

REGIONS = []
for region in _REGIONS:
    REGIONS.append({
        'id': region,
        'description': '',
    })

_SERVICE_CATALOG = [
    {
        'endpoints': [
            {
                'region': _REGIONS[0],
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

SERVICES = []
ENDPOINTS = []
for service_data in _SERVICE_CATALOG:
    service_id = uuid.uuid4().hex

    SERVICES.append({
        'id': service_id,
        'type': service_data['type'],
        'enabled': True,
        'extra': json.dumps({
            'name': service_data['name'],
        }),
    })


    # Create endpoints
    for endpoint_data in service_data['endpoints']:
        interfaces = [
            ('public', endpoint_data['publicURL']),
            ('admin', endpoint_data['adminURL']),
            ('internal', endpoint_data['internalURL']),
        ]
        for interface in interfaces:
            ENDPOINTS.append({
                'id': uuid.uuid4().hex,
                'service_id': service_id,
                'url': interface[1],
                'region_id': endpoint_data['region'],
                'interface': interface[0],
            })

# Endpoint Group Filters
ENDPOINT_GROUPS = []

# one for each region
for region in _REGIONS:
    ENDPOINT_GROUPS.append({
        'id': uuid.uuid4().hex,
        'name': region + ' Region Group',
        'filters': json.dumps({'region_id': region}),
    })

# one for each identity service
for service in [s for s in SERVICES if s['type'] == 'identity']:
    ENDPOINT_GROUPS.append({
        'id': uuid.uuid4().hex,
        'name': json.loads(service['extra'])['name'] + ' Identity Group',
        'filters': json.dumps({'service_id': service['id']}),
    })


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

# Internal FIWARE roles and permissions

APLICATIONS = [
    {
        'id': 'idm_admin_app',
        'name': 'idm_admin_app',
        'description': '',
        'grant_type':'authorization_code',
        'client_type':'confidential',
        'extra': json.dumps({
                'is_default': True,
            }),
    },
]

FIWARE_PERMISSIONS = [
]

FIWARE_ROLES = [
]
    # Default Permissions and roles
    created_permissions = []
    for permission in settings.INTERNAL_PERMISSIONS:
        created_permissions.append(
            keystone.fiware_roles.permissions.create(
                name=permission, application=idm_app, is_internal=True))
    created_roles = []
    for role in settings.INTERNAL_ROLES:
        created_role = keystone.fiware_roles.roles.create(
            name=role, application=idm_app, is_internal=True)
        created_roles.append(created_role)
        # Link roles with permissions
        for index in settings.INTERNAL_ROLES[role]:
            keystone.fiware_roles.permissions.add_to_role(
                created_role, created_permissions[index])

# Finally export all the data
DATA = [
    ('region', REGIONS),
    ('service', SERVICES),
    ('endpoint', ENDPOINTS),
    ('endpoint_group', ENDPOINT_GROUPS),
    ('role', KEYSTONE_ROLES),
    ('user', USERS),
    ('project', PROJECTS),
    ('assignment', ASSIGNMENTS),
]
