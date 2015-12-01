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

import json
import uuid

import migrate
import sqlalchemy as sql
from sqlalchemy import orm

from keystone.contrib.initial_data import core
from keystone.contrib.initial_data import data


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = orm.sessionmaker(bind=migrate_engine)()

	# Keystone services
    _create_services_and_endpoints(meta, session)

    # Enpoint groups
    _create_endpoint_group_filters(meta, session)
    
    # Keystone roles
    _create_keystone_roles(meta, session)

    # Default users and projects
    _create_users_and_projects(meta, session)

    #_create_internal_roles_and_permissions(meta, session)

    # Make the idm user administrator
    #_grant_administrator(meta, session)

def _create_services_and_endpoints(meta, session):
    """Create services and its endpoints from a service catalog. Create also
    all the required regions.
    """

    # Create regions
    region_table = sql.Table('region', meta, autoload=True)
    for region in data.REGIONS:
        region_table.insert({
            'id': region,
            'description': '',
        }).execute()

        session.commit()

    # Create services
    service_table = sql.Table('service', meta, autoload=True)
    endpoint_table = sql.Table('endpoint', meta, autoload=True)
    for service_data in data.SERVICE_CATALOG:
        service_id = uuid.uuid4().hex

        service_table.insert({
            'id': service_id,
            'type': service_data['type'],
            'enabled': True,
        }).execute()

        session.commit()

        # Create endpoints
        for endpoint_data in service_data['endpoints']:
            interfaces = [
                ('public', endpoint_data['publicURL']),
                ('admin', endpoint_data['adminURL']),
                ('internal', endpoint_data['internalURL']),
            ]
            for interface in interfaces:
                endpoint_table.insert({
                    'id': uuid.uuid4().hex,
                    'service_id': service_id,
                    'url': interface[1],
                    'region_id': endpoint_data['region'],
                    'interface': interface[0],
                }).execute()

                session.commit()


def _create_endpoint_group_filters(meta, session):
    """Create an endpoint group that filters for each region and one
    that filters for identity service.
    """
    endpoint_group_table = sql.Table('endpoint_group', meta, autoload=True)
    for region in data.REGIONS:
        endpoint_group_table.insert({
            'id': uuid.uuid4().hex,
            'name': region + ' Region Group',
            'filters': json.dumps({'region_id': region}),
        }).execute()

        session.commit()

    identity_services = [] # TODO(garcianavalon)

    for service in identity_services:
        endpoint_group_table.insert({
            'id': uuid.uuid4().hex,
            'name': service.name + ' Identity Group',
            'filters': json.dumps({'service_id': service.id}),
        }).execute()

        session.commit()

def _create_keystone_roles(meta, session):
    """Default keystone roles.
    NOTE(garcianavalon) don't confuse it with keystone v2 API
    default role (member_role_name=_member_). We need a default
    role to add users to projects. Horizon knows this role throught
    the local_settings.py file.
    """
    core.insert_data(meta, session, 'role', data.KEYSTONE_ROLES)

def _create_users_and_projects(meta, session):
    core.insert_data(meta, session, 'user', data.USERS)
    core.insert_data(meta, session, 'project', data.PROJECTS)
    core.insert_data(meta, session, 'assignment', data.ASSIGNMENTS)


# def _create_internal_roles_and_permissions(meta, session):
#     # Default internal application
#     idm_app = keystone.oauth2.consumers.create(
#         settings.IDM_USER_CREDENTIALS['username'],
#         description='',
#         grant_type='authorization_code',
#         client_type='confidential',
#         is_default=True)

#     # Default Permissions and roles
#     created_permissions = []
#     for permission in settings.INTERNAL_PERMISSIONS:
#         created_permissions.append(
#             keystone.fiware_roles.permissions.create(
#                 name=permission, application=idm_app, is_internal=True))
#     created_roles = []
#     for role in settings.INTERNAL_ROLES:
#         created_role = keystone.fiware_roles.roles.create(
#             name=role, application=idm_app, is_internal=True)
#         created_roles.append(created_role)
#         # Link roles with permissions
#         for index in settings.INTERNAL_ROLES[role]:
#             keystone.fiware_roles.permissions.add_to_role(
#                 created_role, created_permissions[index])
    

# def _grant_administrator(meta, idm_app, users):
#     provider_role = next(
#         r for r in keystone.fiware_roles.roles.list()
#         if r.name == 'provider')

#     for user in users:
#         keystone.fiware_roles.roles.add_to_user(
#             role=provider_role,
#             user=user,
#             application=idm_app,
#             organization=user.default_project_id)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine
    tables = [
        'user',
        'project',
        'role',
        'endpoint_group',
        'service',
        'endpoint',
        'region',
    ]
    for table_name in tables:
        table = sql.Table(table_name, meta, autoload=True).delete().execute()
