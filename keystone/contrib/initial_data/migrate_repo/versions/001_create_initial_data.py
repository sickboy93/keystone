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

from keystone.contrib.initial_data import data

def _insert_data(meta, session, table_name, elements):
    table = sql.Table(table_name, meta, autoload=True)

    for element_data in elements:
        table.insert(element_data).execute()
        session.commit()


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = orm.sessionmaker(bind=migrate_engine)()

	# Create regions
    _insert_data(meta, session, 'region', data.REGIONS)
     # Create services
    _insert_data(meta, session, 'service', data.SERVICES)
    _insert_data(meta, session, 'endpoint', data.ENDPOINTS)

    # Enpoint groups
    _insert_data(meta, session, 'endpoint_group', data.ENDPOINT_GROUPS)
    
    # Keystone roles
    _insert_data(meta, session, 'role', data.KEYSTONE_ROLES)

    # Default users and projects
    _insert_data(meta, session, 'user', data.USERS)
    _insert_data(meta, session, 'project', data.PROJECTS)
    _insert_data(meta, session, 'assignment', data.ASSIGNMENTS)

    #_create_internal_roles_and_permissions(meta, session)

    # Make the idm user administrator
    #_grant_administrator(meta, session)



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
