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

import migrate
import sqlalchemy as sql
from sqlalchemy import orm

from keystone.contrib.initial_data.data import DATA


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = orm.sessionmaker(bind=migrate_engine)()

    for (table_name, elements) in DATA:
        table = sql.Table(table_name, meta, autoload=True)

        for element_data in elements:
            table.insert(element_data).execute()
            session.commit()

    #_create_internal_roles_and_permissions(meta, session)

    # Make the idm user administrator
    #_grant_administrator(meta, session)




    

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
