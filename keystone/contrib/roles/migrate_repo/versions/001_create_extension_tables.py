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

import sqlalchemy as sql

def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    # Load existing tables
    sql.Table('consumer_oauth2', meta, autoload=True)
    sql.Table('user', meta, autoload=True)
    sql.Table('project', meta, autoload=True)

    role_table = sql.Table(
        'role_fiware',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), nullable=False),
        sql.Column('is_internal', sql.Boolean(), default=False, nullable=False),
        sql.Column('application_id', sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True))
    role_table.create(migrate_engine, checkfirst=True)

    permission_table = sql.Table(
        'permission_fiware',
        meta,
        sql.Column('id', sql.String(64), primary_key=True),
        sql.Column('name', sql.String(64), nullable=False),
        sql.Column('is_internal', sql.Boolean(), default=False, nullable=False),
        sql.Column('application_id', sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True))
    permission_table.create(migrate_engine, checkfirst=True)

    role_permission_table = sql.Table(
        'role_permission_fiware',
        meta,
        sql.Column('role_id', sql.String(64), sql.ForeignKey('role_fiware.id')),
        sql.Column('permission_id', sql.String(64), 
            sql.ForeignKey('permission_fiware.id')))
    role_permission_table.create(migrate_engine, checkfirst=True)

    role_user_table = sql.Table(
        'role_user_fiware',
        meta,
        sql.Column('role_id', sql.String(64), sql.ForeignKey('role_fiware.id')),
        sql.Column('user_id', sql.String(64), sql.ForeignKey('user.id')),
        sql.Column('organization_id', sql.String(64), sql.ForeignKey('project.id')),
        sql.Column('application_id', sql.String(64), 
            sql.ForeignKey('consumer_oauth2.id')))
    role_user_table.create(migrate_engine, checkfirst=True)

    role_organization_table = sql.Table(
        'role_organization_fiware',
        meta,
        sql.Column('role_id', sql.String(64), sql.ForeignKey('role_fiware.id')),
        sql.Column('organization_id', sql.String(64), sql.ForeignKey('project.id')),
        sql.Column('application_id', sql.String(64), 
            sql.ForeignKey('consumer_oauth2.id')))
    role_organization_table.create(migrate_engine, checkfirst=True)

def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    tables = ['role_fiware', 'permission_fiware',
              'role_permission_fiware', 'role_user_fiware',
              'role_organization_fiware']
    for t in tables:
        table = sql.Table(t, meta, autoload=True)
        table.drop(migrate_engine, checkfirst=True)
