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

    activation_table = sql.Table(
        'user_registration_activation_profile',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('user_id', sql.String(64), nullable=False, index=True),
        sql.Column('project_id', sql.String(64), nullable=False, index=True),
        sql.Column(
            'cloud_project_id', sql.String(64), nullable=False, index=True),
        sql.Column('expires_at', sql.DateTime(), nullable=False),
        sql.Column(
            'activation_key', sql.String(64), nullable=False, index=True))
    activation_table.create(migrate_engine, checkfirst=True)

    reset_table = sql.Table(
        'user_registration_reset_profile',
        meta,
        sql.Column('id', sql.String(64), primary_key=True, nullable=False),
        sql.Column('user_id', sql.String(64), nullable=False, index=True),
        sql.Column('expires_at', sql.DateTime(), nullable=False),
        sql.Column('reset_token', sql.String(64), nullable=False, index=True))
    reset_table.create(migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    tables = ['user_registration_activation_profile', 
        'user_registration_reset_profile']
    for t in tables:
        table = sql.Table(t, meta, autoload=True)
        table.drop(migrate_engine, checkfirst=True)