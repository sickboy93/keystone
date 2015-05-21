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
    meta = sql.MetaData()
    meta.bind = migrate_engine
    permissions_table = sql.Table('permission_fiware', meta, autoload=True)

    action = sql.Column('action', sql.String(10), nullable=True)
    resource = sql.Column('resource', sql.String(256), nullable=True)
    xacml = sql.Column('xacml', sql.Text(), nullable=True)

    action.create(permissions_table, populate_default=True)
    resource.create(permissions_table, populate_default=True)
    xacml.create(permissions_table, populate_default=True)

def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    permissions_table = sql.Table('permission_fiware', meta, autoload=True)
    permissions_table.c.action.drop()
    permissions_table.c.resource.drop()
    permissions_table.c.xacml.drop()

