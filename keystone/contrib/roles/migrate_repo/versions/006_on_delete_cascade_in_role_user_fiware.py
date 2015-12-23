# Copyright (C) 2014 Universidad Politecnica de Madrid
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
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
from migrate.changeset.constraint import ForeignKeyConstraint


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if 'mysql' in str(meta):
        role_user_table = sql.Table('role_user_fiware', meta, autoload=True)
        user = sql.Table('user', meta, autoload=True)

        ForeignKeyConstraint(
            columns=[role_user_table.c.user_id],
            refcolumns=[user.c.id],
            name='role_user_fiware_ibfk_2').drop()

        ForeignKeyConstraint(
            columns=[role_user_table.c.user_id],
            refcolumns=[user.c.id],
            name='role_user_fiware_ibfk_2',
            ondelete='CASCADE').create()

def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if 'mysql' in str(meta):
        role_user_table = sql.Table('role_user_fiware', meta, autoload=True)
        user = sql.Table('user', meta, autoload=True)

        ForeignKeyConstraint(
            columns=[role_user_table.c.user_id],
            refcolumns=[user.c.id],
            name='role_user_fiware_ibfk_2',
            ondelete='CASCADE').drop()

        ForeignKeyConstraint(
            columns=[role_user_table.c.user_id],
            refcolumns=[user.c.id],
            name='role_user_fiware_ibfk_2').create()

