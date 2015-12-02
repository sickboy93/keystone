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

import getpass
import migrate
import sqlalchemy as sql
from sqlalchemy import orm

from keystone.common import utils
from keystone.contrib.initial_data import data

_PASS_PROMT = (
    'Set a password for the {0} user. '
    '(If you forget it, the password can be changed later using the admin token): '
)

def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    meta = sql.MetaData()
    meta.bind = migrate_engine
    session = orm.sessionmaker(bind=migrate_engine)()

    for (table_name, elements) in data.DATA:
        table = sql.Table(table_name, meta, autoload=True)

        for element_data in elements:
            if table_name == 'user':
                # set up users passwords
                element_data['password'] = getpass.getpass(
                    _PASS_PROMT.format(element_data['name']))
                element_data = utils.hash_user_password(element_data)
            table.insert(element_data).execute()
            session.commit()

def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine
    tables = [table_name for (table_name, elements) in data.DATA]
    for table_name in tables:
        table = sql.Table(table_name, meta, autoload=True).delete().execute()
