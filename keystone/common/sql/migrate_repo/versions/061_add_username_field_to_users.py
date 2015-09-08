#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# This is a placeholder for Juno backports. Do not use this number for new
# Kilo work. New Kilo work starts after all the placeholders.

import sqlalchemy as sql

from oslo.serialization import jsonutils

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)

    username = sql.Column('username', sql.String(255), nullable=True)
    username.create(user_table, populate_default=True)

    all_users = list(user_table.select().execute())

    for user in all_users:

        extra_dict = jsonutils.loads(user.extra)

        if 'username' not in extra_dict:
            continue

        new_values = {
            'username': extra_dict.pop('username'),
            'extra': jsonutils.dumps(extra_dict),
        }
        f = user_table.c.id == user.id
        update = user_table.update().where(f).values(new_values)
        migrate_engine.execute(update)


def downgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)

    all_users = list(user_table.select().execute())

    for user in all_users:

        extra_dict = jsonutils.loads(user.extra)

        if not user.username:
            continue

        new_values = {
            'extra': jsonutils.dumps(extra_dict),
        }
        f = user_table.c.id == user.id
        update = user_table.update().where(f).values(new_values)
        migrate_engine.execute(update)

    user_table.c.username.drop()
