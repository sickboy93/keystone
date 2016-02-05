# Copyright (C) 2016 Universidad Politecnica de Madrid
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

    if 'postgres' in str(meta):
        migration_003_up(meta)
        migration_004_up(meta)
        migration_005_up(meta)
        migration_006_up(meta)


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    meta = sql.MetaData()
    meta.bind = migrate_engine

    if 'postgres' in str(meta):
        migration_003_down(meta)
        migration_004_down(meta)
        migration_005_down(meta)
        migration_006_down(meta)


def migration_003_up(meta):
    role_user_table = sql.Table('role_user_fiware', meta, autoload=True)
    role_fiware_table = sql.Table('role_fiware', meta, autoload=True)
    role_organization_table = sql.Table('role_organization_fiware', meta, autoload=True)
    consumer_oauth2 = sql.Table('consumer_oauth2', meta, autoload=True)
    project = sql.Table('project', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[role_user_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_user_fiware_application_id_fkey').drop()
    ForeignKeyConstraint(
        columns=[role_user_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_user_fiware_application_id_fkey',
        ondelete='CASCADE').create()

    ForeignKeyConstraint(
        columns=[role_fiware_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_fiware_application_id_fkey').drop()
    ForeignKeyConstraint(
        columns=[role_fiware_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_fiware_application_id_fkey',
        ondelete='CASCADE').create()  

    ForeignKeyConstraint(
        columns=[role_organization_table.c.organization_id],
        refcolumns=[project.c.id],
        name='role_organization_fiware_organization_id_fkey').drop()    
    ForeignKeyConstraint(
        columns=[role_organization_table.c.organization_id],
        refcolumns=[project.c.id],
        name='role_organization_fiware_organization_id_fkey',
        ondelete='CASCADE').create()

def migration_003_down(meta):
    role_user_table = sql.Table('role_user_fiware', meta, autoload=True)
    role_organization_table = sql.Table('role_organization_fiware', meta, autoload=True)
    consumer_oauth2 = sql.Table('consumer_oauth2', meta, autoload=True)
    project = sql.Table('project', meta, autoload=True)
    role_fiware_table = sql.Table('role_fiware', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[role_user_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_user_fiware_application_id_fkey',
        ondelete='CASCADE').drop()
    ForeignKeyConstraint(
        columns=[role_user_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_user_fiware_application_id_fkey').create()

    ForeignKeyConstraint(
        columns=[role_fiware_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_fiware_application_id_fkey',
        ondelete='CASCADE').drop()
    ForeignKeyConstraint(
        columns=[role_fiware_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='role_fiware_application_id_fkey').create()

    ForeignKeyConstraint(
        columns=[role_organization_table.c.organization_id],
        refcolumns=[project.c.id],
        name='role_organization_fiware_application_id_fkey',
        ondelete='CASCADE').drop()    
    ForeignKeyConstraint(
        columns=[role_organization_table.c.organization_id],
        refcolumns=[project.c.id],
        name='role_organization_fiware_application_id_fkey').create()    

    ForeignKeyConstraint(
        columns=[role_organization_table.c.organization_id],
        refcolumns=[project.c.id],
        name='role_organization_fiware_organization_id_fkey',
        ondelete='CASCADE').drop()    
    ForeignKeyConstraint(
        columns=[role_organization_table.c.organization_id],
        refcolumns=[project.c.id],
        name='role_organization_fiware_organization_id_fkey').create()

def migration_004_up(meta):
    permission_table = sql.Table('permission_fiware', meta, autoload=True)
    consumer_oauth2 = sql.Table('consumer_oauth2', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[permission_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='permission_fiware_application_id_fkey').drop()

    ForeignKeyConstraint(
        columns=[permission_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='permission_fiware_application_id_fkey', ondelete='CASCADE').create()

def migration_004_down(meta):
    permission_table = sql.Table('permission_fiware', meta, autoload=True)
    consumer_oauth2 = sql.Table('consumer_oauth2', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[permission_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='permission_fiware_application_id_fkey', ondelete='CASCADE').drop()

    ForeignKeyConstraint(
        columns=[permission_table.c.application_id],
        refcolumns=[consumer_oauth2.c.id],
        name='permission_fiware_application_id_fkey').create()

def migration_005_up(meta):
    role_permission_table = sql.Table('role_permission_fiware', meta, autoload=True)
    role_fiware = sql.Table('role_fiware', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[role_permission_table.c.role_id],
        refcolumns=[role_fiware.c.id],
        name='role_permission_fiware_role_id_fkey').drop()

    ForeignKeyConstraint(
        columns=[role_permission_table.c.role_id],
        refcolumns=[role_fiware.c.id],
        name='role_permission_fiware_role_id_fkey', ondelete='CASCADE').create()

def migration_005_down(meta):
    role_permission_table = sql.Table('role_permission_fiware', meta, autoload=True)
    role_fiware = sql.Table('role_fiware', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[role_permission_table.c.role_id],
        refcolumns=[role_fiware.c.id],
        name='role_permission_fiware_role_id_fkey', ondelete='CASCADE').drop()

    ForeignKeyConstraint(
        columns=[role_permission_table.c.role_id],
        refcolumns=[role_fiware.c.id],
        name='role_permission_fiware_role_id_fkey').create()

def migration_006_up(meta):
    role_user_table = sql.Table('role_user_fiware', meta, autoload=True)
    user = sql.Table('user', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[role_user_table.c.user_id],
        refcolumns=[user.c.id],
        name='role_user_fiware_user_id_fkey').drop()

    ForeignKeyConstraint(
        columns=[role_user_table.c.user_id],
        refcolumns=[user.c.id],
        name='role_user_fiware_user_id_fkey',
        ondelete='CASCADE').create()

def migration_006_down(meta):
    role_user_table = sql.Table('role_user_fiware', meta, autoload=True)
    user = sql.Table('user', meta, autoload=True)

    ForeignKeyConstraint(
        columns=[role_user_table.c.user_id],
        refcolumns=[user.c.id],
        name='role_user_fiware_user_id_fkey',
        ondelete='CASCADE').drop()

    ForeignKeyConstraint(
        columns=[role_user_table.c.user_id],
        refcolumns=[user.c.id],
        name='role_user_fiware_user_id_fkey').create()
