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

from keystone.common import sql
from keystone.contrib import roles
from keystone import exception
from keystone.i18n import _

# TODO(garcianavalon) In development we are using the implicit value of 
# "sqlite:///keystone.db" so we just paste it here.
# For deployment check in etc/keystone.conf [database], read the OpenStack
# Identity Service Installation Manual and take a look at 
# oslo.config (CONF["database"]["connection"]) and oslo.sql
# to configure the database and use that option here
engine = sql.sql.create_engine("sqlite:///keystone.db")

role_permission_fiware_table = sql.sql.Table(
     'role_permission_fiware', 
     sql.ModelBase.metadata, 
     autoload=True,
     autoload_with=engine)

class Role(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'role_fiware'
    __table_args__ = (sql.UniqueConstraint('name'), {'extend_existing': True})
    attributes = ['id', 'name', 'is_editable', 'application', 'permissions']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    is_editable = sql.Column(sql.Boolean(), default=True, nullable=False)
    application = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=True)
    permissions = sql.sql.orm.relationship("Permission",
                                            secondary=role_permission_fiware_table)

class Permission(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'permission_fiware'
    __table_args__ = (sql.UniqueConstraint('name'), {'extend_existing': True})
    attributes = ['id', 'name', 'is_editable', 'application']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    is_editable = sql.Column(sql.Boolean(), default=True, nullable=False)
    application = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=True)

class Roles(roles.RolesDriver):
    """ CRUD driver for the SQL backend """
    # ROLES
    def list_roles(self):
        session = sql.get_session()
        roles = session.query(Role)
        return [role.to_dict() for role in roles]

    def create_role(self, role):
        session = sql.get_session()

        with session.begin():
            role_ref = Role.from_dict(role)
            session.add(role_ref)
        return role_ref.to_dict()

    def _get_role(self, session, role_id):
        role_ref = session.query(Role).get(role_id)
        if role_ref is None:
            raise exception.NotFound(_('No Role found with id: %s' %role_id))
        return role_ref

    def get_role(self, role_id):
        session = sql.get_session()
        with session.begin():
            role_ref = self._get_role(session, role_id) 
        return role_ref.to_dict()

    
    def update_role(self, role_id, role):
        session = sql.get_session()
        with session.begin():
            role_ref = self._get_role(session, role_id)
            for k in role:
                setattr(role_ref, k, role[k])
        return role_ref.to_dict()
        
    def delete_role(self, role_id):
        session = sql.get_session()
        with session.begin():
            role_ref = self._get_role(session, role_id)
            session.delete(role_ref)

    # PERMISSIONS
    def list_permissions(self):
        session = sql.get_session()
        permissions = session.query(Permission)
        return [permission.to_dict() for permission in permissions]

    def create_permission(self, permission):
        session = sql.get_session()

        with session.begin():
            permission_ref = Permission.from_dict(permission)
            session.add(permission_ref)
        return permission_ref.to_dict()

            