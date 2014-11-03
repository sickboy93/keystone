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


class Role(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'role_fiware'
    attributes = ['id', 'name', 'is_editable', 'application']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    is_editable = sql.Column(sql.Boolean(), default=True, nullable=False)
    application = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=True, index=True)

class Permission(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'permission_fiware'
    attributes = ['id', 'name', 'is_editable', 'application']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    is_editable = sql.Column(sql.Boolean(), default=True, nullable=False)
    application = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=True, index=True)

class Roles(roles.RolesDriver):
    """ CRUD driver for the SQL backend """
    # Roles
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

            