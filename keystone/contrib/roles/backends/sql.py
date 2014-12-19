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


class Role(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'role_fiware'
    __table_args__ = (sql.UniqueConstraint('name', 'application'), {'extend_existing': True})
    attributes = ['id', 'name', 'is_internal', 'application']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    is_internal = sql.Column(sql.Boolean(), default=False, nullable=False)
    application = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True)

class Permission(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'permission_fiware'
    __table_args__ = (sql.UniqueConstraint('name', 'application'), {'extend_existing': True})
    attributes = ['id', 'name', 'is_internal', 'application']
                    
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    name = sql.Column(sql.String(64), nullable=False)
    is_internal = sql.Column(sql.Boolean(), default=False, nullable=False)
    application = sql.Column(sql.String(64), sql.ForeignKey('consumer_oauth2.id'),
                             nullable=False, index=True)

class RolePermission(sql.ModelBase, sql.DictBase):
    """Role\'s permissions join table."""
    __tablename__ = 'role_permission_fiware'
    role_id = sql.Column(sql.String(64),
                         sql.ForeignKey('role_fiware.id'),
                         primary_key=True)
    permission_id = sql.Column(sql.String(64),
                          sql.ForeignKey('permission_fiware.id'),
                          primary_key=True)

class RoleUser(sql.ModelBase, sql.DictBase):
    """Role\'s users join table."""
    __tablename__ = 'role_user_fiware'
    role_id = sql.Column(sql.String(64),
                         sql.ForeignKey('role_fiware.id'),
                         primary_key=True)
    user_id = sql.Column(sql.String(64),
                         sql.ForeignKey('user.id'),
                         primary_key=True)
    organization_id = sql.Column(sql.String(64),
                         sql.ForeignKey('project.id'),
                         primary_key=True)

class Roles(roles.RolesDriver):
    """ CRUD driver for the SQL backend """
    # ROLES
    def list_roles(self, **kwargs):
        session = sql.get_session()
        roles = session.query(Role)
        if kwargs:
            import pdb; pdb.set_trace()
            roles = roles.filter_by(**kwargs)
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

            q1 = session.query(RolePermission)
            q1 = q1.filter_by(role_id=role_id)
            q1.delete(False)

            q2 = session.query(RoleUser)
            q2 = q2.filter_by(role_id=role_id)
            q2.delete(False)

            session.delete(role_ref)

    def list_roles_for_user(self, user_id, organization_id=None):
        session = sql.get_session()
        self.identity_api.get_user(user_id)
        query = session.query(Role, RoleUser.organization_id).join(RoleUser)
        query = query.filter(RoleUser.user_id == user_id)
        if organization_id:
            query = query.filter(RoleUser.organization_id == organization_id)
        # query objects are now a tuple (Role, organization_id
        roles_as_dict = []
        for tuple in query:
            role = tuple[0]
            role_dict = role.to_dict()
            role_dict['organization_id'] = tuple[1]
            roles_as_dict.append(role_dict)

        return roles_as_dict
        

    def add_role_to_user(self, role_id, user_id, organization_id):
        session = sql.get_session()
        self.get_role(role_id)
        self.identity_api.get_user(user_id)
        self.assignment_api.get_project(organization_id)
        query = session.query(RoleUser)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(role_id=role_id)
        query = query.filter_by(organization_id=organization_id)
        ref = query.first()
        if ref:
            return

        with session.begin():
            session.add(RoleUser(user_id=user_id,
                                role_id=role_id,
                                organization_id=organization_id)) 

    def remove_role_from_user(self, role_id, user_id, organization_id):
        session = sql.get_session()
        self.get_role(role_id)
        self.identity_api.get_user(user_id)
        self.assignment_api.get_project(organization_id)
        query = session.query(RoleUser)
        query = query.filter_by(user_id=user_id)
        query = query.filter_by(role_id=role_id)
        query = query.filter_by(organization_id=organization_id)
        ref = query.first()
        if not ref:
            return

        with session.begin():
            session.delete(ref)

    # PERMISSIONS
    def list_permissions(self, **kwargs):
        session = sql.get_session()
        permissions = session.query(Permission)
        if kwargs:
            import pdb; pdb.set_trace()
            permissions = permissions.filter_by(**kwargs)
        return [permission.to_dict() for permission in permissions]

    def create_permission(self, permission):
        session = sql.get_session()

        with session.begin():
            permission_ref = Permission.from_dict(permission)
            session.add(permission_ref)
        return permission_ref.to_dict()

    def _get_permission(self, session, permission_id):
        permission_ref = session.query(Permission).get(permission_id)
        if permission_ref is None:
            raise exception.NotFound(_('No Permission found with id: %s' %permission_id))
        return permission_ref

    def get_permission(self, permission_id):
        session = sql.get_session()
        with session.begin():
            permission_ref = self._get_permission(session, permission_id) 
        return permission_ref.to_dict()

    def update_permission(self, permission_id, permission):
        session = sql.get_session()
        with session.begin():
            permission_ref = self._get_permission(session, permission_id)
            for k in permission:
                setattr(permission_ref, k, permission[k])
        return permission_ref.to_dict()
        
    def delete_permission(self, permission_id):
        session = sql.get_session()
        with session.begin():            
            permission_ref = self._get_permission(session, permission_id)

            q = session.query(RolePermission)
            q = q.filter_by(permission_id=permission_id)
            q.delete(False)

            session.delete(permission_ref) 

    def list_permissions_for_role(self, role_id):
        session = sql.get_session()
        self.get_role(role_id)
        query = session.query(Permission).join(RolePermission)
        query = query.filter(RolePermission.role_id == role_id)
        
        return [g.to_dict() for g in query]

    def add_permission_to_role(self, role_id, permission_id):
        session = sql.get_session()
        self.get_role(role_id)
        self.get_permission(permission_id)
        query = session.query(RolePermission)
        query = query.filter_by(permission_id=permission_id)
        query = query.filter_by(role_id=role_id)
        ref = query.first()
        if ref:
            return

        with session.begin():
            session.add(RolePermission(permission_id=permission_id,
                                            role_id=role_id))

    def remove_permission_from_role(self, role_id, permission_id):
        session = sql.get_session()
        self.get_role(role_id)
        self.get_permission(permission_id)
        query = session.query(RolePermission)
        query = query.filter_by(permission_id=permission_id)
        query = query.filter_by(role_id=role_id)
        ref = query.first()
        if not ref:
            return

        with session.begin():
            session.delete(ref)


    

    
            