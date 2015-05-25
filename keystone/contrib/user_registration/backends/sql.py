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

import uuid

from keystone import exception
from keystone.common import sql
from keystone.contrib import user_registration
from keystone.i18n import _
from oslo.utils import timeutils

class ActivationProfile(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'user_registration_activation_profile'
    attributes = ['id', 'user_id', 'expires_at', 'activation_key']              
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    user_id = sql.Column(sql.String(64), nullable=False, index=True)
    project_id = sql.Column(sql.String(64), nullable=False, index=True)
    cloud_project_id = sql.Column(
        sql.String(64), nullable=False, index=True)
    expires_at = sql.Column(sql.DateTime(), nullable=False)
    activation_key = sql.Column(sql.String(64), nullable=False, index=True)

class ResetProfile(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'user_registration_reset_profile'
    attributes = ['id', 'user_id', 'expires_at', 'reset_token']              
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    user_id = sql.Column(sql.String(64), nullable=False, index=True)
    expires_at = sql.Column(sql.DateTime(), nullable=False)
    reset_token = sql.Column(sql.String(64), nullable=False, index=True)

class Registration(user_registration.Driver):
    """ CRUD driver for the SQL backend """

    def create_reset_profile(self, profile):
        session = sql.get_session()
        with session.begin():
            profile_ref = ResetProfile.from_dict(profile)
            session.add(profile_ref)
        return profile_ref.to_dict()

    def get_reset_profile(self, user_id, reset_token):
        session = sql.get_session()
        with session.begin():
            profile_ref = session.query(ResetProfile).filter_by(
                                                reset_token=reset_token,
                                                user_id=user_id).first()
        if profile_ref is None:
            raise exception.NotFound(_('No Profile found for user: %s' %user_id))
        return profile_ref.to_dict()

    def create_activation_profile(self, profile):
        session = sql.get_session()
        with session.begin():
            profile_ref = ActivationProfile.from_dict(profile)
            session.add(profile_ref)
        return profile_ref.to_dict()

    def get_activation_profile(self, user_id, activation_key=None):
        session = sql.get_session()
        with session.begin():
            query = session.query(ActivationProfile).filter_by(user_id=user_id)
            if activation_key:
                query = query.filter_by(activation_key=activation_key)
            profile_ref = query.first()

        if profile_ref is None:
            raise exception.NotFound(_('No Profile found for user: %s' %user_id))
        return profile_ref.to_dict()

    def store_new_activation_key(self, profile_id, new_ref):
        session = sql.get_session()
        with session.begin():
            profile_ref = session.query(ActivationProfile).get(profile_id)
            profile_ref.activation_key = new_ref['activation_key']
            profile_ref.expires_at = new_ref['expires_at']
        return profile_ref.to_dict()

    def delete_user_profiles(self, user_id):
        session = sql.get_session()
        with session.begin():
            for profile_class in (ResetProfile, ActivationProfile):
                q = session.query(profile_class)
                q = q.filter_by(user_id=user_id)
                q.delete(False)