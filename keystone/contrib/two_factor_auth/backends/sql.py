# Copyright (C) 2015 Universidad Politecnica de Madrid
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
from keystone.contrib import two_factor_auth
from keystone.i18n import _
from oslo.utils import timeutils
from keystone.openstack.common import log


LOG = log.getLogger(__name__)


class TwoFactor(sql.ModelBase, sql.ModelDictMixin):
    __tablename__ = 'two_factor_auth'
    attributes = ['user_id', 'two_factor_key', 'security_question', 'security_answer']              
    user_id = sql.Column(sql.String(64), nullable=False, primary_key=True)
    two_factor_key = sql.Column(sql.String(32), nullable=False)
    security_question = sql.Column(sql.String(128), nullable=False)
    security_answer = sql.Column(sql.String(128), nullable=False)


class TwoFactorAuth(two_factor_auth.Driver):
    """ CRUD driver for the SQL backend """

    def create_two_factor_key(self, user_id, two_factor_auth):
        session = sql.get_session()
        twofactor = session.query(TwoFactor).get(user_id)
        with session.begin():
            if twofactor is None:
                twofactor = TwoFactor(user_id=user_id,
                                      two_factor_key=two_factor_auth['key'],
                                      security_question=two_factor_auth['security_question'],
                                      security_answer=two_factor_auth['security_answer'])
            else:
                twofactor.two_factor_key = two_factor_auth['key']
            session.add(twofactor)   
        return twofactor.to_dict()

    def is_two_factor_enabled(self, user_id):
        session = sql.get_session()
        twofactor = session.query(TwoFactor).get(user_id)

        if twofactor is None:
            return False
        else:
            return True

    def delete_two_factor_key(self, user_id):
        session = sql.get_session()
        twofactor = session.query(TwoFactor).get(user_id)
        if twofactor is None:
            raise exception.NotFound(_('No two factor key found for user: %s' %user_id))
        else:
            with session.begin():
                session.delete(twofactor)

    def get_two_factor_info(self, user_id):
        session = sql.get_session()
        twofactor = session.query(TwoFactor).get(user_id)
        if twofactor is None:
            raise exception.NotFound(_('Two Factor Authentication is not enabled for user %s.' %user_id))
        else:
            return twofactor

    def check_security_question(self, user_id, two_factor_auth):
        session = sql.get_session()
        twofactor = session.query(TwoFactor).get(user_id)
        if twofactor is None:
            raise exception.NotFound(_('Two Factor Authentication is not enabled for user %s.' % user_id))
        else:
            if (two_factor_auth['security_answer'] != twofactor.security_answer):
                return False
            else:
                return True