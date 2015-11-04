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

from keystone.tests import test_v3
from keystone.common import dependency
from keystone.contrib.two_factor_auth import controllers
from keystone.contrib.two_factor_auth import core

TWOFACTOR_BASE_URL = '/users/{user_id}/OS-TWOFACTOR'
TWOFACTOR_URL = TWOFACTOR_BASE_URL + '/two_factor_auth'
TWOFACTOR_QUESTION_URL = TWOFACTOR_BASE_URL + '/sec_question'

class TwoFactorBaseTests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'two_factor_auth'
    EXTENSION_TO_ADD = 'two_factor_auth_extension'

    SAMPLE_SECURITY_QUESTION = 'Sample question'
    SAMPLE_SECURITY_ANSWER = 'Sample answer'

    def setUp(self):
        super(TwoFactorBaseTests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        self.controller = controllers.TwoFactorV3Controller()

        # TODO(garcianavalon) I've put this line for dependency injection to work, 
        # but I don't know if its the right way to do it...
        self.manager = core.TwoFactorAuthManager()


    def _create_two_factor_key(self, user_id, expected_status=None):
        data = self.new_ref()
        data['security_question'] = self.SAMPLE_SECURITY_QUESTION
        data['security_answer'] = self.SAMPLE_SECURITY_ANSWER

        return self.post(TWOFACTOR_URL.format(user_id=user_id), 
                         body = {'two_factor_auth': data},
                         expected_status=expected_status)

    def _delete_two_factor_key(self, user_id, expected_status=None):
        return self.delete(TWOFACTOR_URL.format(user_id=user_id),expected_status=expected_status)

    def _check_is_two_factor_enabled(self, user_id, expected_status=None):
        return self.head(TWOFACTOR_URL.format(user_id=user_id), expected_status=expected_status)

    def _check_security_question(self, user_id, sec_answer, expected_status=None):
        body = {
            'two_factor_auth': {
                'security_answer': sec_answer
            }
        }
        return self.get(TWOFACTOR_QUESTION_URL.format(user_id=user_id), 
                        expected_status=expected_status,
                        body=body)

    def _create_user(self):
        user = self.new_user_ref(domain_id=self.domain_id)
        password = user['password']
        user = self.identity_api.create_user(user)
        user['password'] = password
        return user

    def _delete_user(self, user_id):
        self.identity_api.delete_user(user_id)


class TwoFactorAuthTests(TwoFactorBaseTests):

    def test_two_factor_enable(self):
        self._create_two_factor_key(user_id=self.user_id)

    def test_two_factor_new_code(self):
        key1 = self._create_two_factor_key(user_id=self.user_id)
        key2 = self._create_two_factor_key(user_id=self.user_id)
        self.assertNotEqual(key1,key2)

    def test_two_factor_disable_after_enabling(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._delete_two_factor_key(user_id=self.user_id)

    def test_two_factor_disable_without_enabling(self):
        self._delete_two_factor_key(user_id=self.user_id, expected_status=404)

    def test_two_factor_is_enabled_after_creating(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._check_is_two_factor_enabled(user_id=self.user_id)

    def test_two_factor_is_disabled(self):
        self._check_is_two_factor_enabled(user_id=self.user_id, expected_status=404)

    def test_two_factor_is_enabled_after_deleting(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._check_is_two_factor_enabled(user_id=self.user_id)
        self._delete_two_factor_key(user_id=self.user_id)
        self._check_is_two_factor_enabled(user_id=self.user_id, expected_status=404)

    def test_two_factor_create_key_for_nonexistent_user(self):
        self._create_two_factor_key(user_id='nonexistent_user', expected_status=404)

    def test_two_factor_delete_user(self):
        user = self._create_user()
        self._create_two_factor_key(user_id=user['id'])
        self._check_is_two_factor_enabled(user_id=user['id'])
        self._delete_user(user_id=user['id'])
        self._check_is_two_factor_enabled(user_id=user['id'], expected_status=404)


class TwoFactorSecQuestionTests(TwoFactorBaseTests):

    def test_security_question_correct(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._check_security_question(user_id=self.user_id, 
                                      sec_answer=self.SAMPLE_SECURITY_ANSWER)

    def test_security_question_wrong(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._check_security_question(user_id=self.user_id,
                                      sec_answer='Wrong answer',
                                      expected_status=401)

    def test_security_question_nonexistent(self):
        self._check_security_question(user_id=self.user_id,
                                      sec_answer='Does not matter',
                                      expected_status=404)