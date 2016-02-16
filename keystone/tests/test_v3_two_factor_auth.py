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

import urllib

from keystone.tests import test_v3
from keystone.common import config as common_cfg

from keystone.contrib.two_factor_auth import controllers
from keystone.contrib.two_factor_auth import core

from keystone.openstack.common import log
from keystone import exception

import pyotp
import json

LOG = log.getLogger(__name__)

TWO_FACTOR_USER_URL = '/users/{user_id}'
TWO_FACTOR_BASE_URL = '/OS-TWO-FACTOR'
AUTH_ENDPOINT = '/two_factor_auth'
QUESTION_ENDPOINT = '/sec_question'
DATA_ENDPOINT = '/two_factor_data'
DEVICES_ENDPOINT = '/devices'

TWO_FACTOR_URL = TWO_FACTOR_USER_URL + TWO_FACTOR_BASE_URL + AUTH_ENDPOINT
TWO_FACTOR_QUESTION_URL = TWO_FACTOR_USER_URL + TWO_FACTOR_BASE_URL + QUESTION_ENDPOINT
TWO_FACTOR_DATA_URL = TWO_FACTOR_USER_URL + TWO_FACTOR_BASE_URL + DATA_ENDPOINT
TWO_FACTOR_DEVICES_URL = TWO_FACTOR_USER_URL + TWO_FACTOR_BASE_URL + DEVICES_ENDPOINT

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
        self.manager = core.TwoFactorAuthManager()


    def _create_two_factor_key(self, user_id, expected_status=None):
        data = self.new_ref()
        data['security_question'] = self.SAMPLE_SECURITY_QUESTION
        data['security_answer'] = self.SAMPLE_SECURITY_ANSWER

        return self.post(
            TWO_FACTOR_URL.format(user_id=user_id), 
            body={'two_factor_auth': data},
            expected_status=expected_status
        )

    def _create_two_factor_key_no_data(self, user_id, expected_status=None):
        return self.post(
            TWO_FACTOR_URL.format(user_id=user_id),
            expected_status=expected_status
        )

    def _delete_two_factor_key(self, user_id, expected_status=None):
        return self.delete(TWO_FACTOR_URL.format(user_id=user_id), expected_status=expected_status)

    def _check_is_two_factor_enabled(self, expected_status=None, **kwargs):
        return self.head(
            TWO_FACTOR_BASE_URL + AUTH_ENDPOINT + '?' +urllib.urlencode(kwargs), 
            expected_status=expected_status)

    def _check_security_question(self, user_id, sec_answer, expected_status=None):
        body = {
            'two_factor_auth': {
                'security_answer': sec_answer
            }
        }
        return self.get(TWO_FACTOR_QUESTION_URL.format(user_id=user_id), 
                        expected_status=expected_status,
                        body=body)

    def _get_two_factor_data(self, user_id, expected_status=None):
        return self.get(TWO_FACTOR_DATA_URL.format(user_id=user_id),
                        expected_status=expected_status)

    def _remember_device(self, user_id, expected_status=None, **kwargs):
        try:
            kwargs['user_id'] = user_id
            self.manager.is_two_factor_enabled(user_id=user_id)
        except exception.NotFound:
            self._create_two_factor_key(user_id=user_id)
        return json.loads(self.post(TWO_FACTOR_BASE_URL + DEVICES_ENDPOINT + '?' + urllib.urlencode(kwargs)).body)['two_factor_auth']

    def _check_for_device(self, expected_status=None, **kwargs):
        response = self.head(TWO_FACTOR_BASE_URL + DEVICES_ENDPOINT + '?' + urllib.urlencode(kwargs), expected_status=expected_status)

    def _delete_devices(self, user_id, expected_status=None):
        return self.delete(TWO_FACTOR_DEVICES_URL.format(user_id=user_id), expected_status=expected_status)


    def _create_user(self):
        user = self.new_user_ref(domain_id=self.domain_id)
        password = user['password']
        user = self.identity_api.create_user(user)
        user['password'] = password
        return user

    def _delete_user(self, user_id):
        self.delete(TWO_FACTOR_USER_URL.format(user_id=user_id))


class TwoFactorCRUDTests(TwoFactorBaseTests):

    def test_two_factor_enable(self):
        self._create_two_factor_key(user_id=self.user_id)

    def test_two_factor_new_code(self):
        key1 = self._create_two_factor_key(user_id=self.user_id)
        key2 = self._create_two_factor_key(user_id=self.user_id)
        self.assertNotEqual(key1, key2)

    def test_two_factor_new_code_no_data_right(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._create_two_factor_key_no_data(user_id=self.user_id)

    def test_two_factor_new_code_no_data_wrong(self):
        self._create_two_factor_key_no_data(user_id=self.user_id, expected_status=400)

    def test_two_factor_disable_after_enabling(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._delete_two_factor_key(user_id=self.user_id)

    def test_two_factor_disable_without_enabling(self):
        self._delete_two_factor_key(user_id=self.user_id, expected_status=404)

    def test_two_factor_is_enabled(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._check_is_two_factor_enabled(user_id=self.user_id)

    def test_two_factor_is_enabled_name_and_domain(self):
        self._create_two_factor_key(user_id=self.user_id)
        self._check_is_two_factor_enabled(
            user_name=self.user['name'],
            domain_id=self.user['domain_id'])

    def test_two_factor_is_disabled(self):
        self._check_is_two_factor_enabled(user_id=self.user_id, expected_status=404)

    def test_two_factor_is_disabled_name_and_domain(self):
        self._check_is_two_factor_enabled(
            user_name=self.user['name'],
            domain_id=self.user['domain_id'],
            expected_status=404)

    def test_two_factor_check_no_params(self):
        self._check_is_two_factor_enabled(expected_status=400)

    def test_two_factor_check_no_domain(self):
        self._check_is_two_factor_enabled(
            user_name=self.user['name'],
            expected_status=400)

    def test_two_factor_check_no_username(self):
        self._check_is_two_factor_enabled(
            domain_id=self.user['domain_id'],
            expected_status=400)

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
        self._delete_user(user['id'])
        self._check_is_two_factor_enabled(user_id=user['id'], expected_status=404)


class TwoFactorSecQuestionTests(TwoFactorBaseTests):

    def test_security_question_get(self):
        self._create_two_factor_key(user_id=self.user_id)
        data = self._get_two_factor_data(user_id=self.user_id)
        self.assertEqual(data.result['two_factor_auth']['security_question'],
                         self.SAMPLE_SECURITY_QUESTION)

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


class TwoFactorDevicesCRUDTests(TwoFactorBaseTests):

    def test_remember_device(self):
        self._remember_device(user_id=self.user_id)

    def test_remember_device_name_and_domain(self):
        self._remember_device(user_id=self.user_id,
                              user_name=self.user['name'],
                              domain_id=self.user['domain_id'])

    def test_device_right_data(self):
        data = self._remember_device(user_id=self.user_id)
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'])

    def test_device_right_data_name_and_domain(self):
        data = self._remember_device(user_id=self.user_id,
                                     user_name=self.user['name'],
                                     domain_id=self.user['domain_id'])
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'])

    def test_device_updates_token(self):
        data = self._remember_device(user_id=self.user_id)
        new_data = self._remember_device(user_id=self.user_id,
                                         device_id=data['device_id'],
                                         device_token=data['device_token'])
        
        self.assertEqual(new_data['device_id'], data['device_id'])
        self.assertEqual(new_data['user_id'], data['user_id'])
        self.assertNotEqual(new_data['device_token'], data['device_token'])

    def test_device_wrong_user(self):
        user = self._create_user()
        data = self._remember_device(user_id=self.user_id)
        self._check_for_device(user_id=user['id'],
                               device_id=data['device_id'],
                               device_token=data['device_token'],
                               expected_status=404)

    def test_device_wrong_device(self):
        data = self._remember_device(user_id=self.user_id)
        self._check_for_device(user_id=self.user_id,
                               device_id='just_another_device',
                               device_token=data['device_token'],
                               expected_status=404)

    def test_device_fake_token(self):
        data = self._remember_device(user_id=self.user_id)
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token='fake_token',
                               expected_status=404)

    def test_device_old_token(self):
        data = self._remember_device(user_id=self.user_id)
        self._remember_device(user_id=self.user_id,
                              device_id=data['device_id'],
                              device_token=data['device_token'])
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'],
                               expected_status=401)

    def test_device_delete_all(self):
        data = self._remember_device(user_id=self.user_id)
        self._delete_devices(user_id=self.user_id)
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'],
                               expected_status=404)

    def test_device_does_not_delete_all_devices_when_fake_token(self):
        data = self._remember_device(user_id=self.user_id)
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token='fake_token',
                               expected_status=404)
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'])

    def test_device_deletes_all_devices_when_old_token(self):
        data = self._remember_device(user_id=self.user_id)
        new_data = self._remember_device(user_id=self.user_id,
                                         device_id=data['device_id'],
                                         device_token=data['device_token'])
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'],
                               expected_status=401)
        self._check_for_device(user_id=self.user_id,
                               device_id=new_data['device_id'],
                               device_token=new_data['device_token'],
                               expected_status=404)

    def test_device_delete_user(self):
        user = self._create_user()
        data = self._remember_device(user_id=user['id'])
        self._delete_user(user['id'])
        self._check_for_device(user_id=user['id'],
                               device_id=data['device_id'],
                               device_token=data['device_token'],
                               expected_status=404)

    def test_device_disable_two_factor(self):
        data = self._remember_device(user_id=self.user_id)
        self._delete_two_factor_key(user_id=self.user_id)
        self._check_for_device(user_id=self.user_id,
                               device_id=data['device_id'],
                               device_token=data['device_token'],
                               expected_status=404)


class TwoFactorAuthTests(TwoFactorBaseTests):

    def auth_plugin_config_override(self, methods=None, **method_classes):
        if methods is None:
            methods = ['external', 'password', 'token', 'oauth1', 'saml2', 'oauth2']
            if not method_classes:
                method_classes = dict(
                    external='keystone.auth.plugins.external.DefaultDomain',
                    password='keystone.auth.plugins.two_factor.TwoFactor',
                    token='keystone.auth.plugins.token.Token',
                    oauth1='keystone.auth.plugins.oauth1.OAuth',
                    saml2='keystone.auth.plugins.saml2.Saml2',
                    oauth2='keystone.auth.plugins.oauth2.OAuth2',
                )
        self.config_fixture.config(group='auth', methods=methods)
        common_cfg.setup_authentication()
        if method_classes:
            self.config_fixture.config(group='auth', **method_classes)

    def _auth_body(self, **kwargs):
        body = {
            "auth": {
                "identity": {  
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                        }
                    },
                }
            }
        }

        payload = body['auth']['identity']['password']

        if 'user_id' in kwargs:
            payload['user']['id'] = kwargs['user_id']
        if 'password' in kwargs:
            payload['user']['password'] = kwargs['password']
        if 'user_name' in kwargs:
            payload['user']['name'] = kwargs['user_name']
        if 'domain_id' in kwargs:
            payload['user']['domain'] = {}
            payload['user']['domain']['id'] = kwargs['domain_id']
        if 'verification_code' in kwargs:
            payload['user']['verification_code'] = kwargs['verification_code']
        if 'device_data' in kwargs:
            payload['user']['device_data'] = kwargs['device_data']

        return body

    def _authenticate(self, auth_body, expected_status=201):
        return self.post('/auth/tokens', body=auth_body, expected_status=expected_status, noauth=True)

    def _get_current_code(self, user_id):
        two_factor_info = self.manager.get_two_factor_info(user_id)

        totp = pyotp.TOTP(two_factor_info.two_factor_key)
        return totp.now()

    def test_auth_correct(self):
        self._create_two_factor_key(user_id=self.user_id)

        req = self._auth_body(user_id=self.user_id,
                              password=self.user['password'],
                              verification_code=self._get_current_code(self.user_id))
        self._authenticate(auth_body=req)

    def test_auth_correct_two_factor_disabled(self):
        req = self._auth_body(
            user_id=self.user_id, 
            password=self.user['password'])
        self._authenticate(auth_body=req)

    def test_auth_correct_name_and_domain(self):
        self._create_two_factor_key(user_id=self.user_id)
        req = self._auth_body(
            user_name=self.user['name'],
            domain_id=self.user['domain_id'],
            verification_code=self._get_current_code(self.user_id),
            password=self.user['password'])
        self._authenticate(auth_body=req)

    def test_auth_correct_two_factor_disabled_name_and_domain(self):
        req = self._auth_body(
            user_name=self.user['name'],
            domain_id=self.user['domain_id'],
            password=self.user['password'])
        self._authenticate(auth_body=req)

    def test_auth_no_code(self):
        self._create_two_factor_key(user_id=self.user_id)
        req = self._auth_body(
            user_id=self.user_id, 
            password=self.user['password'])
        self._authenticate(auth_body=req, expected_status=400)

    def test_auth_wrong_code(self):
        self._create_two_factor_key(user_id=self.user_id)
        req = self._auth_body(
            user_id=self.user_id, 
            verification_code='123456', 
            password=self.user['password'])
        self._authenticate(auth_body=req, expected_status=401)

    def test_auth_right_device_data(self):
        self._create_two_factor_key(user_id=self.user_id)
        data = self.manager.remember_device(user_id=self.user_id)
        req = self._auth_body(
            user_id=self.user_id, 
            device_data=data,
            password=self.user['password'])
        self._authenticate(auth_body=req)