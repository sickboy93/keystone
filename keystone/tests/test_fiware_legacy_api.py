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

from keystone import config
from keystone import tests
from keystone.contrib.roles import core
from keystone.tests import test_v3

CONF = config.CONF

def generate_paste_config(extensions_name):
    """ Override to allow multiple extensions in one test."""
    # Generate a file, based on keystone-paste.ini, that is named:
    # extension_name.ini, and includes extension_name in the pipeline
    with open(tests.dirs.etc('keystone-paste.ini'), 'r') as f:
        contents = f.read()

    new_contents = contents.replace(' service_v3',
                                    ' %s service_v3' %' '.join(extensions_name))

    new_paste_file = tests.dirs.tmp('fiware_legacy_api_tests.ini')
    with open(new_paste_file, 'w') as f:
        f.write(new_contents)

    return new_paste_file

class RolesBaseTests(test_v3.RestfulTestCase):

    EXTENSIONS_NAME = ['fiware_legacy_api', 'roles']
    EXTENSIONS_TO_ADD = ['fiware_legacy_api_extension', 'roles_extension']

    ROLES_URL = '/OS-ROLES/roles'

    def get_extensions(self):
        """ Override to allow multiple extensions in one test."""
        extensions = set(['revoke'])
        extensions.update(self.EXTENSIONS_NAME)
        return extensions

    def generate_paste_config(self):
        """ Override to allow multiple extensions in one test."""
        new_paste_file = None
        try:
            new_paste_file = tests.generate_paste_config(self.EXTENSIONS_TO_ADD)
        except AttributeError:
            # no need to report this error here, as most tests will not have
            # EXTENSION_TO_ADD defined.
            pass
        finally:
            return new_paste_file

    def setUp(self):
        super(RolesBaseTests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v2.0'
        self.roles_manager = core.RolesManager()

    def _create_role(self, name, is_editable=True):
        data = {
            'name': name,   
        }
        if not is_editable:
            data['is_editable'] = False

        response = self.post(self.ROLES_URL, body={'role': data})

        return response.result['role']


    def _create_user(self):
        user_ref = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        user = self.identity_api.create_user(user_ref)
        user['password'] = user_ref['password']
        return user

    def _add_user_to_role(self, role_id, user_id, expected_status=204):
        
        ulr_args = {
            'role_id':role_id,
            'user_id':user_id
        }   
        url = self.ROLES_URL + '/%(role_id)s/users/%(user_id)s' \
                                %ulr_args
        return self.put(url, expected_status=expected_status)


    def _assert_role(self, role, expected_name, expected_is_editable):
        self.assertIsNotNone(role)
        self.assertIsNotNone(role['id'])
        self.assertEqual(expected_name, role['name'])
        self.assertEqual(expected_is_editable, role['is_editable'])


    def test_validate_token_unscoped(self):
        # create user
        user = self._create_user()

        # assign some roles
        number_of_roles = 2
        roles = []
        for i in range(number_of_roles):
            roles.append(self._create_role(uuid.uuid4().hex))
            self._add_user_to_role(role_id=roles[i]['id'], 
                                    user_id=user['id'])

        # get a token for the user
        auth_data = self.build_authentication_request(
            username=user['name'],
            user_domain_id=test_v3.DEFAULT_DOMAIN_ID,
            password=user['password'])
        auth_response = self.post('/auth/tokens', body=auth_data)
        token_id = auth_response.headers.get('X-Subject-Token')

        # acces the resource
        url = '/access-tokens/%s' %token_id
        #import pdb; pdb.set_trace()
        response = self.get(url)

        # check stuff
        entities = response.result['roles']
        self.assertIsNotNone(entities)

        self.assertEqual(number_of_roles, len(entities))

        

        

        

        ulr_args = {
            'user_id':user['id']
        }   
        url = self.USERS_URL + '/%(user_id)s/roles/' \
                                %ulr_args

        response = self.get(url)
        entities = response.result['roles']

        self.assertIsNotNone(entities)

        self.assertEqual(1, len(entities))


