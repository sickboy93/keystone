# Copyright 2013 OpenStack Foundation
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

import base64
import copy
import json
import urllib
import urlparse
import uuid

from keystone import config
from keystone.contrib.oauth2 import core
from keystone.tests import test_v3

CONF = config.CONF

class OAuth2Tests(test_v3.RestfulTestCase):

    EXTENSION_NAME = 'oauth2'
    EXTENSION_TO_ADD = 'oauth2_extension'

    CONSUMER_URL = '/OS-OAUTH2/consumers'

    DEFAULT_REDIRECT_URIS = [
        'https://%s.com' %uuid.uuid4().hex,
        'https://%s.com' %uuid.uuid4().hex
    ]
    DEFAULT_SCOPES = [
        uuid.uuid4().hex,
        uuid.uuid4().hex,
        'all_info'
    ]

    def setUp(self):
        super(OAuth2Tests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        # TODO(garcianavalon) I've put this line for dependency injection to work, but I don't know if its the right way to do it...
        self.manager = core.Manager()

    def _create_consumer(self, description=None,
                         client_type='confidential',
                         redirect_uris=DEFAULT_REDIRECT_URIS,
                         grant_type='authorization_code',
                         scopes=DEFAULT_SCOPES):
        data = {
            'description': description,
            'client_type': client_type,
            'redirect_uris': redirect_uris,
            'grant_type': grant_type,
            'scopes': scopes
        }
        response = self.post(self.CONSUMER_URL, body={'consumer': data})

        return response.result['consumer'], data

    def _create_user_and_tenant(self):
        pass

class ConsumerCRUDTests(OAuth2Tests):

    def _consumer_assertions(self, consumer,data):
        self.assertEqual(consumer['description'], data['description'])
        self.assertIsNotNone(consumer['id'])
        self.assertIsNotNone(consumer['secret'])

        return consumer

    def _test_create_consumer(self,consumer_data=None):
        consumer,data = self._create_consumer(consumer_data)
        self._consumer_assertions(consumer,data)

    def test_create_consumer_no_data(self):
        self._test_create_consumer()

    def test_consumer_delete(self):
        consumer,data = self._create_consumer()
        consumer_id = consumer['id']
        response = self.delete(self.CONSUMER_URL + '/%s' % consumer_id)
        self.assertResponseStatus(response, 204)

    def test_consumer_get(self):
        consumer,data = self._create_consumer()
        consumer_id = consumer['id']
        response = self.get(self.CONSUMER_URL + '/%s' % consumer_id)
        self_url = ['http://localhost/v3', self.CONSUMER_URL,
                    '/', consumer_id]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['consumer']['links']['self'], self_url)
        self.assertEqual(response.result['consumer']['id'], consumer_id)

    def test_consumer_list(self):
        self._create_consumer()
        response = self.get(self.CONSUMER_URL)
        entities = response.result['consumers']
        self.assertIsNotNone(entities)
        self_url = ['http://localhost/v3', self.CONSUMER_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])

    def test_consumer_update(self):
        consumer,data = self._create_consumer()
        original_id = consumer['id']
        original_description = consumer['description'] or ''
        update_description = original_description + '_new'

        update_ref = {'description': update_description}
        update_response = self.patch(self.CONSUMER_URL + '/%s' % original_id,
                                 body={'consumer': update_ref})
        consumer = update_response.result['consumer']
        self.assertEqual(consumer['description'], update_description)
        self.assertEqual(consumer['id'], original_id)

    def test_consumer_update_bad_secret(self):
        consumer,data = self._create_consumer()
        original_id = consumer['id']
        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = uuid.uuid4().hex
        update_ref['secret'] = uuid.uuid4().hex
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_bad_id(self):
        consumer,data = self._create_consumer()
        original_id = consumer['id']
        original_description = consumer['description'] or ''
        update_description = original_description + "_new"

        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = update_description
        update_ref['id'] = update_description
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_get_bad_id(self):
        self.get(self.CONSUMER_URL + '/%(consumer_id)s'
                 % {'consumer_id': uuid.uuid4().hex},
                 expected_status=404)


class OAuth2FlowTests(OAuth2Tests):

    def setUp(self):
        super(OAuth2FlowTests, self).setUp()
        self.consumer, self.data = self._create_consumer()

    def _flowstep_request_authorization(self, redirect_uri, scope, expected_status=200):
        # NOTE(garcianavalon) we use a list of tuples to ensure param order
        # in the query string to be able to mock it during testing.
        credentials = [
            ('response_type', 'code'),
            ('client_id', self.consumer['id']),
            ('redirect_uri', redirect_uri),
            ('scope', scope),
            ('state', uuid.uuid4().hex)
        ]
        query= urllib.urlencode(credentials)
        authorization_url ='/OS-OAUTH2/authorize?%s' %query

        # GET authorization_url to request the authorization
        return self.get(authorization_url, 
                        expected_status=expected_status)


    def _flowstep_grant_authorization(self, redirect_uri=None, scope=None, 
                                    expected_status=302, **kwargs):
        if not scope:
            scope = self.DEFAULT_SCOPES[0]
        if not redirect_uri:
            redirect_uri = self.DEFAULT_REDIRECT_URIS[0]

        get_response = self._flowstep_request_authorization(
                                    redirect_uri=redirect_uri, 
                                    scope=scope)

        return self._simulate_authorization(get_response, 
                                scopes=[scope], 
                                expected_status=expected_status,
                                **kwargs)

    def _simulate_authorization(self, get_response, scopes, 
                                expected_status=302, **kwargs):
        # POST authorization url to simulate ResourceOwner granting authorization
        consumer_id = get_response.result['data']['consumer']['id']
        data = {
            "user_auth": {
                "client_id":consumer_id,
                "scopes":scopes
            }
        }
        return self.post('/OS-OAUTH2/authorize', 
                        body=data, 
                        expected_status=expected_status,
                        **kwargs)

    def _extract_header_query_string(self, response):
        redirect_uri = response.headers['Location']
        query_params = urlparse.parse_qs(urlparse.urlparse(redirect_uri).query)
        return query_params

    def _http_basic(self, consumer_id, consumer_secret):
        auth_string = consumer_id + ':' + consumer_secret
        return 'Basic ' + base64.b64encode(auth_string)

    def _generate_urlencoded_request(self, authorization_code, 
                                    consumer_id, consumer_secret):
        # NOTE(garcianavalon) No use for now, keystone only accepts JSON bodies
        body = 'grant_type=authorization_code&code=%s&redirect_uri=%s' %authorization_code, self.DEFAULT_REDIRECT_URIS[0]
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': self._http_basic(consumer_id, consumer_secret)
        }
        return headers, body

    def _generate_json_request(self, authorization_code, consumer_id, consumer_secret):
        body = {
            'token_request' : {
                'grant_type':'authorization_code',
                'code': authorization_code,
                'redirect_uri':self.DEFAULT_REDIRECT_URIS[0]
            }
        }    
        headers = {
            'Authorization': self._http_basic(consumer_id, consumer_secret)
        }
        return headers, body

    def _extract_authorization_code_from_header(self, response):
        query_params = self._extract_header_query_string(response)
        authorization_code = query_params['code'][0]
        return authorization_code

    def _flowstep_obtain_access_token(self, redirect_uri=None, scope=None):
        if not scope:
            scope = self.DEFAULT_SCOPES[0]
        if not redirect_uri:
            redirect_uri = self.DEFAULT_REDIRECT_URIS[0]

        response = self._flowstep_grant_authorization(
                                    redirect_uri=redirect_uri, 
                                    scope=scope)
        authorization_code = self._extract_authorization_code_from_header(response)

        consumer_id = self.consumer['id']
        consumer_secret = self.consumer['secret']

        headers, body = self._generate_json_request(authorization_code,
                                                   consumer_id, consumer_secret)
        #POST to the token url
        return self.post('/OS-OAUTH2/access_token', body=body,
                        headers=headers, expected_status=200)

    def _auth_body(self, access_token, project=None):
        body = {
            "auth": {
                "identity": {  
                    "methods": [
                        "oauth2"
                    ],
                    "oauth2": {
                        'access_token_id':access_token['access_token']
                    },
                }
            }
        }
        if project:
            body['auth']['scope'] = {
                "project": {
                    "id": project
                }
            }
        return body


class OAuth2AuthorizationCodeFlowTests(OAuth2FlowTests):


    def test_flowstep_request_authorization(self):
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0]
        expected_scope = self.DEFAULT_SCOPES[0]
        response = self._flowstep_request_authorization(
                                scope=expected_scope,
                                redirect_uri=expected_redirect_uri)

        self.assertIsNotNone(response.result['data'])

        data = response.result['data']
        self.assertIsNotNone(data['redirect_uri'])
        self.assertIsNotNone(data['requested_scopes'])
        self.assertIsNotNone(data['consumer'])
        self.assertIsNotNone(data['consumer']['id'])

        consumer_id = data['consumer']['id']
        self.assertEqual(consumer_id, self.consumer['id'])

        self.assertEqual(data['requested_scopes'], [expected_scope])

        self.assertEqual(data['redirect_uri'], expected_redirect_uri)

    def test_flowstep_grant_authorization(self):
        response = self._flowstep_grant_authorization()

        self.assertIsNotNone(response.headers['Location'])
    
        query_params = self._extract_header_query_string(response)

        self.assertIsNotNone(query_params['code'][0])
        self.assertIsNotNone(query_params['state'][0])

    def test_granting_authorization_by_different_user_fails(self):
        # make the grant authorization with a different
        # authenticated user
        # to check the code is only granted to the redirected user
        # the response should be a 404 Not Found because no
        # consumer has requested authorization for this user

        # create the other user
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assignment_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.assignment_api.create_project(project1['id'], project1)
        user_foo = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        password = user_foo['password']
        user_foo = self.identity_api.create_user(user_foo)
        user_foo['password'] = password

        # FIXME(garcianavalon) Im sure there is a better way to do this
        roles = self.assignment_api.list_roles()
        role_admin = next(r for r in roles if r['name'] == 'admin')

        self.assignment_api.create_grant(
            user_id=user_foo['id'],
            project_id=project1['id'],
            role_id=role_admin['id'])

        # Get a scoped token for the project
        auth_data = self.build_authentication_request(
            username=user_foo['name'],
            user_domain_id=test_v3.DEFAULT_DOMAIN_ID,
            password=user_foo['password'],
            project_name=project1['name'],
            project_domain_id=domain1['id'])

        response = self._flowstep_grant_authorization(expected_status=404, 
                                                        auth=auth_data)
        
    def test_second_request_overrides_previous_credentials(self):
        """ Simulate the use case where the user gets redirected a
        second time by the same client.
        """
        # First make two requests with different scopes
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0]
        expected_scope1 = self.DEFAULT_SCOPES[0]
        get_response1 = self._flowstep_request_authorization(
                                scope=expected_scope1,
                                redirect_uri=expected_redirect_uri)
        scopes1 = get_response1.result['data']['requested_scopes']
        self.assertEqual(scopes1, [expected_scope1])

        expected_scope2 = self.DEFAULT_SCOPES[1]
        get_response2 = self._flowstep_request_authorization(
                                scope=expected_scope2,
                                redirect_uri=expected_redirect_uri)
        scopes2 = get_response2.result['data']['requested_scopes']
        self.assertEqual(scopes2, [expected_scope2])

        self.assertNotEqual(scopes2, scopes1)

        # TODO(garcianavalon) without using states this test is stupid because
        # the scopes returned in the response object are directly the ones in the
        # request and they are not stored with the credentials. Therefore, when
        # the client grants authorization it doesn't matter wich scopes where
        # requested in the first place because they are not saved, permission is
        # granted directly to the scopes in the POST request.
        # Solutions possible: add support for states and/or store the requested
        # scopes too

        # Now try to grant authorization using the first credentials to verify
        # it's not valid anymore
        response1 = self._simulate_authorization(get_response1,
                                    scopes=scopes1, 
                                    expected_status=302)

        # Now grant authorization using the second credentials
        response2 = self._simulate_authorization(get_response2,
                                    scopes=scopes2, 
                                    expected_status=302)

class OAuth2AccessTokenFlowTests(OAuth2FlowTests):


    def test_flowstep_obtain_access_token(self):
        response = self._flowstep_obtain_access_token()
        # TODO(garcianavalon) test more stuff
        access_token = response.result

        self.assertIsNotNone(access_token['access_token'])
        self.assertIsNotNone(access_token['token_type'])
        self.assertIsNotNone(access_token['expires_in'])

        scope = response.result['scope']
        # TODO(garcianavalon) this is not working
        #self.assertEqual(scope, self.DEFAULT_SCOPES)

    def test_access_code_only_one_use(self):
        # TODO(garcianavalon) refractor this for better code reuse
        response = self._flowstep_grant_authorization()
        authorization_code = self._extract_authorization_code_from_header(response)

        consumer_id = self.consumer['id']
        consumer_secret = self.consumer['secret']

        headers,body = self._generate_json_request(authorization_code,
                                                   consumer_id, consumer_secret)
        # POST to the token url
        response1 = self.post('/OS-OAUTH2/access_token',body=body,
                        headers=headers, expected_status=200)
        # POST again to check its invalid
        response2 = self.post('/OS-OAUTH2/access_token',body=body,
                        headers=headers, expected_status=401)        


    def _exchange_access_token_assertions(self, response):
        token = json.loads(response.body)['token']
        #self.assertEqual(token['project']['id'],self.project_id)
        self.assertEqual(token['user']['id'], self.user_id)
        self.assertEqual(token['methods'], ["oauth2"])
        self.assertIsNotNone(token['expires_at'])

    def test_auth_with_access_token_no_scope(self):
        access_token = self._flowstep_obtain_access_token(scope='all_info').result
        body = self._auth_body(access_token)

        # POST to the auth url as an unauthenticated user to get a keystone token
        response = self.post('/auth/tokens', body=body, noauth=True)
        self._exchange_access_token_assertions(response)

    def test_auth_with_access_token_with_scope(self):
        access_token = self._flowstep_obtain_access_token(scope='all_info').result
        body = self._auth_body(access_token, project=self.project_id)
        
        # POST to the auth url as an unauthenticated user to get a keystone token
        response = self.post('/auth/tokens', body=body)
        self._exchange_access_token_assertions(response)