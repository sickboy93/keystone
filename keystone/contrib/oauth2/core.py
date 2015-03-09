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

from __future__ import absolute_import

import six
import abc

from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone import exception
from keystone.openstack.common import log


LOG = log.getLogger(__name__)

EXTENSION_DATA = {
    'name': 'OpenStack OAUTH2 API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-OAUTH2/v1.0',
    'alias': 'OS-OAUTH2',
    'updated': '2014-09-11T12:00:0-00:00',
    'description': 'Openstack OAuth2.0 Auth Mechanism',
    'links': [
        {
            'rel': 'describedby',
            # TODO(garcianavalon): needs a description
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)

@dependency.provider('oauth2_api')
class Manager(manager.Manager):
    """Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(
            'keystone.contrib.oauth2.backends.sql.OAuth2')# TODO(garcianavalon) set as configuration option in keystone.conf

    # TODO(garcianavalon) revoke tokens on consumer delete
    # TODO(garcianavalon) revoke Identity tokens issued by an access token on token revokation
    
@dependency.requires('identity_api')
@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for OAuth2 drivers"""

    # CONSUMERS
    @abc.abstractmethod
    def list_consumers(self):
        """List all registered consumers

        :returns: List of registered consumers

        """
        raise exception.NotImplemented()  

    # NOTE(garcianavalon) removed because owner field is removed
    # @abc.abstractmethod
    # def list_consumers_for_user(self, user_id):
    #     """List all registered consumers owned by the user
        
    #     :param user_id: user id
    #     :type user_id: string
    #     :returns: List of consumers

    #     """
    #     raise exception.NotImplemented()  

    @abc.abstractmethod
    def create_consumer(self, consumer):
        """Register a consumer

        :param consumer: consumer data
        :type consumer: dict
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer(self, consumer_id):
        """Get consumer details, except the private ones
        like secret
        
        :param consumer_id: id of consumer
        :type consumer_id: string
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_consumer(self, consumer_id, consumer):
        """Update consumer details
        
        :param consumer_id: id of consumer to update
        :type consumer_id: string
        :param consumer: new consumer data
        :type consumer: dict
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_consumer(self, consumer_id):
        """Delete consumer.

        :param consumer_id: id of consumer to delete
        :type consumer_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    # AUTHORIZATION CODES
    @abc.abstractmethod
    def list_authorization_codes(self, user_id):
        """List authorization codes.

        :param user_id: search for authorization codes authorized by given user id
        :type user_id: string
        :returns: list of authorization codes the user has authorized

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_authorization_code(self, code):
        """Get an authorization_code. Should never be exposed by the APi, its called from the oauth2 flow through the validator

        :param code: the code
        :type code: string
        :returns: authorization_code as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def store_authorization_code(self, authorization_code):
        """Stores an authorization_code. This should never be exposed by the API, its called from the oauth2 flow through the validator

        :param authorization_code: All the requiered info
        :type authorization_code: dict
        :returns: Nothing

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def invalidate_authorization_code(self, code):
        """Invalidate an authorization_code. 
        This method is called from the oauth2 flow through the validator but
        is safe to expose it in the REST API if the use case is needed.

        :param code: the code
        :type code: string
        :returns: Nothing

        """
        raise exception.NotImplemented()

    # CONSUMER CREDENTIALS
    @abc.abstractmethod
    def store_consumer_credentials(self, credentials):
        """Saves the consumer credentials until the user gives authorization to it

        :param credentials: Contains all the requiered credentials from the client
        :type credentials: dict
        :returns: The stored credentials

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer_credentials(self, client_id, user_id):
        """Retrieves the consumer credentials saved when the authorization request

        :param client_id: client_id
        :type client_id: string
        :param user_id: the id of the keystone user that stored the client credentials
            in the request_authorization step
        :type user_id: string
        :returns: The stored credentials

        """
        raise exception.NotImplemented()

    # ACCESS TOKEN
    @abc.abstractmethod
    def list_access_tokens(self, user_id=None):
        """Lists all the access tokens granted by a user.

        :param user_id: optional filter to check the token belongs to a user
        :type user_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_access_token(self, access_token_id, user_id=None):
        """Get an already existent access_token. If exposed by the Identity API, use
        the user_id check.

        :param access_token_id: the access_token_id (the string itself)
        :type access_token_id: string
        :param user_id: optional filter to check the token belongs to a user
        :type user_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    
    @abc.abstractmethod
    def revoke_access_token(self, access_token_id, user_id=None):
        """Invalidate an access token.

        :param access_token_id: the access_token_id (the string itself)
        :type access_token_id: string
        :param user_id: optional filter to check the token belongs to a user
        :type user_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def store_access_token(self, access_token):
        """Stores an access_token created by the validator. Should never be exposed 
        by the Identity API.

        :param access_token: All the requiered info
        :type access_token: dict
        :returns: Nothing

        """
        raise exception.NotImplemented()