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
            # TODO: needs a description
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
            'keystone.contrib.oauth2.backends.sql.OAuth2')#TODO set as configuration option in keystone.conf


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

    @abc.abstractmethod
    def create_consumer(self,consumer):
        """Register a consumer

        :param consumer: consumer data
        :type consumer: dict
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer(self,consumer_id):
        """Get consumer details, except the private ones
        like secret
        
        :param consumer_id: id of consumer
        :type consumer_id: string
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_consumer(self,consumer_id,consumer):
        """Update consumer details
        
        :param consumer_id: id of consumer to update
        :type consumer_id: string
        :param consumer: new consumer data
        :type consumer: dict
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_consumer(self,consumer_id):
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
    def get_consumer_credentials(self, client_id):
        """Retrieves the consumer credentials saved when the authorization request

        :param client_id: client_id
        :type client_id: string
        :returns: The stored credentials

        """
        # TODO(garcianavalon) we need more info to get the credentials, or define constrains like
        # only allowing one pending authorization request from each consumer so consumer_id
        # could be use as a PK and/or a unique value
        raise exception.NotImplemented()

    # ACCESS TOKEN
    @abc.abstractmethod
    def get_access_token(self, access_token_id):
        """Get an access_token. Should never be exposed by the Identity API.

        :param access_token_id: the access_token_id (the string itself)
        :type access_token_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def store_access_token(self, access_token):
        """Stores an access_token. Should never be exposed by the Identity API.

        :param access_token: All the requiered info
        :type access_token: dict
        :returns: Nothing

        """
        raise exception.NotImplemented()