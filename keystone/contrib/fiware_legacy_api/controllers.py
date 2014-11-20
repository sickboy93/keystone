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

from keystone.common import controller
from keystone.openstack.common import log
from keystone.common import wsgi

LOG = log.getLogger(__name__)

class FiwareControllerV3(controller.V3Controller):

    def validate_token(self, context, token_id):
        """ Redirect to the roles extension."""
        message = ("Recieved request to the legacy endpoint access-token/{token_id}\
            for token_id=%(token_id)s. Redirecting to the new endpoint.")
        LOG.info(message, {'token_id': token_id})
        body = ''
        headers = [
            ('Location', '/v3/access-tokens/%s' %token_id)
        ]
        response = wsgi.render_response(body,
                                        status=(301, 'Moved Permanently'),
                                        headers=headers)
        return response