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
from keystone.common import dependency
from keystone.models import token_model

@dependency.requires('roles_api', 'token_provider_api')
class FiwareControllerV3(controller.V3Controller):

    collection_name = 'roles'
    member_name = 'role'

    @controller.protected()
    def validate_token(self, context, token_id):
        """ Return a list of the roles and permissions of the user associated 
        with this token.

            See https://github.com/ging/fi-ware-idm/wiki
        """
        print "DEBUG!!! Insde validate_token"
        import pdb; pdb.set_trace()
        token = token_model.KeystoneToken(
                            token_id=token_id,
                            token_data=self.token_provider_api.validate_token(
                                token_id))

        user_id = token.user_id
        # return the roles associated with this user
        ref = self.roles_api.list_roles_for_user(user_id)
        return FiwareControllerV3.wrap_collection(context, ref)