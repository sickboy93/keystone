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

from keystone import exception
from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
from keystone.contrib.user_registration import core as user_registration
from keystone.i18n import _
from keystone.openstack.common import log

LOG = log.getLogger(__name__)

@dependency.requires('registration_api', 'identity_api', 'assignment_api') 
class UserRegistrationV3(controller.V3Controller):
    
    collection_name = 'users'
    member_name = 'user'

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""
        path = '/OS-REGISTRATION/' + cls.collection_name
        return super(UserRegistrationV3, cls).base_url(context, path=path)

    @controller.protected()
    def register_user(self, context, user):
        # TODO(garcianavalon) this method is to long, refactor it into smaller ones
        # Create a new user
        self._require_attribute(user, 'name')
        # The manager layer will generate the unique ID for users
        user_ref = self._normalize_dict(user)
        user_ref = self._normalize_domain_id(context, user_ref)
        # disabled by default
        user_ref['enabled'] = False

        # NOTE(garcianavalon) in order for the user to get project scoped tokens
        # we create a default project with his name, and add the user to the project
        project = {
            'name':user_ref['name'],
            'domain_id':user_ref['domain_id'],
            'enabled': False,
        }
        project_ref = self._assign_unique_id(self._normalize_dict(project))
        project_ref = self._normalize_domain_id(context, project_ref)
        project_ref = self.assignment_api.create_project(project_ref['id'], project_ref)

        # create the user finally
        user_ref['default_project_id'] = project_ref['id']
        user_ref = self.identity_api.create_user(user_ref)

        # get a default role and give it to the user in the project
        # NOTE(garcianavalon) this is written for the v3 Identity API, if v2
        # support is needed use add_user_to_project(tenant_id, user_id) which
        # automatically uses de default role defined in keystone.conf
        default_role = self.registration_api.get_default_role()
        self.assignment_api.create_grant(default_role['id'], 
                                        user_id=user_ref['id'],
                                        project_id=project_ref['id'])


        # Create an activation key 
        activation_profile = self.registration_api.register_user(user_ref)
        user_ref['activation_key'] = activation_profile['activation_key']
        return UserRegistrationV3.wrap_member(context, user_ref)

    @controller.protected()
    def activate_user(self, context, user_id, activation_key):
        # Check the activation key is valid
        activation_profile = self.registration_api.get_activation_profile(user_id,
                                                                    activation_key)
        if not activation_profile:
            raise exception.Forbidden()

        # Enable the user and the project
        project_ref = {
            'enabled': True,
        }
        project_ref = self.assignment_api.update_project(
                                        activation_profile['project_id'], 
                                        project_ref)

        user_ref = {
            'enabled': True,
        }
        user_ref = self.identity_api.update_user(user_id, user_ref)

        return UserRegistrationV3.wrap_member(context, user_ref)

    @controller.protected()
    def get_reset_token(self, context, user_id):
        # check if the user is enabled
        user_ref = self.identity_api.get_user(user_id)
        if not user_ref['enabled']:
            raise exception.Forbidden(message=_('The user is not activated.'))
        # create a new reset token
        reset_profile = self.registration_api.request_password_reset(user_id)
        return {
            'reset_token': {
                'id': reset_profile['reset_token']
            }
        }

    def reset_password(self, context, user_id, token_id, user):
        # check if the token is valid
        reset_profile = self.registration_api.get_reset_profile(user_id,
                                                                token_id)
        if not reset_profile:
            raise exception.Forbidden()

        # update only user password
        user_ref = {
            'password': user['password'],
        }
        user_ref = self.identity_api.update_user(user_id, user_ref)
        return UserRegistrationV3.wrap_member(context, user_ref)

    def new_activation_key(self, context, user_id):
        # check if the user is enabled
        user_ref = self.identity_api.get_user(user_id)
        if user_ref['enabled']:
            raise exception.ValidationError(
                    message=_('The user is already activated.'))
        # create a new activation key
        activation_profile = self.registration_api.new_activation_key(user_id)
        return {
            'activation_key': {
                'id': activation_profile['activation_key']
            }
        }