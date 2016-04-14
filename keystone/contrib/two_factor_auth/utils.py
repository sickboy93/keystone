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

import passlib.hash

from keystone.common import config
from keystone import exception
from keystone.openstack.common import log
from keystone.i18n import _

LOG = log.getLogger(__name__)

def verify_length_and_trunc_security_answer(security_answer):
    """Verify and truncate the provided security_answer to the max_security_answer_length."""
    max_length = config.CONF.two_factor_auth.max_security_answer_length
    try:
        if len(security_answer) > max_length:
            if config.CONF.strict_security_answer_check:
                raise exception.TwoFactorSecurityAnswerVerificationError(size=max_length)
            else:
                LOG.warning(
                    _('Truncating user security_answer to '
                      '%d characters.'), max_length)
                return security_answer[:max_length]
        else:
            return security_answer
    except TypeError:
        raise exception.ValidationError(attribute='string', target='security_answer')

def hash_two_factor_security_answer(two_factor_auth):
    """Hash a two_factor_auth dict's security_answer without modifying the passed-in dict."""
    security_answer = two_factor_auth.get('security_answer')
    if security_answer is None:
        return two_factor_auth

    return dict(two_factor_auth, security_answer=hash_security_answer(security_answer))

def hash_security_answer(security_answer):
    """Hash a security_answer. Hard."""
    security_answer_utf8 = verify_length_and_trunc_security_answer(security_answer).encode('utf-8')
    return passlib.hash.sha512_crypt.encrypt(
        security_answer_utf8, rounds=config.CONF.crypt_strength)

def check_security_answer(security_answer, hashed):
    """Check that a plaintext security_answer matches hashed.

    hashpw returns the salt value concatenated with the actual hash value.
    It extracts the actual salt if this value is then passed as the salt.

    """
    if security_answer is None or hashed is None:
        return False
    security_answer_utf8 = verify_length_and_trunc_security_answer(security_answer).encode('utf-8')
    return passlib.hash.sha512_crypt.verify(security_answer_utf8, hashed)
