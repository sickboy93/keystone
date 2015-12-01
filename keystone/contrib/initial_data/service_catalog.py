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

from keystone import config

CONF = config.CONF

KEYSTONE_PUBLIC_ADDRESS = '127.0.0.1'
KEYSTONE_ADMIN_ADDRESS = '127.0.0.1'
KEYSTONE_INTERNAL_ADDRESS = '127.0.0.1'

REGIONS = [
  'Spain2', 
]

SERVICE_CATALOG = [
  {
    'endpoints': [
      {
        'region': REGIONS[0],
        'adminURL': 'http://{url}:{port}/v3/'.format(
          url=KEYSTONE_ADMIN_ADDRESS,
          port=CONF.admin_port),
        'internalURL': 'http://{url}:{port}/v3/'.format(
          url=KEYSTONE_INTERNAL_ADDRESS,
          port=CONF.admin_port),
        'publicURL': 'http://{url}:{port}/v3/'.format(
          url=KEYSTONE_PUBLIC_ADDRESS,
          port=CONF.public_port)
      }
    ],
    'type': 'identity',
    'name': 'keystone'
  }
]