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

from __future__ import absolute_import

import sqlalchemy as sql

from keystone import exception
from keystone import notifications
from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone.openstack.common import log

LOG = log.getLogger(__name__)

EXTENSION_DATA = {
    'name': 'FIWARE KeyRock Initial Data',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-OAUTH2/v1.0',
    'alias': 'FI-INITIAL-DATA',
    'updated': '2015-11-25T12:00:0-00:00',
    'description': 'Provide a migration to populate Keystone with initial data',
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


def insert_data(meta, session, table_name, elements):
    table = sql.Table(table_name, meta, autoload=True)

    for data in elements:
        table.insert(data).execute()
        session.commit()

