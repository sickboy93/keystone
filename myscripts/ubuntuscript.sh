#!/bin/sh
set -x
PASSW=coritel
YOUR_TOKEN=ADMIN
YOUR_USER=sandro
YOUR_PASSW=sandro

apt-get -y update && apt-get -y upgrade

apt-get -y install gcc g++ python python-dev python-pip \
                   libxml2-dev libxslt1-dev libsasl2-dev libssl-dev libldap2-dev libffi-dev libsqlite3-dev libmysqlclient-dev python-mysqldb git \
                   libssl-dev libffi-dev libjpeg8-dev sqlite3
sudo pip install --upgrade virtualenv

cd /home/ubuntu
git clone https://github.com/sickboy93/keystone
cd keystone

python tools/install_venv.py

cp etc/keystone.conf.sample etc/keystone.conf
sed -i "s|#admin_token|admin_token|g" ~/keystone/etc/keystone.conf
sed -i "s|#public_port|public_port|g" ~/keystone/etc/keystone.conf
sed -i "s|#admin_port|admin_port|g" ~/keystone/etc/keystone.conf

tools/with_venv.sh bin/keystone-manage -v db_sync

tools/with_venv.sh bin/keystone-manage -v db_sync --extension=oauth2

tools/with_venv.sh bin/keystone-manage -v db_sync --extension=roles

tools/with_venv.sh bin/keystone-manage -v db_sync --extension=user_registration

tools/with_venv.sh bin/keystone-manage -v db_sync --extension=two_factor_auth

tools/with_venv.sh bin/keystone-manage -v db_sync --extension=endpoint_filter

printf 'coritel' | tools/with_venv.sh bin/keystone-manage -v db_sync --populate

install -m755 myscripts/keystone-idm.service /lib/systemd/system/keystone-idm.service
install -m755 myscripts/keystone-idm /usr/bin/keystone-idm
systemctl daemon-reload
systemctl enable keystone-idm
systemctl start keystone-idm

#cd /home/ubuntu
#git clone https://github.com/ging/horizon && cd horizon
#virtualenv .venv
#. .venv/bin/activate
#sudo -H .venv/bin/pip install six==1.9.0
#deactivate
#sudo -H python tools/install_venv.py

#curl -sL https://deb.nodesource.com/setup_4.x | sudo -E bash -
#sudo apt-get install -y nodejs sqlite3

#cd fiware-pep-proxy/
#npm install

curl -i -X POST localhost:5000/v3/users -H "Content-type: application/json" -H "X-Auth-Token: $YOUR_TOKEN" \
-d @- <<EOF
{
    "user": {
        "default_project_id": "idm_project",
        "domain_id": "default",
        "enabled": true,
        "name": "$YOUR_USER",
        "password": "$YOUR_PASSW",
        "description": "user",
        "email": "$YOUR_USER@example.com"
    }
}
EOF

ADMIN_ID=$(sqlite3 keystone.db "select(id) from role where name='admin'")
sqlite3 keystone.db "insert into role (id, name, extra) values ('pep_proxy', 'pep_proxy', '{"is_default": "true"}');"

sqlite3 keystone.db "insert into assignment (type, actor_id, target_id, role_id, inherited) values ('GroupDomain', '$YOUR_USER', 'default', 'pep_proxy', 0);"
sqlite3 keystone.db "insert into assignment (type, actor_id, target_id, role_id, inherited) values ('GroupDomain', '$YOUR_USER', 'default', '$ADMIN_ID', 0);"

curl -i -X POST http://localhost:5000/v3/auth/tokens -H "Content-Type: application/json" -H "X-Auth-Token: $YOUR_TOKEN" \
-d @- <<EOF
{
    "auth": {
        "identity": {
            "methods": [
                "password"
            ],
            "password": {
                "user": {
                    "id": "$YOUR_USER",
                    "password": "$YOUR_PASSW"
                }
            }
        },
        "scope": {
            "project": {
                "id": "idm_project"
            }
        }
    }
}
EOF

cd /home/ubuntu
curl -sL https://deb.nodesource.com/setup_4.x | sudo -E bash -
sudo apt-get install -y nodejs

cd fiware-pep-proxy/
npm install

