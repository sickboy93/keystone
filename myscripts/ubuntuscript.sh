#!/bin/sh
set -x
PASSW=coritel

apt-get -y update

apt-get -y install gcc g++ python python-dev python-pip \
                   #libxml2-dev libxslt1-dev libsasl2-dev libssl-dev libldap2-dev libffi-dev libsqlite3-dev libmysqlclient-dev python-mysqldb git \
                   #libssl-dev libffi-dev libjpeg8-dev
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

#curl -i -X POST localhost:5000/v3/users -H "Content-type: application/json" -H "X-Auth-Token: $YOUR_TOKEN" \
#-d @- <<EOF
#{
    #"user": {
        #"default_project_id": "idm_project",
        #"domain_id": "default",
        #"enabled": true,
        #"name": "$YOUR_USER",
        #"password": "$YOUR_PASSW",
        #"description": "user",
        #"email": "$YOUR_USER@example.com"
    #}
#}
#EOF

#sqlite



#wget http://repo1.maven.org/maven2/org/ow2/authzforce/authzforce-ce-server-dist/8.0.1/authzforce-ce-server-dist-8.0.1.deb


