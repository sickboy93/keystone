#This script simulates a Client asking a Resource Owner for authorization.
#The expect resoult is the provider storing the Client credentials until
#the Resource Owner gives the authorization, which will return an authorization
#code.

from base import *
from  requests_oauthlib import OAuth2Session

#This info is obtanined after registration on the Authorization Server
client_id = r'e3196e4458a04372a7571dd536022c3c'
client_secret = r'a6cc837004fa457598169a239fe127e0'
redirect_uri = 'https://TEST.URI.com'

# This scopes are specific to the Authorization Server
scope = ['']
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri,
                          scope=scope)
url = KEYSTONE_URL_V3 + EXTENSION + 'authorize'
authorization_url, state = oauth.authorization_url(url)




