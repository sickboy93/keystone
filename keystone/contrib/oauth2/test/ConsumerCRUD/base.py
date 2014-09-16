import requests
import json
BASE_HEADERS = {'X-Auth-Token':'ADMIN','content-type': 'application/json'}

KEYSTONE_URL_V3 = 'http://localhost:5000/v3/'
EXTENSION ='OS-OAUTH2/'