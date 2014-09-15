import requests
import json
BASE_HEADERS = {'X-Auth-Token':'ADMIN','content-type': 'application/json'}

KEYSTONE_URL_V3 = 'http://localhost:5000/v3/'
EXTENSION ='OS-OAUTH2/'

print "Testing %s API" %EXTENSION

endpoint = 'consumers'
url = KEYSTONE_URL_V3 + EXTENSION + endpoint
print "Testing endpoint: %s " %endpoint

#r = requests.get(url,headers=BASE_HEADERS)
#print 'Response to GET at %s: ' %endpoint, r.json()

CREATE_DATA = {
		"consumer":{
			"description" : "TEST CONSUMER",
			"client_type" : "confidential",
			"redirect_uris" : [
				"https://TEST.URI.com"
			],
			"grant_type" : "authorization_code",
	}
}
r = requests.post(url,headers=BASE_HEADERS,data=json.dumps(CREATE_DATA))
print 'Response to POST at %s: ' %endpoint, r.json()

UPDATE_DATA = {
		"consumer":{
			"description" : "TEST CONSUMER NEW DESCRIPTION",
			"redirect_uris" : [
				"https://TEST.URI.com"
			],
	}
}

created_consumer_id = r.json()['consumer']['id']
print "CREATED CONSUMER ID: %s" %created_consumer_id

url = KEYSTONE_URL_V3 + EXTENSION + endpoint
endpoint = 'consumers/%s' %created_consumer_id
print "Testing endpoint: %s " %endpoint

r = requests.get(url,headers=BASE_HEADERS)
print 'Response to GET at %s: ' %endpoint, r.json()

r = requests.patch(url,headers=BASE_HEADERS,data=json.dumps(UPDATE_DATA))
print 'Response to PATCH at %s: ' %endpoint, r.json()

#r = requests.delete(url,headers=BASE_HEADERS,data=json.dumps(data))
#print 'Response to DELETE at %s: ' %endpoint, r.json()
