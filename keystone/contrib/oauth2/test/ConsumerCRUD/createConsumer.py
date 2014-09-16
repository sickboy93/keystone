
from base import *

endpoint = 'consumers'
url = KEYSTONE_URL_V3 + EXTENSION + endpoint
print "Testing endpoint: %s " %endpoint

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

created_consumer_id = r.json()['consumer']['id']
print "CREATED CONSUMER ID: %s" %created_consumer_id