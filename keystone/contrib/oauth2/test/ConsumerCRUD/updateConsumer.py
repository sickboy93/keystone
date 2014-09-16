from base import *
import sys

endpoint = 'consumers/%s' %sys.argv[1]

url = KEYSTONE_URL_V3 + EXTENSION + endpoint

print "Testing endpoint: %s " %endpoint


UPDATE_DATA = {
		"consumer":{
			"description" : "TEST CONSUMER NEW DESCRIPTION",
			"redirect_uris" : [
				"https://TEST.URI.com"
			],
	}
}

r = requests.patch(url,headers=BASE_HEADERS,data=json.dumps(UPDATE_DATA))
print 'Response to PATCH at %s: ' %endpoint, r.json()