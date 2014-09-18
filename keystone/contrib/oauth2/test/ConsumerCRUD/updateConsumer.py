from base import *

endpoint = 'consumers/%s' %sys.argv[1]

url = KEYSTONE_URL_V3 + EXTENSION + endpoint

print "Testing endpoint: %s " %endpoint


UPDATE_DATA = {
		"consumer":{
			"description" : sys.argv[2],
			"redirect_uris" : [
				sys.argv[3]
			],
			"scopes":sys.argv[4]
	}
}

r = requests.patch(url,headers=BASE_HEADERS,data=json.dumps(UPDATE_DATA))
print 'Response to PATCH at %s: ' %endpoint, r.json()