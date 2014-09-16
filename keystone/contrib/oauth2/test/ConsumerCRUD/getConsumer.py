from base import *
import sys

endpoint = 'consumers/%s' %sys.argv[1]

url = KEYSTONE_URL_V3 + EXTENSION + endpoint

print "Testing endpoint: %s " %endpoint

r = requests.get(url,headers=BASE_HEADERS)
print 'Response to GET at %s: ' %endpoint, r.json()