from base import *

endpoint = 'consumers/%s' %sys.argv[1]

url = KEYSTONE_URL_V3 + EXTENSION + endpoint

print "Testing endpoint: %s " %endpoint


r = requests.delete(url,headers=BASE_HEADERS)
#TODO no json response, fix this print
print 'Response to DELETE at %s: ' %endpoint, r.json()