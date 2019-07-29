import sys
import base64

filename = sys.argv[1]
with open(filename, 'r') as myfile:
    print(base64.b64decode(myfile.read()))
