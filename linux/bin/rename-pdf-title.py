#!/usr/bin/env python2.7

from pdfrw import PdfReader

import re
import sys

# Extract pdf title from pdf file
fullName = sys.argv[1]
newName = PdfReader(fullName).Info.Title
if newName is not None:
    # Remove surrounding brackets
    newName = newName.strip('()')
    newName = re.sub('[ \t]*$', '', newName)
    newName += '.pdf'
else:
    newName = ''
print(newName)
