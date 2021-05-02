#!/usr/bin/env python2

# A small PoC of making a HTTP-backed file-like object. In this case it's
# used by the zipfile library, so you can basically list all the files in
# a ZIP archive that's placed on a server that supports partial downloads.
# You can also download just a single specific file from that archive.
# This might be useful for huge archives where you need only a couple of
# smaller files :)

# Consider this public domian, no magic is here.
# Initially written by gynvael.coldwind//vx (2013)


import zipfile
import os
import sys
import httplib
import urlparse

DEBUG=False

def HTTPGetFileSize(url):
  u = urlparse.urlsplit(url)
  conn = httplib.HTTPConnection(u.netloc)

  path = u.path
  if len(u.query) > 0:
    path += "?" + u.query

  conn.request("HEAD", path)
  res = conn.getresponse()

  if res.status != 200:
    print res
    return False

  data = res.getheader("Content-Length")
  conn.close()
  return int(data)

def HTTPGetPartialData(url, f, t):
  u = urlparse.urlsplit(url)
  conn = httplib.HTTPConnection(u.netloc)

  path = u.path
  if len(u.query) > 0:
    path += "?" + u.query

  conn.request("GET", path, "", {
    "Range": "bytes=%u-%u" % (f, t)
    })
  res = conn.getresponse()

  if res.status not in [200, 206]:
    print res.status, res.reason
    return False

  data = res.read()
  conn.close()

  return data

class MyFileWrapper:
  def __init__(self, url):
    self.url = url
    self.position = 0
    self.total_size = HTTPGetFileSize(url)

    if self.total_size == False:
      raise Exception("file not found or sth like that")
    pass

  def seek(self, offset, whence):

    if whence == 0:
      self.position = offset
    elif whence == 1:
      self.position += offset
    elif whence == 2:
      self.position = self.total_size + offset

    if DEBUG==True:
      print "seek: (%u) %u -> %u" % (whence, offset, self.position)
    pass

  def tell(self):
    if DEBUG==True:
      print "tell: -> %u" % self.position
    return self.position

  def read(self, amount=-1):

    if amount == -1:
      amount = self.total_size - self.position

    d = HTTPGetPartialData(self.url, self.position, self.position + amount - 1)
    self.position += len(d)

    if DEBUG==True:
      print "read: %u %u -> %u" % (self.position - len(d), amount, self.position)

    return d

# Let's start the code.
if len(sys.argv) not in [2, 3]:
  print "usage: zipdl.py <URL-to-zip> [<filename-to-extract>]"
  sys.exit(1)

f = MyFileWrapper(sys.argv[1])
z = zipfile.ZipFile(f, "r")

if len(sys.argv) == 2:
  z.printdir()
else:
  # Note, running this on Python 2.5 is shooting urself in the foot
  # since there are no anti-path-traversal measures in <2.6.
  z.extract(sys.argv[2])
