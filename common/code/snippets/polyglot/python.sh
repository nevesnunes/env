#!/bin/sh
# -*- mode: python; coding: utf-8 -*-

# This file is used as both a shell script and as a Python script.

""":"
# This part is run by the shell.  It looks for an appropriate Python
# interpreter then uses it to re-exec this script.

if test -x /usr/bin/python2.6
then
  PYTHON=/usr/bin/python2.6
elif test -x /usr/bin/python2.5
then
  PYTHON=/usr/bin/python2.5
else
  echo 1>&2 "No usable Python interpreter was found!"
  exit 1
fi

exec $PYTHON "$0" "$@"
" """

# The rest of the file is run by the Python interpreter.
__doc__ = """This string is treated as the module docstring."""

print "Hello world!"
