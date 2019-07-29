#!/bin/bash

# Option 1
./autogen.sh
./configure

# Option 2
mkdir -p build-aux
touch build-aux/config.rpath
libtoolize
aclocal
autoconf
# ||
# autoreconf --verbose --install --force
automake --force-missing --add-missing --foreign
./configure

# Option 1 manual
autopoint -f
aclocal $ACLOCAL_FLAGS -I m4
autoheader
autoconf
(libtoolize --copy --automake || glibtoolize --automake)
automake --add-missing --copy --gnu
intltoolize --force --automake
