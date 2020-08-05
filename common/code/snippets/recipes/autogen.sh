#!/bin/sh

# Given: `configure.ac`
# Run: aclocal
# Output: `aclocal.m4`

# Given: `aclocal.m4`, `configure.ac`
# Run: autoconf
# Output: `configure`

# Given: `aclocal.m4`, `configure.ac:AM_INIT_AUTOMAKE`, `configure.ac:AC_CONFIG_FILES([Makefile])`, `Makefile.am`
# Run: automake
# Output: `Makefile.in`

# Given: `configure`, `Makefile.in`
# Run: ./configure
# Output: `Makefile`

# References:
# https://thoughtbot.com/blog/the-magic-behind-configure-make-make-install
# https://www.gnu.org/software/automake/manual/html_node/

set -x
autopoint -f
set -e
# shellcheck disable=SC2086
aclocal $ACLOCAL_FLAGS
autoheader
autoconf
libtoolize --copy --automake \
  || glibtoolize --automake
automake --add-missing --copy --gnu
set +e
intltoolize --force --automake
