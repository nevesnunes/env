# Customize to fit your system

# paths
PREFIX      = /usr/local/plan9
MANPREFIX   = ${PREFIX}/share/man

VERSION     = 7
OBJTYPE     = 386
#OBJTYPE     = arm
#OBJTYPE     = x86_64
#OBJTYPE     = sun4u

# Linux/BSD
#CFLAGS      += -Wall -Wno-missing-braces -Wno-parentheses -Wno-switch -c -I. -DPREFIX="\"${PREFIX}\""
CFLAGS      += -c -I. -DPLAN9PORT -DPREFIX="\"${PREFIX}\""
LDFLAGS     += -static

# Solaris
#CFLAGS      = -fast -xtarget=ultra -D__sun__ -c -I. -DPREFIX="\"${PREFIX}\""
#LDFLAGS     = -dn

# compiler
AR          = ar rc
CC          = cc
YACC        = ../yacc/9yacc
