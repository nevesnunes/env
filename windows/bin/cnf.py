#!/usr/bin/python

EX_NOTFOUND = 127
SUDO_CMD = "sudo"
INSTALL_CMD = "zypper install"

def print_found(rows):
    print >> sys.stderr
print >> sys.stderr, ngettext("The program '%(prog)s' can be found in the following package:", "The program '%(prog)s'     can be found in following packages:", len(rows)) % \
        ({'prog' : term})
for row in rows:
    print >> sys.stderr, _("  * %(prog)s [ path: %(path)s/%(binary)s, repository: %(repo)s ]") % \
            ({'prog' : row[1], 'path' : row[2], 'binary' : row[3], 'repo' : row[0]})
print >> sys.stderr
print >> sys.stderr, _('Try installing with:\n   '),
if os.getuid() != 0:
    print >> sys.stderr, SUDO_CMD,
print >> sys.stderr, INSTALL_CMD,
if len( set( [ i[1] for i in rows] ) ) > 1:
    print >> sys.stderr, _('<selected_package>')
else:
    print >> sys.stderr, rows[0][1]
print >> sys.stderr
sys.exit(EX_NOTFOUND)

def print_installed(term, pkg, path):
    print >> sys.stderr
print >> sys.stderr, _("Program '%(prog)s' is present in package '%(pkg)s', which is installed on your system.") % ( {    'prog' : term, 'pkg' : pkg } )
print >> sys.stderr
if '/sbin' in path:
    print >> sys.stderr, _("Absolute path to '%(prog)s' is '%(path)s/%(prog)s', so running it may require superuser pr    ivileges (eg. root).") % \
            ( {'prog' : term , 'path' : path} )
else:
    print >> sys.stderr, _("Absolute path to '%(prog)s' is '%(path)s/%(prog)s'. Please check your $PATH variable to se    e whether it contains the mentioned path.") % \
            ( {'prog' : term , 'path' : path} )
print >> sys.stderr
sys.exit(EX_NOTFOUND)

def check_installed(term, pkg, path):
    if not os.path.isfile('%s/%s' % (path, term)):
        return False
ts = rpm.TransactionSet()
mi = ts.dbMatch('name', pkg)
return mi.count() > 0

def find_package_by_file(term):
    ts = rpm.TransactionSet()
mi = ts.dbMatch('basenames', term)
for i in mi:
    return i['name']
return None

try:
    import os
import sys

if len(sys.argv) < 2:
    sys.exit(EX_NOTFOUND)

import scout

default_lang = scout.DefaultLang(textdomain="command-not-found")
default_lang.install()

term = sys.argv[1]
print >> sys.stderr, '%s:' % term, _('searching ...'),
lendel = len(term) + 3 + len(_('searching ...'))

import rpm

for path in ['/usr/sbin', '/sbin']:
    pkg = find_package_by_file(path + '/' + term)
if pkg:
    print >> sys.stderr, '\r', lendel*' ',
print_installed(term, pkg, path)
sys.exit(EX_NOTFOUND)

sys.path.append(scout.Config.module_path)

import bin

if len(sys.argv) == 3:
    repo = sys.argv[2]
else:
    repo = 'zypp'

module = bin.ScoutModule()
if repo == 'zypp':
    rows = module.query_zypp(term)
else:
    rows = module.query_repo(repo, term)

if rows == None or len(rows) == 0:
    print >> sys.stderr, '\r', '%s:' % term, _('command not found'), lendel*' '
sys.exit(EX_NOTFOUND)

print >> sys.stderr, '\r', lendel*' ',

for row in rows:
    if check_installed(term, row[1], row[2]):
        print_installed(term, row[1], row[2])

print_found(rows)

except:
    pass

sys.exit(EX_NOTFOUND)
