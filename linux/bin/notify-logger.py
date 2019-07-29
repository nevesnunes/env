from datetime import datetime
import os
from os.path import expanduser
from signal import *
import sys

import dbus
from dbus.mainloop.glib import DBusGMainLoop
import glib

def notifications(bus, message):
    arg_list = message.get_args_list(utf8_strings=True)

    # Check if notification has title and body
    if len(arg_list) > 4:
        dt_now = datetime.now().strftime('[Date] %Y/%m/%d, %H:%M:%S\n')
        title = str('%s\n' % arg_list[3])
        body = str('%s\n\n' % arg_list[4])

        # Write to the beginning
        with open(log_file, 'r+') as f:
            content = f.read()
            f.seek(0, 0)
            f.write(dt_now + title + body + content)

def clean(*args):
    os.remove(lock_file)
    sys.exit(0)

for sig in (SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGSEGV, SIGTERM):
    signal(sig, clean)

# Extract log filename
home = expanduser("~")
log_home = os.getenv('XDG_RUNTIME_DIR') or \
    os.path.join(home, 'tmp')
log_file = os.path.join(log_home, 'notify.log')

# Grab a lock
# FIXME: Avoid race conditions
lock_file = '%s.lock' % log_file
if os.path.exists(lock_file):
    print('[Error] Lock file is present. Exiting...')
    sys.exit(1)
else:
    with open(lock_file, 'a'):
        os.utime(lock_file, None)

# Create file if it doesn't exist
with open(log_file, 'a'):
    os.utime(log_file, None)

# Listen to notifications
DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
bus.add_match_string_non_blocking("eavesdrop=true, " + \
    "interface='org.freedesktop.Notifications', " + \
    "member='Notify'")
bus.add_message_filter(notifications)

mainloop = glib.MainLoop()
mainloop.run()
