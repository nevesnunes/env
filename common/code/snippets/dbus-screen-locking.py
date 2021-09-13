#!/usr/bin/env python3

import dbus
from dbus.mainloop.glib import DBusGMainLoop
import gobject
import os

# Hosts which should be locked/unlocked
hosts = ['starks', 'mmior-laptop']
# Set to True to turn on displays of other
# hosts after unlocking
wake = False

def toggle_lock(x):
  if x == 0:
    for host in hosts:
      os.system('ssh ' + host + ' export DISPLAY=:0; gnome-screensaver-command -d')
      if wake:
        os.system('ssh ' + host + ' export DISPLAY=:0; xset dpms force on; gnome-screensaver-command -d')
  if x == 1:
    os.system('xset s activate')
    for host in hosts:
      os.system('ssh ' + host + ' export DISPLAY=:0; xset dpms force off; gnome-screensaver-command -l')

DBusGMainLoop(set_as_default=True)

# Connect to the session bus and
# install our signal handler
bus = dbus.SessionBus()
bus.add_signal_receiver(toggle_lock,
  'ActiveChanged',
  'org.gnome.ScreenSaver',
  path='/org/gnome/ScreenSaver')

# Start the loop and wait for the signal
gobject.MainLoop().run()

# Clean up by removing the signal handler
bus.remove_signal_receiver(toggle_lock,
  'ActiveChanged',
  'org.gnome.ScreenSaver',
  path='/org/gnome/ScreenSaver')
