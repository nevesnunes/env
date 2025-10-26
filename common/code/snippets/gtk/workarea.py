#!/usr/bin/env python3

from gi import require_version
require_version("Gdk", "3.0")

from gi.repository import Gdk
display = Gdk.Display.get_default()
monitor = display.get_primary_monitor()
wa = monitor.get_workarea()
print(wa.width, wa.height)
