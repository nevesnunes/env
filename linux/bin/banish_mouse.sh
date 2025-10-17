#!/bin/sh

set -eu

python3 -c '
from gi import require_version
require_version("Gdk", "3.0")

from gi.repository import Gdk
display = Gdk.Display.get_default()
monitor = display.get_primary_monitor()
wa = monitor.get_workarea()
print(wa.width - 15, wa.height - 10)
' | xargs xdotool mousemove
