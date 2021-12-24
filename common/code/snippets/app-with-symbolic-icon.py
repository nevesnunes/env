#!/usr/bin/env python3

# References:
# - [System tray does not respect dark theme for symbolic icons\. \(\#824\) · Issues · o9000 / tint2 · GitLab](https://gitlab.com/o9000/tint2/-/issues/824)

import signal
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')
from gi.repository import Gtk
from gi.repository import AppIndicator3

def main():
    ICON = 'microphone-sensitivity-high-symbolic'
    indicator = AppIndicator3.Indicator.new(
        "test", ICON, AppIndicator3.IndicatorCategory.APPLICATION_STATUS)
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
    Gtk.main()

if __name__ == '__main__':
    main()
