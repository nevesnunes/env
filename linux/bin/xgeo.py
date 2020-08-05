#!/usr/bin/env python3

import gi

# References:
# - https://developer.gnome.org/gdk3/stable/
# - https://developer.gnome.org/libwnck/stable/
# TODO:
# - Rewrite in more performant languages:
#    - https://docs.rs/wnck-sys/0.1.0/wnck_sys/index.html
#    - https://stackoverflow.com/questions/26834145/memory-leak-in-libwnck


def xgeo_wnck():
    gi.require_version('Wnck', '3.0')
    from gi.repository import Wnck
    screen = Wnck.Screen.get_default()
    screen.force_update()

    #for window in screen.get_windows():
    #    if window.is_active():
    #        print(window.get_geometry())
    #        window_name = window.get_name()
    #        print(window_name)

    screen = None
    Wnck.shutdown()


def xgeo_gdk():
    gi.require_version('Gdk', '3.0')
    from gi.repository import Gdk
    screen = Gdk.Screen.get_default()

    #geo = screen.get_monitor_geometry(screen.get_primary_monitor())
    #print("extended desktop: {}x{}".format(geo.width, geo.height))

    display = screen.get_display()
    monitor = display.get_monitor_at_window(screen.get_active_window())
    workarea = monitor.get_workarea()
    print("workarea: {}x{}".format(workarea.width, workarea.height))


xgeo_gdk()
