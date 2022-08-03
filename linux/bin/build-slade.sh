#!/bin/sh

mkdir -p build && (cd build && cmake -DNO_WEBVIEW=ON -DWX_GTK3=ON -DwxWidgets_CONFIG_EXECUTABLE=/usr/bin/wx-config-3.0 .. && make)
