#!/bin/sh

set -eux

dconf load /org/gnome/terminal/legacy/ \
  < ../linux/code/config/dconf-gnome-terminal-legacy.txt

dconf write /org/gnome/desktop/interface/clock-show-date true
dconf write /org/gnome/desktop/privacy/report-technical-problems false
dconf write /org/gnome/desktop/search-providers/disable-external true
dconf write /org/gnome/desktop/wm/preferences/audible-bell false
dconf write /org/gnome/settings-daemon/plugins/xsettings/overrides "{'Gtk/ShellShowsAppMenu': <1>, 'Gtk/MenuImages': <1>}"
dconf write /org/gnome/software/download-updates false
dconf write /org/gnome/terminal/legacy/default-show-menubar false
# dconf write /org/gnome/terminal/legacy/profiles:/:b1dcc9dd-5262-4d8d-a863-c897e6d979b9/palette "['#dddddd', '#d22d48', '#37730d', '#622e04', '#4e6cd0', '#8854ab', '#285055', '#222222', '#808080', '#d22d48', '#37730d', '#622e04', '#4e6cd0', '#8854ab', '#285055', '#000000']"

dconf write /org/gnome/shell/extensions/switcher/onboarding-1 "uint32 1"
dconf write /org/gnome/shell/extensions/switcher/onboarding-2 "uint32 1"
dconf write /org/gnome/shell/extensions/switcher/onboarding-3 "uint32 1"
dconf write /org/gnome/shell/extensions/switcher/onboarding-4 "uint32 1"
dconf write /org/gnome/shell/extensions/switcher/onboarding-5 "uint32 1"

dbus-send --type=method_call --print-reply --dest=org.gnome.Shell /org/gnome/Shell org.gnome.Shell.Eval string:'global.reexec_self()' || true
