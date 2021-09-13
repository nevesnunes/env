#!/bin/sh

set -- $(dbus-send --system \
  --dest=org.freedesktop.DBus \
  --type=method_call \
  --print-reply \
  / \
  org.freedesktop.DBus.ListNames \
  | awk '/string "[a-z]/{split($0,a,"\""); print a[2]}')

for name in "$@"; do
  path="/$(echo "$name" | sed 's/\./\//g')"
  dbus-send --system \
    --dest="$name" \
    --type=method_call \
    --print-reply \
    "$path" \
    org.freedesktop.DBus.Introspectable.Introspect
done

set -- $(dbus-send --session \
  --dest=org.freedesktop.DBus \
  --type=method_call \
  --print-reply \
  / \
  org.freedesktop.DBus.ListNames \
  | awk '/string "[a-z]/{split($0,a,"\""); print a[2]}')

for name in "$@"; do
  path="/$(echo "$name" | sed 's/\./\//g')"
  dbus-send --session \
    --dest="$name" \
    --type=method_call \
    --print-reply \
    "$path" \
    org.freedesktop.DBus.Introspectable.Introspect
done
