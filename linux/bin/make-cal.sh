#!/usr/bin/env bash

set -eux

out=$(mktemp --suffix='.pdf')

cleanup() {
  err=$?
  rm -f "$out"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

# https://opendata.stackexchange.com/questions/1926/list-of-public-holidays-by-countries/13215
# =>
# https://github.com/tinohager/Nager.Date
# ||
# curl --location https://www.google.com/calendar/ical/en.portuguese%23holiday%40group.v.calendar.google.com/public/basic.ics
~/opt/pcal/exec/pcal \
    -a 'pt' \
    -b 'all' \
    -d 'FreeSans-Bold/18' \
    -n 'FreeSans-Bold/12' \
    -t 'FreeSans-Bold/24' \
    -s '1.0:0.0:0.0' \
    -w \
    -f <(curl --location https://date.nager.at/PublicHoliday/Country/PT/2020/CSV | \
        grep -v 'False,[^,]*,[^,]*$' | \
        grep -v 'Optional$' | \
        sed 's/^[0-9]*-\([^,]*\).*/\1\*/' | \
        tail -n+2) | \
    sed 's/\(datefontsize\) \[ [0-9]* \]/\1 [ 64 ]/' | \
    ps2pdf - "$out"

# 90mm x 54mm (Standard Name Card Size)
# http://www.imagemagick.org/discourse-server/viewtopic.php?t=35159
density=300
scale_w=$(awk \
  -v d=$density \
  'END {printf "%d", 90 * d / 25.4}' </dev/null)
scale_h=$(awk \
  -v d=$density \
  'END {printf "%d", 54 * d / 25.4}' </dev/null)
resized_out=${out%.*}-card_sized.pdf
convert \
  "$out" \
  -scale "${scale_w}x${scale_h}" \
  -units PixelsPerInch \
  -density "${density}x${density}" \
  "$resized_out"
