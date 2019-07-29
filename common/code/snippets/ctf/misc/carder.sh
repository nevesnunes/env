#!/bin/bash

# Get the card prefixes and suffixes
url_base="http://86dc35f7013f13cdb5a4e845a3d74937f2700c7b.ctf.site:20000/"
url_api="$url_base""api.php"
json='{"action":"start"}'
cards=$(curl \
    --cookie "ekocard3r=qsb7dB8ZLo8dfSDjsC3ecSkw2Qf" \
    --referer "$url_base" \
    -H "Content-Type: application/json" -X POST -d "$json" "$url_api")

nodejs ./gencc.js "$cards"
