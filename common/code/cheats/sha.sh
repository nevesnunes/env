#!/usr/bin/env sh

cat xades.xml | openssl dgst -binary -sha1 | openssl base64
sha1sum xades.xml | cut -f1 -d\  | xxd -r -p | base64
