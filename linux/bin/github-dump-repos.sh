#!/bin/sh

set -eux

API_URL="https://api.github.com/users/foo/repos"
for url in $(curl -s $API_URL | jq -r '.[].html_url'); do
  git clone "$url"
done
