#!/usr/bin/env bash

# TODO:
# https://github.com/saibing/bingo/wiki/F.A.Q
# https://github.com/eclipse/eclipse.jdt.ls

set -e

command -v bash-language-server &>/dev/null || \
  npm install bash-language-server -g
command -v go-langserver &>/dev/null || \
  go get -u github.com/sourcegraph/go-langserver
command -v javascript-typescript-langserver &>/dev/null || \
  npm install javascript-typescript-langserver -g
command -v pyls &>/dev/null || \
  pip install python-language-server --user
