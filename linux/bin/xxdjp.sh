#!/bin/bash

set -eux

iconv -f utf-8 -t shift-jis   <(printf '%s' "$*") | xxd -p | sed 's/\(..\)/\\x\1/g'
iconv -f utf-8 -t euc-jp      <(printf '%s' "$*") | xxd -p | sed 's/\(..\)/\\x\1/g'
iconv -f utf-8 -t iso-2022-jp <(printf '%s' "$*") | xxd -p | sed 's/......\(.*\)....../\1/' | sed 's/\(..\)/\\x\1/g'
