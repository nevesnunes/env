#!/usr/bin/env bash

set -eu
# ^ hover

test_echo() {
  arg1=$1
  echo "test_echo$arg1"
}

foo="foo"
# ^ references
test_e "$foo"
#    ^ omni completion (function)

echo "test_str" # test_string
#            ^ keyword completion
