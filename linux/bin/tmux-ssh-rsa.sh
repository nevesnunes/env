#!/usr/bin/env bash

if ! (ssh-add -L | grep -q -i "ssh-rsa"); then
  echo " ssh-id:none"
else
  echo ""
fi
