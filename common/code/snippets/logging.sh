#!/usr/bin/env bash

set -eu

exec >logfile 2>&1

#||

{
  echo 'test'
} >logfile 2>&1 
