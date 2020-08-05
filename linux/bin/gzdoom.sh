#!/bin/sh

export ZDOOM_BIN=gzdoom
export ZDOOM_DIR=$HOME/opt/gzdoom/build
exec zdoom.sh "$@"
