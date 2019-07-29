#!/usr/bin/env bash

parallel --joblog ./out -j2 < commands.txt
echo $?

xargs -P2 -n1 -d '\n' sh -c < commands.txt
