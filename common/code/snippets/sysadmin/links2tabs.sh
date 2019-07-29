#!/bin/bash

while read line; do 
    firefox -new-tab "$line" & 2>/dev/null
    sleep 2
done < links
