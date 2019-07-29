#!/usr/bin/env bash

# Grab all archived logs for `neiist`, extract the ip in each line,
# and count the unique ips in a file.
# Finish with a sort of the counted unique ips of all files
for i in /var/log/apache2/neiist-access.log-2016*; do
        bzcat "$i" | cut --delimiter=' ' --fields=1 | uniq | wc --lines;
done | sort --numeric-sort
