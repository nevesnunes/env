#!/usr/bin/env bash

sum_file=$(date +"%s")
sha1sum <( find . -type f \
        | sort \
        | xargs -d'\n' -I{} cat {} \
        ) \
    | cut -d' ' -f1 \
    > "$sum_file"
gpg --clearsign "$sum_file"
