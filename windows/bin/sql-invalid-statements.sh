#!/usr/bin/env bash

# Lists SQL statements referencing invalid tables
# for scripts in current directory.

set -eu

file_created="$(mktemp)"
file_referenced="$(mktemp)"

cleanup() {
  rm -f "$file_created" "$file_referenced"
}
trap cleanup EXIT

# Tables by statement
grep -rin "create table " |\
    sed "s/.* table \([[:alnum:]_-]*\).*/\1/gI" |\
    tr "[:lower:]" "[:upper:]" |\
    sort -u > "$file_created"
regex_reference="\(alter table\|insert into\|update\| references\)"
grep -rin "$regex_reference " |\
    sed "s/.*$regex_reference \([[:alnum:]_-]*\).*/\2/gI" |\
    tr "[:lower:]" "[:upper:]" |\
    sort -u > "$file_referenced"

# Tables that didn't appear in a `create` statement
invalid_referenced_tables=()
while IFS="" read -r line; do 
  invalid_referenced_tables+=("$line");
done < <(diff -Naurw "$file_created" "$file_referenced" |\
    grep "^+[^+]" |\
    sed "s/^\+*//")

# Lines with invalid statements
for i in "${invalid_referenced_tables[@]}"; do
    grep -rin "$regex_reference $i "
done
