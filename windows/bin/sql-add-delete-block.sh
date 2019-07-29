#!/usr/bin/env bash

# See: https://stackoverflow.com/a/1801453

set -eux

sql_file=$1

drop_table_file=drop_table.sql
cat << EOF > "$drop_table_file"
BEGIN
   EXECUTE IMMEDIATE 'DROP TABLE %NAME%';
EXCEPTION
   WHEN OTHERS THEN
      IF SQLCODE != -942 THEN
         RAISE;
      END IF;
END;
EOF

drop_seq_file=drop_seq.sql
cat << EOF > "$drop_seq_file"
BEGIN
  EXECUTE IMMEDIATE 'DROP SEQUENCE %NAME%';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE != -2289 THEN
      RAISE;
    END IF;
END;
EOF

trap '{ rm -f "$drop_table_file" "$drop_seq_file"; }' EXIT

function replace {
  source_pattern=$1
  target_file=$2

  while read -r pattern; do
    name=$(echo "$pattern" | sed "s/$source_pattern[[:space:]]*\\([^[:space:]]*\\).*/\\1/g")
    source_statement="$pattern"
    target_statement=$(sed "s/%NAME%/$name/g" < "$target_file")
    awk -v r="$target_statement\\n$source_statement" \
        "{gsub(/$source_statement([[:space:]]+|$)/,r)}1" \
        "$sql_file" > \
        "$output_file"
    mv "$output_file" "$sql_file"
  done <<< "$(grep "$source_pattern" "$sql_file")"
}

dos2unix "$sql_file"

output_file=$(mktemp)
replace "CREATE TABLE" "$drop_table_file"
replace "CREATE SEQUENCE" "$drop_seq_file"
