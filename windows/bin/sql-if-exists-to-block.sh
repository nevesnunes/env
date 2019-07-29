#!/usr/bin/env bash

# See: https://stackoverflow.com/a/1801453

set -eu

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

  while read -r name; do
    source_statement="$source_pattern $name;"
    target_statement=$(sed "s/%NAME%/$name/g" < "$target_file")
    awk -v r="$target_statement" \
        "{gsub(/$source_statement/,r)}1" \
        "$sql_file" > \
        "$tmp_file"
    mv "$tmp_file" "$sql_file"
  done <<< "$(grep "$source_pattern" "$sql_file" | sed "s/$source_pattern \\([^;]*\\);/\\1/g")"
}

tmp_file=$(mktemp)
replace "DROP TABLE IF EXISTS" "$drop_table_file"
replace "DROP SEQUENCE IF EXISTS" "$drop_seq_file"
