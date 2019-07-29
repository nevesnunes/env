#!/usr/bin/env bash

set -eu

declare -i d_count=0
declare -i a_count=0
declare -i m_count=0
d_name=""
a_name=""
m_name=""
while read -r l; do
  if echo "$l" | grep -q "^D"; then 
    d_count+=1
    d_name=$(echo "$l" | sed "s/[A-Za-z0-9]*[ \t]*\([^ \t].*\)/\1/; s/.*\/usr//g")
  elif echo "$l" | grep -q "^A"; then 
    a_count+=1
    a_name=$(echo "$l" | sed "s/[A-Za-z0-9]*[ \t]*\([^ \t].*\)/\1/; s/.*\/usr//g")
  elif echo "$l" | grep -q "^M"; then 
    m_count+=1
    m_name=$(echo "$l" | sed "s/[A-Za-z0-9]*[ \t]*\([^ \t].*\)/\1/; s/.*\/usr//g")
  fi
done <<< "$(git -c color.status=false status --porcelain=v1)"
out=""
[ -n "$d_name" ] && out+="D:$d_name"
[ "$d_count" -gt 0 ] && out+="+$d_count"
[ -n "$out" ] && [ -n "$a_name$m_name" ] && out+=" "

[ -n "$a_name" ] && out+="A:$a_name"
[ "$a_count" -gt 0 ] && out+="+$a_count"
[ -n "$out" ] && [ -n "$m_name" ] && out+=" "

[ -n "$m_name" ] && out+="M:$m_name"
[ "$m_count" -gt 0 ] && out+="+$m_count"

echo "$out"
