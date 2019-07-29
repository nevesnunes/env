#!/usr/bin/env bash

OLD_IFS=$IFS
IFS=''

names=($@)
for i in "${names[@]}"; do
  # Extract from metadata
  extracted_name=$(rename-pdf-title.py "$i")
  extracted_name=$(echo "$extracted_name" | tr '\t\n' ' ' | sed 's/[:/]/-/g' | tr -cd '[[:alnum:]] _-')

  # Extract from text
  if [ ${#extracted_name} -lt 10 ]; then
    extracted_name=$(pdftotext "$i" - | head -n 2 | tr '\t\n' ' ' | sed 's/[:/]/-/g' | tr -cd '[[:alnum:]] _-' | cut -c 1-100)
  fi
  if [ ${#extracted_name} -lt 10 ]; then
    extracted_name=$(pdftotext "$i" - | sed -n 3,10p | tr '\t\n' ' ' | sed 's/[:/]/-/g' | tr -cd '[[:alnum:]] _-' | cut -c 1-100)
  fi

  # Fallback to original filename
  if [ ${#extracted_name} -lt 10 ] || [ -f "$extracted_name"".pdf" ]; then
    new_name=$i
  else
    new_name="$extracted_name"".pdf"
  fi

  mv "$i" "$new_name"
done

IFS=$OLD_IFS
