#!/bin/sh

if [ ! -d ./_posts ] ; then
  echo "Not in a jekyll base directory." >&2
  exit 1
fi

if [ "$#" -lt 1 ] ; then
  echo "Usage: $0 <title>" >&2
  exit 1
fi

title=$*
titleForFile=$(echo "$title" |sed 's/[ :]/-/g')
fileName="_posts/"$(date +%Y-%m-%d-"$titleForFile".markdown)

touch "$fileName"

cat > "$fileName" <<DELIM
---
layout: post
title: $title
date: $(date "+%Y-%m-%d %H:%M:%S") +0000
---

{% include custom.html %}


DELIM

$EDITOR "$fileName" +10
