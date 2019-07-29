echo "$*" | grep -qiE "\[.*\]\(.*\)" && echo -n "$*" && exit 0
title=$(curl "$*" -s | grep -iPo '(?<=<title>)(.*)(?=</title>)' | sed 's/\([\*\.`_{}()#+-]\)/\\\1/g')
echo -n "[$title]($*)"
