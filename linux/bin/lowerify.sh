#!/usr/bin/env bash

# Corrects all mentions of files to their lowercase filenames

for i in $(tree -i | sort | uniq | tail -n +3) ; do
    allLowercase=$i
    oneUppercase=$(echo $i | sed -r 's/^\s*./\U&\E/g')
    allUppercase=${oneUppercase^^}

    mixLowercase=$allLowercase
    mixLowercase=${mixLowercase%.htm}
    mixUppercase=$allUppercase
    mixUppercase=${mixUppercase%.HTM}

    echo "Replacing filename ${i}..."

    sedStringOne="s/${oneUppercase}/${allLowercase}/g"
    find . -iname '*.htm' -exec sed -i "$sedStringOne" '{}' \;

    sedStringAll="s/${allUppercase}/${allLowercase}/g"
    find . -iname '*.htm' -exec sed -i "$sedStringAll" '{}' \;

    sedStringMix="s/${mixUppercase}/${mixLowercase}/g"
    find . -iname '*.htm' -exec sed -i "$sedStringMix" '{}' \;

done
