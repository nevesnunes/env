#!/bin/bash

files=('gtkrc' 'themerc' 'xml' 'css')
sources=('f7f7f7' 'f3f3f3' 'dcdcdc' 'ebebeb')
targets=('f0f0f0' 'ececec' 'dadada' 'd7d7d7')

files_length=${#files[@]}
colors_length=${#sources[@]}

for (( i=0; i<${colors_length}; i++ ));
do
    source=${sources[i]}
    target=${targets[i]}
    pattern="s/"$source"/"$target"/g"
    for (( j=0; j<${files_length}; j++ ));
    do
        file=${files[j]}
        find . -iname "*"$file"*" -print0 | \
                xargs -0 sed -i'' -e $pattern
    done
done
