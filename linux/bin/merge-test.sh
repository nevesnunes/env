#!/bin/sh

set -eux

dir=$(mktemp -d)
mkdir -p "$dir"
cd "$dir"

git init
printf '%s\n' 'apple' 'carrot' > ./1
git add -A
git commit -m '.'

git checkout -b banana
printf '%s\n' 'apple' 'banana' 'carrot' 'orange' > ./1
git add -A
git commit -m '.'

git checkout master
git checkout -b strawberry
printf '%s\n' 'apple' 'carrot' 'strawberry' > ./1
git add -A
git commit -m '.'

git merge banana
# git mergetool
