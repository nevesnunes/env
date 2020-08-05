#!/usr/bin/env bash

set -ux

role=$1
[ -d "$role" ]
target=${2:-/home/$USER/}

git add -A
git commit -m 'sync'
git pull
set -e

dirty_name=$(date +%s)
git checkout -b "$dirty_name"
cleanup() {
  err=$?
  git branch -D "$dirty_name"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

repo_path=$(realpath .)
while read -r role_file; do
  local_role_file="${role_file//$repo_path/}"
  local_file="$target/${local_role_file//$role/}"
  [ -f "$local_file" ] || continue
  git diff \
    --no-index \
    --quiet \
    "$local_file" \
    "$role_file" || \
    cp "$local_file" "$role_file"
done < <(find "$(realpath ./"$role")" -type f)

set +e
git add -A
git commit -m 'sync'
set -e

git checkout master
git merge \
  --allow-unrelated-histories \
  --no-edit \
  -Xignore-all-space \
  -Xpatience \
  "$dirty_name"

#git push origin master
