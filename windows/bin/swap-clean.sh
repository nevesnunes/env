#!/usr/bin/env bash

SWAP_FILE_DIR=~/temp/vim_swp
IFS=$'\n'

TMPDIR=$(mktemp -d) || exit 1
RECTXT="$TMPDIR/vim.recovery.$USER.txt"
RECFN="$TMPDIR/vim.recovery.$USER.fn"
trap 'rm -f "$RECTXT" "$RECFN"; rmdir "$TMPDIR"' 0 1 2 3 15
for q in $SWAP_FILE_DIR/.*sw? $SWAP_FILE_DIR/*; do
  echo $q
  [[ -f $q ]] || continue
  rm -f "$RECTXT" "$RECFN"
  vim -X -r "$q" \
      -c "w! $RECTXT" \
      -c "let fn=expand('%')" \
      -c "new $RECFN" \
      -c "exec setline( 1, fn )" \
      -c w\! \
      -c "qa"
  if [[ ! -f $RECFN ]]; then
    echo "nothing to recover from $q"
    rm -f "$q"
    continue
  fi
  CRNT="$(cat $RECFN)"
  if [ "$CRNT" = "$RECTXT" ]; then
      echo "Can't find original file. Press enter to open vim so you can save the file. The swap file will be deleted afterward!"
      read
      vim "$CRNT"
      rm -f "$q"
  else if diff --strip-trailing-cr --brief "$CRNT" "$RECTXT"; then
      echo "Removing redundant $q"
      echo "  for $CRNT"
      rm -f "$q"
  else
      echo $q contains changes, or there may be no original saved file
      vim -n -d "$CRNT" "$RECTXT"
      rm -i "$q" || exit
  fi
  fi
done
