  #!/bin/bash
  dir="/tmp/vim-anywhere/"
  fn="$(date -Iseconds)"
  [ ! -d $dir ] && mkdir $dir
  vim $dir$fn && cat $dir$fn | xsel -b -i
