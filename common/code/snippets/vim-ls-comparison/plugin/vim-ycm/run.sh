#!/usr/bin/env bash

set -e

if [ ! -d YouCompleteMe/third_party/ycmd/ ]; then
  old_pwd=$PWD
  https://github.com/Valloric/YouCompleteMe
  cd YouCompleteMe
  git submodule update --init --recursive
  bash -c "install.py --clang-completer"
  cd "$old_pwd"
fi

if [ ! -f rc ]; then
	cat <<- EOF > rc
	set nocompatible
	syntax on

	let g:ycm_global_ycm_extra_conf = "$PWD/ycm_extra_conf.py"
	set rtp+=$PWD/YouCompleteMe
	EOF
fi

vim -u rc "$@"
