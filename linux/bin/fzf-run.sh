#!/usr/bin/env sh

set -eu

# `LC_ALL` is expected to be empty
LC_ALL=${LC_ALL:-}
LC_ALL=${SCRATCHPAD_TERMINAL_OLD_LC_ALL-${LC_ALL}}
export LC_ALL
LANG=${SCRATCHPAD_TERMINAL_OLD_LANG:-${LANG}}
export LANG

# Accept commands from either an entry or a query including arguments
export FZF_DEFAULT_OPTS=
fzf_cmd="$HOME/opt/fzf/bin/fzf -0 -1 --color=16,pointer:2 --no-border --print-query"
eval "set -- $fzf_cmd"
if command -v stest >/dev/null 2>&1; then
  cmd=$(IFS=: command eval 'stest -flx $PATH' \
    | awk '!a[$1]++' \
    | "$@" \
    | tail -1)
else
  cmd=$(IFS=: command eval 'printf "%s\n" $PATH' \
    | xargs -I{} find {} \
      -executable \
      -maxdepth 1 \
      -type f \
    | "$@" \
    | tail -1)
fi
eval "set -- $cmd"
cmd_expanded=$(command -v "$1" 2>/dev/null)
shift
if [ -n "$cmd_expanded" ]; then
  # Validation:
  # find /usr/bin -type f -executable -print0 | xargs -0 -i sh -c 'a=$(ldd "$1" 2>/dev/null | grep -q "^\s*lib\(n\?curses\|tinfo\)" && objdump -D "$1" | grep -m 1 "stdin@@"); [ -n "$a" ] && echo $1 --- $a' _ {}
  # => errors
  # objdump: error: /usr/bin/top(.bss) section size (0x27d70 bytes) is larger than file size (0x1f5c8 bytes)
  # objdump: Reading section .bss failed because: memory exhausted
  # => false positives
  # /usr/bin/virt-resize --- 123fe7: e8 74 57 08 00 callq 1a9760 <guestfs_int_mllib_set_keys_from_stdin@@Base>
  # /usr/bin/virt-sparsify --- 11a957: e8 f4 56 08 00 callq 1a0050 <guestfs_int_mllib_set_keys_from_stdin@@Base>
  # /usr/bin/zsh --- 2031f: e8 2c 19 08 00 callq a1c50 <setblock_stdin@@Base>
  #
  # Alternatives:
  # find /usr/bin -type f -executable -print0 | xargs -0 -i sh -c 'a=$(ldd "$1" 2>/dev/null | grep -q "^\s*lib\(n\?curses\|tinfo\)" && objdump -T "$1" | grep -m 1 "\s\s+stdin$"); [ -n "$a" ] && echo $1 --- $a' _ {}
  # objdump -d "$cmd_expanded" 2>/dev/null \
  #   | grep -q '<stdin@@'
  #
  # Test cases:
  # - libncurses: /usr/bin/htop
  # - libtinfo and libX11: /usr/bin/scummvm
  # - xcb: /usr/bin/i3
  requires_tty=
  file -ib "$cmd_expanded" \
    | grep -q '^\s*text/x-shellscript' \
    && grep -q '^[^#]*read ' "$cmd_expanded" \
    && requires_tty=1
  ldd "$cmd_expanded" 2>/dev/null \
    | awk '
      /^[[:space:]]*lib(GLX|wayland|X11|xcb)/{t=0; exit !t}
      /^[[:space:]]*lib(n?curses|tinfo)/{t=1} 
      END{exit !t}
    ' \
    && requires_tty=1
  objdump -C -T "$cmd_expanded" 2>/dev/null \
    | awk '
      /[[:space:]]+(NativeWindow::(.*)|QApplication::(.*)|SDL_CreateWindow|SdlWindow::(.*)|wl_display_connect|wxWindow::(.*)|XCreateWindow|XCreateSimpleWindow|xcb_create_window)$/{t=0; exit !t}
      /[[:space:]]+stdin$/{t=1}
      END{exit !t}
    ' \
    && requires_tty=1
  if [ -n "$requires_tty" ]; then
    exec "$cmd_expanded" "$@"
  else
    exec sh -c -i "nohup $cmd_expanded $* </dev/null >/dev/null 2>&1 &"
  fi
fi
