# Disable auto-hiding overlay
export GTK_OVERLAY_SCROLLING=0
gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.UpdateActivationEnvironment '{"GTK_OVERLAY_SCROLLING": "0"}'

# Workaround PulseAudio crash
export PULSE_LATENCY_MSEC=90

# Perl
# Generated with:
# perl -I$HOME/opt/perl5/lib/perl5 -Mlocal::lib
PATH="$HOME/opt/perl5/bin${PATH:+:${PATH}}"; export PATH;
PERL5LIB="$HOME/opt/perl5/lib/perl5${PERL5LIB:+:${PERL5LIB}}"; export PERL5LIB;
PERL_LOCAL_LIB_ROOT="$HOME/opt/perl5${PERL_LOCAL_LIB_ROOT:+:${PERL_LOCAL_LIB_ROOT}}"; export PERL_LOCAL_LIB_ROOT;
set -- "--install_base" \""$HOME/opt/perl5"\" 
PERL_MB_OPT="$*"; export PERL_MB_OPT;
set --
PERL_MM_OPT="INSTALL_BASE=$HOME/opt/perl5"; export PERL_MM_OPT;

# Java
# References: 
# - https://wiki.archlinux.org/index.php/Java_Runtime_Environment_fonts#Basic_settings
# - https://docs.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
export _JAVA_OPTIONS='-Dawt.useSystemAAFontSettings=lcd -Dswing.aatext=true -Dsun.java2d.xrender=true -Dsun.java2d.dpiaware=true -Dswing.defaultlaf=javax.swing.plaf.metal.MetalLookAndFeel -Dswing.plaf.metal.controlFont="Liberation Sans-16" -Dswing.plaf.metal.systemFont="Liberation Sans-16" -Dswing.plaf.metal.userFont="Liberation Sans-16" -Dswing.plaf.metal.smallFont="Liberation Sans-14"'

# Scala
export SCALA_HOME="$HOME/opt/scala-2.13.3"

# Go
#export GOROOT="$HOME/.local/share/go"
export GOPATH="$HOME/opt/go"

# Android
export ANDROID_PREFS_ROOT="/run/media/$USER/TOSHIBA\ EXT/FN-NUX/.android"
export ANDROID_SDK_HOME="$ANDROID_PREFS_ROOT"

# Paths
# Comment $HOME/.local/bin:$HOME/bin in global configs (i.e. /etc/...{env|rc|login})
export PATH="/usr/local/shim:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$HOME/Dropbox/deploy:$HOME/.local/bin:$HOME/bin:$HOME/opt:$HOME/opt/mx:$GOROOT/bin:$GOPATH/bin:$HOME/.cargo/bin:$SCALA_HOME/bin"
export MANPATH="$MANPATH:/usr/local/man"

# Editors
export VISUAL='gvim -v'

export EDITOR="$VISUAL"
export SUDO_EDITOR="$VISUAL"
export SVN_EDITOR="$VISUAL"

# Pagers
export LESS="--RAW-CONTROL-CHARS"
export MANPAGER="sh -c \"
sed -e 's/\x1b\[[^m]\{1,5\}m//g' |
col -bx 2>/dev/null |
vim -c 'set ft=man ts=8 nomod nonumber nolist nonu noma | nmap q :q<CR>' -MR - \""
export MOST_EDITOR="$EDITOR"
export MOST_SWITCHES="-s"
export PAGER="less"

export BROWSER='user-browser'
export FZF_DEFAULT_OPTS='--bind=ctrl-j:accept,ctrl-k:kill-line,ctrl-u:preview-page-down,ctrl-i:preview-page-up,?:toggle-preview --header "ctrl-u:preview-page-down,ctrl-i:preview-page-up" --border=horizontal --color=16,border:7,pointer:2 --preview '"'"'echo {} | sed -e "s/^ *\([0-9]*\) *//" -e "s/.\{$((COLUMNS-4))\}/&\n/g"'"'"' --preview-window down:6:hidden'
export LC_ALL='en_US.UTF-8'
export LC_TIME='en_GB'
export NAVI_PATH=~/code/cheats
export NODE_PATH=~/.local/lib/node_modules
export PYTHONSTARTUP=~/.config/pythonrc
export SDL_VIDEO_ALLOW_SCREENSAVER=1
export TERMINFO=~/.terminfo
export QT_SCALE_FACTOR=1
export QT_STYLE_OVERRIDE=adwaita
export QT_QPA_PLATFORMTHEME=qt5ct
export WINEDLLOVERRIDES=winemenubuilder.exe=d
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"

export TMPDIR="$XDG_RUNTIME_DIR"

unset SSH_ASKPASS
