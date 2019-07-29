# Install
mkdir ~/.terminfo # optional; can also install to $HOME/share/terminfo
infocmp screen-256color > screen-256color.terminfo.original # backup
mkdir dry-run
tic -o dry-run screen-256color.terminfo
infocmp -A dry-run screen-256color > screen-256color.terminfo.new
diff -u screen-256color.terminfo.{original,new}
tic screen-256color.terminfo # overwrites the old terminfo

# Check existing italic and standout settings:
infocmp $TERM | egrep '(sitm|ritm|smso|rmso)'

# Check that the terminal does the right thing:
echo `tput sitm`italics`tput ritm` `tput smso`standout`tput rmso`
