#!/usr/bin/env sh

set -eu

input="$*"

# Temporary xinitrc
temp_xinit=$(mktemp)
trap 'rm -f -- $temp_xinit' EXIT

# Changing mode only works after doing a query...
cat > "$temp_xinit" << EOF
#!/usr/bin/env bash
xrandr --query
xrandr --output VGA1 --mode 1024x768
$input
EOF

# Allow non-console user to create X server
sudo bash -c 'echo "allowed_users=anybody" > /etc/X11/Xwrapper.config'

xinit "$temp_xinit" -- :1

sudo bash -c 'echo "" > /etc/X11/Xwrapper.config'
