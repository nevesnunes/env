#!/usr/bin/env sh

# See:
# https://wiki.gentoo.org/wiki/Simple_sandbox
# https://apuntesderootblog.wordpress.com/2016/07/14/sandbox-steam-running-it-under-a-different-account/
# https://github.com/netblue30/firejail/issues/1197
# https://unix.stackexchange.com/questions/421184/restrict-clipboard-for-untrusted-x11-clients

set -eux

if [ -z "$*" ]; then
  echo "Usage: $(basename "$0") command"
  exit 1
fi

pulse_socket=/tmp/pulse-socket

if ! id -u nonet; then
  # Create client user and group
  sudo useradd nonet
  sudo passwd nonet
  sudo groupadd nonets
  sudo usermod -a -G nonets nonet

  sudo mkdir -p /home/nonet
  sudo touch /home/nonet/.Xauthority
  sudo chown -R nonet:nonets /home/nonet

  # Run client commands without password
  echo "$(id -nu)"' ALL=(nonet:nonets) NOPASSWD: ALL' > /etc/sudoers.d/nonets

  # Output sound to host's PulseAudio daemon
  mkdir -p /home/"$USER"/.config/pulse
  echo ".include /etc/pulse/default.pa
  load-module module-native-protocol-unix auth-anonymous=1 socket=$pulse_socket" > /home/"$USER"/.config/pulse/default.pa
  sudo mkdir -p /home/nonet/.config/pulse
  echo "default-server = unix:$pulse_socket" | sudo tee /home/nonet/.config/pulse/client.conf
  sudo chown nonet:nonets /home/nonet/.config/pulse/client.conf
  sudo chmod 644 /home/nonet/.config/pulse/client.conf 

  set +e
  pulseaudio -k && sleep 2
  set -e
  pulseaudio --start
fi

# Configure host's PulseAudio daemon
#pactl load-module module-native-protocol-unix auth-anonymous=1 socket=$pulse_socket
pactl load-module module-native-protocol-unix auth-group=nonets auth-group-enable=yes socket=$pulse_socket
pactl -s "$pulse_socket" info
trap 'rm $pulse_socket' EXIT QUIT INT TERM

# Block client's outgoing network packets
sudo iptables -A OUTPUT -m owner --uid-owner "$(id -u nonet)" -j DROP

# Configure X server access control
if xdpyinfo -queryExtensions -ext all | grep -i security; then
  sudo su - nonet -c "unset XAUTHORITY; xauth add $(xauth list)"
  # ||
  # xauth generate :0 . trusted 
  # xauth add ${HOST}:0 . $(xxd -l 16 -p /dev/urandom)
else
  xhost +SI:localuser:nonet
fi

sudo -u nonet -H bash -c "unset XAUTHORITY; $*"
