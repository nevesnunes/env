#!/usr/bin/env bash

# Usage of kickstart file:
# linux text inst.ks=cdrom:/anaconda-ks.cfg
#
# See: https://docs.fedoraproject.org/en-US/fedora/rawhide/install-guide/advanced/Kickstart_Installations/

set -eux

iso=$1
[ -f "$iso" ]
iso_dir=$(realpath "$(dirname "$iso")")
[ -d "$iso_dir" ]
iso_name=$(basename "$iso")
iso_name=${iso_name%.*}
[ -n "$iso_name" ]

volume_name=$2

tmp_dir=$(mktemp -d --tmpdir="$HOME"/tmp)
[ -d "$tmp_dir" ]
tmp_writable_dir=$(mktemp -d --tmpdir="$HOME"/tmp)
[ -d "$tmp_writable_dir" ]

# Use `sudo` due to this restriction:
# mount: only root can use "--options" option
sudo mount -t iso9660 -o loop "$iso" "$tmp_dir"

# See: https://unix.stackexchange.com/a/322213/318118
cleanup() {
  err=$?
  sudo umount -l "$tmp_dir"
  sudo rm -rf "$tmp_dir" "$tmp_writable_dir"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

# Use `sudo` to copy files with root ownership
(cd "$tmp_dir" && sudo tar cfv - .) | \
  (cd "$tmp_writable_dir" && sudo tar xfp -) \

set +x
read -n1 -r -p "ISO unpacked at: $tmp_writable_dir, press any key to rebuild iso..."
set -x

iso_new_name="$iso_name"-dirty_$(date +%s)
cd "$tmp_writable_dir" && sudo mkisofs \
	-o "$iso_dir"/"$iso_new_name".iso \
	-b isolinux/isolinux.bin \
	-c isolinux/boot.cat \
  -no-emul-boot \
	-boot-load-size 4 \
	-boot-info-table \
	-J \
	-R \
	-V "$volume_name" \
  "$tmp_writable_dir"
