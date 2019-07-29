#!/usr/bin/env sh

set -eux

version=${1:-4.4}.
config_dir=${2:-/home/$USER/kernel}
download_dir=${3:-/home/$USER/Downloads}

mkdir -p "$download_dir"
cd "$download_dir"

links=$(curl -s https://www.kernel.org)
tarball=$(echo "$links" | \
  grep -iE "${version}.*tarball" | \
  sed 's/.*href="\([^"]*\)".*/\1/')
sign=$(echo "$links" | \
  grep -iE "${version}.*PGP" | \
  sed 's/.*href="\([^"]*\)".*/\1/')

tarball_name=${tarball##*/}
if [ ! -f "$tarball_name" ]; then
  wget --quiet "$tarball"
  wget --quiet "$sign"
fi

tar_name=${tarball_name%.*}
if [ ! -f "$tar_name" ]; then
  xz -dc < "$tarball_name" > "$tar_name"
fi

kernel_name=${tar_name%.*}
if [ ! -d "$kernel_name" ]; then
  gpg2 --locate-keys torvalds@kernel.org gregkh@kernel.org
  gpg2 --verify "$tar_name".sign

  mkdir -p "$kernel_name" && \
    tar xf "$tar_name" -C "$kernel_name" --strip-components=1
fi

cp "$config_dir"/.config "$kernel_name"
cd "$kernel_name"
make oldconfig && \
  make bzImage && \
  make modules && \
  sudo make modules_install && \
  sudo make install
