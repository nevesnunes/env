#!/usr/bin/env sh

# Given: `.config`
# Updated with:
# - `make localmodconfig`
# - `make menuconfig`

set -eux

version=${1:-5.4}.
config_dir=${2:-/home/$USER/code/config/kernel}
download_dir=${3:-/home/$USER/code/dependencies}

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

mkdir -p "$config_dir"
cp "$config_dir"/.config "$kernel_name"
cd "$kernel_name"

jobs_arg="-j"
if command -v nproc >/dev/null 2>&1; then
  jobs_arg="-j$(nproc --ignore=2)"
fi
make "$jobs_arg" oldconfig && \
  make "$jobs_arg" bzImage && \
  make "$jobs_arg" modules && \
  sudo make modules_install && \
  sudo make install 
