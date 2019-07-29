#!/usr/bin/env sh

set -eu

libretro_dir="$HOME/games/+/libretro-super"
if ! [ -d "$libretro_dir" ]; then
  mkdir -p "$libretro_dir"
  git clone https://github.com/libretro/libretro-super.git "$libretro_dir"
fi

cd "$libretro_dir"
git reset --hard
git pull
cp "$HOME/code/snippets/build-config.sh" .
SHALLOW_CLONE=1 ./libretro-fetch.sh
./retroarch-build.sh
NOCLEAN=1 ./libretro-build.sh

(
  cd retroarch
  git fetch --tags
  git checkout "$(git describe --tags "$(git rev-list --tags --max-count=1)")"
  ./configure --disable-wayland --disable-qt --disable-materialui --disable-xmb
  sudo make install
)

ra_dir="$HOME/games/emus/ra"
mkdir -p "$ra_dir/cores"
./libretro-install.sh "$ra_dir/cores"
