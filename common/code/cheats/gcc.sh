#!/bin/sh

# Cross-Compilation
# https://opensource.com/article/19/7/cross-compiling-gcc

apt install gcc-multilib
gcc -static -nodefaultlibs -m32 -march=i686

# FATAL: kernel too old
# https://stackoverflow.com/questions/7868282/build-modern-4-x-gcc-to-target-a-2-4-x-kernel-on-the-same-architecture-as-the
# https://github.com/fastbuild/fastbuild/issues/66
# https://sourceware.org/ml/libc-help/2011-04/msg00032.html
# => build gcc against the old glibc, and use this gcc to build the executable

# Debug

LD_DEBUG=all foo

# Dynamic linking

echo 'int foo(){return 123;}' | gcc -x c - -shared -o libfoo.so
echo 'int main(){return foo();}' | gcc -x c - -L. -lfoo
LD_LIBRARY_PATH=. ltrace ./a.out
# foo(1, 0x7ffd4adc7828, 0x7ffd4adc7838, 0x7f3ee872a598) = 123
# +++ exited (status 123) +++

# Old distro
# https://wiki.debian.org/DebianSqueeze#FAQ
# https://cdimage.debian.org/mirror/cdimage/archive/6.0.6-live/i386/iso-hybrid/debian-live-6.0.6-i386-standard.iso

printf '%s\n' 'Acquire::Check-Valid-Until false;' >> /etc/apt/apt.conf
printf '%s\n' \
  'deb http://archive.debian.org/debian squeeze main' \
  'deb http://archive.debian.org/debian squeeze-lts main' > /etc/apt/sources.list
apt-get -o APT::Get::AllowUnauthenticated=true update
apt-get -o APT::Get::AllowUnauthenticated=true install gcc

# Custom LiveCD
# https://www.bustawin.com/create-a-custom-live-debian-9-the-pro-way/
# https://www.kali.org/docs/development/live-build-a-custom-kali-iso/
# https://live-team.pages.debian.net/live-manual/html/live-manual/about-manual.en.html
