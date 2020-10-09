# Remove junk

localedef --list-archive \
  | grep -v -i ^en \
  | xargs -I{} localedef --delete-from-archive {};

rpm -q kernel-core \
  | sort -V \
  | head -n-1 \
  | xargs -I{} dnf remove -y {}
dnf remove -y \
  \*-backgrounds\*

dnf clean all
rm -rf \
  /var/cache/dnf/* \
  /var/cache/PackageKit/*
