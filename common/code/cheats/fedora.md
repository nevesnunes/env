# package management

```bash
# Show transactions, take $transaction
dnf history list | head
# Show packages modified in $transaction, take $package
dnf history info $transaction
# Show installed and available versions, take $version
dnf --showduplicates list $package
# Rollback package version
dnf downgrade $package
# ||
dnf remove $package-$version
```

### conflicts

> file `/foo` from install `foo-2` conflicts with file from package `foo-1`

```bash
rpm --erase --nodeps foo-1
dnf upgrade -y --allowerasing --best
```

> All matches were filtered out by exclude filtering

```bash
sudo dnf install --disableexcludes=all foo
# Validation
grep -R exclude -- /etc/yum.repos.d/ /etc/dnf/dnf.conf
```

# upgrade distro version

```bash
dnf install -y dnf-plugin-system-upgrade

dnf upgrade --refresh
dnf system-upgrade download --releasever=99
dnf system-upgrade reboot

dnf system-upgrade clean
dnf clean packages
```

### free up space in root partition

```bash
# core dumps
systemd-tmpfiles --clean
# containers
docker system prune -a --volumes
# journal
journalctl --vaccum-time 1s

for i in cache lib; do
    mkdir -p /home/var/"$i"
    mv /var/"$i"/dnf /home/var/"$i"
    ln -s /home/var/"$i"/dnf /var/"$i"/dnf
done

# rebuildable files
rm -f /var/lib/rpm/Packages
rm -f /var/lib/rpm/__db*
rpm --rebuilddb

dnf clean all
dnf makecache
```
