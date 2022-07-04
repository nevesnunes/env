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
# erase with dependencies
mv /etc/dnf/protected.d/systemd.conf /etc/dnf/protected.d/systemd.conf.0
dnf --disableplugin=protected_packages erase foo-1
mv /etc/dnf/protected.d/systemd.conf.0 /etc/dnf/protected.d/systemd.conf
# || erase without dependencies
rpm -v --erase --nodeps foo-1
# || erase from rpm database
rpm -v --justdb --erase --nodeps foo-1

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

# Issues:
# - `foo` does not belong to a distupgrade repository
#   - fix: `--allowerasing --skip-broken`
# - package `foo` is filtered out by exclude filtering
#   - fix: comment out exclude filters in /etc/dnf/dnf.conf, verify
#     with `dnf config-manager --dump | grep ^exclude` (includes
#     files under /etc/dnf/ and /etc/yum.repos/*conf)
dnf upgrade --refresh
dnf system-upgrade download -y --releasever=99
dnf system-upgrade reboot

dnf system-upgrade clean
dnf clean packages
```

- https://docs.fedoraproject.org/en-US/quick-docs/dnf-system-upgrade/

### free up space in root partition

```bash
# core dumps
systemd-tmpfiles --clean
# containers
docker system prune -a --volumes
# journal
journalctl --vacuum-time 1s

free_dir=/home
for i in cache lib; do
    mkdir -p "$free_dir/var/$i"
    mv "/var/$i/dnf" "$free_dir/var/$i" || break
    ln -s "$free_dir/var/$i/dnf" "/var/$i/dnf"
done

# rebuildable files
rm -f /var/lib/rpm/Packages
rm -f /var/lib/rpm/__db*
rpm --rebuilddb

dnf clean all
dnf makecache
```
