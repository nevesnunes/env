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
