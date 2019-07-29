# Export public key
gpg --list-key
gpg --armor --export pub > ~/pub.key

# Encryption
gpg --output file.gpg --encrypt --recipient _@gmail.com file
gpg --output file --decrypt file.gpg

# Signing
gpg --sign --output file.sha512sum.sig file.sha512sum
gpg --verify secret.sha512sum.sig
gpg --decrypt secret.sha512sum.sig

# Backup
gpg --output pgp-public-keys.asc --armor --export _@gmail.com
# ||
gpg --armor --export > pgp-public-keys.asc
gpg --armor --export-secret-keys > pgp-private-keys.asc
gpg --export-ownertrust > pgp-ownertrust.asc

# Restore
gpg --import < pgp-public-keys.asc
gpg --import < pgp-private-keys.asc
gpg --import-ownertrust < pgp-ownertrust.asc

# Delete
gpg --delete-secret-and-public-keys key-ID
