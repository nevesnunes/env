#!/bin/sh

# this simple script wraps around a mount command and creates a waiter process around it 
# that either exits with an error if the mount is externally unmounted
# or unmounts and then exits without error when send TERM or INT

# for example:

# mount-watch mount -o nosuid,noexec /dev/sdb2 /media/USB
# mount-watch sshfs remote-host:/etc/portage /tmp/remote-portage

set -eu

IFS="
"
# unescape spcial chracters in mount points
unescape_mount () {
    if [ "${1+x}" ]; then
        printf %s\\n "$1" | unescape_mount
    else
        sed -r 's/\\040/ /g;s/\\011/\t/g;s/\\012/\t/g;s/\\134/\\/g;'
        fi
    }

# general function for unmounting
unmount () {
    for line in $(cat /proc/mounts); do
        local mountpoint_="$(printf %s\\n "$line" | awk '{print $2}' | unescape_mount)"
        if [ "$(realpath -sq -- "$mountpoint_")" = "$(realpath -sq -- "$mountpoint")" ]; then
            local type_="$(printf %s\\n "$line" | awk '{print $3}')"

            case "$type_" in
                fuse.?*)
                    fusermount -uz -- "$mountpoint" || local exitc=$?
                    exit ${exitc-0}
                    ;;
                *)
                    umount -l -- "$mountpoint" || local exitc=$?
                    exit ${exitc-0}
                    ;;
                esac
            fi
        done
    # if the mount is not found in fstab something went wrong
    exit 111
    }

# babysitter function
sit () {
    while true; do
        # this idiom is to make sure the trap works
        # signals cannot be handled until a subprocess exits, if you use & wait $! it works for some reason
        inotifywait -qq -e unmount -- "$mountpoint" & wait $! || true 

        if ! mountpoint -q -- "$mountpoint"; then
            # the mountpoint detaching on its own is an error
            exit 50
            fi
        done
    }

# this cryptic piece of code sets the mountpoint variable to the last argument passed
for mountpoint; do true; done

# this just executes the command passed to mount
"$@"

# on INT or TERM we unmount
trap unmount INT TERM
# calls the babysitter
sit
