#!/usr/bin/env bash

echo '#### [update-vbox] Replacing VBox driver...'
su -c '/etc/init.d/vboxdrv setup'
echo '#### [update-vbox] Finished!'
