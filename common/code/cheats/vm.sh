#!/usr/bin/env bash

set -eu

# mount shared folder

user=
share_name=
share_mount_dir=
sudo usermod -a -G vboxsf $user
# After restart
# Take user id from: id -u
sudo mount -t vboxsf -o gid=1000,uid=1000 $share_name $share_mount_dir

# use symbolic links in shared folder
VBoxManage setextradata VM_NAME VBoxInternal2/SharedFoldersEnableSymlinksCreate/SHARE_NAME 1

# vbox to vmware

VBoxManage export myvm -o myvm.ova
ovftool  --lax ../myvm.ova myvm.ovf
#```myvm.ovf
#<vssd:VirtualSystemType>vmx-07</vssd:VirtualSystemType>
#<Item>
#<rasd:Address>0</rasd:Address>
#<rasd:Caption>SCSIController</rasd:Caption>
#<rasd:Description>SCSI Controller</rasd:Description>
#<rasd:ElementName>SCSIController</rasd:ElementName>
#<rasd:InstanceID>5</rasd:InstanceID>
#<rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
#<rasd:ResourceType>6</rasd:ResourceType>
#</Item>
#```

# ||

vboxmanage internalcommands converttoraw .VirtualBox/HardDisks/myvm.vdi vmware/myvm.raw
qemu-img convert -O vmdk myvm.raw myvm.vmdk

# vmware to vbox

ovftool source.vmx export.ovf

# reading
# - 7zip can open VDI, VHD, and VMDK hard disk images
