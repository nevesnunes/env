#!/usr/bin/env bash

set -eu

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
