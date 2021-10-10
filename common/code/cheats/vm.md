# all

```ps1
# Extract
$a=@(
    "CIM_ComputerSystem",
    "CIM_BIOSElement",
    "CIM_OperatingSystem",
    "CIM_PhysicalMemory",
    "CIM_Processor",
    "Win32_LogicalDisk"
)
foreach ($i in $a) {
    Get-CimInstance $i | ConvertTo-Json -Depth 100 > $env:userprofile\Documents\hardware\$i.json
}
Get-Volume | Format-List > $env:userprofile\Documents\hardware\get-volume.json

# Parse
Get-Content $env:userprofile\Documents\hardware\get-volume.json | ConvertFrom-Json
```

# filesystem

```bash
df -h
```

```ps1
Get-Volume
```

# memory

```bash
grep 'MemTotal' /proc/meminfo
```

```ps1
((Get-WmiObject Win32_PhysicalMemory | Measure Capacity -Sum).Sum / 1GB)
```

# cpus

```bash
nproc --all

lscpu | grep -E '^Thread|^Core|^Socket|^CPU\('
# CPU(s):                4
# Thread(s) per core:    1
# Core(s) per socket:    1
# Socket(s):             4

lscpu --all --parse=CPU,SOCKET,CORE | grep -v '^#'
# 0,0,0
# 1,1,1
# 2,2,2
# 3,3,3

grep -E 'processor|core id' /proc/cpuinfo
# processor       : 0
# core id         : 0
# processor       : 1
# core id         : 0
# processor       : 2
# core id         : 0
# processor       : 3
# core id         : 0
```

```ps1
Get-WmiObject Win32_Processor | % { $total = 0 } { $total += $_.NumberOfLogicalProcessors } { $total }
```

# detect vm

```bash
dmidecode  | grep -i product
```

# mount shared folder

```bash
user=
share_name=
share_mount_dir=
sudo usermod -a -G vboxsf $user
# After restart
# Take user id from: id -u
sudo mount -t vboxsf -o gid=1000,uid=1000 $share_name $share_mount_dir
```

# use symbolic links in shared folder

```bash
VBoxManage setextradata VM_NAME VBoxInternal2/SharedFoldersEnableSymlinksCreate/SHARE_NAME 1
```

# 3D acceleration

- Windows 95: PCem
- Windows XP: [virtualbox\.org &bull; View topic \- Direct3D Acceleration not working on Guest Windows XP](https://forums.virtualbox.org/viewtopic.php?t=98113)
- Windows 7: VirtualBox

# vbox to vmware

```bash
VBoxManage export myvm -o myvm.ova
ovftool  --lax ../myvm.ova myvm.ovf

# myvm.ovf
# 
# <vssd:VirtualSystemType>vmx-07</vssd:VirtualSystemType>
# <Item>
# <rasd:Address>0</rasd:Address>
# <rasd:Caption>SCSIController</rasd:Caption>
# <rasd:Description>SCSI Controller</rasd:Description>
# <rasd:ElementName>SCSIController</rasd:ElementName>
# <rasd:InstanceID>5</rasd:InstanceID>
# <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
# <rasd:ResourceType>6</rasd:ResourceType>
# </Item>

# ||
vboxmanage internalcommands converttoraw .VirtualBox/HardDisks/myvm.vdi vmware/myvm.raw
qemu-img convert -O vmdk myvm.raw myvm.vmdk
```

# vmware to vbox

```bash
ovftool source.vmx export.ovf
```

# reading

- 7zip can open VDI, VHD, and VMDK hard disk images

# guest additions

- Devices > Insert Guest Additions CD Image...

```bash
mkdir -p /mnt/foo
sudo mount -o loop /dev/cdrom /mnt/foo
sudo /mnt/foo/VBoxLinuxAdditions.run
```

# debug slowdown

- if vm image on external disk => Machine > Settings > USB > Set: USB 3.0 (xHCI) Controller

# Hyper-V Compatibility

```ps1
# To disable Hyper-V in order to use VirtualBox, open a command prompt as administrator and run the command:
bcdedit /set hypervisorlaunchtype off
# You’ll need to reboot, but then you’ll be all set to run VirtualBox. To turn Hyper-V back on, run:
bcdedit /set hypervisorlaunchtype auto

dism.exe /Online /Disable-Feature:IsolatedUserMode
dism.exe /Online /Disable-Feature:Microsoft-Hyper-V-All
```

- https://stackoverflow.com/questions/39858200/vmware-workstation-and-device-credential-guard-are-not-compatible
- https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage

### Separate boot menu entry

```ps1
bcdedit /copy {current} /d "No Hyper-V" 
bcdedit /set {ff-23-113-824e-5c5144ea} hypervisorlaunchtype off 
```

# vmware manual uninstall

```bash
# modules
rmmod vmnet.o
rmmod vmmon.o
rmmod vmci.o
rmmod vmblock.o
rmmod vmppuser.o
# startup scripts
rm -f /etc/rc2.d/*vmware*
rm -f /etc/rc3.d/*vmware*
rm -f /etc/rc5.d/*vmware*
rm -f /etc/rc6.d/*vmware*
# everything else
rm -rf /etc/vmware*
rm -f /usr/bin/vmware*
rm -f /usr/bin/vmnet*
rm -rf /usr/lib/vmware*
rm -rf /usr/share/doc/vmware*
```

# vmware manual module install

- [!] Note: Custom kernels must include `vmci` and `vsock` modules
    - Validation: `modprobe vmw_vmci && stat /dev/vmci`
    - On `.config`:
        ```
        CONFIG_VSOCKETS=y
        CONFIG_VMWARE_VMCI=y
        CONFIG_VMWARE_VMCI_VSOCKETS=y
        ```

```bash
# Take $version
vmplayer --version

# References:
# - https://ubuntu-mate.community/t/20-04-vmware-workstation-player-fails-to-build-kernel-modules-vmmon-vmnet/21176
wget https://github.com/mkubecek/vmware-host-modules/archive/workstation-$version.tar.gz
cd vmware-host-modules-workstation-$version
tar -cf vmmon.tar vmmon-only
tar -cf vmnet.tar vmnet-only
sudo cp -v vmmon.tar vmnet.tar /usr/lib/vmware/modules/source/
sudo vmware-modconfig --console --install-all

# If `getcwd` or commands with `*.ko` generate no such file errors during install, e.g.:
# ---
# /usr/bin/make -C $PWD SRCROOT=$PWD/. \
#   MODULEBUILDDIR= postbuild
# make[1]: Entering directory '/tmp/modconfig-89IfqQ/vmci-only'
# make[1]: 'postbuild' is up to date.
# make[1]: Leaving directory '/tmp/modconfig-89IfqQ/vmci-only'
# cp -f vmci.ko ./../vmci.o
# cp: cannot stat 'vmci.ko': No such file or directory
# ---
# Then compile manually.
~/bin/make-vmware-modules.sh
# ||
tar -xvf vmmon.tar && cd vmmon-only && make && cp ../vmmon.o "/lib/modules/$(uname -r)/kernel/drivers/misc/vmmon.ko.gz"
tar -xvf vmnet.tar && cd vmnet-only && make && cp ../vmnet.o "/lib/modules/$(uname -r)/kernel/drivers/misc/vmnet.ko.gz"
```

# qemu snapshots

- `savevm` / `loadvm`
    - https://translatedcode.wordpress.com/2015/07/06/tricks-for-debugging-qemu-savevm-snapshots/

# qemu passthrough

- [GitHub \- darkguy2008/hotplugger: VirtIO \(VFIO\) USB Port passthrough helper](https://github.com/darkguy2008/hotplugger)
