@echo off
rem "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo "OTCS-Local" --details
rem "c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "OTCS-Local" nic1 null 
rem "c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "OTCS-Local" nic1 bridged "Intel(R) Ethernet Connection I219-LM"

"c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "OTCS-Local" nicpromisc1 allow-all
"c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "OTCS-Local" nicpromisc1 deny
"c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "OTCS-Local" nicpromisc1 allow-all
