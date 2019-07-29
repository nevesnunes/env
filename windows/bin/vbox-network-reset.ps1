# See:
# https://www.virtualbox.org/ticket/14374
#
# [/Devices/e1000/0/LUN#0/Config/] (level 5)
# IfPolicyPromisc      <string>  = "allow-all" (cb=10)
# IgnoreConnectFailure <integer> = 0x0000000000000001 (1)
# Network              <string>  = "HostInterfaceNetworking-Intel(R) Ethernet Connection (5) I219-LM" (cb=65)
# Trunk                <string>  = "\DEVICE\{00000000-0000-0000-0000-000000000000}" (cb=47)
# TrunkType            <integer> = 0x0000000000000003 (3)
# 
# [/Devices/e1000/1/LUN#0/Config/] (level 5)
# IfPolicyPromisc      <string>  = "allow-all" (cb=10)
# IgnoreConnectFailure <integer> = 0x0000000000000001 (1)
# Network              <string>  = "HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter #2" (cb=65)
# Trunk                <string>  = "VirtualBox Host-Only Ethernet Adapter #2" (cb=41)
# TrunkType            <integer> = 0x0000000000000004 (4)

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string] $vm,
)

& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $vm --details
& "c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm $vm nic1 null 
& "c:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm $vm nic1 bridged "Intel(R) Ethernet Connection (5) I219-LM"
