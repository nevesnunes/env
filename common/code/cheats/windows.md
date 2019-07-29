# modify disk partition

diskmgmt.msc
disable virtual memory

# network packet sniffer

fiddler

# debug crash dump

https://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-15-WinDbg-Bugchecks

# WMI event handlers

https://technet.microsoft.com/en-us/library/ff898417.aspx

# Verbatim Path Syntax

```
\\?\C:\Temp\COM2.TXT
```

# Browse volume over network

Folder Options > View > Uncheck `Use simple file sharing`

```
\\192.168.1.1\C$
```

# Admin privileges

boot repair disk
    replace `C:\Windows\System32\sethc.exe` with `C:\Windows\System32\cmd.exe`

# Disabled command prompt

.bat file
powershell
https://portableapps.com/apps/utilities/command_prompt_portable
https://forum.raymond.cc/threads/re-enable-project-ideas-and-suggestions.12672/
remove HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\DisableCMD DWORD 0

# reserved names, special devices, metadata

file:///c:/con/con
c:\con\con
c:\$MFT\123

# fix ntfs corruption

```bash
# From: sudo fdisk -l
sudo ntfsfix /dev/sdb1
# ||
chkdsk /R
```
# detect vm
Get-WmiObject -Class "Win32_computersystem" | Select *
gwmi Win32_BaseBoard

# detect 32/64 bits
gwmi win32_operatingsystem | select osarchitecture

vol
mountvol

REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\DateTime\Servers
w32tm /query /configuration
w32tm /monitor
w32tm /config /manualpeerlist:x.x.x.x /syncfromflags:manual /update
w32tm /resync /force

w32tm /config /syncfromflags:domhier /update
Restart-Service w32time

C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll

https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-member?view=powershell-6

https://github.com/d1pakda5/PowerShell-for-Pentesters/blob/master/20-Remoting-Part-1.md

– PowerShell functions. These are easy, since the function "is" the source code. You can do something like this to open the file up in the ise, if the command is a function: powershell_ise (Get-Command Get-CMSoftwareUpdate).ScriptBlock.File

– Cmdlets. These are .NET classes, usually written in C#. Unless the source code is open-source, you can't get its original form, but you can decompile back to a somewhat-readable C# file using free tools such as ILSpy or DotPeek. If it's a cmdlet, you can find the file that needs to be decompiled like this: (Get-Command Get-CMSoftwareUpdate).ImplementingType.Assembly.Location

– CIM commands. These are auto-generated PowerShell wrappers around WMI classes; they're generated from cdxml files in the module directory. I'm not sure if there's an easy way to open an individual command's file, but once you know that's what you're dealing with, you can browse to the module's folder and open up the cdxml files to see what it's doing.

# Paths, Shortcuts

```
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
%AppData%\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
%AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar
C:\ProgramData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar

%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles

%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Extensions*
`grep 'foo\|bar' Extensions` > hashes
chrome://extensions > Load unpacked extension... > hash1/version1,hash2/version2...

%windir%\system32\cmd.exe /c "D:\bin\eclipse.cmd"

//VBOXSVR/z
```

### Forbidden names

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileAssociation\AddRemoveNames

# Special Folders, URL Monikers

start shell:RecycleBinFolder

regedit /e C:\folderDescriptions 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions'

https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775149(v=vs.85)
https://stackoverflow.com/questions/3605148/where-can-i-learn-about-the-shell-uri

# Restart Shell

taskmgr.exe (Task Manager) > File > Run New Task > explorer.exe

# Task Scheduler

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2000/bb726974(v=technet.10)
"C:\WINDOWS\system32\mmc.exe" C:\WINDOWS\system32\taskschd.msc

# Event Viewer

eventvwr

Computer management > System Tools > Event Viewer > Windows Logs > System

# Certificates, Policies

certmgr.msc
gpedit.msc
gpupdate

### Prevent exe from running

ClickToRunSvc

https://docs.microsoft.com/en-us/previous-versions/technet-magazine/cc510322(v=msdn.10)

User Configuration > Administrative Templates > System > Don't run specified Windows applications
Software\Policies\Microsoft\Windows\EventLog\Security\System

# Process using file

resmon
perfmon > CPU > Associated Handles

# Process Monitor, env vars of process

Operation is Process Create
Operation is Process Start

Sort Column => Tools > File Summary

# Process Monitor, file access

Operation is ReadFile
Operation is WriteFile
Path contains ...

# Powershell

```ps1
gci env:*
$env:Path.split(';')

[Environment]::SetEnvironmentVariable("k", "v", "User")

Get-Command _ | Select-Object -ExpandProperty Definition

[System.Net.ServicePointManager]::CertificatePolicy | Get-Member -Type All
[System.Reflection.Assembly]::GetAssembly([System.Net.ServicePointManager]::CertificatePolicy.GetType()) | Format-Table -Wrap 

gwmi win32_operatingsystem | select osarchitecture
```

# Hyper-V

To disable Hyper-V in order to use VirtualBox, open a command prompt as administrator and run the command:

bcdedit /set hypervisorlaunchtype off

You’ll need to reboot, but then you’ll be all set to run VirtualBox. To turn Hyper-V back on, run:

bcdedit /set hypervisorlaunchtype auto

### Separate boot menu entry

bcdedit /copy {current} /d "No Hyper-V" 
bcdedit /set {ff-23-113-824e-5c5144ea} hypervisorlaunchtype off 

# Network, Hosts, IP

netstat -bano

ipconfig /flushdns

getmac
ipconfig -all
nbtstat -A $IP
ping -a $IP
nslookup $IP

# Disable warnings

REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoLowDiskSpaceChecks /t REG_DWORD /d 1

# Allow remove/uninstall program

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# DHCP

https://www.microsoft.com/en-us/download/details.aspx?id=45520
REG ADD HKLM\SOFTWARE\Microsoft\NetSh /v dhcpmon /t REG_SZ /d dhcpmon.dll

netsh dhcp server 10.254.64.188 show clients 1
netsh -r 10.254.64.188 dhcp server dump

# Routing and Remote Access

net stop dns; net start dns; net stop remoteaccess; net start remoteaccess

# Clear cached credentials

net use * /delete
klist purge

cmdkey /delete:targetname
    batch script to iterate through targets

rundll32.exe keymgr.dll,KRShowKeyMgr

# Run as another user credentials

```
$username = 'user'
$password = 'password'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process Notepad.exe -Credential $credential

# ||

Start-Process powershell.exe -Credential $Credential -Verb RunAs -ArgumentList ("-file $args")
Start-Process -Verb RunAs powershell.exe -Args "-executionpolicy bypass -command Set-Location \`"$PWD\`"; .\install.ps1"
Powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File .\Install.ps1
```

# Language bar

ctfmon.exe

# Registry

regedit /e C:\dump.txt "HKEY_LOCAL_MACHINE\SYSTEM"

# flags, compatibility mode

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers

# event tracing

logman start "NT Kernel Logger" –p "Windows Kernel Trace" (process,thread,img,disk,net,registry) –o systemevents.etl –ets
logman stop "NT Kernel Logger" –ets
tracerpt systemevents.etl

logman start -ets mywinsocksession -o winsocklogfile.etl -p Microsoft-Windows-Winsock-AFD
logman stop -ets mywinsocksession
tracerpt winsocktracelog.etl –o winsocktracelog.txt

# tcp, connection

https://blogs.technet.microsoft.com/nettracer/2010/08/02/have-you-ever-wanted-to-see-which-windows-process-sends-a-certain-packet-out-to-network/
https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview

netstat -t

https://community.microstrategy.com/s/article/KB16328-How-to-enable-and-configure-Keep-Alive-options-for
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters

# dns

Can ping dns server, can't resolve addresses
=> DNS Manager > Properties > Interfaces > Listen on: Only the following IP addresses: $VPN_IP

# run as current login user

1. C:\Windows\System32\runas.exe /user:CORPPRO\776079E /savecreds cmd.exe
2. D:\msys2-32bits\msys2.exe > start cmd

# wireless password

netsh.exe wlan show profiles name='Profile Name' key=clear

# import root certificates

$files = Get-ChildItem -File .\*; foreach ($f in $files) { Import-Certificate -FilePath $f.FullName -CertStoreLocation Cert:\LocalMachine\Root }
# ||
certutil -addstore -user "Trusted Root Certification Authorities" cert.pem

# groups

gpresult /v
gpresult /r
whoami /groups
net user USERNAME /domain

# file handlers

https://blogs.technet.microsoft.com/markrussinovich/2009/09/29/pushing-the-limits-of-windows-handles/
https://stackoverflow.com/questions/31108693/increasing-no-of-file-handles-in-windows-7-64-bit

# Environment Variables

https://en.wikipedia.org/wiki/Environment_variable#Windows

# find in time range

$today = (Get-Date)
$startDate = $today.Date.AddDays(-14)
$endDate = $startDate.AddDays(7)
gci -Recurse -Path '*/logs/*' | sort lastwritetime | Where-Object { [DateTime]$_.Timestamp -ge $startDate -and [DateTime]$_.Timestamp -lt $endDate }

# grep

gci -recurse | sls -pattern "foo"

# == ls -ltr

dir | Sort-Object LastAccessTime


# +

```
get-command notepad.exe | select Source
for %i in (java.exe) do @echo. %~$PATH:i
dir /s /b c:\*java.exe

cd HKCU:\

shutdown /r /t 0

findstr /I /S /P /C:"foo" *
dir /s/b *.wsdl

tasklist /fi "pid eq 15004"
taskkill /IM firefox.exe /F
taskkill /PID 26356 /F

https://www.sans.org/security-resources/sec560/windows_command_line_sheet_v1.pdf
https://www.lemoda.net/windows/windows2unix/windows2unix.html

wget "_" -Verbose | select -ExpandProperty "Headers"

ffmpeg -f gdigrab -framerate 30 -i desktop output.mkv

./Windows/Microsoft.NET/Framework/v4.0.30319/ASP.NETWebAdminFiles/web.config
./Windows/Microsoft.NET/Framework/v4.0.30319/Config/web.config

---

https://winaero.com/blog/find-hard-disk-serial-number-windows-10/
https://superuser.com/questions/498083/how-to-get-hard-drive-serial-number-from-command-line
GWMI -namespace root\cimv2 -class win32_volume | FL -property DriveLetter, DeviceID
Get-WmiObject Win32_volume | Format-table Name, @{Label = "SerialNumber"; Expression = {"{0:X}" -f $_.SerialNumber}}  -auto
Get-WmiObject Win32_logicaldisk | Format-table Name, volumeserialnumber
```
