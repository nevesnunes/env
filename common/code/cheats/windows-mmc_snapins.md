<!--
References:
- https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/throw-away-your-mouse-a-list-of-windows-snap-ins-and-applets/ba-p/395183
- https://serverfault.com/questions/158075/what-are-the-names-of-common-mmc-snapins
- https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/registering-and-unregistering-a-snap-in
- https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms692759(v%3Dvs.85)
- $env:userprofile\opt\mmcsnapinsview-x64\MMCSnapInsView.exe /scomma windows-mmcsnapinsview.csv
- Get-ItemProperty -Path HKLM:\Software\Microsoft\MMC\SnapIns\* | Select-Object -Property NameString,NameStringIndirect | Format-Table
- Get-ChildItem -File -Filter '*.msc' -Path C:\Windows\System32 | Select-Object -Property Name

Usage:
- InstallUtil.exe foo.dll
-->

# Common

azman.msc                  | Authorization Manager
comexp.msc                 | Component Services
devmgmt.msc                | Device Manager
DevModeRunAsUserConfig.msc | Start Menu and Taskbar 
diskmgmt.msc               | Disk Management
fsmgmt.msc                 | Shared folders
perfmon.msc                | Performance Monitor
printmanagement.msc        | Print Management
taskschd.msc               | Task Scheduler
tpm.msc                    | Trusted Platform Module
WF.msc                     | Windows Defender Firewall with Advanced Security
WmiMgmt.msc                | Console Root\WMI Control (Local)
adfs.msc                   | AD Federation Services
certlm.msc                 | Certificate Management - Local Machine
certmgr.msc                | Certificate Management - Current User
certsrv.msc                | Certification Authority
certtmpl.msc               | Certificate Templates
compmgmt.msc               | Computer Management
comexp.msc                 | Component Services - C:\windows\system32\com
dcomcnfg                   | Component Services
dsa.msc                    | ADUC (AD Users and Computers)
dfsgui.msc                 | DFS Management
dfsmgmt.msc                | DFS Management R2
dnsmgmt.msc                | DNS Management
domain.msc                 | Domains and Trusts
dssite.msc                 | Sites and Services
eventvwr.msc               | Event Viewer
gpedit.msc                 | Local Policy
gpmc.msc                   | Group Policy Management Console
lusrmgr.msc                | Local Users
pkiview.msc                | PKI management
rsop.msc                   | Resultant set of Policy
secpol.msc                 | Local Security Policy
services.msc               | Services
schmmgmt.msc               | Schema Management
taskmgr                    | Task Manager
tscc.msc                   | TS Configuration

# Executables

tsadmin                    | TS Administrator
licmgr                     | TS Licensing

# Windows Server 2003 Administration Tools Pack

admgmt.msc                 | AD Management –Domains, Sites, DNS and ADUC
ipaddrmgmt.msc             | WINS, DNS and DHCP in one console
pkmgmt.msc                 | PKI Management – Authorities, Templates

# Windows Server 2008

cluadmin.msc               | Failover Cluster Manager
napclcfg.msc               | Network Access Protection Client Configuration
servermanager.msc          | Server Manager
storexpl.msc               | Storage Manager
tsconfig                   | TS Configuration
wbadmin                    | Windows Server Backup
wf.msc                     | Windows Firewall + Advanced Security
