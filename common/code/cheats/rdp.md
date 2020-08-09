# rdp

# Use multiple monitors

```
mstsc /w:5000 /h:1600
```

# Workaround client path validations

```
net use X: \\tsclient\x
net use
```

# Mapping client devices

```
net use com1: \\tsclient\com2:
net use
```

https://docs.citrix.com/en-us/receiver/windows/current-release/optimize/map-client-devices.html#map-client-drives-to-host-side-drive-letters

# Automation

```ps1
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Collections.Specialized.StringCollection
$f.Add("D:\tmp\mypic1.bmp")
[System.Windows.Forms.Clipboard]::SetFileDropList($f)
```

https://superuser.com/questions/966428/is-there-a-way-to-programatically-copy-and-paste-to-an-rdp

# process name

mstsc.exe

# credentials

rdp > Edit

```
reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f
wmic /node:Testserver /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSGeneralSetting get SSLCertificateSHA1Hash
```

```ps1
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
```

# config

alternate shell:s:c:\winnt\system32\notepad.exe

# tsclient

Local devices and resources

On mRemoteNG:

Connections > Select: [entry] > Redirect > Set: Disk Drives = yes

On remote host:

Run mmc.
Under File, choose Add/Remove Snap-In.
Add the Resultant Set of Policy (RSoP) snap-in.
Right-click on Resultant Set of Policy and choose "Generate RSoP Data."
Choose logging mode and follow the on-screen prompts to select the computer you're interested in. You don't need user policy settings.

On local host:

Run gpedit.msc.
Navigate to Computer Configuration, Administrative Templates, Windows Components, Remote Desktop Services, Remote Desktop Session Host, Device and Resource Redirection.
Check whether "Do not allow drive redirection" is listed as Enabled.

https://serverfault.com/questions/254530/tsclient-share-is-blank-when-rdping-to-remote-windows-server

# test

```
grep -iE 'server port|full address' foo.rdp

qwinsta /server:1.2.3.4
quser /server:1.2.3.4
wmic /node:1.2.3.4 computersystem get username
```

```ps1
curl -v telnet://foo:3389
$socket = New-Object Net.Sockets.TcpClient($CurrentComputer, 3389);if ($socket.Connected) {$true};$socket.Close()} catch {})} {$true}
```

### remote login

```
gpreport /h report.html
```

# signatures

By default validated client-side
If validated server-side, error is:

> Your computer can't connect to the remote computer because the Connection Broker couldn't validate the settings specified in your RDP file. Contact your network administrator for assistance.

- [Feature Request: Support for RemoteApps · Issue \#226 · mRemoteNG/mRemoteNG · GitHub](https://github.com/mRemoteNG/mRemoteNG/issues/226)
- [Settings RDP loadbalanceinfo causes An internal error has occured · Issue \#1113 · mRemoteNG/mRemoteNG · GitHub](https://github.com/mRemoteNG/mRemoteNG/issues/1113)
- [Feature request: Add support for signed RDP connections · Issue \#1295 · mRemoteNG/mRemoteNG · GitHub](https://github.com/mRemoteNG/mRemoteNG/issues/1295)

- https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-roles#remote-desktop-connection-broker

# display the security dialog box

Ctrl+Alt+End (= Ctrl+Alt+Del on Host)


