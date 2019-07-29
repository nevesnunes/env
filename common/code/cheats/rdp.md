# process name

mstsc

# credentials

rdp > Edit

reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "AuthenticationLevelOverride" /t "REG_DWORD" /d 0 /f
wmic /node:Testserver /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSGeneralSetting get SSLCertificateSHA1Hash
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

# test

grep -iE 'server port|full address' foo.rdp

qwinsta /server:10.254.63.47
quser /server:10.254.63.47
wmic /node:10.254.63.47 computersystem get username

curl -v telnet://foo_host:3389
$socket = New-Object Net.Sockets.TcpClient($CurrentComputer, 3389);if ($socket.Connected) {$true};$socket.Close()} catch {})} {$true}

### remote login
gpreport /h report.html

# signatures

By default validated client-side
If validated server-side, error is:
```
Your computer can't connect to the remote computer because the Connection Broker couldn't validate the settings specified in your RDP file. Contact your network administrator for assistance.
```

https://github.com/mRemoteNG/mRemoteNG/issues/226
https://github.com/mRemoteNG/mRemoteNG/issues/1113
https://github.com/mRemoteNG/mRemoteNG/issues/1295

https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-roles#remote-desktop-connection-broker

# process

mstsc.exe

# display the security dialog box

Ctrl+Alt+End (= Ctrl+Alt+Del on Host)
