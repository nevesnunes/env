# Executables

```
%windir%\system32\inetsrv\InetMgr.exe
```

# Debug

```
%SystemDrive%\inetpub\logs\LogFiles
```

# Disable server-side file cache

IIS Manager > Select entry: Server > Sites > Default Web Site > Select entry: Site > Compression

- Uncheck: Enable dynamic content compression
- Uncheck: Enable static content compression

# Enable Integrated Windows Authentication

```
%windir%\System32\inetsrv\appcmd.exe set config "Default Web Site" -section:system.webServer/security/authentication/windowsAuthentication /enabled:"True" /commit:apphost
%windir%\System32\inetsrv\appcmd.exe set config "Default Web Site" -section:system.webServer/security/authentication/windowsAuthentication /-"providers.[value='Negotiate']" /commit:apphost
```

# Authentication

https://docs.microsoft.com/en-us/archive/blogs/david.wang/howto-diagnose-401-x-http-errors-on-iis
