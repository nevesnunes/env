# Allow content

Tools menu > Internet Options > Advanced > Security > Check: "Allow active content to run in files on My Computer"

# Allow sites

Tools menu > Internet Options > Security > Trusted Sites > Sites...

# Enable file downloads

Tools menu > Internet Options > Security > Custom Level > Security Settings > Downloads > On "File download", select: Enable

# Enable java

1. Tools menu > Internet Options > Security > Custom Level > Security Settings > Scripting > On "Scripting of Java applets", select: Enable
2. Tools menu > Internet Options > Security > Custom Level > Security Settings > ActiveX controls and plug-ins > On "Run ActiveX controls and plug-ins", select: Enable
3. Tools menu > Internet Options > Programs > Manage add-ons > On "Toolbars and Extensions", select entry, set status = Enabled

On missing ActiveX plugin in "Manage Add-ons":

```ps1
regsvr32 -s 'C:\Program Files\Java\jre1.8.0_*\bin\jp2iexp.dll'
```

On "An add-on for this site failed to run":

1. Tools menu > Internet Options > Security > Trusted sites > Sites > Add
2. Tools menu > Internet Options > Security > Restricted sites > Sites > On entry present: Delete

On "For security, applications must now meet the requirements [...]":

javacpl.exe > Security > On "Exception Site List", select: Edit Site List... > Add > Location = https://foo.com/

Validation:

Tools > Manage Add-ons > Show = Run without permission > Select entry: Java plug-in > More Information > Extract: Class ID

```ps1
$ClassID="08B0E5C0-4FCB-11CF-AAA5-00401C608501"
reg query "HKLM\Software\Classes\Wow6432Node\CLSID\{$ClassID}"
reg query "HKLM\Software\Classes\CLSID\{$ClassID}"
```

Output:

```
May have indirect reference to plug-in CLSID:

HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{08B0E5C0-4FCB-11CF-AAA5-00401C608501}\TreatAs
    (Default)    REG_SZ    {8AD9C840-044E-11D1-B3E9-00805F499D93}

Value matches plug-in name:

HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8AD9C840-044E-11D1-B3E9-00805F499D93}
    (Default)    REG_SZ    Java Plug-in 11.251.2
```

# Enable javascript

Tools menu > Internet Options > Security > Custom Level > Security Settings > Scripting > On "Active scripting", select: Enable

# Single Sign On

Tools menu > Internet Options > Security > Custom Level > Security Settings > On "User Authentication", select: Prompt for user name and password’ in User Authentication

# Debug

Developer Tools (F12) > Debugger (Tab, CTRL-3) > Change Exception Behavior (CTRL-SHIFT-E) > Select: Break on unhandled exceptions
||
Tools > Internet Options > Advanced > Browsing > Uncheck: Disable script debugging (Internet Explorer), Disable script debugging (other)

# Compatibility

https://kangax.github.io/compat-table/es6/
https://caniuse.com/

https://github.com/amilajack/eslint-plugin-compat
http://jshint.com/docs/
    esversion = 3
