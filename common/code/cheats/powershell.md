# +

```ps1
Compare-Object -SyncWindow 0
Invoke-WebRequest -UseBasicParsing
... | Format-Table -AutoSize
```

https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod

# References

https://4sysops.com/
https://aka.ms/pskoans

# WinForms

https://4sysops.com/archives/how-to-create-an-open-file-folder-dialog-box-with-powershell/
    dialog
https://theitbros.com/powershell-gui-for-scripts/
    combobox, button
https://maikthulhu.github.io/2018-07-14-powershell-forms-controls/
    class
https://adamtheautomator.com/build-powershell-gui/
    designed in visualstudio, imported via xaml
    textbox
https://poshgui.com/
    web designer

# Memory Usage

Get-Process -Name foo | %{$_.PM} | Measure-Object -Sum

# Testing

https://stackoverflow.com/questions/43213624/how-can-i-automatically-syntax-check-a-powershell-script-file

# man

```ps1
Update-Help
Get-Help Format-Table -Full
```

https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help?view=powershell-7

# system info

```ps1
Get-ComputerInfo
# ||
Get-WmiObject Win32_ComputerSystem
Get-WmiObject Win32_OperatingSystem
Get-WmiObject Win32_BIOS
Get-WmiObject Win32_Processor
Get-WmiObject Win32_LogicalDisk
```

# pager

```ps1
foo | out-host -paging
# Search = Context Menu > Edit > Find...
# ||
more
# ||
foo | sls 'FATAL|ERROR|WARN'
# ||
# match in time range
```

# current running processes cmdline

```ps1
Get-WmiObject Win32_Process | Select-Object Name,CommandLine
```

# run as nt authority\system

```ps1
powershell -ep bypass "Install-Module -Name NtObjectManager; $v = start-Win32ChildProcess cmd"
```

# balloon notifications

System.Windows.Forms.NotifyIcon
https://www.powershellgallery.com/packages/BurntToast/0.6.2
```
msg.exe 5 /server:server1 This is a message to the user in Session 5 on server 1
```

# test file exists

```ps1
if ([System.IO.File]::Exists($AbsoluteFilePath)) {
    # ...
}
```

# search all logs

```ps1
$search = 'hrome'
Get-WinEvent -ListLog * |
    ? { $_.RecordCount -gt 0 } |
    % { Get-WinEvent -FilterHashtable @{StartTime=((Get-Date).AddDays(-1)); LogName=$_.logname} -ea 0 } |
    where message -match $search 2>$null

$search = 'hrome'
Get-WinEvent -ListLog * |
    ? { $_.RecordCount -gt 0 } |
    % { (Get-EventLog -LogName $_.logname -after (Get-Date).AddDays(-1) | 
        Select-Object -Property Category,Index,TimeGenerated,
        EntryType,Source,InstanceID,Message 2>$nul) -match $search | Format-Table -AutoSize } 2>$null
```
