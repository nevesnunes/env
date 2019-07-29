[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)] [string] $folderPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try {
	$PSDefaultParameterValues['*:ErrorAction']='Stop'
} catch {
	$PSDefaultParameterValues=@{'*:ErrorAction'='Stop'}
}

#$pathInfo=[System.Uri]$folderPath
#if ($pathInfo.IsUnc) {
#    "echo off; net use Z: $localPath" | cmd
#    $folderPath="Z:\\"
#}

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $folderPath
$watcher.Filter = "*.*"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $logline = "$(Get-Date), $changeType, $path"
    Write-Host "Got event: $logline"
    #Add-content "$env:USERPROFILE\watch.log.txt" -value $logline
}
$changed = Register-ObjectEvent $watcher Changed -Action $action
$created = Register-ObjectEvent $watcher Created -Action $action
$deleted = Register-ObjectEvent $watcher Deleted -Action $action
$renamed = Register-ObjectEvent $watcher Renamed -Action $action

try {
    Write-Host "Waiting for events..."
    while ($true) {
        $result = $watcher.WaitForChanged( `
            [System.IO.WatcherChangeTypes]::Changed -bor  `
            [System.IO.WatcherChangeTypes]::Created -bor  `
            [System.IO.WatcherChangeTypes]::Deleted -bor  `
            [System.IO.WatcherChangeTypes]::Renamed,  `
            1000);
        if ($result.TimedOut) {
            continue;
        }
    }
} finally {
    Write-Host "Unregistering events..."
    Unregister-Event $changed.Id
    Unregister-Event $created.Id
    Unregister-Event $deleted.Id
    Unregister-Event $renamed.Id
}
