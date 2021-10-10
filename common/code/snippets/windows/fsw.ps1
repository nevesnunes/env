# https://stackoverflow.com/questions/29066742/watch-file-for-changes-and-run-command-with-powershell
function WaitFileChange {
    param(
        [string]$File,
        [string]$Action
    )
    $FilePath = Split-Path $File -Parent
    $FileName = Split-Path $File -Leaf
    $ScriptBlock = [scriptblock]::Create($Action)

    $Watcher = New-Object IO.FileSystemWatcher $FilePath, $FileName -Property @{
        IncludeSubdirectories = $false
        EnableRaisingEvents = $true
    }
    $onChange = Register-ObjectEvent $Watcher Changed -Action {$global:FileChanged = $true}

    while ($global:FileChanged -eq $false){
        Start-Sleep -Milliseconds 100
    }

    & $ScriptBlock
    Unregister-Event -SubscriptionId $onChange.Id
}
WaitFileChange -File $(gci hello) -Action {
    Write-Host "File changed!"
}
