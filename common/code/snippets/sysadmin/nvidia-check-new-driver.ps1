$URI = 'http://www.geforce.com/proxy?proxy_url=http%3A%2F%2Fgfwsl.geforce.com%2Fservices_toolkit%2Fservices%2Fcom%2Fnvidia%2Fservices%2FAjaxDriverService.php%3Ffunc%3DDriverManualLookup%26psid%3D101%26pfid%3D815%26osID%3D57%26languageCode%3D1078%26beta%3D0%26isWHQL%3D1%26dltype%3D-1%26sort1%3D0%26numberOfResults%3D10'
$Download = (Invoke-WebRequest $URI | ConvertFrom-Json | Select -ExpandProperty IDS)[0].downloadInfo.DownloadURL

# Installed driver version (21.21.13.7570) > NVIDIA driver version (375.70)
[Version]$Driver = (Get-WmiObject Win32_PnPSignedDriver | Select DeviceName, DriverVersion, Manufacturer | Where { $_.Manufacturer -eq "NVIDIA" -and $_.DeviceName -like "*GeForce GTX*" }).DriverVersion
[Version]$CurrentDriver = ("{0}{1}" -f $Driver.Build,$Driver.Revision).Substring(1).Insert(3,'.')

# Latest driver on NVIDIA's website
[Version]$LatestDriver = ([System.Uri]$Download).Segments[-2].Trim('/')

If ($CurrentDriver -lt $LatestDriver) {
  Write-Output "New driver available"
  Start-BitsTransfer -Source $Download -Destination "$env:USERPROFILE\Downloads"
  (New-Object -ComObject WScript.Shell).Popup("New NVIDIA driver downloaded",0,"Update")
} Else {
  Write-Output "Same version. Nothing to download"
}
