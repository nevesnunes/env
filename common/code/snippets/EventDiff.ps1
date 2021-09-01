# Log the time prior to executing the action.
# This will be used as parth of an event log XPath filter.
$DateTimeBefore = [Xml.XmlConvert]::ToString((Get-Date).ToUniversalTime(), [System.Xml.XmlDateTimeSerializationMode]::Utc)

# Do the thing now that you want to see potential relevant events surface...
$null = Mount-DiskImage -ImagePath "$PWD\FeelTheBurn.iso" -StorageType ISO -Access ReadOnly

# Allow a moment to allow events to populate
Start-Sleep -Seconds 5

# Iterate over every event log that has populated events and
# has events that were generated after we noted the time.
$Events = Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object {
    Get-WinEvent -LogName $_.LogName -FilterXPath "*[System[TimeCreated[@SystemTime >= '$DateTimeBefore']]]" -ErrorAction Ignore
}

$Events
