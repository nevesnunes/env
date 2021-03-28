Set tables = GetObject("winmgmts:\\.\root\wmi").ExecQuery _
    ("SELECT * FROM MSSmBios_RawSMBiosTables")
For Each obj In tables
    size = 64 * obj.SMBiosData(9) + 64
Next
If size > 128 Then
    Console-Out "vm detected"
End If
