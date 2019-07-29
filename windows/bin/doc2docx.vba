Sub SaveAllAsDOCX()
Dim strFileName As String
Dim strDocName As String
Dim strPath As String
Dim oDoc As Document

With Dialogs(wdDialogCopyFile)
If .Display <> 0 Then
strPath = .Directory
Else
MsgBox "Cancelled by User"
Exit Sub
End If
End With

If Documents.Count > 0 Then
Documents.Close SaveChanges:=wdPromptToSaveChanges
End If
If Left(strPath, 1) = Chr(34) Then
strPath = Mid(strPath, 2, Len(strPath) - 2)
End If
strFileName = Dir$(strPath & "*.doc")

While Len(strFileName) <> 0
Set oDoc = Documents.Open(strPath & strFileName)

strDocName = ActiveDocument.FullName
intPos = InStrRev(strDocName, ".")
strDocName = Left(strDocName, intPos - 1)
strDocName = strDocName & ".docx"
oDoc.SaveAs FileName:=strDocName, _
FileFormat:=wdFormatDocumentDefault
oDoc.Close SaveChanges:=wdDoNotSaveChanges
strFileName = Dir$()
Wend
End Sub
