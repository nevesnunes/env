@ECHO OFF
setlocal enabledelayedexpansion
for /r %%G in (*contextIMI.properties) do (
  for /f "tokens=2 delims=\" %%a in ("%%~pG") do (
   if not exist "D:\sand\contexts\%%a\" mkdir "D:\sand\contexts\%%a"
   copy "%%G" "D:\sand\contexts\%%a\"
  )
)
