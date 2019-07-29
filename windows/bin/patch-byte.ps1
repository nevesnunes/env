echo "abcd" > a.txt
$bytes = [System.IO.File]::ReadAllBytes("a.txt")
$bytes[2] = 0x06
[System.IO.File]::WriteAllBytes("a.txt", $bytes)
xxd a.txt
