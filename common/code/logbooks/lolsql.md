# Living off the land - SQL

## parsing

? keeping track of last line / seek offset on file, continuing after file modified notify event
! https://powershell.org/forums/topic/parsing-log-files/
    https://devblogs.microsoft.com/powershell/parsing-text-with-powershell-1-3/
```ps1
$pattern = [regex]"(?'datetime'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}).*User \`"(?'user'.+)\`" authenticated successfully"
Get-Content $src | % {
    if ($_ -match $pattern) {
        $timestamp = [datetime]$Matches['datetime']
    }
    # ...
}
```
|| https://stackoverflow.com/questions/48097865/how-to-use-the-log-parser-in-windows-powershell-by-using-for-each-loops-to-query
|| ConvertFrom-String
|| Import-CSV
StreamReader vs. Get-Content
https://www.sqlshack.com/reading-file-data-with-powershell/
```ps1
$sr = New-Object System.IO.StreamReader("C:\foo.log")
while (($line =$sr.ReadLine()) -ne $null) {
    # ...
}
$sr.Dispose()
```
https://github.com/AdysTech/PowerScripts

## hierarchies

```python
import networkx as nx
from networkx.readwrite import json_graph
G = nx.DiGraph([(1,2),(1,3),(3,4)])
data = json_graph.tree_data(G,root=1)
# Given graph with cycles:
# G = nx.DiGraph([(1,2),(1,3),(3,4),(4,1)])
# data = json_graph.tree_data(nx.bfs_tree(G, 1),root=1)
import json
s = json.dumps(data)
import pprint
pprint.pprint(s)
```

## querying

https://www.red-gate.com/simple-talk/sql/t-sql-programming/using-sqlite-powershell-sql-server/
    connector direct usage
https://github.com/RamblingCookieMonster/PSSQLite
    wrapper
    :) bundled connector
https://archive.codeplex.com/?p=psqlite
    mount database as drive
https://github.com/sql-js/sql.js
    wasm

Install-Module -Name PSSQLite -Scope CurrentUser
$home\Documents\PowerShell\Modules
https://docs.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershell-7


