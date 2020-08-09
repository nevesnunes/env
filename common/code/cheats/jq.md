# +

[jq Cheet Sheet · GitHub](https://gist.github.com/olih/f7437fb6962fb3ee9fe95bda8d2c8fa4)
https://megamorf.gitlab.io/cheat-sheets/cheat-sheet-jq.html

https://stackoverflow.com/questions/47551333/jq-convert-a-list-of-objects-into-a-summarized-object
https://stackoverflow.com/questions/42427725/using-jq-convert-array-of-objects-to-object-with-named-keys

# beautify / format

```bash
echo '{"a":1,"b":2}' | jq
# sort keys
echo '{"b":2,"a":1}' | jq -S '.'
# sort values
echo '{"b":2,"c":1}' | jq 'to_entries|sort_by(.value)|from_entries'
# reverse sort values
echo '{"b":2,"c":1}' | jq 'to_entries|sort_by(-.value)|from_entries'
```
