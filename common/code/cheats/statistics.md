# throughput, 95th percentile

```bash
{ seq 1 100 | xargs -i echo 50 & seq 1 100 } | python2 ~/opt/data_hacks/data_hacks/ninety_five_percent.py
# 91
seq 1 200 | python2 ~/opt/data_hacks/data_hacks/ninety_five_percent.py 
# 191
```

https://github.com/bitly/data_hacks
https://github.com/makeyourownmaker/apache-response-time

https://www.sumologic.com/insight/apache-response-time/
https://www.semaphore.com/95th-percentile-bandwidth-metering-explained-and-analyzed/

# ngrams, ranked sort

https://github.com/datascopeanalytics/datascope-tools
