# Monitoring

https://www.elastic.co/guide/en/apm/server/current/overview.html
    https://medium.com/@vrishod/fetching-apm-application-performance-metrics-in-python-flask-using-elasticsearch-and-kibana-in-1ed0600a19b0

# Indexing

e.g. elasticsearch index guidelines
[xref] feature engineering

https://thoughts.t37.net/designing-the-perfect-elasticsearch-cluster-the-almost-definitive-guide-e614eabc1a87#9898

# Related Work

https://stackshare.io/elasticsearch
http://solr-vs-elasticsearch.com/

# +

https://blog.bitsrc.io/how-to-build-an-autocomplete-widget-with-react-and-elastic-search-dd4f846f784
https://medium.appbase.io/how-to-build-a-movie-search-app-with-react-and-elasticsearch-2470f202291c
https://www.freecodecamp.org/news/building-a-github-repo-explorer-with-react-and-elasticsearch-8e1190e59c13/

https://dejavu.appbase.io/?&appname=hackernews-live&url=https://kxBY7RnNe:4d69db99-6049-409d-89bd-e1202a2ad48e@scalr.api.appbase.io&mode=view
https://github.com/appbaseio/dejavu
```
docker run -p 1358:1358 -d appbaseio/dejavu
docker run -d --rm --name elasticsearch -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" -e "http.cors.enabled=true" -e "http.cors.allow-origin=*" -e "http.cors.allow-headers=X-Requested-With,X-Auth-Token,Content-Type,Content-Length,Authorization" -e "http.cors.allow-credentials=true" docker.elastic.co/elasticsearch/elasticsearch-oss:7.0.1
```

https://stackoverflow.com/questions/48711455/how-do-i-create-a-dockerized-elasticsearch-index-using-a-python-script-running
https://blog.patricktriest.com/text-search-docker-elasticsearch/
https://medium.appbase.io/building-booksearch-application-using-vue-and-elasticsearch-a39615f4d6b3
https://reactivesearch-vue-playground.netlify.com/
https://www.google.com/search?q=elasticsearch+python+docker+tutorial

https://www.html5rocks.com/en/tutorials/file/dndfiles/
https://www.npmjs.com/package/react-file-viewer
https://github.com/rexxars/react-markdown
https://github.com/highlightjs/highlight.js

https://www.elastic.co/guide/en/elasticsearch/plugins/current/ingest-attachment.html
    https://stackoverflow.com/questions/37861279/how-to-index-a-pdf-file-in-elasticsearch-5-0-0-with-ingest-attachment-plugin?rq=1
    https://stackoverflow.com/questions/7797217/how-to-index-source-code-with-elasticsearch
    https://discuss.elastic.co/t/index-and-query-source-code/38979/6
    https://dzone.com/articles/elasticsearch-mapping-the-basics-two-types-and-a-f
https://github.com/jimmylai/knowledge
    synonyms, structure data
http://blog.comperiosearch.com/blog/2014/09/18/bitbucket-elasticsearch-connector/
http://blog.comperiosearch.com/blog/2014/01/30/elasticsearch-indexing-sql-databases-the-easy-way/
http://springer.iq-technikum.de/article/10.1007/s10664-019-09697-7
hierarchical facets
    https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations.html
    http://www.springyweb.com/2012/01/hierarchical-faceting-with-elastic.html
    https://sharing.luminis.eu/blog/faceted-search-with-elasticsearch/


