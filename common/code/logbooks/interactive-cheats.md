# interactive-cheats

aka. typecheat - composing snippets by typified inputs and outputs
! consider merging with markdown-wiki

## features

- inline live demos
    - repl || docker shell session
- custom url handler, generated for each snippet
    - e.g. ic://file/section/index?arg1type=file&arg1=foo&arg2type=int&arg2=
- on query refining, filter progressively more snippets/pipelines
    - e.g. search = n results, search file recursively = n-m results...
- order results by number of query tokens matched and expanded synonym weight

## graphs

? model snippets so that a graph of composable commands can be built
=> typify arguments in comments, collect snippets, build AST, create edges between snippets with same type of arguments
```bash
# @args
# foo: file
# bar: file
cp foo bar
```
:) enables snippet builder, where arguments from distinct snippets can be matched, composed as a result snippet

## schemas

[Ask HN: why isn&\#x27;t RDF more popular on HN? | Hacker News](https://news.ycombinator.com/item?id=7491925)
[SPARQL Protocol for RDF | Hacker News](https://news.ycombinator.com/item?id=14599462)
    https://graphql.org/learn/schema/
vs. markdown-wiki - links between pages, with description foreach task in target page manipulating concepts from current page (~= flow-chart)
    task validation for these conditional branches can also have dedicated snippets
vs. relational databases - multiple tables foreach relation type, recursive CTEs for traversal
vs. graph databases - query by task / concept, compose commands by selecting nodes in result graph
    https://neo4j.com/sandbox/
    https://neo4j.com/graphgists/
    https://neo4j.com/developer/neo4j-browser/
    https://neo4j.com/developer/example-project/
    https://stackoverflow.com/questions/32982626/how-to-embed-a-neo4j-graph-in-another-site
        https://github.com/neo4j-examples?utf8=%E2%9C%93&q=movie&type=&language=
xref. search-engine - synonym expansion

## related work

[Fig: Visual Apps and Shortcuts for Your Terminal | Hacker News](https://news.ycombinator.com/item?id=23766980)
