- [ ] make generic parser for 2 column lists (source-target)
    - examples/c_call_graph.txt
- [ ] use argparse in parser scripts
- [ ] GCC RTL/tree Clang IR/parse tree

# categorization

- https://docs.oracle.com/javase/8/docs/api/overview-summary.html
    - java.net
    - java.nio
    - java.io
    - java.sql
    - javax.xml.soap
- https://github.com/spring-projects/spring-ws/search?q=soap&unscoped_q=soap
- https://github.com/spring-projects/spring-ws-samples
    - ! https://github.com/spring-projects/spring-ws-samples/tree/master/weather
- https://github.com/spring-guides/gs-producing-web-service
- https://github.com/spring-guides/gs-consuming-web-service

```bash
mvn clean compile assembly:single
mvn clean package assembly:assembly -DdescriptorId=jar-with-dependencies
```

- https://stackoverflow.com/questions/278596/list-of-dependency-jar-files-in-maven
- https://stackoverflow.com/questions/574594/how-can-i-create-an-executable-jar-with-dependencies-using-maven
- [T] manually specified assembly file with moduleSet
    - https://books.sonatype.com/mvnref-book/reference/assemblies-sect-best-practices.html
        > [INFO] Failed to create assembly: Artifact: org.sonatype.mavenbook.assemblies:app-web:jar:1.0-SNAPSHOT (included by module) does not have an artifact with a file. Please ensure the package phase is run before the assembly is generated.

```bash
mvn dependency:copy-dependencies -DoutputDirectory="$(realpath ../../data/)"
mvn package
cp target/*.jar ../../data/

grep -i 'send\|weather' examples/data/calls.txt > examples/data/calls2.txt
./parsers/java-callgraph/parser.py <(echo examples/data/calls2.txt) > examples/data/calls.json
```

code/src/sum
code/src/call-summaries
deploy/imi/bin/call-summaries-master
env/imi/bin/call-summaries-master/sum.py
opt/call-explorer

# related work

- binary link graph - https://github.com/trishume/wikicrush
- [Show HN: Codemap – Codebase Visualizer for JavaScript, TypeScript, and Python | Hacker News](https://news.ycombinator.com/item?id=24241997)
