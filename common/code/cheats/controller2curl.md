https://stackoverflow.com/questions/34197169/how-to-invoke-a-java-class-of-another-jar-file
    URLClassLoader
        war => pass directly or extract and pass dir
http://static.javadoc.io/com.github.javaparser/java-symbol-solver-core/0.6.3/com/github/javaparser/symbolsolver/javaparsermodel/declarations/JavaParserClassDeclaration.html
type references
    https://github.com/javaparser/javasymbolsolver/issues/258

ccv
    marker
        name == RestController
    singlemember
        name == RequestMapping
        value => url
cmv
    childnodes
        RequestParam => continue
        value = "foo"
            childnodes
                value
                "foo" => url
    parentNode
        type
            ClassOrInterfaceDeclaration clazz = JavaParser.parse(file).getClassByName(name).get();
                => default value
        name
                => ?name=,&name=
