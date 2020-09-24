# git-dsl

define commands to closely match mental model, using vocabulary specific to state, graphs, and other objects

https://www.google.com/search?q=git+mental+model

# case studies

https://stackoverflow.com/questions/2530060/in-plain-english-what-does-git-reset-do
    git reset --hard => rollback working tree, point to commit X in branch X

# related work

[Vincent Ogloblinsky \- Hidden Gems of TypeScript compiler \- YouTube](https://www.youtube.com/watch?v=WkJagE7b5U0)
    https://slides.com/vogloblinsky/hidden-gems-of-typescript-compiler#/

https://thorny.io/blog/how-and-why-i-wrote-a-transpiler
visitor pattern vs. direct AST manipulation
```cs
static void Convert(string indent, StringBuilder sb, MemberAccessExpressionSyntax memberExpr)
{
    ConvertExpression(indent, sb, memberExpr.Expression);
    sb.Append(".");
    ConvertSimpleName(indent, sb, memberExpr.Name);
}
```

https://engineering.mongodb.com/post/transpiling-between-any-programming-languages-part-1

https://www.bugsnag.com/blog/source-maps
https://www.html5rocks.com/en/tutorials/developertools/sourcemaps/#toc-base64vlq
https://github.com/Rich-Harris/vlq
https://docs.google.com/document/d/1U1RGAehQwRypUTovF1KRlpiOFze0b-_2gc6fAH0KY0k/edit#

https://en.wikipedia.org/wiki/XSLT

https://en.wikipedia.org/wiki/Source-to-source_compiler
https://en.wikipedia.org/wiki/Intermediate_representation


