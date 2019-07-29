import ast

class MyVisitor(ast.NodeVisitor):
    def visit_Str(self, node):
        print 'Found string "%s"' % node.s


class MyTransformer(ast.NodeTransformer):
    def visit_Str(self, node):
        return ast.Str('str: ' + node.s)


node = ast.parse('''
favs = ['berry', 'apple']
name = 'peter'

for item in favs:
    print '%s likes %s' % (name, item)
''')

MyTransformer().visit(node)
MyVisitor().visit(node)
